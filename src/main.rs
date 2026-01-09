/**********************************************************************************************
 *  Modulname : secure_p2p_ext
 *  Datei     : main.rs
 *  Autor     : Marcus Schlieper
 *---------------------------------------------------------------------------------------------
 *  Beschreibung
 *  - P2P Chat Client mit Datei Transfer, Volltext Suche (Tantivy), Vektor Suche, Hybrid Suche.
 *  - Erweiterung: Vollstaendige IAM Integration in main.rs (Menue, Befehle, Session, Rechtecheck).
 *
 *  Historie
 *  09.11.2025  MS  - Grundversion (Chat, DOS Befehle, Handshake Topic)
 *  10.11.2025  MS  - Kryptographische Erweiterungen, Offline Queue, Audit
 *  13.11.2025  MS  - RAG Schlagwortsuche (Tantivy)
 *  15.11.2025  MS  - Hybrid combi_search
 *  09.01.2026  MS  - IAM Integration: Menue + Kommandos + Session Handling + Access Checks
 **********************************************************************************************/

#![allow(clippy::needless_return)]
#![allow(warnings)]

/* ===================================== Imports =========================================== */
use aes_gcm_siv::{
    aead::{Aead, KeyInit, OsRng},
    Aes256GcmSiv,
};
use blsttc::{SecretKeySet, SecretKeyShare, SignatureShare};
use futures::StreamExt;
use libp2p::{
    gossipsub, mdns, noise,
    swarm::{NetworkBehaviour, Swarm, SwarmEvent},
    tcp, yamux, PeerId,
};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sled::Db;
use std::{
    collections::{hash_map::DefaultHasher, HashMap, VecDeque},
    error::Error,
    fs,
    hash::{Hash, Hasher},
    io::Read,
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::{
    io,
    io::AsyncBufReadExt,
    select,
    sync::mpsc::{self, UnboundedSender},
};
use tracing_subscriber::{fmt, EnvFilter};

/* --- Tantivy ------------------------------------------------------------------------------ */
use tantivy::{
    collector::TopDocs,
    directory::MmapDirectory,
    doc,
    schema::{Schema, STORED, TEXT},
    Index, IndexReader, IndexWriter, ReloadPolicy, Term,
};

/* --- Dateiextraktion ---------------------------------------------------------------------- */
use calamine::{open_workbook_auto, Reader as _};
use pdf_extract::extract_text;
use sled::IVec;
use zip::read::ZipArchive;

/* --- Eigene Importe vector_idx ------------------------------------------------------------ */
mod vector_idx;
use crate::vector_idx::cosine;
use crate::vector_idx::VecSearchHit;
use crate::vector_idx::VectorIndex;
use vector_idx::{load_or_init_index, persist_index};

/* --- Eigene Importe IAM ------------------------------------------------------------------- */
mod iam;
mod iam_net;
use crate::iam::{
    iam_config, iam_error, iam_store, right_admin, right_create, right_local, right_public,
    right_publish, right_read, right_write, rights_mask,
};
use crate::iam_net::{iam_delta_push, iam_delta_request, iam_delta_response};
use rpassword;

/* ===================================== Konstanten ======================================== */
const CHUNK_SIZE: usize = 65_536;
const GLOBAL_TOPIC: &str = "expchat-main";
const DOC_DIR: &str = "Documents";
const IDX_DIR: &str = "tantivy_idx";
const IDX_INTERVAL_SEC: u64 = 30;

/* IAM: Pfad Scope fuer Remote Requests. */
const IAM_REMOTE_SCOPE_PUBLIC: bool = true;

/* ===================================== Payload =========================================== */
#[derive(Serialize, Deserialize, Debug, Clone)]
enum PayloadType {
    Text(String),
    DirRequest,
    DirResponse(String),
    FileRequest(String),
    FileTransfer(FileChunk),
    ChunkAck(u32),
    ConnectRequest,
    ConnectAck,
    OfflineFlush,

    SearchRequest {
        i_id: u64,
        s_query: String,
    },
    SearchResponse {
        i_id: u64,
        s_peer: String,
        v_hits: Vec<SearchHit>,
    },

    VecSearchRequest {
        i_id: u64,
        s_query: String,
    },
    VecSearchResponse {
        i_id: u64,
        s_peer: String,
        v_hits: Vec<VecSearchHit>,
    },

    CombiSearchRequest {
        i_id: u64,
        s_query: String,
    },
    CombiSearchResponse {
        i_id: u64,
        s_peer: String,
        v_hits: Vec<(String, f32)>,
    },

    /* IAM replication */
    IamDeltaPush(iam_delta_push),
    IamDeltaRequest(iam_delta_request),
    IamDeltaResponse(iam_delta_response),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ChatMessage {
    s_sender: String,
    payload: PayloadType,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct FileChunk {
    s_name: String,
    i_index: u32,
    i_total: u32,
    v_bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct SearchHit {
    s_doc: String,
    d_score: f32,
}

/* ===================================== Kryptographie ===================================== */
#[derive(Clone)]
struct CryptoContext {
    cipher: Aes256GcmSiv,
    bls_key: SecretKeyShare,
}
impl CryptoContext {
    fn new(a_aes_key: &[u8; 32], bls_share: SecretKeyShare) -> Self {
        Self {
            cipher: Aes256GcmSiv::new_from_slice(a_aes_key).expect("AES key invalid"),
            bls_key: bls_share,
        }
    }
    fn encrypt(&self, v_plain: &[u8]) -> Vec<u8> {
        let mut a_nonce = [0u8; 12];
        OsRng.fill_bytes(&mut a_nonce);
        let nonce = aes_gcm_siv::Nonce::from_slice(&a_nonce);
        let mut v_ct = self.cipher.encrypt(nonce, v_plain).expect("encrypt");
        let mut v_out = a_nonce.to_vec();
        v_out.append(&mut v_ct);
        v_out
    }
    fn decrypt(&self, v_data: &[u8]) -> Option<Vec<u8>> {
        if v_data.len() <= 12 {
            return None;
        }
        let (a_nonce, v_ct) = v_data.split_at(12);
        let nonce = aes_gcm_siv::Nonce::from_slice(a_nonce);
        self.cipher.decrypt(nonce, v_ct).ok()
    }
}

/* ===================================== Audit ============================================= */
struct Auditor {
    v_hashes: Vec<[u8; 32]>,
}
impl Auditor {
    fn new() -> Self {
        Self {
            v_hashes: Vec::new(),
        }
    }
    fn record(&mut self, v_entry: &[u8]) {
        self.v_hashes.push(Sha256::digest(v_entry).into());
    }
}

/* ===================================== DocTracker ======================================== */
struct DocTracker {
    db: sled::Db,
}
impl DocTracker {
    fn new() -> Self {
        let db = sled::open("processed_docs").expect("Tracker DB init");
        Self { db }
    }
    fn mtime(&self, s_path: &str) -> Option<u64> {
        self.db.get(s_path).ok().flatten().map(|ivec| {
            let mut a = [0u8; 8];
            if ivec.len() == 8 {
                a.copy_from_slice(&ivec);
                u64::from_le_bytes(a)
            } else {
                0
            }
        })
    }
    fn set_mtime(&self, s_path: &str, i_mtime: u64) {
        let bytes = i_mtime.to_le_bytes();
        let _ = self.db.insert(s_path, IVec::from(&bytes[..]));
    }
    fn remove(&self, s_path: &str) {
        let _ = self.db.remove(s_path);
    }
    fn all_paths(&self) -> Vec<String> {
        self.db
            .iter()
            .keys()
            .flatten()
            .map(|k| String::from_utf8_lossy(&k).into_owned())
            .collect()
    }
}

/* ===================================== Tantivy =========================================== */
struct TantivyIndex {
    index: Index,
    writer: Mutex<IndexWriter>,
    reader: IndexReader,
    f_path: tantivy::schema::Field,
    f_content: tantivy::schema::Field,
    tracker: DocTracker,
}
impl TantivyIndex {
    fn new(_p_dir: &Path) -> Self {
        fs::create_dir_all(IDX_DIR).ok();
        let mut schema_builder = Schema::builder();
        let f_path = schema_builder.add_text_field("path", STORED);
        let f_content = schema_builder.add_text_field("content", TEXT);
        let schema = schema_builder.build();

        let idx =
            Index::open_or_create(MmapDirectory::open(IDX_DIR).unwrap(), schema.clone()).unwrap();
        let writer = idx.writer(50_000_000).unwrap();
        let reader = idx
            .reader_builder()
            .reload_policy(ReloadPolicy::OnCommit)
            .try_into()
            .unwrap();
        let tracker = DocTracker::new();

        Self {
            index: idx,
            writer: Mutex::new(writer),
            reader,
            f_path,
            f_content,
            tracker,
        }
    }

    fn sync(&self, p_scan: &Path) {
        let mut w = self.writer.lock().unwrap();
        let mut v_seen: Vec<String> = Vec::new();

        Self::walk_dir(
            p_scan,
            &mut w,
            self.f_path,
            self.f_content,
            &self.tracker,
            &mut v_seen,
        );

        for s_path in self.tracker.all_paths() {
            if !v_seen.contains(&s_path) {
                let term = Term::from_field_text(self.f_path, &s_path);
                w.delete_term(term);
                self.tracker.remove(&s_path);
            }
        }

        w.commit().unwrap();
        let _ = self.reader.reload();
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_dir(
        p_dir: &Path,
        w: &mut IndexWriter,
        f_path: tantivy::schema::Field,
        f_content: tantivy::schema::Field,
        tracker: &DocTracker,
        v_seen: &mut Vec<String>,
    ) {
        if let Ok(rd) = fs::read_dir(p_dir) {
            for entry in rd.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    Self::walk_dir(&p, w, f_path, f_content, tracker, v_seen);
                } else if let Ok(md) = entry.metadata() {
                    let s_p = p.display().to_string();
                    v_seen.push(s_p.clone());

                    let i_mtime = md
                        .modified()
                        .unwrap_or(SystemTime::UNIX_EPOCH)
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    if tracker.mtime(&s_p).map_or(true, |old| old != i_mtime) {
                        if let Some(s_txt) = extract_doc_text(&p).ok().filter(|s| !s.is_empty()) {
                            w.delete_term(Term::from_field_text(f_path, &s_p));
                            let _ =
                                w.add_document(doc!(f_path => s_p.as_str(), f_content => s_txt));
                            tracker.set_mtime(&s_p, i_mtime);
                        }
                    }
                }
            }
        }
    }

    fn search(&self, s_query: &str, i_limit: usize) -> Vec<SearchHit> {
        let searcher = self.reader.searcher();
        let qp = tantivy::query::QueryParser::for_index(&self.index, vec![self.f_content]);
        let query = match qp.parse_query(s_query) {
            Ok(q) => q,
            Err(_) => return Vec::new(),
        };
        let v_docs = searcher
            .search(&query, &TopDocs::with_limit(i_limit))
            .unwrap_or_default();

        v_docs
            .into_iter()
            .map(|(score, addr)| {
                let retrieved = searcher.doc(addr).unwrap();
                let s_doc = retrieved
                    .get_first(self.f_path)
                    .and_then(|f| f.as_text())
                    .unwrap_or("")
                    .to_owned();
                SearchHit {
                    s_doc,
                    d_score: score as f32,
                }
            })
            .collect()
    }
}

/* ===================================== Hybrid Suche ====================================== */
const GAMMA: f32 = 2.0;
const BM25_WEIGHT: f32 = 0.7;
const VEC_WEIGHT: f32 = 0.3;
const EXACT_BONUS: f32 = 0.15;
const LLM_WEIGHT: f32 = 0.2;

pub fn combi_search(
    idx_tan: &TantivyIndex,
    idx_vec: &Arc<VectorIndex>,
    s_query: &str,
    i_limit: usize,
) -> Vec<(String, f32)> {
    let mut v_bm = idx_tan.search(s_query, 200);
    if v_bm.is_empty() {
        return idx_vec.query(s_query, i_limit);
    }

    let v_q_vec = idx_vec.encode_query(s_query);
    let d_bm_max = v_bm.first().map(|h| h.d_score).unwrap_or(1.0);
    let mut v_combined = Vec::new();

    for SearchHit { s_doc, d_score } in v_bm.drain(..) {
        if let Some(v_doc_vec) = (idx_vec.vec_of(&s_doc)) {
            let d_bm_n = d_score / d_bm_max.max(1.0);
            let d_vec_n = cosine(&v_q_vec, &v_doc_vec).max(0.0);

            let d_final: f32 = BM25_WEIGHT * d_bm_n + VEC_WEIGHT * d_vec_n;
            v_combined.push((s_doc, d_final));
        }
    }

    v_combined.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    v_combined.truncate(i_limit);
    v_combined
}

/* ===================================== Extraktion ======================================== */
pub type ResultStr = std::result::Result<String, Box<dyn Error + Send + Sync>>;

pub fn extract_doc_text(p_file: &Path) -> ResultStr {
    let s_ext = p_file
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    match s_ext.as_str() {
        "txt" => Ok(fs::read_to_string(p_file)?),
        "pdf" => extract_pdf_text(p_file),
        "docx" => extract_docx_text(p_file),
        "xlsx" | "xls" | "csv" => extract_excel_text(p_file),
        "pptx" => extract_pptx_text(p_file),
        _ => Ok(String::new()),
    }
}

fn extract_pdf_text(p_path: &Path) -> ResultStr {
    let text = extract_text(p_path)?;
    Ok(text)
}

fn extract_docx_text(p: &Path) -> ResultStr {
    let file = fs::File::open(p)?;
    let mut zip = ZipArchive::new(file)?;
    let mut s_all = String::new();

    if let Ok(mut xml) = zip.by_name("word/document.xml") {
        let mut s_buf = String::new();
        xml.read_to_string(&mut s_buf)?;
        for seg in s_buf.split(|c| c == '<' || c == '>') {
            if !seg.starts_with('/') && !seg.contains(' ') {
                s_all.push_str(seg);
                s_all.push(' ');
            }
        }
    }
    Ok(s_all)
}

fn extract_excel_text(p: &Path) -> ResultStr {
    let mut wb = open_workbook_auto(p)?;
    let mut s_acc = String::new();

    for sheet in wb.sheet_names().to_owned() {
        if let Ok(range) = wb.worksheet_range(&sheet) {
            for row in range.rows() {
                for cell in row {
                    s_acc.push_str(&cell.to_string());
                    s_acc.push(' ');
                }
            }
        }
    }
    Ok(s_acc)
}

fn extract_pptx_text(p: &Path) -> ResultStr {
    let file = fs::File::open(p)?;
    let mut zip = ZipArchive::new(file)?;
    let mut s_all = String::new();

    for slide_idx in 1..=200 {
        let s_name = format!("ppt/slides/slide{}.xml", slide_idx);
        if let Ok(mut slide) = zip.by_name(&s_name) {
            let mut s_buf = String::new();
            slide.read_to_string(&mut s_buf)?;
            for seg in s_buf.split(|c| c == '<' || c == '>') {
                if !seg.starts_with('/') && !seg.contains(' ') {
                    s_all.push_str(seg);
                    s_all.push(' ');
                }
            }
        } else {
            break;
        }
    }
    Ok(s_all)
}

/* ===================================== Persistence ======================================= */
struct PersistenceLayer;
impl PersistenceLayer {
    fn new() -> Db {
        sled::open("expchat_queue").expect("DB init")
    }
    fn enqueue(db: &Db, peer: &PeerId, v_bytes: &[u8]) {
        let _ = db.insert(peer.to_bytes(), v_bytes);
    }
    fn dequeue(db: &Db, peer: &PeerId) -> Option<Vec<u8>> {
        db.remove(peer.to_bytes())
            .ok()
            .flatten()
            .map(|ivec| ivec.to_vec())
    }
}

/* ===================================== Behaviour ========================================= */
#[derive(NetworkBehaviour)]
struct Behaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
}

/* ===================================== IAM: CLI und State ================================= */

#[derive(Clone)]
struct IamCliState {
    s_user: String,
    s_session: String,
}

fn print_menu() {
    println!(
        "Verfuegbare Befehle
  ========================================================================================================
  help | menu                     : Dieses Menue
  peers                           : Peerliste anzeigen
  connect <idx>                   : Verbindung zu Peer herstellen
  write <txt>                     : Nachricht senden
  dir                             : Verzeichnis des Partners abfragen
  type <file>                     : Datei anzeigen (remote request)
  get  <file>                     : Datei herunterladen (remote request)
  put  <pfad>                     : Datei hochladen
  search <query>                  : Schlagwortsuche im P2P Netz
  vec_search <query>              : Vektor Suche im P2P Netz
  combi_search <query>            : Hybrid Suche (BM25 + Vektor)
  ========================================================================================================
  iam_status                                                : IAM Status anzeigen
  iam_group_add <group> <rights>                            : Gruppe anlegen (rights als hex oder dezimal)
  iam_user_add <user> <pass> <group>                        : User anlegen und Gruppe setzen
  iam_user_add_to_group <user> <group>                      : User in Gruppe aufnehmen
  iam_path_add <path> <group_or_dash> <public0or1> <rights> : Pfadregel anlegen

  iam_begin_login <user>                                    : Challenge erzeugen (lokal)
  iam_finish_login <user> <challenge_id> <proof_hex_64>     : Login abschliessen (lokal)
  iam_logout                                                : Session loeschen (lokal)

  iam_access_check <path> <right> <public0or1>              : Rechte pruefen (lokal)
  iam_sync                                                  : IAM Snapshot an Netz senden
  ========================================================================================================
  exit                                                      : Programm beenden"
    );
}

fn print_iam_help() {
    println!(
        "IAM Hinweise
  - proof wird lokal aus pw_hash_string gebildet, nicht aus Klartext Passwort.
  - proof = sha256( sha256(pw_hash_string) || nonce32 || challenge_id_ascii || node_id_ascii )

IAM Befehle
  iam_status
  iam_group_add <group> <rights>
  iam_user_add <user> <pass> <group>
  iam_user_add_to_group <user> <group>
  iam_path_add <path> <group_or_dash> <public0or1> <rights>
  iam_begin_login <user>
  iam_finish_login <user> <challenge_id> <proof_hex_64>
  iam_logout
  iam_access_check <path> <right> <public0or1>
  iam_sync"
    );
}

fn parse_u64_any(s_in: &str) -> Option<u64> {
    let s_t = s_in.trim();
    if s_t.is_empty() {
        return None;
    }
    if let Some(s_hex) = s_t.strip_prefix("0x") {
        return u64::from_str_radix(s_hex, 16).ok();
    }
    u64::from_str_radix(s_t, 10).ok()
}

fn parse_right_name_or_number(s_in: &str) -> Option<rights_mask> {
    let s = s_in.trim().to_ascii_lowercase();
    if s.is_empty() {
        return None;
    }
    match s.as_str() {
        "read" => Some(right_read),
        "write" => Some(right_write),
        "create" => Some(right_create),
        "publish" => Some(right_publish),
        "local" => Some(right_local),
        "public" => Some(right_public),
        "admin" => Some(right_admin),
        _ => parse_u64_any(&s).map(|x| x as rights_mask),
    }
}

fn parse_bool_01(s_in: &str) -> Option<bool> {
    match s_in.trim() {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    }
}

fn parse_hex_32_bytes(s_hex: &str) -> Option<[u8; 32]> {
    let s_t = s_hex.trim();
    if s_t.len() != 64 {
        return None;
    }
    let mut a_out = [0u8; 32];
    for i in 0..32 {
        let i_pos = i * 2;
        let byte = u8::from_str_radix(&s_t[i_pos..i_pos + 2], 16).ok()?;
        a_out[i] = byte;
    }
    Some(a_out)
}
fn prompt_password_no_echo(s_prompt: &str) -> Result<String, String> {
    // ASCII-only prompt and defensive flushing for web/terminal consistency.
    print!("{}", s_prompt);
    let _ = std::io::stdout().flush();

    rpassword::read_password().map_err(|_| "password_read_failed".to_string())
}
/* ========================================================================================== */
/* Main                                                                                       */
/* ========================================================================================== */
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let filter = EnvFilter::from_default_env()
        .add_directive("info".parse()?)
        .add_directive("tantivy=warn".parse()?);

    fmt().with_env_filter(filter).with_target(false).init();

    let a_aes_key = *b"01234567012345670123456701234567";
    let sk_set = SecretKeySet::random(1, &mut rand::thread_rng());
    let bls_share = sk_set.secret_key_share(0);
    let ctx_global = CryptoContext::new(&a_aes_key, bls_share);
    let mut auditor = Auditor::new();

    let mut swarm: Swarm<Behaviour> = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_behaviour(|k| {
            let msg_id_fn = |m: &gossipsub::Message| {
                let mut h = DefaultHasher::new();
                m.data.hash(&mut h);
                h.finish().to_string().into()
            };
            let g_cfg = gossipsub::ConfigBuilder::default()
                .validation_mode(gossipsub::ValidationMode::Strict)
                .heartbeat_interval(Duration::from_secs(10))
                .message_id_fn(msg_id_fn)
                .max_transmit_size(1_048_576)
                .build()
                .map_err(io::Error::other)?;
            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(k.clone()),
                g_cfg,
            )?;
            let mdns =
                mdns::tokio::Behaviour::new(mdns::Config::default(), k.public().to_peer_id())?;
            Ok(Behaviour { gossipsub, mdns })
        })?
        .build();

    let global_topic = gossipsub::IdentTopic::new(GLOBAL_TOPIC);
    swarm.behaviour_mut().gossipsub.subscribe(&global_topic)?;

    let iam_topic = gossipsub::IdentTopic::new("expchat-iam");
    swarm.behaviour_mut().gossipsub.subscribe(&iam_topic)?;

    let mut stdin = io::BufReader::new(io::stdin()).lines();
    let mut v_peers: Vec<PeerId> = Vec::new();
    let mut h_peer_index: HashMap<PeerId, usize> = HashMap::new();
    let mut o_chat_peer: Option<PeerId> = None;
    let mut o_chat_topic: Option<gossipsub::IdentTopic> = None;
    let mut h_chunk_queue: HashMap<PeerId, VecDeque<FileChunk>> = HashMap::new();
    let _db = PersistenceLayer::new();
    let (tx_ack, mut rx_ack) = mpsc::unbounded_channel::<(PeerId, u32)>();
    let mut i_search_ctr: u64 = 0;

    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
    swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;

    println!("ExpChat.ai gestartet - help zeigt Menue.");
    print_menu();

    let idx_vec = tokio::task::block_in_place(|| load_or_init_index(Path::new(".")));
    let idx_tan = Arc::new(TantivyIndex::new(Path::new(DOC_DIR)));

    let mut idx_timer = tokio::time::interval(Duration::from_secs(IDX_INTERVAL_SEC));
    let mut persist_timer = tokio::time::interval(Duration::from_secs(900));

    /* IAM store + CLI Session State */
    //let cfg_iam = iam_config { s_node_id: swarm.local_peer_id().to_string() };
    //let iam = std::sync::Arc::new(iam_store::open(cfg_iam).expect("iam open"));
    let mut o_iam_cli: Option<IamCliState> = None;
    /* IAM store */
    let cfg_iam = iam_config {
        s_node_id: swarm.local_peer_id().to_string(),
    };
    let iam = std::sync::Arc::new(iam_store::open(cfg_iam).expect("iam open"));

    // Bootstrap: initUser nur wenn IAM leer ist
    {
        let r = iam.ensure_init_user_admin("admin", "admin");
        if r.is_ok() {
            // Absichtlich knapp: CLI Ausgabe als Operator-Hinweis
            println!("iam: bootstrap checked (default admin may be created if iam was empty)");
        } else {
            println!("iam: bootstrap failed");
        }
    }

    loop {
        select! {
            _ = idx_timer.tick() => {
                idx_vec.sync(Path::new(DOC_DIR));
                idx_tan.sync(Path::new(DOC_DIR));
            }

            _ = persist_timer.tick() => {
                persist_index(&idx_vec, Path::new("."));
            }

            Ok(Some(s_line)) = stdin.next_line() => {
                handle_user_input(
                    &s_line,
                    &mut swarm,
                    &global_topic,
                    &iam_topic,
                    &mut v_peers,
                    &mut h_peer_index,
                    &mut o_chat_peer,
                    &mut o_chat_topic,
                    idx_tan.clone(),
                    idx_vec.clone(),
                    &mut i_search_ctr,
                    iam.clone(),
                    &mut o_iam_cli,
                ).await;
            }

            Some((pid, i_idx)) = rx_ack.recv() => {
                if let Some(q) = h_chunk_queue.get_mut(&pid) {
                    while let Some(f) = q.front() {
                        if f.i_index <= i_idx { q.pop_front(); } else { break }
                    }
                }
            }

            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                    for (pid, _) in list {
                        if !h_peer_index.contains_key(&pid) {
                            let i_idx = v_peers.len();
                            h_peer_index.insert(pid, i_idx);
                            v_peers.push(pid);
                            println!("Peer entdeckt [{i_idx}] {pid}");
                        }
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&pid);
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                    for (pid, _) in list {
                        swarm.behaviour_mut().gossipsub.remove_explicit_peer(&pid);
                        if let Some(i) = h_peer_index.remove(&pid) {
                            v_peers.retain(|p| p != &pid);
                            println!("Peer [{i}] {pid} nicht mehr erreichbar.");
                        }
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(
                    gossipsub::Event::Message { propagation_source, message, .. }
                )) => {
                    if let Ok(env) = serde_json::from_slice::<Envelope>(&message.data) {
                        if let Some(v_plain) = ctx_global.decrypt(&env.v_payload) {
                            auditor.record(&v_plain);
                            if let Ok(msg) = serde_json::from_slice::<ChatMessage>(&v_plain) {
                                handle_incoming(
                                    msg,
                                    &propagation_source,
                                    &mut swarm,
                                    &global_topic,
                                    &mut o_chat_topic,
                                    &mut o_chat_peer,
                                    &mut h_chunk_queue,
                                    &tx_ack,
                                    idx_tan.clone(),
                                    idx_vec.clone(),
                                    iam.clone(),
                                ).await;
                            }
                        }
                    }
                }
                SwarmEvent::NewListenAddr { address, .. } => println!("Listening on {address}"),
                _ => {}
            }
        }
    }
}

/* ========================================================================================== */
/* Benutzer Eingabe                                                                            */
/* ========================================================================================== */
#[allow(clippy::too_many_arguments)]
async fn handle_user_input(
    s_input: &str,
    swarm: &mut Swarm<Behaviour>,
    global_topic: &gossipsub::IdentTopic,
    iam_topic: &gossipsub::IdentTopic,
    v_peers: &mut Vec<PeerId>,
    h_peer_index: &mut HashMap<PeerId, usize>,
    o_chat_peer: &mut Option<PeerId>,
    o_chat_topic: &mut Option<gossipsub::IdentTopic>,
    idx_tan: Arc<TantivyIndex>,
    idx_vec: Arc<VectorIndex>,
    i_search_ctr: &mut u64,
    iam: Arc<iam_store>,
    o_iam_cli: &mut Option<IamCliState>,
) {
    let s_cmd = s_input.trim();
    if s_cmd.is_empty() {
        return;
    }

    match s_cmd {
        "help" | "menu" => {
            print_menu();
        }
        "iam_help" => {
            print_iam_help();
        }
        "iam_status" => {
            if let Some(st) = o_iam_cli.as_ref() {
                println!("iam: logged_in user={} session={}", st.s_user, st.s_session);
            } else {
                println!("iam: not_logged_in");
            }
        }
        "peers" => {
            if v_peers.is_empty() {
                println!("Keine Peers entdeckt.");
            } else {
                for (i, p) in v_peers.iter().enumerate() {
                    println!("[{i}] {p}");
                }
            }
        }
        "exit" => {
            println!("Programmende.");
            std::process::exit(0);
        }

        /* ----------------------------- IAM Verwaltung ------------------------------------ */
        s if s.starts_with("iam_group_add ") => {
            let v: Vec<&str> = s.split_whitespace().collect();
            if v.len() != 3 {
                println!("usage: iam_group_add <group> <rights>");
                return;
            }
            let s_group = v[1];
            let o_rights = parse_u64_any(v[2]);
            let Some(i_rights) = o_rights else {
                println!("invalid rights");
                return;
            };

            let s_actor = o_iam_cli
                .as_ref()
                .map(|x| x.s_user.as_str())
                .unwrap_or("local_admin");
            match iam.add_group(s_actor, s_group, i_rights as rights_mask) {
                Ok(_) => println!("iam: group added {}", s_group),
                Err(e) => println!("iam error: {:?}", e),
            }
        }

        s if s.starts_with("iam_user_add ") => {
            let v: Vec<&str> = s.split_whitespace().collect();
            if v.len() != 4 {
                println!("usage: iam_user_add <user> <pass> <group>");
                return;
            }
            let s_user = v[1];
            let s_pass = v[2];
            let s_group = v[3];

            let s_actor = o_iam_cli
                .as_ref()
                .map(|x| x.s_user.as_str())
                .unwrap_or("local_admin");
            match iam.add_user(s_actor, s_user, s_pass, s_group) {
                Ok(_) => println!("iam: user added {}", s_user),
                Err(e) => println!("iam error: {:?}", e),
            }
        }

        s if s.starts_with("iam_user_add_to_group ") => {
            let v: Vec<&str> = s.split_whitespace().collect();
            if v.len() != 3 {
                println!("usage: iam_user_add_to_group <user> <group>");
                return;
            }
            let s_user = v[1];
            let s_group = v[2];

            let s_actor = o_iam_cli
                .as_ref()
                .map(|x| x.s_user.as_str())
                .unwrap_or("local_admin");
            match iam.add_user_to_group(s_actor, s_user, s_group) {
                Ok(_) => println!("iam: membership added user={} group={}", s_user, s_group),
                Err(e) => println!("iam error: {:?}", e),
            }
        }

        s if s.starts_with("iam_path_add ") => {
            /* usage: iam_path_add <path> <group_or_dash> <public0or1> <rights> */
            let v: Vec<&str> = s.split_whitespace().collect();
            if v.len() != 5 {
                println!("usage: iam_path_add <path> <group_or_dash> <public0or1> <rights>");
                return;
            }
            let s_path = v[1];
            let s_group = v[2];
            let s_public = v[3];
            let s_rights = v[4];

            let Some(b_public) = parse_bool_01(s_public) else {
                println!("invalid public flag");
                return;
            };
            let Some(i_rights_u64) = parse_u64_any(s_rights) else {
                println!("invalid rights");
                return;
            };

            let o_group = if s_group == "-" { None } else { Some(s_group) };
            let s_actor = o_iam_cli
                .as_ref()
                .map(|x| x.s_user.as_str())
                .unwrap_or("local_admin");

            match iam.add_path(
                s_actor,
                s_path,
                o_group,
                b_public,
                i_rights_u64 as rights_mask,
            ) {
                Ok(s_id) => println!("iam: path rule added id={}", s_id),
                Err(e) => println!("iam error: {:?}", e),
            }
        }

        s if s.starts_with("iam_begin_login ") => {
            let v: Vec<&str> = s.split_whitespace().collect();
            if v.len() != 2 {
                println!("usage: iam_begin_login <user>");
                return;
            }

            let s_user = v[1];

            match iam.begin_login(s_user) {
                Ok(ch) => {
                    // Prompt for password immediately and validate locally on this node.
                    let s_pw = match prompt_password_no_echo("iam password: ") {
                        Ok(x) => x,
                        Err(e) => {
                            println!("iam error: {}", e);
                            return;
                        }
                    };

                    // Complete login with local password verification, no external proof.
                    match iam.finish_login_with_password(s_user, &ch.s_challenge_id, &s_pw) {
                        Ok(s_session) => {
                            *o_iam_cli = Some(IamCliState {
                                s_user: s_user.to_string(),
                                s_session: s_session.clone(),
                            });
                            println!("iam: login ok session={}", s_session);
                        }
                        Err(e) => {
                            println!("iam error: {:?}", e);
                        }
                    }
                }
                Err(e) => println!("iam error: {:?}", e),
            }
        }

        s if s.starts_with("iam_finish_login ") => {
            let v: Vec<&str> = s.split_whitespace().collect();
            if v.len() != 4 {
                println!("usage: iam_finish_login <user> <challenge_id> <proof_hex_64>");
                return;
            }
            let s_user = v[1];
            let s_challenge_id = v[2];
            let s_proof_hex = v[3];

            let Some(a_proof) = parse_hex_32_bytes(s_proof_hex) else {
                println!("invalid proof hex");
                return;
            };

            match iam.finish_login(s_user, s_challenge_id, &a_proof) {
                Ok(s_session) => {
                    *o_iam_cli = Some(IamCliState {
                        s_user: s_user.to_string(),
                        s_session: s_session.clone(),
                    });
                    println!("iam: login ok session={}", s_session);
                }
                Err(e) => println!("iam error: {:?}", e),
            }
        }

        "iam_logout" => {
            *o_iam_cli = None;
            println!("iam: logged_out");
        }

        s if s.starts_with("iam_access_check ") => {
            /* usage: iam_access_check <path> <right> <public0or1> */
            let v: Vec<&str> = s.split_whitespace().collect();
            if v.len() != 4 {
                println!("usage: iam_access_check <path> <right> <public0or1>");
                return;
            }
            let s_path = v[1];
            let s_right = v[2];
            let s_public = v[3];

            let Some(b_public) = parse_bool_01(s_public) else {
                println!("invalid public flag");
                return;
            };
            let Some(i_right) = parse_right_name_or_number(s_right) else {
                println!("invalid right");
                return;
            };
            let Some(st) = o_iam_cli.as_ref() else {
                println!("iam: not_logged_in");
                return;
            };

            match iam.check_access(&st.s_session, s_path, i_right, b_public) {
                Ok(dec) => {
                    println!(
                        "iam: allowed={} reason={} effective_rights=0x{:016x}",
                        dec.b_allowed, dec.s_reason, dec.i_effective_rights
                    );
                }
                Err(e) => println!("iam error: {:?}", e),
            }
        }

        "iam_sync" => {
            let v_events = iam.export_all_events().unwrap_or_default();
            let msg = iam_delta_push {
                s_epoch: "full".to_string(),
                i_ts: 0,
                v_events,
                s_merkle_root_hex: "na".to_string(),
            };
            let local_id = swarm.local_peer_id().clone();
            send_encrypted(&local_id, swarm, iam_topic, &PayloadType::IamDeltaPush(msg));
            println!("iam: sync push sent");
        }

        /* ----------------------------- Standard Funktionen -------------------------------- */
        s if s.starts_with("connect ") => {
            if let Some(peer) = parse_connect(s, v_peers) {
                let topic = build_chat_topic(&swarm.local_peer_id(), &peer);
                swarm.behaviour_mut().gossipsub.subscribe(&topic).ok();
                *o_chat_peer = Some(peer);
                *o_chat_topic = Some(topic.clone());
                let local_id = swarm.local_peer_id().clone();
                send_encrypted(&local_id, swarm, global_topic, &PayloadType::ConnectRequest);
                println!("Handshake zu {peer} initiiert.");
            }
        }

        s if s.starts_with("write ") => {
            if let Some(topic) = o_chat_topic {
                let s_text = s.strip_prefix("write ").unwrap_or("").to_owned();
                let msg = PayloadType::Text(s_text.clone());
                let local_id = swarm.local_peer_id().clone();
                send_encrypted(&local_id, swarm, topic, &msg);
                println!("(you) {s_text}");
            } else {
                println!("Kein Chat Partner verbunden.");
            }
        }

        "dir" => {
            if let Some(topic) = o_chat_topic {
                let local_id = swarm.local_peer_id().clone();
                send_encrypted(&local_id, swarm, topic, &PayloadType::DirRequest);
                println!("Verzeichnis angefragt ...");
            } else {
                println!("Kein Chat Partner.");
            }
        }

        s if s.starts_with("type ") || s.starts_with("get ") => {
            /* IAM: Zugriff auf Remote Datei Request erzwingen, falls Session vorhanden. */
            let Some(topic) = o_chat_topic else {
                println!("Kein Chat Partner.");
                return;
            };

            let s_file = s.split_whitespace().nth(1).unwrap_or("").to_string();
            if s_file.trim().is_empty() {
                println!("missing file name");
                return;
            }

            /* Lokale Policy: Nur wenn IAM Session vorhanden und Zugriff erlaubt, wird Request gesendet. */
            let Some(st) = o_iam_cli.as_ref() else {
                println!("iam: not_logged_in - file request denied");
                return;
            };

            let i_need = right_read;
            match iam.check_access(&st.s_session, &s_file, i_need, IAM_REMOTE_SCOPE_PUBLIC) {
                Ok(dec) => {
                    if !dec.b_allowed {
                        println!("iam: deny file request reason={}", dec.s_reason);
                        return;
                    }
                }
                Err(e) => {
                    println!("iam error: {:?} - deny file request", e);
                    return;
                }
            }

            let local_id = swarm.local_peer_id().clone();
            send_encrypted(&local_id, swarm, topic, &PayloadType::FileRequest(s_file));
        }

        s if s.starts_with("put ") => {
            if let Some(topic) = o_chat_topic {
                let s_path = s.strip_prefix("put ").unwrap_or("").trim();
                if s_path.is_empty() {
                    println!("missing path");
                    return;
                }

                /* IAM: Upload nur wenn Session vorhanden und write erlaubt. */
                let Some(st) = o_iam_cli.as_ref() else {
                    println!("iam: not_logged_in - put denied");
                    return;
                };

                match iam.check_access(&st.s_session, s_path, right_write, false) {
                    Ok(dec) => {
                        if !dec.b_allowed {
                            println!("iam: deny put reason={}", dec.s_reason);
                            return;
                        }
                    }
                    Err(e) => {
                        println!("iam error: {:?} - deny put", e);
                        return;
                    }
                }

                match fs::read(s_path) {
                    Ok(v_buf) => {
                        let msg = PayloadType::FileTransfer(FileChunk {
                            s_name: s_path.to_string(),
                            i_index: 0,
                            i_total: 1,
                            v_bytes: v_buf,
                        });
                        let local_id = swarm.local_peer_id().clone();
                        send_encrypted(&local_id, swarm, topic, &msg);
                    }
                    Err(e) => println!("Lesefehler: {e}"),
                }
            } else {
                println!("Kein Chat Partner.");
            }
        }

        s if s.starts_with("search ") => {
            let s_query = s.strip_prefix("search ").unwrap_or("").to_string();
            {
                let v_res = idx_tan.search(&s_query, 5);
                if v_res.is_empty() {
                    println!("(lokal) keine Treffer");
                } else {
                    println!("(lokal)");
                    for SearchHit { s_doc, d_score } in &v_res {
                        println!("  {d_score:.3}  {s_doc}");
                    }
                }
            }

            *i_search_ctr += 1;
            let i_id = *i_search_ctr;
            let local_id = swarm.local_peer_id().clone();
            send_encrypted(
                &local_id,
                swarm,
                global_topic,
                &PayloadType::SearchRequest { i_id, s_query },
            );
            println!("Suche (ID {i_id}) an Peers gesendet.");
        }

        s if s.starts_with("vec_search ") => {
            let s_query = s.strip_prefix("vec_search ").unwrap_or("").to_string();

            {
                let v_res = idx_vec.query_with_snippets(&s_query, 5);
                if v_res.is_empty() {
                    println!("(lokal) keine Vektor Treffer");
                } else {
                    println!("(lokal)");
                    for h in &v_res {
                        println!("==========================");
                        println!(
                            "  {d_score:.4}  {s_doc}",
                            d_score = h.d_score,
                            s_doc = h.s_doc
                        );
                        if !h.s_snippet.is_empty() {
                            println!("    snippet: {s}", s = h.s_snippet);
                        }
                        println!("==========================");
                    }
                }
            }

            *i_search_ctr += 1;
            let i_id = *i_search_ctr;
            let local_id = swarm.local_peer_id().clone();
            send_encrypted(
                &local_id,
                swarm,
                global_topic,
                &PayloadType::VecSearchRequest { i_id, s_query },
            );
            println!("Vektor Suche (ID {i_id}) gesendet.");
        }

        s if s.starts_with("combi_search ") => {
            let s_query = s.strip_prefix("combi_search ").unwrap_or("").to_string();

            let v_res = combi_search(&idx_tan, &idx_vec, &s_query, 5);
            if v_res.is_empty() {
                println!("(lokal) keine Hybrid Treffer");
            } else {
                println!("(lokal)");
                for (s_doc, d_score) in &v_res {
                    println!("  {:>7.4}  {}", d_score, s_doc);
                }
            }

            *i_search_ctr += 1;
            let i_id = *i_search_ctr;
            let local_id = swarm.local_peer_id().clone();
            send_encrypted(
                &local_id,
                swarm,
                global_topic,
                &PayloadType::CombiSearchRequest { i_id, s_query },
            );
            println!("Hybrid Suche (ID {i_id}) gesendet.");
        }

        _ => println!("Unbekanntes Kommando - help hilft."),
    }
}

/* ========================================================================================== */
/* Incoming                                                                                    */
/* ========================================================================================== */
#[allow(clippy::too_many_arguments)]
async fn handle_incoming(
    msg: ChatMessage,
    src: &PeerId,
    swarm: &mut Swarm<Behaviour>,
    global_topic: &gossipsub::IdentTopic,
    o_chat_topic: &mut Option<gossipsub::IdentTopic>,
    o_chat_peer: &mut Option<PeerId>,
    h_queues: &mut HashMap<PeerId, VecDeque<FileChunk>>,
    tx_ack: &UnboundedSender<(PeerId, u32)>,
    idx_tan: Arc<TantivyIndex>,
    idx_vec: Arc<VectorIndex>,
    iam: Arc<iam_store>,
) {
    match msg.payload {
        PayloadType::IamDeltaPush(p) => {
            let i_len = p.v_events.len();
            for ev in &p.v_events {
                let _ = iam.apply_event(ev);
            }
            println!("iam: applied delta_push events={}", i_len);
        }
        PayloadType::IamDeltaRequest(_r) => {
            let v_events = iam.export_all_events().unwrap_or_default();
            let resp = iam_delta_response {
                s_epoch: "full".to_string(),
                i_ts: 0,
                v_events,
                s_merkle_root_hex: "na".to_string(),
            };
            let local_id = swarm.local_peer_id().clone();
            send_encrypted(
                &local_id,
                swarm,
                global_topic,
                &PayloadType::IamDeltaResponse(resp),
            );
        }
        PayloadType::IamDeltaResponse(r) => {
            let i_len = r.v_events.len();
            for ev in &r.v_events {
                let _ = iam.apply_event(ev);
            }
            println!("iam: applied delta_response events={}", i_len);
        }

        PayloadType::Text(t) => println!("({src}) {t}"),

        PayloadType::DirRequest => {
            if let Ok(s_listing) = build_dir_listing() {
                let topic = build_chat_topic(&swarm.local_peer_id(), src);
                let local_id = swarm.local_peer_id().clone();
                send_encrypted(
                    &local_id,
                    swarm,
                    &topic,
                    &PayloadType::DirResponse(s_listing),
                );
            }
        }
        PayloadType::DirResponse(s_ls) => {
            println!("-- Verzeichnis von {src} --\n{s_ls}-- Ende --");
        }

        PayloadType::FileRequest(s_name) => {
            /* IAM: Remote FileRequest wird als public scope bewertet. Ohne Session Konzept fuer Remote:
            Der Node kann hier eine lokale Policy erzwingen. Minimal: nur Pfadregeln public+read. */
            let b_allow = {
                /* Keine Session vom Remote vorhanden, daher keine echte Identitaet.
                Node erzwingt public scope, und laesst Requests nur zu, wenn Pfadregel public+read existiert.
                In einem vollstaendigen Protokoll wird s_session und actor uebergeben und verifiziert. */
                let s_dummy_session = "00000000000000000000000000000000";
                match iam.check_access(s_dummy_session, &s_name, right_read, true) {
                    Ok(dec) => dec.b_allowed,
                    Err(_) => false,
                }
            };

            if !b_allow {
                println!("iam: deny remote file request path={}", s_name);
                return;
            }

            match fs::read(&s_name) {
                Ok(v_buf) => {
                    let topic = build_chat_topic(&swarm.local_peer_id(), src);
                    let local_id = swarm.local_peer_id().clone();
                    send_encrypted(
                        &local_id,
                        swarm,
                        &topic,
                        &PayloadType::FileTransfer(FileChunk {
                            s_name,
                            i_index: 0,
                            i_total: 1,
                            v_bytes: v_buf,
                        }),
                    );
                }
                Err(e) => println!("Datei Fehler: {e}"),
            }
        }

        PayloadType::FileTransfer(chunk) => {
            let dir = PathBuf::from("inbox");
            fs::create_dir_all(&dir).ok();

            /* Defensive: Datei Name bereinigen (keine Pfad Traversal). */
            let s_name_only = Path::new(&chunk.s_name)
                .file_name()
                .and_then(|x| x.to_str())
                .unwrap_or("file.bin")
                .to_string();

            let mut file = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(dir.join(&s_name_only))
                .await
                .unwrap();

            tokio::io::AsyncWriteExt::write_all(&mut file, &chunk.v_bytes)
                .await
                .unwrap();

            println!(
                "Datei Teil {} von {} Bytes empfangen.",
                chunk.i_index,
                chunk.v_bytes.len()
            );
            let _ = tx_ack.send((*src, chunk.i_index));
        }

        PayloadType::ChunkAck(_i_idx) => {}

        PayloadType::ConnectRequest => {
            let topic = build_chat_topic(&swarm.local_peer_id(), src);
            swarm.behaviour_mut().gossipsub.subscribe(&topic).ok();
            *o_chat_peer = Some(*src);
            *o_chat_topic = Some(topic.clone());
            let local_id = swarm.local_peer_id().clone();
            send_encrypted(&local_id, swarm, global_topic, &PayloadType::ConnectAck);
            println!("Handshake von {src} akzeptiert.");
        }
        PayloadType::ConnectAck => println!("Peer {src} bestaetigt Verbindung."),
        PayloadType::OfflineFlush => println!("Peer {src} meldet: Queue abgearbeitet."),

        PayloadType::SearchRequest { i_id, s_query } => {
            let v_hits = idx_tan.search(&s_query, 5);
            let local_id = swarm.local_peer_id().clone();
            send_encrypted(
                &local_id,
                swarm,
                global_topic,
                &PayloadType::SearchResponse {
                    i_id,
                    s_peer: local_id.to_string(),
                    v_hits,
                },
            );
        }
        PayloadType::SearchResponse {
            i_id,
            s_peer,
            v_hits,
        } => {
            if v_hits.is_empty() {
                println!("(ID {i_id}) {s_peer}: keine Treffer");
            } else {
                for SearchHit { s_doc, d_score } in v_hits {
                    println!("(ID {i_id}) {s_peer}: {d_score:.3} {s_doc}");
                }
            }
        }

        PayloadType::VecSearchRequest { i_id, s_query } => {
            idx_vec.sync(std::path::Path::new(DOC_DIR));
            let v_hits = idx_vec.query_with_snippets(&s_query, 5);

            let local_id = swarm.local_peer_id().clone();
            send_encrypted(
                &local_id,
                swarm,
                global_topic,
                &PayloadType::VecSearchResponse {
                    i_id,
                    s_peer: local_id.to_string(),
                    v_hits,
                },
            );
        }
        PayloadType::VecSearchResponse {
            i_id,
            s_peer,
            v_hits,
        } => {
            if v_hits.is_empty() {
                println!("(ID {i_id}) {s_peer}: keine Vektor Treffer");
            } else {
                for h in v_hits {
                    println!("==========================");
                    println!(
                        "(ID {i_id}) {s_peer}: {d_score:.4} {s_doc}",
                        d_score = h.d_score,
                        s_doc = h.s_doc
                    );
                    if !h.s_snippet.trim().is_empty() {
                        println!(
                            "(ID {i_id}) {s_peer}: snippet: {s_snippet}",
                            s_snippet = h.s_snippet
                        );
                    }
                    println!("==========================");
                }
            }
        }

        PayloadType::CombiSearchRequest { i_id, s_query } => {
            idx_vec.sync(Path::new(DOC_DIR));
            let v_hits = combi_search(&idx_tan, &idx_vec, &s_query, 5);

            let local_id = swarm.local_peer_id().clone();
            send_encrypted(
                &local_id,
                swarm,
                global_topic,
                &PayloadType::CombiSearchResponse {
                    i_id,
                    s_peer: local_id.to_string(),
                    v_hits,
                },
            );
        }
        PayloadType::CombiSearchResponse {
            i_id,
            s_peer,
            v_hits,
        } => {
            if v_hits.is_empty() {
                println!("(ID {i_id}) {s_peer}: keine Hybrid Treffer");
            } else {
                for (s_doc, d_score) in v_hits {
                    println!("(ID {i_id}) {s_peer}: {:>7.4} {}", d_score, s_doc);
                }
            }
        }
    }
}

/* ========================================================================================== */
/* Utils                                                                                      */
/* ========================================================================================== */
fn build_dir_listing() -> Result<String, Box<dyn Error>> {
    let mut s_out = String::new();
    for e in fs::read_dir(".")? {
        let e = e?;
        let s_name = e.file_name().to_string_lossy().into_owned();
        let md = e.metadata()?;
        if md.is_dir() {
            s_out.push_str(&format!("   {s_name}\n"));
        } else {
            s_out.push_str(&format!("{:>10}  {s_name}\n", md.len()));
        }
    }
    Ok(s_out)
}

fn parse_connect(s_cmd: &str, v_peers: &[PeerId]) -> Option<PeerId> {
    s_cmd
        .split_whitespace()
        .nth(1)?
        .parse::<usize>()
        .ok()
        .and_then(|i| v_peers.get(i).copied())
}

fn build_chat_topic(a: &PeerId, b: &PeerId) -> gossipsub::IdentTopic {
    let mut a_ids = [a.to_string(), b.to_string()];
    a_ids.sort();
    gossipsub::IdentTopic::new(format!("chat-{}-{}", a_ids[0], a_ids[1]))
}

#[derive(Serialize, Deserialize, Debug)]
struct Envelope {
    v_sigshares: Vec<(u16, SignatureShare)>,
    v_payload: Vec<u8>,
}

fn send_encrypted(
    local_id: &PeerId,
    swarm: &mut Swarm<Behaviour>,
    topic: &gossipsub::IdentTopic,
    payload: &PayloadType,
) {
    let a_aes_key = *b"01234567012345670123456701234567";
    let sk_set = SecretKeySet::random(1, &mut rand::thread_rng());
    let ctx = CryptoContext::new(&a_aes_key, sk_set.secret_key_share(0));

    let v_plain = serde_json::to_vec(&ChatMessage {
        s_sender: local_id.to_string(),
        payload: payload.clone(),
    })
    .unwrap();

    let v_ct = ctx.encrypt(&v_plain);
    let sig = ctx.bls_key.sign(&v_ct);

    let v_env = Envelope {
        v_sigshares: vec![(0u16, sig)],
        v_payload: v_ct,
    };
    let v_buf = serde_json::to_vec(&v_env).unwrap();
    let _ = swarm
        .behaviour_mut()
        .gossipsub
        .publish(topic.clone(), v_buf);
}
