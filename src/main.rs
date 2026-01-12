/**********************************************************************************************
 *  Modulname : secure_p2p_ext
 *  Datei     : main.rs
 *  Autor     : Marcus Schlieper
 *---------------------------------------------------------------------------------------------
 *  Beschreibung
 *  - P2P Chat Client mit Datei Transfer, Volltext Suche (Tantivy), Vektor Suche, Hybrid Suche.
 *  - IAM Integration (CLI), Webserver Integration (Command Bridge, Shared State).
 *  - Web: Netzwerk Combi Search (dispatch + result polling) mit PeerId pro Hit.
 *  - Web: Erweiterung fuer Snippets und Dokumentanzeige per Klick (lokal und remote).
 *
 *  Historie
 *  09.11.2025  MS  - Grundversion (Chat, DOS Befehle, Handshake Topic)
 *  10.11.2025  MS  - Kryptographische Erweiterungen, Offline Queue, Audit
 *  13.11.2025  MS  - RAG Schlagwortsuche (Tantivy)
 *  15.11.2025  MS  - Hybrid combi_search
 *  09.01.2026  MS  - IAM Integration: Menue + Kommandos + Session Handling + Access Checks
 *  11.01.2026  MS  - Webserver: Integration (start + command bridge + shared state updates)
 *  11.01.2026  MS  - Web: network combi search dispatch + result cache + peer_id per hit
 *  12.01.2026  MS  - Web: Snippets fuer local+remote combi search + DocText fetch via P2P
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
    gossipsub, mdns,
    swarm::{NetworkBehaviour, Swarm, SwarmEvent},
    PeerId,
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
    iam_config, iam_store, right_admin, right_create, right_local, right_public, right_publish,
    right_read, right_write, rights_mask,
};
use crate::iam_net::{iam_delta_push, iam_delta_request, iam_delta_response};
use rpassword;

/* --- Webserver --------------------------------------------------------------------------- */
mod web_server;
use crate::web_server::{
    run_web_server, web_command, web_doc_text_resp, web_ok_resp, web_peer_view,
    web_search_dispatch_resp, web_search_hit, web_search_resp, web_shared_state, web_status_view,
    I_EVENT_RING_MAX,
};

mod config;
use crate::config::app_config;
use crate::config::cfg_get;


mod pdf_text_extractor;
use crate::pdf_text_extractor::extract_pdf_text;

/* ===================================== Config ============================================ */
fn load_cfg_or_exit() -> app_config {
    /* Defensive: explicit error handling, no panic, ascii messages only */
    config::app_config::load_from_env().unwrap_or_else(|e| {
        println!("config error: {}", e);
        std::process::exit(2);
    })
}

/* ===================================== Payload =========================================== */
#[derive(Serialize, Deserialize, Debug, Clone)]
struct CombiSearchHit {
    /* Web and P2P: include snippet to avoid follow up calls during result polling */
    s_doc: String,
    d_score: f32,
    s_snippet: String,
}

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

    SearchRequest { i_id: u64, s_query: String },
    SearchResponse {
        i_id: u64,
        s_peer: String,
        v_hits: Vec<SearchHit>,
    },

    VecSearchRequest { i_id: u64, s_query: String },
    VecSearchResponse {
        i_id: u64,
        s_peer: String,
        v_hits: Vec<VecSearchHit>,
    },

    CombiSearchRequest { i_id: u64, s_query: String },
    CombiSearchResponse {
        i_id: u64,
        s_peer: String,
        v_hits: Vec<CombiSearchHit>,
    },

    /* Web: click on hit -> request document text from local or remote peer */
    DocTextRequest { i_id: u64, s_path: String },
    DocTextResponse {
        i_id: u64,
        s_peer: String,
        s_path: String,
        s_text: String,
        s_error: String,
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

        let mut v_ct = self.cipher.encrypt(nonce, v_plain).unwrap_or_default();
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
        Self { v_hashes: Vec::new() }
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
        let db = sled::open(crate::config::path_processed_docs_dir()).expect("Tracker DB init");
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

fn canonicalize_best_effort_str(p_in: &Path) -> String {
    /* Defensive: best effort canonicalize, fallback; ASCII-only safe output. */
    match std::fs::canonicalize(p_in) {
        Ok(p) => p.to_string_lossy().into_owned(),
        Err(_) => p_in.to_string_lossy().into_owned(),
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
        let p_idx_dir = crate::config::path_tantivy_idx_dir();

        fs::create_dir_all(&p_idx_dir).ok();
        let mut schema_builder = Schema::builder();
        let f_path = schema_builder.add_text_field("path", STORED);
        let f_content = schema_builder.add_text_field("content", TEXT);
        let schema = schema_builder.build();

        let idx = Index::open_or_create(MmapDirectory::open(&p_idx_dir).unwrap(), schema.clone())
            .unwrap();

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

        let _ = w.commit();
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
        if let Ok(rd) = std::fs::read_dir(p_dir) {
            for entry in rd.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    Self::walk_dir(&p, w, f_path, f_content, tracker, v_seen);
                } else if let Ok(md) = entry.metadata() {
                    /* Fix: gleicher Pfad-Key wie im VectorIndex (kanonisiert) */
                    let s_p = canonicalize_best_effort_str(&p);
                    v_seen.push(s_p.clone());

                    let i_mtime = md
                        .modified()
                        .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
                        .duration_since(std::time::SystemTime::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    if tracker.mtime(&s_p).map_or(true, |old| old != i_mtime) {
                        if let Some(s_txt) = extract_doc_text(&p).ok().filter(|s| !s.is_empty()) {
                            w.delete_term(Term::from_field_text(f_path, &s_p));
                            let _ = w.add_document(doc!(f_path => s_p.as_str(), f_content => s_txt));
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
const BM25_WEIGHT: f32 = 0.7;
const VEC_WEIGHT: f32 = 0.3;

const I_SNIPPET_MAX_LEN: usize = 320;
const I_DOC_TEXT_MAX_LEN: usize = 2_000_000;

fn safe_truncate_chars(s_in: &str, i_max_chars: usize) -> String {
    /* Defensive: char based truncate, avoids invalid UTF-8 slicing */
    if i_max_chars == 0 {
        return String::new();
    }
    s_in.chars().take(i_max_chars).collect::<String>()
}

fn build_snippet_for_query_simple(s_text: &str, s_query: &str) -> String {
    /* Defensive: simple snippet builder, bounded output, ASCII safe code path */
    let s_t = s_text.trim();
    if s_t.is_empty() {
        return String::new();
    }

    let s_q = s_query.trim();
    if s_q.is_empty() {
        return safe_truncate_chars(s_t, I_SNIPPET_MAX_LEN);
    }

    let s_low = s_t.to_ascii_lowercase();
    let s_q_low = s_q.to_ascii_lowercase();

    if let Some(i_pos) = s_low.find(&s_q_low) {
        let i_half: usize = I_SNIPPET_MAX_LEN / 2;
        let i_start = i_pos.saturating_sub(i_half);

        /* Note: We must not slice by bytes at arbitrary offsets; use chars */
        let s_tail = s_t.chars().skip(i_start).collect::<String>();
        return safe_truncate_chars(&s_tail, I_SNIPPET_MAX_LEN);
    }

    safe_truncate_chars(s_t, I_SNIPPET_MAX_LEN)
}

fn combi_search_with_snippets(
    idx_tan: &TantivyIndex,
    idx_vec: &Arc<VectorIndex>,
    s_query: &str,
    i_limit: usize,
) -> Vec<CombiSearchHit> {
    /* Historie: 12.01.2026 MS - Web: return combi hits with snippets */
    let mut v_bm = idx_tan.search(s_query, 200);
    if v_bm.is_empty() {
        let v_vec_only = idx_vec.query_with_snippets(s_query, i_limit);
        return v_vec_only
            .into_iter()
            .map(|h| CombiSearchHit {
                s_doc: h.s_doc,
                d_score: h.d_score,
                s_snippet: safe_truncate_chars(&h.s_snippet, I_SNIPPET_MAX_LEN),
            })
            .collect();
    }

    let v_q_vec = idx_vec.encode_query(s_query);
    let d_bm_max = v_bm.first().map(|h| h.d_score).unwrap_or(1.0);

    let mut v_combined: Vec<(String, f32)> = Vec::new();

    for SearchHit { s_doc, d_score } in v_bm.drain(..) {
        if let Some(v_doc_vec) = idx_vec.vec_of(&s_doc) {
            let d_bm_n = d_score / d_bm_max.max(1.0);
            let d_vec_n = cosine(&v_q_vec, &v_doc_vec).max(0.0);
            let d_final: f32 = BM25_WEIGHT * d_bm_n + VEC_WEIGHT * d_vec_n;
            v_combined.push((s_doc, d_final));
        }
    }

    /* Degradation: if no vec matches exist, fallback to BM25 only */
    if v_combined.is_empty() {
        let mut v_fallback = idx_tan.search(s_query, i_limit);
        v_fallback.sort_by(|a, b| {
            b.d_score
                .partial_cmp(&a.d_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        return v_fallback
            .into_iter()
            .map(|h| {
                let s_txt = extract_doc_text(Path::new(&h.s_doc)).unwrap_or_else(|_| String::new());
                let s_snip = build_snippet_for_query_simple(&s_txt, s_query);
                CombiSearchHit {
                    s_doc: h.s_doc,
                    d_score: h.d_score,
                    s_snippet: safe_truncate_chars(&s_snip, I_SNIPPET_MAX_LEN),
                }
            })
            .collect();
    }

    v_combined.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    v_combined.truncate(i_limit);

    let mut v_out: Vec<CombiSearchHit> = Vec::with_capacity(v_combined.len());
    for (s_doc, d_score) in v_combined.into_iter() {
        let s_txt = extract_doc_text(Path::new(&s_doc)).unwrap_or_else(|_| String::new());
        let s_snip = build_snippet_for_query_simple(&s_txt, s_query);

        v_out.push(CombiSearchHit {
            s_doc,
            d_score,
            s_snippet: safe_truncate_chars(&s_snip, I_SNIPPET_MAX_LEN),
        });
    }

    v_out
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
        "pdf" => call_extract_pdf_text(p_file),
        "docx" => extract_docx_text(p_file),
        "xlsx" | "xls" | "csv" => extract_excel_text(p_file),
        "pptx" => extract_pptx_text(p_file),
        _ => Ok(String::new()),
    }
}

fn call_extract_pdf_text(p_path: &Path) -> ResultStr {
    let text = extract_pdf_text(p_path)?;
    Ok(text.s_text)
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
        sled::open(crate::config::path_queue_dir()).expect("DB init")
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

/* ===================================== CLI Menu ========================================== */
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
    /* ASCII-only prompt and defensive flushing for web/terminal consistency. */
    print!("{}", s_prompt);
    let _ = std::io::stdout().flush();

    rpassword::read_password().map_err(|_| "password_read_failed".to_string())
}

/* ========================================================================================== */
/* Diagnose Helper                                                                             */
/* ========================================================================================== */
fn diag_print_index_paths(p_vec_root: &Path) {
    /* Defensive: print effective paths that should be read/written by vector index persistence. */
    let mut p_ann = std::path::PathBuf::from(p_vec_root);
    p_ann.push("ann_graph.bin");

    let s_root = p_vec_root.to_string_lossy().into_owned();
    let s_file = p_ann.to_string_lossy().into_owned();

    println!("diag: vec_root={}", s_root);
    println!("diag: vec_ann_graph_file={}", s_file);
}

/* ========================================================================================== */
/* Index Init                                                                                  */
/* ========================================================================================== */
async fn init_indices() -> (Arc<TantivyIndex>, Arc<VectorIndex>) {
    /* Historie: 12.01.2026 MS - central init for vector and tantivy indices with diagnostics */

    let p_vec_root = crate::config::path_vector_idx_dir();
    let p_vec_tracker = crate::config::path_vec_tracker_dir();

    /* Diagnose: show paths early and deterministically. */
    diag_print_index_paths(p_vec_root.as_path());

    /* Vector index: load persisted graph if present. */
    let idx_vec = tokio::task::block_in_place(|| load_or_init_index(p_vec_root.as_path(), p_vec_tracker.as_path()));

    /* Tantivy index: prefer stable canonical doc dir, fallback to configured path. */
    let s_doc_dir: String = cfg_get().s_doc_dir.clone();
    let p_doc_dir = PathBuf::from(&s_doc_dir);
    let p_doc_dir_norm = match std::fs::canonicalize(&p_doc_dir) {
        Ok(p) => p,
        Err(_) => p_doc_dir,
    };

    let idx_tan = Arc::new(TantivyIndex::new(p_doc_dir_norm.as_path()));

    println!("diag: idx_vec_entries_init_done");
    println!("diag: idx_tan_init_done");

    return (idx_tan, idx_vec);
}

/* ========================================================================================== */
/* Main                                                                                       */
/* ========================================================================================== */
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /* -------------------- Logging --------------------------------------------------------- */
    let filter = tracing_subscriber::EnvFilter::from_default_env()
        .add_directive("info".parse()?)
        .add_directive("tantivy=warn".parse()?);

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    {
        let _ = crate::config::ensure_data_layout();
    }

    let _i_chunk_size: usize = cfg_get().i_chunk_size;
    let s_global_topic: String = cfg_get().s_global_topic.clone();
    let s_doc_dir: String = cfg_get().s_doc_dir.clone();
    let _s_idx_dir: String = cfg_get().s_idx_dir.clone();
    let i_idx_interval_sec: u64 = cfg_get().i_idx_interval_sec as u64;
    let s_web_bind: String = cfg_get().s_web_bind.clone();
    let _i_max_transmit_size: usize = cfg_get().i_max_transmit_size;
    let i_persist_interval_sec: u64 = cfg_get().i_persist_interval_sec as u64;

    /* -------------------- Crypto Context -------------------------------------------------- */
    let a_aes_key = *b"01234567012345670123456701234567";
    let sk_set = blsttc::SecretKeySet::random(1, &mut rand::thread_rng());
    let bls_share = sk_set.secret_key_share(0);
    let ctx_global = CryptoContext::new(&a_aes_key, bls_share);
    let mut auditor = Auditor::new();

    /* -------------------- Swarm ----------------------------------------------------------- */
    let mut swarm: libp2p::swarm::Swarm<Behaviour> = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_quic()
        .with_behaviour(|k| {
            let msg_id_fn = |m: &libp2p::gossipsub::Message| {
                let mut h = std::collections::hash_map::DefaultHasher::new();
                m.data.hash(&mut h);
                h.finish().to_string().into()
            };

            let g_cfg = libp2p::gossipsub::ConfigBuilder::default()
                .validation_mode(libp2p::gossipsub::ValidationMode::Strict)
                .heartbeat_interval(std::time::Duration::from_secs(10))
                .message_id_fn(msg_id_fn)
                .max_transmit_size(cfg_get().i_max_transmit_size)
                .build()
                .map_err(tokio::io::Error::other)?;

            let gossipsub = libp2p::gossipsub::Behaviour::new(
                libp2p::gossipsub::MessageAuthenticity::Signed(k.clone()),
                g_cfg,
            )?;

            let mdns = libp2p::mdns::tokio::Behaviour::new(
                libp2p::mdns::Config::default(),
                k.public().to_peer_id(),
            )?;

            Ok(Behaviour { gossipsub, mdns })
        })?
        .build();

    let s_node_id: String = swarm.local_peer_id().to_string();
    let _cfg_iam = iam_config { s_node_id: s_node_id.clone() };

    let global_topic = libp2p::gossipsub::IdentTopic::new(s_global_topic.clone());
    swarm.behaviour_mut().gossipsub.subscribe(&global_topic)?;

    let iam_topic = libp2p::gossipsub::IdentTopic::new(cfg_get().s_iam_topic.clone());
    swarm.behaviour_mut().gossipsub.subscribe(&iam_topic)?;

    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin()).lines();

    let mut v_peers: Vec<libp2p::PeerId> = Vec::new();
    let mut h_peer_index: std::collections::HashMap<libp2p::PeerId, usize> = std::collections::HashMap::new();
    let mut o_chat_peer: Option<libp2p::PeerId> = None;
    let mut o_chat_topic: Option<libp2p::gossipsub::IdentTopic> = None;

    let mut h_chunk_queue: std::collections::HashMap<libp2p::PeerId, std::collections::VecDeque<FileChunk>> =
        std::collections::HashMap::new();

    let _db = PersistenceLayer::new();
    let (tx_ack, mut rx_ack) = tokio::sync::mpsc::unbounded_channel::<(libp2p::PeerId, u32)>();
    let mut i_search_ctr: u64 = 0;

    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
    swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;

    println!("ExpChat.ai gestartet - help zeigt Menue.");
    print_menu();

    /* -------------------- Indizes (Fix: via init_indices) -------------------------------- */
    let (idx_tan, idx_vec) = init_indices().await;

    let p_vec_root = crate::config::path_vector_idx_dir();
    let mut idx_timer = tokio::time::interval(std::time::Duration::from_secs(i_idx_interval_sec));
    let mut persist_timer = tokio::time::interval(std::time::Duration::from_secs(i_persist_interval_sec));

    /* -------------------- IAM -------------------------------------------------------------- */
    let cfg_iam = iam_config { s_node_id: swarm.local_peer_id().to_string() };
    let iam = std::sync::Arc::new(iam_store::open(cfg_iam).expect("iam open"));

    {
        let r = iam.ensure_init_user_admin("admin", "admin");
        if r.is_ok() {
            println!("iam: bootstrap checked (default admin may be created if iam was empty)");
        } else {
            println!("iam: bootstrap failed");
        }
    }

    let mut o_iam_cli: Option<IamCliState> = None;

    /* -------------------- Webserver: Shared State + Command Channel ------------------------ */
    let st_web: Arc<std::sync::Mutex<web_shared_state>> = Arc::new(std::sync::Mutex::new(
        web_shared_state::new(swarm.local_peer_id().to_string()),
    ));
    {
        let mut g = st_web.lock().unwrap();
        g.push_event("web: state initialized".to_string());
    }

    let (tx_web_cmd, mut rx_web_cmd) = tokio::sync::mpsc::channel::<web_command>(64);
    {
        let st_web_clone = st_web.clone();
        let tx_web_cmd_clone = tx_web_cmd.clone();

        tokio::spawn(async move {
            let _ = run_web_server(&cfg_get().s_web_bind, tx_web_cmd_clone, st_web_clone).await;
        });
    }
    println!("web: listening on http://{}", cfg_get().s_web_bind);

    /* ====================================================================================== */
    /* Event Loop                                                                              */
    /* ====================================================================================== */
    loop {
        tokio::select! {
            _ = idx_timer.tick() => {
                idx_vec.sync(Path::new(&cfg_get().s_doc_dir.clone()));
                idx_tan.sync(Path::new(&cfg_get().s_doc_dir.clone()));
                let mut g = st_web.lock().unwrap();
                g.push_event("idx: sync done".to_string());
            }

            _ = persist_timer.tick() => {
                persist_index(&idx_vec, p_vec_root.as_path());
                let mut g = st_web.lock().unwrap();
                g.push_event("idx: persist done".to_string());
            }

            Some(cmd) = rx_web_cmd.recv() => {
                handle_web_command(
                    cmd,
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
                    st_web.clone(),
                ).await;
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
                libp2p::swarm::SwarmEvent::Behaviour(BehaviourEvent::Mdns(libp2p::mdns::Event::Discovered(list))) => {
                    for (pid, _) in list {
                        if !h_peer_index.contains_key(&pid) {
                            let i_idx = v_peers.len();
                            h_peer_index.insert(pid, i_idx);
                            v_peers.push(pid);
                            println!("Peer entdeckt [{i_idx}] {pid}");

                            let mut g = st_web.lock().unwrap();
                            g.v_peers.push(web_peer_view {
                                s_peer_id: pid.to_string(),
                                b_online: true,
                            });
                            g.push_event(format!("mdns: discovered peer={}", pid));
                        }
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&pid);
                    }
                }
                libp2p::swarm::SwarmEvent::Behaviour(BehaviourEvent::Mdns(libp2p::mdns::Event::Expired(list))) => {
                    for (pid, _) in list {
                        swarm.behaviour_mut().gossipsub.remove_explicit_peer(&pid);
                        if let Some(i) = h_peer_index.remove(&pid) {
                            v_peers.retain(|p| p != &pid);
                            println!("Peer [{i}] {pid} nicht mehr erreichbar.");

                            let mut g = st_web.lock().unwrap();
                            for pv in g.v_peers.iter_mut() {
                                if pv.s_peer_id == pid.to_string() {
                                    pv.b_online = false;
                                }
                            }
                            g.push_event(format!("mdns: expired peer={}", pid));
                        }
                    }
                }
                libp2p::swarm::SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(
                    libp2p::gossipsub::Event::Message { propagation_source, message, .. }
                )) => {
                    if let Ok(env) = serde_json::from_slice::<Envelope>(&message.data) {
                        if let Some(v_plain) = ctx_global.decrypt(&env.v_payload) {
                            auditor.record(&v_plain);
                            if let Ok(msg) = serde_json::from_slice::<ChatMessage>(&v_plain) {
                                {
                                    let mut g = st_web.lock().unwrap();
                                    g.push_event(format!("gossip: msg from={}", propagation_source));
                                }

                                update_web_cache_from_payload(st_web.clone(), &msg.payload);

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
                                    st_web.clone(),
                                ).await;
                            }
                        }
                    }
                }
                libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Listening on {address}");
                    let mut g = st_web.lock().unwrap();
                    g.push_event(format!("swarm: listen addr={}", address));
                }
                _ => {}
            }
        }
    }
}

/* ========================================================================================== */
/* Web Command Handler                                                                         */
/* ========================================================================================== */
#[allow(clippy::too_many_arguments)]
async fn handle_web_command(
    cmd: web_command,
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
    st_web: Arc<Mutex<web_shared_state>>,
) {
    /* Historie: 12.01.2026 MS - zentrale Schaltstelle fuer Web API Kommandos (inkl. doc text) */
    match cmd {
        web_command::status_get { tx } => {
            let g = st_web.lock().unwrap();
            let v = web_status_view {
                s_node_peer_id: g.s_node_peer_id.clone(),
                i_known_peers: g.v_peers.len(),
                s_chat_peer: g.s_chat_peer.clone().unwrap_or_else(|| "".to_string()),
                s_chat_topic: g.s_chat_topic.clone().unwrap_or_else(|| "".to_string()),
                i_event_ring_len: g.v_event_ring.len(),
            };
            let _ = tx.send(v);
        }

        web_command::peers_get { tx } => {
            let g = st_web.lock().unwrap();
            let _ = tx.send(g.v_peers.clone());
        }

        web_command::events_get { tx } => {
            let g = st_web.lock().unwrap();
            let v: Vec<String> = g.v_event_ring.iter().cloned().collect();
            let _ = tx.send(v);
        }

        web_command::iam_login_local {
            s_user,
            s_password,
            tx,
        } => {
            let r = iam.begin_login(&s_user);
            let resp = match r {
                Ok(ch) => match iam.finish_login_with_password(&s_user, &ch.s_challenge_id, &s_password) {
                    Ok(s_session) => {
                        *o_iam_cli = Some(IamCliState {
                            s_user: s_user.clone(),
                            s_session: s_session.clone(),
                        });
                        {
                            let mut g = st_web.lock().unwrap();
                            g.push_event(format!("iam: login ok user={}", s_user));
                        }
                        web_server::web_login_resp {
                            b_ok: true,
                            s_session,
                            s_error: "".to_string(),
                        }
                    }
                    Err(_) => web_server::web_login_resp {
                        b_ok: false,
                        s_session: "".to_string(),
                        s_error: "unauthorized".to_string(),
                    },
                },
                Err(_) => web_server::web_login_resp {
                    b_ok: false,
                    s_session: "".to_string(),
                    s_error: "begin_login_failed".to_string(),
                },
            };
            let _ = tx.send(resp);
        }

        web_command::iam_group_add {
            s_actor,
            s_group,
            s_rights,
            tx,
        } => {
            let i_rights = parse_u64_any(&s_rights).unwrap_or(0);
            let r = iam.add_group(&s_actor, &s_group, i_rights as rights_mask);
            let v = match r {
                Ok(_) => web_ok_resp { b_ok: true, s_error: "".to_string() },
                Err(_) => web_ok_resp { b_ok: false, s_error: "iam_error".to_string() },
            };
            {
                let mut g = st_web.lock().unwrap();
                g.push_event(format!("iam: group_add group={} ok={}", s_group, v.b_ok));
            }
            let _ = tx.send(v);
        }

        web_command::iam_groups_get { tx } => {
            let v = match iam.list_groups() {
                Ok(v_groups) => v_groups
                    .into_iter()
                    .map(|g| web_server::web_iam_group_view {
                        s_group: g.s_group,
                        s_rights: g.i_rights.to_string(),
                    })
                    .collect::<Vec<web_server::web_iam_group_view>>(),
                Err(_) => Vec::new(),
            };

            {
                let mut g = st_web.lock().unwrap();
                g.push_event(format!("iam: groups_get count={}", v.len()));
            }

            let _ = tx.send(v);
        }

        web_command::iam_user_add {
            s_actor,
            s_user,
            s_password,
            s_group,
            tx,
        } => {
            let r = iam.add_user(&s_actor, &s_user, &s_password, &s_group);
            let v = match r {
                Ok(_) => web_ok_resp { b_ok: true, s_error: "".to_string() },
                Err(_) => web_ok_resp { b_ok: false, s_error: "iam_error".to_string() },
            };
            {
                let mut g = st_web.lock().unwrap();
                g.push_event(format!("iam: user_add user={} ok={}", s_user, v.b_ok));
            }
            let _ = tx.send(v);
        }

        web_command::iam_path_add {
            s_actor,
            s_path,
            s_group_or_dash,
            b_public,
            s_rights,
            tx,
        } => {
            let i_rights = parse_u64_any(&s_rights).unwrap_or(0);
            let o_group = if s_group_or_dash.trim() == "-" { None } else { Some(s_group_or_dash.as_str()) };
            let r = iam.add_path(&s_actor, &s_path, o_group, b_public, i_rights as rights_mask);
            let v = match r {
                Ok(_) => web_ok_resp { b_ok: true, s_error: "".to_string() },
                Err(_) => web_ok_resp { b_ok: false, s_error: "iam_error".to_string() },
            };
            {
                let mut g = st_web.lock().unwrap();
                g.push_event(format!("iam: path_add path={} ok={}", s_path, v.b_ok));
            }
            let _ = tx.send(v);
        }

        web_command::p2p_connect_by_peer_id { s_peer_id, tx } => {
            let peer = match s_peer_id.parse::<PeerId>() {
                Ok(p) => p,
                Err(_) => {
                    let _ = tx.send(web_ok_resp { b_ok: false, s_error: "invalid_peer_id".to_string() });
                    return;
                }
            };

            if !h_peer_index.contains_key(&peer) {
                let i_idx = v_peers.len();
                v_peers.push(peer);
                h_peer_index.insert(peer, i_idx);
            }

            let topic = build_chat_topic(&swarm.local_peer_id(), &peer);
            let _ = swarm.behaviour_mut().gossipsub.subscribe(&topic);

            *o_chat_peer = Some(peer);
            *o_chat_topic = Some(topic.clone());

            {
                let mut g = st_web.lock().unwrap();
                g.s_chat_peer = Some(peer.to_string());
                g.s_chat_topic = Some(topic.to_string());
                g.push_event(format!("p2p: connect initiated peer={}", peer));
            }

            let local_id = swarm.local_peer_id().clone();
            send_encrypted(&local_id, swarm, global_topic, &PayloadType::ConnectRequest);

            let _ = tx.send(web_ok_resp { b_ok: true, s_error: "".to_string() });
        }

        web_command::p2p_send_text { s_text, tx } => {
            let Some(topic) = o_chat_topic else {
                let _ = tx.send(web_ok_resp { b_ok: false, s_error: "no_chat_partner".to_string() });
                return;
            };

            let local_id = swarm.local_peer_id().clone();
            send_encrypted(&local_id, swarm, topic, &PayloadType::Text(s_text.clone()));

            {
                let mut g = st_web.lock().unwrap();
                g.push_event("p2p: send_text ok".to_string());
            }

            let _ = tx.send(web_ok_resp { b_ok: true, s_error: "".to_string() });
        }

        web_command::search_network_combi_dispatch { s_query, i_limit, tx } => {
            *i_search_ctr = i_search_ctr.saturating_add(1);
            let i_id = *i_search_ctr;

            {
                let mut g = st_web.lock().unwrap();
                g.search_cache_insert_new(i_id, s_query.clone(), i_limit, now_ms());
                g.push_event(format!(
                    "search: combi dispatch id={} q_len={} limit={}",
                    i_id,
                    s_query.len(),
                    i_limit
                ));
            }

            /* 1) Local: compute and cache local hits immediately (WITH snippets) */
            let s_local_peer = swarm.local_peer_id().to_string();
            let v_local = combi_search_with_snippets(&idx_tan, &idx_vec, &s_query, i_limit);

            if !v_local.is_empty() {
                let mut v_web_hits: Vec<web_search_hit> = Vec::with_capacity(v_local.len());
                for h in v_local {
                    v_web_hits.push(web_search_hit {
                        s_peer_id: s_local_peer.clone(),
                        s_doc: h.s_doc,
                        d_score: h.d_score,
                        s_snippet: h.s_snippet,
                    });
                }

                {
                    let mut g = st_web.lock().unwrap();
                    g.search_cache_add_hits(i_id, v_web_hits);
                    let i_hits_len: usize = g.search_cache_hits_len(i_id).unwrap_or(0);

                    g.push_event(format!("search: combi local cached id={} hits={}", i_id, i_hits_len));
                }
            } else {
                let mut g = st_web.lock().unwrap();
                g.push_event(format!("search: combi local cached id={} hits=0", i_id));
            }

            /* 2) Network: send request to peers (remote hits arrive async) */
            let local_id = swarm.local_peer_id().clone();
            send_encrypted(
                &local_id,
                swarm,
                global_topic,
                &PayloadType::CombiSearchRequest { i_id, s_query: s_query.clone() },
            );

            let _ = tx.send(web_search_dispatch_resp {
                b_ok: true,
                s_error: "".to_string(),
                i_search_id: i_id,
            });
        }

        web_command::search_network_combi_get { i_search_id, tx } => {
            let o = {
                let mut g = st_web.lock().unwrap();
                g.search_cache_get(i_search_id)
            };

            let resp = match o {
                Some(st) => web_search_resp {
                    b_ok: true,
                    s_error: "".to_string(),
                    i_search_id: st.i_search_id,
                    v_hits: st.v_hits,
                    b_partial: st.b_partial,
                },
                None => web_search_resp {
                    b_ok: false,
                    s_error: "not_found".to_string(),
                    i_search_id,
                    v_hits: Vec::new(),
                    b_partial: true,
                },
            };
            let _ = tx.send(resp);
        }

        web_command::doc_text_get { s_peer_id, s_path, tx } => {
            /* Web click: local read or remote P2P request */
            let s_local_peer = swarm.local_peer_id().to_string();

            if s_peer_id == s_local_peer {
                let s_txt = extract_doc_text(Path::new(&s_path)).unwrap_or_else(|_| String::new());
                let s_out = safe_truncate_chars(&s_txt, I_DOC_TEXT_MAX_LEN);

                let resp = web_doc_text_resp {
                    b_ok: !s_out.is_empty(),
                    s_error: if s_out.is_empty() { "doc_empty_or_unreadable".to_string() } else { "".to_string() },
                    s_peer_id,
                    s_path,
                    s_text: s_out,
                };
                let _ = tx.send(resp);
                return;
            }

            /* Remote: dispatch DocTextRequest and respond immediately with a pending marker */
            *i_search_ctr = i_search_ctr.saturating_add(1);
            let i_id = *i_search_ctr;

            {
                let mut g = st_web.lock().unwrap();
                g.doc_cache_insert_pending(i_id, s_peer_id.clone(), s_path.clone(), now_ms());
                g.push_event(format!(
                    "doc: dispatch id={} peer={} path_len={}",
                    i_id,
                    s_peer_id,
                    s_path.len()
                ));
            }

            let peer = match s_peer_id.parse::<PeerId>() {
                Ok(p) => p,
                Err(_) => {
                    let _ = tx.send(web_doc_text_resp {
                        b_ok: false,
                        s_error: "invalid_peer_id".to_string(),
                        s_peer_id,
                        s_path,
                        s_text: "".to_string(),
                    });
                    return;
                }
            };

            /* Ensure topic exists */
            let topic = build_chat_topic(&swarm.local_peer_id(), &peer);
            let _ = swarm.behaviour_mut().gossipsub.subscribe(&topic);

            let local_id = swarm.local_peer_id().clone();
            send_encrypted(&local_id, swarm, &topic, &PayloadType::DocTextRequest { i_id, s_path: s_path.clone() });

            /* For web: immediate response indicates pending; UI can poll doc cache endpoint if added */
            let _ = tx.send(web_doc_text_resp {
                b_ok: true,
                s_error: format!("pending:{}", i_id),
                s_peer_id,
                s_path,
                s_text: "".to_string(),
            });
        }

        _ => {
            let mut g = st_web.lock().unwrap();
            g.push_event("web: unsupported_command".to_string());
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
        "help" | "menu" => print_menu(),
        "iam_help" => print_iam_help(),

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
            let Some(i_rights) = parse_u64_any(v[2]) else {
                println!("invalid rights");
                return;
            };

            let s_actor = o_iam_cli.as_ref().map(|x| x.s_user.as_str()).unwrap_or("local_admin");
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

            let s_actor = o_iam_cli.as_ref().map(|x| x.s_user.as_str()).unwrap_or("local_admin");
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

            let s_actor = o_iam_cli.as_ref().map(|x| x.s_user.as_str()).unwrap_or("local_admin");
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
            let s_actor = o_iam_cli.as_ref().map(|x| x.s_user.as_str()).unwrap_or("local_admin");

            match iam.add_path(s_actor, s_path, o_group, b_public, i_rights_u64 as rights_mask) {
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
                    let s_pw = match prompt_password_no_echo("iam password: ") {
                        Ok(x) => x,
                        Err(e) => {
                            println!("iam error: {}", e);
                            return;
                        }
                    };

                    match iam.finish_login_with_password(s_user, &ch.s_challenge_id, &s_pw) {
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

            let Some(_b_public) = parse_bool_01(s_public) else {
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

            match iam.check_access(&st.s_session, s_path, i_right, cfg_get().b_iam_remote_scope_public) {
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
            let Some(topic) = o_chat_topic else {
                println!("Kein Chat Partner.");
                return;
            };

            let s_file = s.split_whitespace().nth(1).unwrap_or("").to_string();
            if s_file.trim().is_empty() {
                println!("missing file name");
                return;
            }

            let Some(st) = o_iam_cli.as_ref() else {
                println!("iam: not_logged_in - file request denied");
                return;
            };

            let i_need = right_read;
            match iam.check_access(&st.s_session, &s_file, i_need, cfg_get().b_iam_remote_scope_public) {
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
            send_encrypted(&local_id, swarm, global_topic, &PayloadType::SearchRequest { i_id, s_query });
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
                        println!("  {d_score:.4}  {s_doc}", d_score = h.d_score, s_doc = h.s_doc);
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
            send_encrypted(&local_id, swarm, global_topic, &PayloadType::VecSearchRequest { i_id, s_query });
            println!("Vektor Suche (ID {i_id}) gesendet.");
        }

        s if s.starts_with("combi_search ") => {
            let s_query = s.strip_prefix("combi_search ").unwrap_or("").to_string();

            let v_res = combi_search_with_snippets(&idx_tan, &idx_vec, &s_query, 5);
            if v_res.is_empty() {
                println!("(lokal) keine Hybrid Treffer");
            } else {
                println!("(lokal)");
                for h in &v_res {
                    println!("  {:>7.4}  {}", h.d_score, h.s_doc);
                }
            }

            *i_search_ctr += 1;
            let i_id = *i_search_ctr;
            let local_id = swarm.local_peer_id().clone();
            send_encrypted(&local_id, swarm, global_topic, &PayloadType::CombiSearchRequest { i_id, s_query });
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
    st_web: Arc<Mutex<web_shared_state>>,
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
            send_encrypted(&local_id, swarm, global_topic, &PayloadType::IamDeltaResponse(resp));
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
                send_encrypted(&local_id, swarm, &topic, &PayloadType::DirResponse(s_listing));
            }
        }
        PayloadType::DirResponse(s_ls) => {
            println!("-- Verzeichnis von {src} --\n{s_ls}-- Ende --");
        }

        PayloadType::FileRequest(s_name) => {
            /* IAM: Remote FileRequest wird als public scope bewertet. */
            let b_allow = {
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

            println!("Datei Teil {} von {} Bytes empfangen.", chunk.i_index, chunk.v_bytes.len());
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
                &PayloadType::SearchResponse { i_id, s_peer: local_id.to_string(), v_hits },
            );
        }
        PayloadType::SearchResponse { i_id, s_peer, v_hits } => {
            if v_hits.is_empty() {
                println!("(ID {i_id}) {s_peer}: keine Treffer");
            } else {
                for SearchHit { s_doc, d_score } in v_hits {
                    println!("(ID {i_id}) {s_peer}: {d_score:.3} {s_doc}");
                }
            }
        }

        PayloadType::VecSearchRequest { i_id, s_query } => {
            idx_vec.sync(Path::new(&cfg_get().s_doc_dir.clone()));
            let v_hits = idx_vec.query_with_snippets(&s_query, 5);

            let local_id = swarm.local_peer_id().clone();
            send_encrypted(
                &local_id,
                swarm,
                global_topic,
                &PayloadType::VecSearchResponse { i_id, s_peer: local_id.to_string(), v_hits },
            );
        }
        PayloadType::VecSearchResponse { i_id, s_peer, v_hits } => {
            if v_hits.is_empty() {
                println!("(ID {i_id}) {s_peer}: keine Vektor Treffer");
            } else {
                for h in v_hits {
                    println!("==========================");
                    println!("(ID {i_id}) {s_peer}: {d_score:.4} {s_doc}", d_score = h.d_score, s_doc = h.s_doc);
                    if !h.s_snippet.trim().is_empty() {
                        println!("(ID {i_id}) {s_peer}: snippet: {s_snippet}", s_snippet = h.s_snippet);
                    }
                    println!("==========================");
                }
            }
        }

        PayloadType::CombiSearchRequest { i_id, s_query } => {
            idx_vec.sync(Path::new(&cfg_get().s_doc_dir.clone()));
            let v_hits = combi_search_with_snippets(&idx_tan, &idx_vec, &s_query, 5);

            let local_id = swarm.local_peer_id().clone();
            send_encrypted(
                &local_id,
                swarm,
                global_topic,
                &PayloadType::CombiSearchResponse { i_id, s_peer: local_id.to_string(), v_hits },
            );
        }
        PayloadType::CombiSearchResponse { i_id, s_peer, v_hits } => {
            if v_hits.is_empty() {
                println!("(ID {i_id}) {s_peer}: keine Hybrid Treffer");
            } else {
                for h in v_hits {
                    println!("(ID {i_id}) {s_peer}: {:>7.4} {}", h.d_score, h.s_doc);
                }
            }
        }

        PayloadType::DocTextRequest { i_id, s_path } => {
            /* IAM: remote doc requests are evaluated with public scope */
            let b_allow = {
                let s_dummy_session = "00000000000000000000000000000000";
                match iam.check_access(s_dummy_session, &s_path, right_read, true) {
                    Ok(dec) => dec.b_allowed,
                    Err(_) => false,
                }
            };

            let local_id = swarm.local_peer_id().clone();
            let topic = build_chat_topic(&swarm.local_peer_id(), src);

            if !b_allow {
                send_encrypted(
                    &local_id,
                    swarm,
                    &topic,
                    &PayloadType::DocTextResponse {
                        i_id,
                        s_peer: local_id.to_string(),
                        s_path,
                        s_text: "".to_string(),
                        s_error: "iam_deny".to_string(),
                    },
                );
                return;
            }

            let s_txt = extract_doc_text(Path::new(&s_path)).unwrap_or_else(|_| String::new());
            let s_out = safe_truncate_chars(&s_txt, I_DOC_TEXT_MAX_LEN);

            send_encrypted(
                &local_id,
                swarm,
                &topic,
                &PayloadType::DocTextResponse {
                    i_id,
                    s_peer: local_id.to_string(),
                    s_path,
                    s_text: s_out,
                    s_error: "".to_string(),
                },
            );
        }

        PayloadType::DocTextResponse { i_id, s_peer, s_path, s_text, s_error } => {
            let mut g = st_web.lock().unwrap();
            g.doc_cache_set_result(i_id, s_peer, s_path, s_text, s_error);
            g.push_event(format!("doc: resp cached id={}", i_id));
        }
    }
}

/* ========================================================================================== */
/* Web Cache Update (aus Payload)                                                              */
/* ========================================================================================== */
fn update_web_cache_from_payload(st_web: Arc<Mutex<web_shared_state>>, payload: &PayloadType) {
    /* Historie: 12.01.2026 MS - Web: store network combi results with peer_id per hit + snippet */
    match payload {
        PayloadType::CombiSearchResponse { i_id, s_peer, v_hits } => {
            let mut v_web_hits: Vec<web_search_hit> = Vec::new();
            for h in v_hits.iter() {
                v_web_hits.push(web_search_hit {
                    s_peer_id: s_peer.clone(),
                    s_doc: h.s_doc.clone(),
                    d_score: h.d_score,
                    s_snippet: h.s_snippet.clone(),
                });
            }

            let mut g = st_web.lock().unwrap();
            g.search_cache_add_hits(*i_id, v_web_hits);
            g.push_event(format!("search: combi resp cached id={} peer={}", i_id, s_peer));
        }
        _ => {}
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
    /* NOTE: Existing project behavior kept as-is. */
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
    let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), v_buf);
}

fn now_ms() -> u64 {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0));
    d.as_millis() as u64
}
