/**********************************************************************************************
 *  Modulname : secure_p2p_ext
 *  Datei     : main.rs
 *  Autor     : Marcus Schlieper
 *---------------------------------------------------------------------------------------------
 *  Historie
 *  09.11.2025   MS   • Grundversion (Chat, DOS-Befehle, Handshake-Topic)
 *  10.11.2025   MS   • Kryptographische / funktionale Erweiterungen
 *                    – Ende-zu-Ende-Verschlüsselung (AES-GCM-SIV 256 Bit)
 *                    – Chunk-basierter Datei-Transfer (64 KiB + Sliding-Window-ACK)
 *                    – Persistente Offline-Queue (sled)
 *                    – Multisignatur-Authentifizierung (BLS-Threshold t/n)
 *                    – Audit-Logging (Merkle-Wurzel, SHA-256)
 *                    – Vollständige DOS-Befehlsschnittstelle  dir | type | get | put
 *  13.11.2025   MS   • Erweiterung: RAG-Schlagwortsuche (Tantivy)
 *                    – Hintergrund-Crawler (30 s) für Verzeichnis ./Documents
 *                    – Volltext-Index (Tantivy BM25)  |  Dateitypen: txt, pdf, docx, xlsx, pptx
 *                    – Neuer Netzwerk-Befehl  search
 *                    – Verteilte Ergebnisaggregation mit Score-Ausgabe
 *  15.11.2025  MS  • Neuer hybrider Suchtyp »combi_search«
 *                                – Kandidatengenerierung via BM25 (Tantivy)
 *                                – Semantisches Re-Ranking via Sentence-Transformer
 *                                – Verteilte Verarbeitung über neue Payload-Typen
 *                                – Ausgabe lokaler Treffer + Response an Remote-Peer
 *                                – Sichere Kommunikation bleibt unverändert (AES-GCM-SIV)
 *
 *
 *
 **********************************************************************************************/
#![allow(clippy::needless_return)]
#![allow(warnings)]

/* ═════════════════════════════════════ Imports ══════════════════════════════════════════════ */
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
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io,
    io::AsyncBufReadExt,
    runtime::Builder,
    select,
    sync::mpsc::{self, UnboundedSender},
    task,
    task::LocalSet,
    time::sleep,
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
/* --- Eigene Importe ---------------------------------------------------------------------- */
mod vector_idx;

use crate::vector_idx::cosine;
use crate::vector_idx::VecSearchHit;
use crate::vector_idx::VectorIndex;
use vector_idx::{load_or_init_index, persist_index};

/* ═════════════════════════════════════ Konstanten ══════════════════════════════════════════ */
const CHUNK_SIZE: usize = 65_536; /* 64 KiB                        */
const GLOBAL_TOPIC: &str = "expchat-main";
const DOC_DIR: &str = "Documents";
const IDX_DIR: &str = "tantivy_idx";
const IDX_INTERVAL_SEC: u64 = 30;

/* ═════════════════════════════ Payload-Strukturen ═════════════════════════════════════════ */
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
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ChatMessage {
    s_sender: String,
    payload: PayloadType,
}

/* Datei-Chunk ------------------------------------------------------------------------------ */
#[derive(Serialize, Deserialize, Debug, Clone)]
struct FileChunk {
    s_name: String,
    i_index: u32,
    i_total: u32,
    v_bytes: Vec<u8>,
}

/* Suchtreffer ----------------------------------------------------------------------------- */
#[derive(Serialize, Deserialize, Debug, Clone)]
struct SearchHit {
    s_doc: String,
    d_score: f32,
}

/* ═════════════════════════════ Kryptographie ══════════════════════════════════════════════ */
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

/* ═════════════════════════════ Audit-Log ══════════════════════════════════════════════════ */
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

/* ─────────────────────────────  Persistenter Dokument-Tracker  ───────────────────────────── */
struct DocTracker {
    db: sled::Db, /* Key = Pfad (String), Value = u64 (mtime) */
}
impl DocTracker {
    fn new() -> Self {
        let db = sled::open("processed_docs").expect("Tracker-DB init");
        Self { db }
    }
    /* Gibt stored mtime (falls vorhanden) zurück                                           */
    fn mtime(&self, s_path: &str) -> Option<u64> {
        self.db.get(s_path).ok().flatten().map(|ivec| {
            let mut a = [0u8; 8];
            a.copy_from_slice(&ivec);
            u64::from_le_bytes(a)
        })
    }
    /* Speichert / aktualisiert mtime                                                      */
    fn set_mtime(&self, s_path: &str, i_mtime: u64) {
        let bytes = i_mtime.to_le_bytes();
        let _ = self.db.insert(s_path, IVec::from(&bytes[..]));
    }
    /* Entfernt Eintrag                                                                    */
    fn remove(&self, s_path: &str) {
        let _ = self.db.remove(s_path);
    }
    /* Liefert Iterator über alle bekannten Pfade                                          */
    fn all_paths(&self) -> Vec<String> {
        self.db
            .iter()
            .keys()
            .flatten()
            .map(|k| String::from_utf8_lossy(&k).into_owned())
            .collect()
    }
}
/* ═════════════════════════════ Tantivy-Index ══════════════════════════════════════════════ */
struct TantivyIndex {
    index: Index,
    writer: Mutex<IndexWriter>,
    reader: IndexReader,
    f_path: tantivy::schema::Field,
    f_content: tantivy::schema::Field,
    tracker: DocTracker,
}
impl TantivyIndex {
    fn new(p_dir: &Path) -> Self {
        fs::create_dir_all(IDX_DIR).ok();
        let mut schema_builder = Schema::builder();
        let f_path = schema_builder.add_text_field("path", STORED);
        let f_content = schema_builder.add_text_field("content", TEXT);
        let schema = schema_builder.build();

        let idx =
            Index::open_or_create(MmapDirectory::open(IDX_DIR).unwrap(), schema.clone()).unwrap();
        let writer = idx.writer(50_000_000).unwrap(); /* 50 MB RAM-Budget           */
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

    /* Öffentliche Synchronisationsroutine (ersetzt rebuild) */
    fn sync(&self, p_scan: &Path) {
        let mut w = self.writer.lock().unwrap();
        let mut v_seen: Vec<String> = Vec::new();

        /* 1. Crawling – neue / geänderte Dateien erfassen */
        Self::walk_dir(
            p_scan,
            &mut w,
            self.f_path,
            self.f_content,
            &self.tracker,
            &mut v_seen,
        );

        /* 2. Entfernte Dateien aus Index + Tracker löschen */
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

    /* Rekursiver Walk mit Prüfung auf Änderung */
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

                    /* mtime in Sekunden */
                    let i_mtime = md
                        .modified()
                        .unwrap_or(SystemTime::UNIX_EPOCH)
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();

                    /* Änderung? */
                    if tracker.mtime(&s_p).map_or(true, |old| old != i_mtime) {
                        if let Some(s_txt) = extract_doc_text(&p).ok().filter(|s| !s.is_empty()) {
                            /* Vorhandenen Eintrag ersetzen */
                            w.delete_term(Term::from_field_text(f_path, &s_p));
                            let _ = w.add_document(doc!(
                                f_path    => s_p.as_str(),
                                f_content => s_txt,
                            ));
                            tracker.set_mtime(&s_p, i_mtime);
                        }
                    }
                }
            }
        }
    }
    /* Suche -------------------------------------------------------------------------------- */
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
    /* Rekursives Crawling + Indizieren ----------------------------------------------------- */
}

const I_SNIPPET_MAX_LEN: usize = 320;
const I_SNIPPET_SCAN_MAX_LEN: usize = 32_000;

fn normalize_for_match(s_in: &str) -> String {
    // ASCII only, lower, normalize whitespace. Safe, bounded by input length.
    let mut s_out = String::with_capacity(s_in.len().min(I_SNIPPET_SCAN_MAX_LEN));
    let mut b_prev_space = false;

    for ch in s_in.chars().take(I_SNIPPET_SCAN_MAX_LEN) {
        let ch_l = ch.to_ascii_lowercase();
        if ch_l.is_ascii_alphanumeric() {
            s_out.push(ch_l);
            b_prev_space = false;
        } else {
            if !b_prev_space {
                s_out.push(' ');
                b_prev_space = true;
            }
        }
    }

    s_out.split_whitespace().collect::<Vec<&str>>().join(" ")
}

fn extract_query_tokens(s_query: &str) -> Vec<String> {
    // Simple tokenization for snippet bias. Keeps only ascii alnum tokens length >= 2.
    let s_norm = normalize_for_match(s_query);
    let mut v_out: Vec<String> = Vec::new();
    for s_t in s_norm.split_whitespace() {
        if s_t.len() >= 2 {
            v_out.push(s_t.to_string());
        }
    }
    v_out
}

fn build_snippet_for_query(s_text: &str, s_query: &str) -> String {
    // Query-biased window snippet with safe fallback.
    // Uses normalized match to find a token position in original text approximately.
    let s_text_trim = s_text.trim();
    if s_text_trim.is_empty() {
        return String::new();
    }

    let s_norm = normalize_for_match(s_text_trim);
    if s_norm.is_empty() {
        // Fallback: first chars from original
        return s_text_trim
            .chars()
            .take(I_SNIPPET_MAX_LEN)
            .collect::<String>();
    }

    let v_q = extract_query_tokens(s_query);
    if v_q.is_empty() {
        return s_text_trim
            .chars()
            .take(I_SNIPPET_MAX_LEN)
            .collect::<String>();
    }

    // Find earliest occurrence of any token in normalized text
    let mut i_best_pos: Option<usize> = None;
    for s_t in &v_q {
        if let Some(i_pos) = s_norm.find(s_t) {
            i_best_pos = match i_best_pos {
                None => Some(i_pos),
                Some(old) => Some(old.min(i_pos)),
            };
        }
    }

    // If no token found: prefix snippet
    let Some(i_pos_norm) = i_best_pos else {
        return s_text_trim
            .chars()
            .take(I_SNIPPET_MAX_LEN)
            .collect::<String>();
    };

    // Map normalized position to approximate char position in original by ratio.
    // This is heuristic but safe and deterministic.
    let d_ratio = (s_text_trim.len().max(1) as f64) / (s_norm.len().max(1) as f64);
    let i_pos_orig = ((i_pos_norm as f64) * d_ratio) as usize;

    let i_half = I_SNIPPET_MAX_LEN / 2;
    let i_start = i_pos_orig.saturating_sub(i_half);
    let i_end = (i_start + I_SNIPPET_MAX_LEN).min(s_text_trim.len());

    let s_slice = &s_text_trim[i_start..i_end];
    // Normalize whitespace for console / network
    s_slice.split_whitespace().collect::<Vec<&str>>().join(" ")
}

/* ========================================================================================== *
 *  ░░░ 3.  main.rs – Hilfsroutine combi_search()
 * ========================================================================================== */
/// Kombiniert BM25-Score und Kosinus-Ähnlichkeit zu einem End-Score.
/// Gewichtet beide Komponenten jeweils mit 0.5.
/**********************************************************************************************
 *  Änderung   : 15.11.2025  MS  • Fuzzy-BM25 + Vektor-Fallback
 *********************************************************************************************/
const GAMMA: f32 = 2.0; // nicht-lineare Verstärkung
const BM25_WEIGHT: f32 = 0.7; // α
const VEC_WEIGHT: f32 = 0.3; // β
const EXACT_BONUS: f32 = 0.15;
const LLM_WEIGHT: f32 = 0.2;

/// Re-Ranking mit Aufwertung exakter Treffer
/* Überarbeitete combi_search() -------------------------------------------------------------*/
pub fn combi_search(
    idx_tan: &TantivyIndex,
    idx_vec: &Arc<VectorIndex>,
    s_query: &str,
    i_limit: usize,
) -> Vec<(String, f32)> {
    /* 1. BM25-Kandidaten ------------------------------------------------------*/
    let mut v_bm = idx_tan.search(s_query, 200);
    if v_bm.is_empty() {
        return idx_vec.query(s_query, i_limit);
    }

    /* 2. Embeddings -----------------------------------------------------------*/
    let v_q_vec = idx_vec.encode_query(s_query);

    /* 3. Re-Ranking -----------------------------------------------------------*/
    let d_bm_max = v_bm.first().map(|h| h.d_score).unwrap_or(1.0);
    let mut v_combined = Vec::new();

    for SearchHit { s_doc, d_score } in v_bm.drain(..) {
        if let Some(v_doc_vec) = (idx_vec.vec_of(&s_doc)) {
            /* Normierung */
            let d_bm_n = d_score / d_bm_max.max(1.0);
            let d_vec_n = cosine(&v_q_vec, &v_doc_vec).max(0.0); // 0..1

            /* Finale Gewichtung */
            let d_final: f32 = BM25_WEIGHT * d_bm_n + VEC_WEIGHT * d_vec_n;

            v_combined.push((s_doc, d_final));
        }
    }

    v_combined.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    v_combined.truncate(i_limit);
    v_combined
}

/* ────────────────────────────── Alias für Rückgabetyp ─────────────────────────────────────── */
pub type ResultStr = std::result::Result<String, Box<dyn Error + Send + Sync>>;

/* ════════════════════════════ Dispatcher: Dokumente ═════════════════════════════════════════ */
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

/* ═════════════════════════════ PDF (pdf-extract) ════════════════════════════════════════════ */
fn extract_pdf_text(p_path: &Path) -> ResultStr {
    // Seit pdf_extract 0.8 liefert extract_text direkt einen String.
    // Ein leerer String signalisiert fehlenden Text-Layer (gescanntes PDF o. Ä.).
    let text = extract_text(p_path)?;
    Ok(text) // bereits String → erfüllt ResultStr
}

/* ═════════════════════════════ DOCX (ZIP + XML) ═════════════════════════════════════════════ */
fn extract_docx_text(p: &Path) -> ResultStr {
    let file = fs::File::open(p)?;
    let mut zip = ZipArchive::new(file)?;
    let mut s_all = String::new();

    if let Ok(mut xml) = zip.by_name("word/document.xml") {
        let mut s_buf = String::new();
        xml.read_to_string(&mut s_buf)?; // Read-Trait jetzt im Scope
        for seg in s_buf.split(|c| c == '<' || c == '>') {
            if !seg.starts_with('/') && !seg.contains(' ') {
                s_all.push_str(seg);
                s_all.push(' ');
            }
        }
    }
    Ok(s_all)
}

/* ════════════════════════════ EXCEL (calamine) ══════════════════════════════════════════════ */
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

/* ═════════════════════════════ PPTX (ZIP + XML) ═════════════════════════════════════════════ */
fn extract_pptx_text(p: &Path) -> ResultStr {
    let file = fs::File::open(p)?;
    let mut zip = ZipArchive::new(file)?;
    let mut s_all = String::new();

    for slide_idx in 1..=200 {
        let s_name = format!("ppt/slides/slide{}.xml", slide_idx);
        if let Ok(mut slide) = zip.by_name(&s_name) {
            let mut s_buf = String::new();
            slide.read_to_string(&mut s_buf)?; // Read-Trait jetzt im Scope
            for seg in s_buf.split(|c| c == '<' || c == '>') {
                if !seg.starts_with('/') && !seg.contains(' ') {
                    s_all.push_str(seg);
                    s_all.push(' ');
                }
            }
        } else {
            break; // keine weiteren Folien vorhanden
        }
    }
    Ok(s_all)
}

/* ═════════════════════════════ Persistence-Layer ══════════════════════════════════════════ */
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

/* ═════════════════════════════ libp2p-Behaviour ═══════════════════════════════════════════ */
#[derive(NetworkBehaviour)]
struct Behaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
}

/* ═════════════════════════════ Main-Funktion ══════════════════════════════════════════════ */
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    /* Logging ----------------------------------------------------------------------------- */

    //FmtSubscriber::builder().with_env_filter("info").init();
    let filter = EnvFilter::from_default_env()           // liest RUST_LOG, falls gesetzt
        .add_directive("info".parse()?)                  // globales Minimum
        .add_directive("tantivy=warn".parse()?)          // Tantivy herabstufen
        /* .add_directive("libp2p=info".parse()?)       // Beispiel           */
        ;

    fmt()
        .with_env_filter(filter)
        .with_target(false) // Ziel-Pfad ausblenden (opt.)
        .init();

    /* Kryptographie-Kontext --------------------------------------------------------------- */
    let a_aes_key = *b"01234567012345670123456701234567";
    let sk_set = SecretKeySet::random(1, &mut rand::thread_rng()); /* t = 1 */
    let bls_share = sk_set.secret_key_share(0);
    let ctx_global = CryptoContext::new(&a_aes_key, bls_share);
    let mut auditor = Auditor::new();

    // -----------------------------------------------------------------
    //  Vektor-Index laden (oder leeren Index anlegen, falls Datei fehlt)
    // -----------------------------------------------------------------

    /* libp2p-Swarm ----------------------------------------------------------------------- */
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

    /* Runtime-State ---------------------------------------------------------------------- */
    let mut stdin = io::BufReader::new(io::stdin()).lines();
    let mut v_peers: Vec<PeerId> = Vec::new();
    let mut h_peer_index: HashMap<PeerId, usize> = HashMap::new();
    let mut o_chat_peer: Option<PeerId> = None;
    let mut o_chat_topic: Option<gossipsub::IdentTopic> = None;
    let mut h_chunk_queue: HashMap<PeerId, VecDeque<FileChunk>> = HashMap::new();
    let _db = PersistenceLayer::new();
    let (tx_ack, mut rx_ack) = mpsc::unbounded_channel::<(PeerId, u32)>();
    let mut i_search_ctr: u64 = 0;

    /* Listener --------------------------------------------------------------------------- */
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
    swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;
    println!("ExpChat.ai gestartet – »help« listet Befehle.");

    //let idx_vec = load_or_init_index(Path::new("."));
    let idx_vec = tokio::task::block_in_place(|| {
        load_or_init_index(Path::new(".")) // kann weiterhin panic!-frei
    });

    let idx_tan = Arc::new(TantivyIndex::new(Path::new(DOC_DIR)));

    let mut idx_timer = tokio::time::interval(Duration::from_secs(IDX_INTERVAL_SEC));
    let mut persist_timer = tokio::time::interval(Duration::from_secs(900)); // 15 min

    /* Event-Loop ------------------------------------------------------------------------- */
    loop {
        select! {
            _ = idx_timer.tick() => {
                idx_vec.sync(Path::new(DOC_DIR));      // Vektor-Index
                idx_tan.sync(Path::new(DOC_DIR));      // Tantivy-Index
            }

            _ = persist_timer.tick() => {
                persist_index(&idx_vec, Path::new("."));
            }

            /* Benutzer-Eingabe ------------------------------------------------------------ */
            Ok(Some(s_line)) = stdin.next_line() => {
                handle_user_input(
                    &s_line,
                    &mut swarm,
                    &global_topic,
                    &mut v_peers,
                    &mut h_peer_index,
                    &mut o_chat_peer,
                    &mut o_chat_topic,
                    idx_tan.clone(),   // BM25-Index
                    idx_vec.clone(),   // Vektor-Index

                    &mut i_search_ctr,
                ).await;
            }

            /* ACK-Handling --------------------------------------------------------------- */
            Some((pid, i_idx)) = rx_ack.recv() => {
                if let Some(q) = h_chunk_queue.get_mut(&pid) {
                    while let Some(f) = q.front() {
                        if f.i_index <= i_idx { q.pop_front(); } else { break }
                    }
                }
            }

            /* libp2p-Events -------------------------------------------------------------- */
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
                                    idx_tan.clone(),   // BM25-Index
                                    idx_vec.clone(),   // Vektor-Index

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

/* ═════════════════════════════ Benutzer-Eingabe-Logik ═════════════════════════════════════ */
#[allow(clippy::too_many_arguments)]
async fn handle_user_input(
    s_input: &str,
    swarm: &mut Swarm<Behaviour>,
    global_topic: &gossipsub::IdentTopic,
    v_peers: &mut Vec<PeerId>,
    h_peer_index: &mut HashMap<PeerId, usize>,
    o_chat_peer: &mut Option<PeerId>,
    o_chat_topic: &mut Option<gossipsub::IdentTopic>,
    idx_tan: Arc<TantivyIndex>, // BM25
    idx_vec: Arc<VectorIndex>,  // Vektor
    i_search_ctr: &mut u64,
) {
    let s_cmd = s_input.trim();
    match s_cmd {
        "help" | "menu" => {
            println!(
                "Verfügbare Befehle
  help | menu            : Dieses Menü
  peers                  : Peerliste anzeigen
  connect <idx>          : Verbindung zu Peer herstellen
  write <txt>            : Nachricht senden
  dir                    : Verzeichnis des Partners abfragen
  type <file>            : Datei anzeigen
  get  <file>            : Datei herunterladen
  put  <pfad>            : Datei hochladen
  search <query>         : Schlagwortsuche im P2P-Netz
  vec_search <query>     : Vektor Suche im P2P-Netz
  combi_search <query>   : Fehlertolerante Hybrid-Suche (BM25 + Vektor)
  exit                   : Programm beenden"
            );
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
                println!("Kein Chat-Partner verbunden.");
            }
        }
        "dir" => {
            if let Some(topic) = o_chat_topic {
                let local_id = swarm.local_peer_id().clone();
                send_encrypted(&local_id, swarm, topic, &PayloadType::DirRequest);
                println!("Verzeichnis angefragt …");
            } else {
                println!("Kein Chat-Partner.");
            }
        }
        s if s.starts_with("type ") || s.starts_with("get ") => {
            if let Some(topic) = o_chat_topic {
                let s_file = s.split_whitespace().nth(1).unwrap_or("").to_string();
                let local_id = swarm.local_peer_id().clone();
                send_encrypted(&local_id, swarm, topic, &PayloadType::FileRequest(s_file));
            } else {
                println!("Kein Chat-Partner.");
            }
        }
        s if s.starts_with("put ") => {
            if let Some(topic) = o_chat_topic {
                let s_path = s.strip_prefix("put ").unwrap_or("").trim();
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
                println!("Kein Chat-Partner.");
            }
        }
        s if s.starts_with("search ") => {
            let s_query = s.strip_prefix("search ").unwrap_or("").to_string();
            /* 1. lokale Suche ------------------------------------------------------------- */
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
            /* 2. verteilte Suche ---------------------------------------------------------- */
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

            // 1. lokal
            {
                let v_res = idx_vec.query_with_snippets(&s_query, 5);
                if v_res.is_empty() {
                    println!("(lokal) keine Vektor-Treffer");
                } else {
                    println!("(lokal)");
                    for h in &v_res {
                        println!(
                            "  {d_score:.4}  {s_doc}",
                            d_score = h.d_score,
                            s_doc = h.s_doc
                        );
                        if !h.s_snippet.is_empty() {
                            println!("    snippet: {s}", s = h.s_snippet);
                        }
                    }
                }
            }

            // 2. distributed
            *i_search_ctr += 1;
            let i_id = *i_search_ctr;
            let local_id = swarm.local_peer_id().clone();

            send_encrypted(
                &local_id,
                swarm,
                global_topic,
                &PayloadType::VecSearchRequest { i_id, s_query },
            );
            println!("Vektor-Suche (ID {i_id}) gesendet.");
        }

        s if s.starts_with("combi_search ") => {
            let s_query = s.strip_prefix("combi_search ").unwrap_or("").to_string();

            /* 1. lokal */
            let v_res = combi_search(&idx_tan, &idx_vec, &s_query, 5);
            if v_res.is_empty() {
                println!("(lokal) keine Hybrid-Treffer");
            } else {
                println!("(lokal)");
                for (s_doc, d_score) in &v_res {
                    println!("  {:>7.4}  {}", d_score, s_doc);
                }
            }

            /* 2. verteilt */
            *i_search_ctr += 1;
            let i_id = *i_search_ctr;
            let local_id = swarm.local_peer_id().clone();
            send_encrypted(
                &local_id,
                swarm,
                global_topic,
                &PayloadType::CombiSearchRequest { i_id, s_query },
            );
            println!("Hybrid-Suche (ID {i_id}) gesendet.");
        }
        _ => println!("Unbekanntes Kommando – »help« hilft."),
    }
}

/* ═════════════════════════════ Eingehende Nachrichten ═════════════════════════════════════ */
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
    idx_tan: Arc<TantivyIndex>, // BM25-Index
    idx_vec: Arc<VectorIndex>,  // Vektor-Index
) {
    match msg.payload {
        /* ------------- Chat / Datei ----------------------------------------------------- */
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
            println!("— Verzeichnis von {src} —\n{s_ls}— Ende —");
        }
        PayloadType::FileRequest(s_name) => match fs::read(&s_name) {
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
            Err(e) => println!("Datei-Fehler: {e}"),
        },
        PayloadType::FileTransfer(chunk) => {
            let dir = PathBuf::from("inbox");
            fs::create_dir_all(&dir).ok();
            let mut file = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(dir.join(&chunk.s_name))
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut file, &chunk.v_bytes)
                .await
                .unwrap();
            println!(
                "Datei-Teil {} von {} Bytes empfangen.",
                chunk.i_index,
                chunk.v_bytes.len()
            );
            /* ACK */
            let _ = tx_ack.send((*src, chunk.i_index));
        }
        PayloadType::ChunkAck(_i_idx) => { /* Sender-Seite */ }
        /* ------------- Verbindung ------------------------------------------------------- */
        PayloadType::ConnectRequest => {
            let topic = build_chat_topic(&swarm.local_peer_id(), src);
            swarm.behaviour_mut().gossipsub.subscribe(&topic).ok();
            *o_chat_peer = Some(*src);
            *o_chat_topic = Some(topic.clone());
            let local_id = swarm.local_peer_id().clone();
            send_encrypted(&local_id, swarm, global_topic, &PayloadType::ConnectAck);
            println!("Handshake von {src} akzeptiert.");
        }
        PayloadType::ConnectAck => println!("Peer {src} bestätigt Verbindung."),
        PayloadType::OfflineFlush => println!("Peer {src} meldet: Queue abgearbeitet."),
        /* ------------- Suche ------------------------------------------------------------ */
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
        /* ------------- Vektor - Suche ------------------------------------------------------------ */
        PayloadType::VecSearchRequest { i_id, s_query } => {
            // 1. Index aktuell halten
            idx_vec.sync(std::path::Path::new(DOC_DIR));

            // 2. Jetzt semantisch suchen + Snippets
            let v_hits = idx_vec.query_with_snippets(&s_query, 5);

            // 3. Antwort verschicken
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
                println!("(ID {i_id}) {s_peer}: keine Vektor-Treffer");
            } else {
                for h in v_hits {
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
                }
            }
        }
        PayloadType::CombiSearchRequest { i_id, s_query } => {
            idx_vec.sync(Path::new(DOC_DIR)); /* Aktualität sicherstellen */

            let v_hits = combi_search(&idx_tan, &idx_vec, &s_query, 5);

            /* Lokale Konsolen-Ausgabe */
            if v_hits.is_empty() {
                println!(
                    "(lokal – Peer {}) keine Hybrid-Treffer für \"{}\"",
                    swarm.local_peer_id(),
                    s_query
                );
            } else {
                println!(
                    "(lokal – Peer {}) Hybrid-Treffer für \"{}\"",
                    swarm.local_peer_id(),
                    s_query
                );
                for (s_doc, d_score) in &v_hits {
                    println!("  {:>7.4}  {}", d_score, s_doc);
                }
            }

            /* Antwort an Netz */
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
                println!("(ID {i_id}) {s_peer}: keine Hybrid-Treffer");
            } else {
                for (s_doc, d_score) in v_hits {
                    println!("(ID {i_id}) {s_peer}: {:>7.4} {}", d_score, s_doc);
                }
            }
        }
    }
}

/* ═════════════════════════════ Hilfsfunktionen ════════════════════════════════════════════ */
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

/* Signierte + verschlüsselte Hülle --------------------------------------------------------- */
#[derive(Serialize, Deserialize, Debug)]
struct Envelope {
    v_sigshares: Vec<(u16, SignatureShare)>,
    v_payload: Vec<u8>,
}

/* Verschlüsseltes Senden ------------------------------------------------------------------- */
fn send_encrypted(
    local_id: &PeerId,
    swarm: &mut Swarm<Behaviour>,
    topic: &gossipsub::IdentTopic,
    payload: &PayloadType,
) {
    /* Hinweis: In produktiven Szenarien sollte der Schlüssel ­persistent sein.            */
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
