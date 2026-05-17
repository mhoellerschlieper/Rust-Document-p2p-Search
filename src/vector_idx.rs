/**********************************************************************************************
 * Modulname : vector_idx
 * Datei     : vector_idx.rs
 * Autor     : Marcus Schlieper
 * Firma     : ExpChat.ai
 *---------------------------------------------------------------------------------------------
 * Beschreibung
 * - Persistenter 5 gram Retrieval Index mit invertiertem Index in eigenem Verzeichnis.
 * - Dokumente und Chunks werden in sled persistiert.
 * - Jeder 5 gram Term wird als eigene Posting Datei unter inv_idx gespeichert.
 * - Embeddings werden in einer separaten sled Tree gespeichert.
 * - Boolesche Suche, Synonymlisten, Woerterbuecher und konfigurierbare Normalisierung.
 * - Synonyme, Dictionary und Normalisierung werden aus JSON Dateien geladen.
 * - Sichere Validierung und defensive Fehlerbehandlung.
 * - Delta Reindexing: Nur neue oder geaenderte Dokumente loesen Reindex aus.
 * - Beim Reindex werden nur betroffene Dokumente in den Indizes ersetzt oder ergaenzt.
 * - Normale Suche: Bool wirkt als Score.
 * - Explizite Bool Query: Bool wirkt als Score Filter.
 *
 * Historie
 * 13.11.2025   MS   - Ausgangsmodul fuer einfachen Vektor Index
 * 16.05.2026   MS   - Persistenter 5 gram Posting Index
 * 17.05.2026   MS   - Leichtgewichtiges Embedding Modul
 * 17.05.2026   MS   - Boolesche Operatoren AND OR NOT
 * 17.05.2026   MS   - Synonymlisten, Woerterbuecher und JSON Konfiguration ergaenzt
 * 17.05.2026   MS   - Umbau auf invertierten 5 gram Dateindex unter inv_idx
 * 17.05.2026   MS   - Delta Reindexing fuer neue und geaenderte Dokumente ergaenzt
 * 17.05.2026   MS   - Bool Scoring fuer normale Suche und Bool Score Filter ergaenzt
 **********************************************************************************************/

#![allow(clippy::needless_return)]
#![allow(clippy::type_complexity)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sled::{Db, Tree};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{Error, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    mpsc::{channel, Receiver, Sender},
    Arc, Mutex,
};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::extract_doc_text;

const I_BM25_TOP_CANDIDATES: usize = 40;
const D_BM25_K1: f32 = 1.5;
const D_BM25_B: f32 = 0.75;
const I_SNIPPET_MAX_LEN: usize = 320;
const I_SNIPPET_SCAN_MAX_LEN: usize = 32_000;
const I_DEFAULT_CHUNK_CHARS: usize = 1200;
const I_DEFAULT_CHUNK_OVERLAP_CHARS: usize = 200;
const I_FIVE_GRAM_SIZE: usize = 5;
const I_POSTING_PER_GRAM_LIMIT: usize = 20_000;
const I_TARGET_CANDIDATES: usize = 30_000;
const S_DOC_STORE_DB_DIR: &str = "doc_store_db";
const S_INV_IDX_DIR: &str = "inv_idx";
const I_EMBEDDING_DIM_DEFAULT: usize = 64;
const I_EMBEDDING_TEXT_LIMIT: usize = 16_000;
const D_HYBRID_EMBEDDING_WEIGHT: f32 = 0.25;
const D_HYBRID_LEXICAL_WEIGHT: f32 = 0.35;
const D_HYBRID_BM25_WEIGHT: f32 = 0.40;
const D_BOOL_FILTER_THRESHOLD: f32 = 0.55;
const D_NORMAL_SEARCH_BOOL_WEIGHT: f32 = 0.15;
const D_EXPLICIT_BOOL_SEARCH_BOOL_WEIGHT: f32 = 0.30;

pub type DocId = u64;
pub type ChunkId = u64;
pub type PayloadMap = HashMap<String, String>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VecSearchHit {
    pub s_doc: String,
    pub d_score: f32,
    pub s_snippet: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum PayloadFilterOp {
    Eq,
    Ne,
    Contains,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PayloadFilter {
    pub s_field: String,
    pub op: PayloadFilterOp,
    pub s_value: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QueryOptions {
    pub i_k: usize,
    pub v_filters: Vec<PayloadFilter>,
    pub b_enable_token_level_rescore: bool,
    pub b_enable_embedding_rescore: bool,
}

impl Default for QueryOptions {
    fn default() -> Self {
        return Self {
            i_k: 10,
            v_filters: Vec::new(),
            b_enable_token_level_rescore: false,
            b_enable_embedding_rescore: true,
        };
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DocumentMeta {
    pub i_doc_id: DocId,
    pub s_doc_path: String,
    pub i_created_ts: u64,
    pub i_updated_ts: u64,
    pub payload: PayloadMap,
    pub b_deleted: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChunkMeta {
    pub i_chunk_id: ChunkId,
    pub i_doc_id: DocId,
    pub i_chunk_ordinal: u32,
    pub s_text: String,
    pub payload: PayloadMap,
    pub i_model_version: u32,
    pub b_deleted: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SourceState {
    pub i_doc_id: DocId,
    pub i_last_modified_ts: u64,
    pub a_sha256: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChunkingConfig {
    pub i_chunk_chars: usize,
    pub i_chunk_overlap_chars: usize,
}

impl Default for ChunkingConfig {
    fn default() -> Self {
        return Self {
            i_chunk_chars: I_DEFAULT_CHUNK_CHARS,
            i_chunk_overlap_chars: I_DEFAULT_CHUNK_OVERLAP_CHARS,
        };
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GramPostingRecord {
    pub i_chunk_id: ChunkId,
    pub i_tf: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GramPostingFileEntry {
    pub s_rel_file: String,
    pub i_doc_freq: u32,
    pub i_byte_len: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EmbeddingRecord {
    pub i_chunk_id: ChunkId,
    pub v_embedding: Vec<f32>,
    pub i_embedding_dim: u32,
    pub i_model_version: u32,
    pub i_created_ts: u64,
    pub i_updated_ts: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SynonymConfig {
    pub synonyms: HashMap<String, Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct DictionaryConfig {
    pub dictionary_terms: Vec<String>,
    pub replacements: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NormalizationConfig {
    pub b_to_lowercase: bool,
    pub b_ascii_only: bool,
    pub b_collapse_whitespace: bool,
    pub b_keep_alphanumeric_only: bool,
    pub b_map_umlauts: bool,
    pub v_stopwords: Vec<String>,
}

impl Default for NormalizationConfig {
    fn default() -> Self {
        return Self {
            b_to_lowercase: true,
            b_ascii_only: true,
            b_collapse_whitespace: true,
            b_keep_alphanumeric_only: true,
            b_map_umlauts: true,
            v_stopwords: Vec::new(),
        };
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BoolOp {
    And,
    Or,
    Not,
}

#[derive(Debug, Clone)]
struct ParsedBoolQuery {
    v_required_terms: Vec<String>,
    v_optional_terms: Vec<String>,
    v_excluded_terms: Vec<String>,
}

#[derive(Debug, Clone)]
enum IndexJob {
    UpsertPath {
        p_path: PathBuf,
        payload: PayloadMap,
    },
    DeletePath {
        s_doc_path: String,
    },
    RebuildAll {
        p_root: PathBuf,
    },
    ReprojectDirty {
        v_chunk_ids: Vec<ChunkId>,
    },
}

pub trait EmbeddingBackend: Send + Sync {
    fn model_name(&self) -> &str;
    fn model_version(&self) -> u32;
    fn embedding_dim(&self) -> usize;
    fn encode(&self, s_text: &str) -> Result<Vec<f32>, String>;
}

pub struct SimpleHashEmbeddingBackend {
    i_embedding_dim: usize,
    i_model_version: u32,
    s_model_name: String,
}

impl SimpleHashEmbeddingBackend {
    pub fn new(i_embedding_dim: usize, i_model_version: u32) -> Self {
        return Self {
            i_embedding_dim: i_embedding_dim.max(8),
            i_model_version,
            s_model_name: "simple_hash_embedding".to_string(),
        };
    }
}

impl EmbeddingBackend for SimpleHashEmbeddingBackend {
    fn model_name(&self) -> &str {
        return &self.s_model_name;
    }

    fn model_version(&self) -> u32 {
        return self.i_model_version;
    }

    fn embedding_dim(&self) -> usize {
        return self.i_embedding_dim;
    }

    fn encode(&self, s_text: &str) -> Result<Vec<f32>, String> {
        let s_norm = normalize_text_default(s_text);
        if s_norm.is_empty() {
            return Ok(vec![0.0; self.i_embedding_dim]);
        }

        let mut v_out = vec![0.0f32; self.i_embedding_dim];
        let mut i_non_zero: usize = 0;

        for s_token in s_norm.split_whitespace().take(4096) {
            let mut o_hasher = Sha256::new();
            o_hasher.update(s_token.as_bytes());
            let a_hash = o_hasher.finalize();

            let mut a_idx = [0u8; 8];
            a_idx.copy_from_slice(&a_hash[0..8]);
            let i_idx = (u64::from_le_bytes(a_idx) as usize) % self.i_embedding_dim;

            let mut a_sign = [0u8; 4];
            a_sign.copy_from_slice(&a_hash[8..12]);
            let d_sign = if u32::from_le_bytes(a_sign) % 2 == 0 {
                1.0f32
            } else {
                -1.0f32
            };

            let d_weight = 1.0f32 + (s_token.len() as f32 / 32.0f32);
            v_out[i_idx] += d_sign * d_weight;
            i_non_zero = i_non_zero.saturating_add(1);
        }

        if i_non_zero == 0 {
            return Ok(v_out);
        }

        let d_norm = v_out.iter().map(|d_v| d_v * d_v).sum::<f32>().sqrt();
        if d_norm > 0.0 {
            for d_v in v_out.iter_mut() {
                *d_v /= d_norm;
            }
        }

        Ok(v_out)
    }
}

struct BackgroundIndexer {
    tx: Sender<IndexJob>,
}

impl BackgroundIndexer {
    fn new() -> (Self, Receiver<IndexJob>) {
        let (tx, rx) = channel::<IndexJob>();
        return (Self { tx }, rx);
    }
}

pub struct InvertedIndexStore {
    p_root_dir: PathBuf,
    o_lock: Mutex<()>,
}

impl InvertedIndexStore {
    pub fn new(p_root_dir: PathBuf) -> Self {
        let _ = fs::create_dir_all(&p_root_dir);
        return Self {
            p_root_dir,
            o_lock: Mutex::new(()),
        };
    }

    fn gram_to_safe_file_name(&self, s_gram: &str) -> String {
        let mut o_hasher = Sha256::new();
        o_hasher.update(s_gram.as_bytes());
        let a_hash = o_hasher.finalize();

        let mut s_hex = String::with_capacity(a_hash.len() * 2);
        for b_val in a_hash.iter() {
            s_hex.push(nibble_to_hex((b_val >> 4) & 0x0f));
            s_hex.push(nibble_to_hex(b_val & 0x0f));
        }

        return format!("{}.bin", s_hex);
    }

    fn gram_to_file_path(&self, s_gram: &str) -> PathBuf {
        let mut p = self.p_root_dir.clone();
        p.push(self.gram_to_safe_file_name(s_gram));
        return p;
    }

    pub fn write_posting_list(
        &self,
        s_gram: &str,
        v_postings: &[GramPostingRecord],
    ) -> std::io::Result<(String, u64)> {
        /*
        Beschreibung:
        - Schreibt eine Posting Liste fuer genau ein 5 gram in eine eigene Datei.
        - Format:
          u32 count
          count mal:
            u64 chunk_id
            u32 tf
        - Die Datei liegt im Verzeichnis inv_idx.
        - Der Rueckgabewert enthaelt den relativen Dateinamen und die Byte Laenge.

        Historie:
        - 17.05.2026   Marcus Schlieper   - Umstellung von Sammeldatei auf invertierten Dateindex
        */

        if s_gram.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput, "gram_empty"));
        }

        let _g = self
            .o_lock
            .lock()
            .expect("inverted_index_store_lock_failed");

        let p_file = self.gram_to_file_path(s_gram);
        let s_rel_file = p_file
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("")
            .to_string();

        if s_rel_file.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "inverted_index_rel_file_invalid",
            ));
        }

        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&p_file)?;

        let i_count = v_postings.len() as u32;
        let i_byte_len = 4u64.saturating_add((i_count as u64).saturating_mul(12));

        f.write_all(&i_count.to_le_bytes())?;
        for o_posting in v_postings.iter() {
            f.write_all(&o_posting.i_chunk_id.to_le_bytes())?;
            f.write_all(&o_posting.i_tf.to_le_bytes())?;
        }

        f.flush()?;
        Ok((s_rel_file, i_byte_len))
    }

    pub fn read_posting_list(
        &self,
        s_rel_file: &str,
        i_limit: usize,
    ) -> std::io::Result<Vec<GramPostingRecord>> {
        if s_rel_file.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput, "rel_file_empty"));
        }

        if s_rel_file.contains('/') || s_rel_file.contains('\\') || s_rel_file.contains("..") {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "rel_file_path_traversal_rejected",
            ));
        }

        let _g = self
            .o_lock
            .lock()
            .expect("inverted_index_store_lock_failed");

        let mut p_file = self.p_root_dir.clone();
        p_file.push(s_rel_file);

        let mut f = OpenOptions::new().read(true).open(&p_file)?;
        let i_file_len = f.metadata()?.len();

        if i_file_len < 4 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "posting_file_too_small",
            ));
        }

        let mut a_count = [0u8; 4];
        f.read_exact(&mut a_count)?;
        let i_count = u32::from_le_bytes(a_count) as usize;

        let i_expected_len = 4u64.saturating_add((i_count as u64).saturating_mul(12));
        if i_expected_len != i_file_len {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "posting_file_length_mismatch",
            ));
        }

        let i_read_count = i_count.min(i_limit);
        let mut v_out: Vec<GramPostingRecord> = Vec::with_capacity(i_read_count);

        for _ in 0..i_read_count {
            let mut a_chunk = [0u8; 8];
            let mut a_tf = [0u8; 4];
            f.read_exact(&mut a_chunk)?;
            f.read_exact(&mut a_tf)?;

            v_out.push(GramPostingRecord {
                i_chunk_id: u64::from_le_bytes(a_chunk),
                i_tf: u32::from_le_bytes(a_tf),
            });
        }

        Ok(v_out)
    }

    pub fn delete_posting_file_by_rel(&self, s_rel_file: &str) -> Result<(), String> {
        if s_rel_file.is_empty() {
            return Ok(());
        }

        if s_rel_file.contains('/') || s_rel_file.contains('\\') || s_rel_file.contains("..") {
            return Err("rel_file_path_traversal_rejected".to_string());
        }

        let _g = self
            .o_lock
            .lock()
            .expect("inverted_index_store_lock_failed");

        let mut p_file = self.p_root_dir.clone();
        p_file.push(s_rel_file);

        if p_file.exists() {
            fs::remove_file(&p_file).map_err(|_| "inverted_index_remove_file_failed".to_string())?;
        }

        Ok(())
    }

    pub fn reset_dir(&self) -> Result<(), String> {
        let _g = self
            .o_lock
            .lock()
            .expect("inverted_index_store_lock_failed");

        if self.p_root_dir.exists() {
            let rd = fs::read_dir(&self.p_root_dir)
                .map_err(|_| "inverted_index_read_dir_failed".to_string())?;
            for entry in rd {
                let entry = entry.map_err(|_| "inverted_index_entry_failed".to_string())?;
                let p_path = entry.path();
                if p_path.is_file() {
                    fs::remove_file(&p_path)
                        .map_err(|_| "inverted_index_remove_file_failed".to_string())?;
                }
            }
        } else {
            fs::create_dir_all(&self.p_root_dir)
                .map_err(|_| "inverted_index_create_dir_failed".to_string())?;
        }

        Ok(())
    }
}

pub struct EmbeddingStore {
    t_embedding_by_chunk: Tree,
    db: Db,
}

impl EmbeddingStore {
    pub fn new(db: &Db) -> Self {
        return Self {
            t_embedding_by_chunk: db
                .open_tree("embedding_by_chunk")
                .expect("embedding_by_chunk_open_failed"),
            db: db.clone(),
        };
    }

    pub fn save_chunk_embedding(&self, o_record: &EmbeddingRecord) -> Result<(), String> {
        if o_record.i_embedding_dim == 0 {
            return Err("embedding_dim_invalid".to_string());
        }

        if o_record.v_embedding.len() != o_record.i_embedding_dim as usize {
            return Err("embedding_dim_mismatch".to_string());
        }

        let v_buf =
            bincode::serialize(o_record).map_err(|_| "embedding_serialize_failed".to_string())?;

        self.t_embedding_by_chunk
            .insert(o_record.i_chunk_id.to_le_bytes(), v_buf)
            .map_err(|_| "embedding_insert_failed".to_string())?;

        self.db
            .flush()
            .map_err(|_| "embedding_flush_failed".to_string())?;

        Ok(())
    }

    pub fn get_chunk_embedding(&self, i_chunk_id: ChunkId) -> Option<EmbeddingRecord> {
        return self
            .t_embedding_by_chunk
            .get(i_chunk_id.to_le_bytes())
            .ok()
            .flatten()
            .and_then(|v| bincode::deserialize::<EmbeddingRecord>(v.as_ref()).ok());
    }

    pub fn delete_chunk_embedding(&self, i_chunk_id: ChunkId) -> Result<(), String> {
        let _ = self
            .t_embedding_by_chunk
            .remove(i_chunk_id.to_le_bytes())
            .map_err(|_| "embedding_delete_failed".to_string())?;

        self.db
            .flush()
            .map_err(|_| "embedding_flush_failed".to_string())?;

        Ok(())
    }
}

pub struct DocStore {
    db: Db,
    t_doc_by_id: Tree,
    t_doc_id_by_path: Tree,
    t_chunk_by_id: Tree,
    t_chunks_by_doc: Tree,
    t_source_state: Tree,
    t_counters: Tree,
    t_gram_posting_meta: Tree,
    t_chunk_terms: Tree,
}

impl DocStore {
    pub fn new(p_root: &Path) -> Self {
        let mut p_db = p_root.to_path_buf();
        p_db.push(S_DOC_STORE_DB_DIR);

        let _ = fs::create_dir_all(&p_db);
        let db = sled::open(&p_db).expect("doc_store_db_open_failed");

        return Self {
            t_doc_by_id: db.open_tree("doc_by_id").expect("doc_by_id_open_failed"),
            t_doc_id_by_path: db
                .open_tree("doc_id_by_path")
                .expect("doc_id_by_path_open_failed"),
            t_chunk_by_id: db
                .open_tree("chunk_by_id")
                .expect("chunk_by_id_open_failed"),
            t_chunks_by_doc: db
                .open_tree("chunks_by_doc")
                .expect("chunks_by_doc_open_failed"),
            t_source_state: db
                .open_tree("source_state")
                .expect("source_state_open_failed"),
            t_counters: db.open_tree("counters").expect("counters_open_failed"),
            t_gram_posting_meta: db
                .open_tree("gram_posting_meta")
                .expect("gram_posting_meta_open_failed"),
            t_chunk_terms: db
                .open_tree("chunk_terms")
                .expect("chunk_terms_open_failed"),
            db,
        };
    }

    pub fn db(&self) -> &Db {
        return &self.db;
    }

    fn next_id(&self, s_name: &str) -> u64 {
        let v_old = self.t_counters.get(s_name).ok().flatten();
        let i_old = if let Some(v) = v_old {
            if v.len() == 8 {
                let mut a = [0u8; 8];
                a.copy_from_slice(v.as_ref());
                u64::from_le_bytes(a)
            } else {
                0
            }
        } else {
            0
        };

        let i_new = i_old.saturating_add(1);
        let _ = self.t_counters.insert(s_name, &i_new.to_le_bytes());
        let _ = self.db.flush();
        i_new
    }

    pub fn get_doc_id_by_path(&self, s_doc_path: &str) -> Option<DocId> {
        return self
            .t_doc_id_by_path
            .get(s_doc_path.as_bytes())
            .ok()
            .flatten()
            .and_then(|v| {
                if v.len() == 8 {
                    let mut a = [0u8; 8];
                    a.copy_from_slice(v.as_ref());
                    Some(u64::from_le_bytes(a))
                } else {
                    None
                }
            });
    }

    pub fn get_document_meta(&self, i_doc_id: DocId) -> Option<DocumentMeta> {
        return self
            .t_doc_by_id
            .get(i_doc_id.to_le_bytes())
            .ok()
            .flatten()
            .and_then(|v| bincode::deserialize::<DocumentMeta>(v.as_ref()).ok());
    }

    pub fn save_document_meta(&self, o_meta: &DocumentMeta) {
        if let Ok(v_buf) = bincode::serialize(o_meta) {
            let _ = self.t_doc_by_id.insert(o_meta.i_doc_id.to_le_bytes(), v_buf);
            let _ = self
                .t_doc_id_by_path
                .insert(o_meta.s_doc_path.as_bytes(), &o_meta.i_doc_id.to_le_bytes());
            let _ = self.db.flush();
        }
    }

    pub fn upsert_document_meta(&self, s_doc_path: &str, payload: PayloadMap) -> DocumentMeta {
        let i_now = now_ts();

        if let Some(i_doc_id) = self.get_doc_id_by_path(s_doc_path) {
            let mut o_meta = self.get_document_meta(i_doc_id).unwrap_or(DocumentMeta {
                i_doc_id,
                s_doc_path: s_doc_path.to_string(),
                i_created_ts: i_now,
                i_updated_ts: i_now,
                payload: PayloadMap::new(),
                b_deleted: false,
            });

            o_meta.s_doc_path = s_doc_path.to_string();
            o_meta.i_updated_ts = i_now;
            o_meta.payload = payload;
            o_meta.b_deleted = false;
            self.save_document_meta(&o_meta);
            o_meta
        } else {
            let i_doc_id = self.next_id("doc_id");
            let o_meta = DocumentMeta {
                i_doc_id,
                s_doc_path: s_doc_path.to_string(),
                i_created_ts: i_now,
                i_updated_ts: i_now,
                payload,
                b_deleted: false,
            };
            self.save_document_meta(&o_meta);
            o_meta
        }
    }

    pub fn mark_document_deleted(&self, i_doc_id: DocId) {
        if let Some(mut o_meta) = self.get_document_meta(i_doc_id) {
            o_meta.b_deleted = true;
            o_meta.i_updated_ts = now_ts();
            self.save_document_meta(&o_meta);
        }
    }

    pub fn create_chunk(
        &self,
        i_doc_id: DocId,
        i_chunk_ordinal: u32,
        s_text: String,
        payload: PayloadMap,
        i_model_version: u32,
    ) -> ChunkMeta {
        let i_chunk_id = self.next_id("chunk_id");

        let o_chunk = ChunkMeta {
            i_chunk_id,
            i_doc_id,
            i_chunk_ordinal,
            s_text,
            payload,
            i_model_version,
            b_deleted: false,
        };

        if let Ok(v_buf) = bincode::serialize(&o_chunk) {
            let _ = self.t_chunk_by_id.insert(i_chunk_id.to_le_bytes(), v_buf);
        }

        let mut a_rel = [0u8; 12];
        a_rel[0..8].copy_from_slice(&i_doc_id.to_be_bytes());
        a_rel[8..12].copy_from_slice(&i_chunk_ordinal.to_be_bytes());
        let _ = self.t_chunks_by_doc.insert(a_rel, &i_chunk_id.to_le_bytes());

        let _ = self.db.flush();
        o_chunk
    }

    pub fn get_chunk(&self, i_chunk_id: ChunkId) -> Option<ChunkMeta> {
        return self
            .t_chunk_by_id
            .get(i_chunk_id.to_le_bytes())
            .ok()
            .flatten()
            .and_then(|v| bincode::deserialize::<ChunkMeta>(v.as_ref()).ok());
    }

    pub fn save_chunk(&self, o_chunk: &ChunkMeta) {
        if let Ok(v_buf) = bincode::serialize(o_chunk) {
            let _ = self.t_chunk_by_id.insert(o_chunk.i_chunk_id.to_le_bytes(), v_buf);
            let _ = self.db.flush();
        }
    }

    pub fn update_chunk_deleted(&self, i_chunk_id: ChunkId, b_deleted: bool) {
        if let Some(mut o_chunk) = self.get_chunk(i_chunk_id) {
            o_chunk.b_deleted = b_deleted;
            self.save_chunk(&o_chunk);
        }
    }

    pub fn list_chunk_ids_by_doc(&self, i_doc_id: DocId) -> Vec<ChunkId> {
        let a_prefix = i_doc_id.to_be_bytes();
        let mut v_out: Vec<ChunkId> = Vec::new();

        for item in self.t_chunks_by_doc.scan_prefix(a_prefix) {
            let Ok((_, v)) = item else {
                continue;
            };

            if v.len() == 8 {
                let mut a = [0u8; 8];
                a.copy_from_slice(v.as_ref());
                v_out.push(u64::from_le_bytes(a));
            }
        }

        v_out.sort_unstable();
        v_out
    }

    pub fn replace_document_chunks_soft_delete(&self, i_doc_id: DocId) {
        for i_chunk_id in self.list_chunk_ids_by_doc(i_doc_id).iter() {
            self.update_chunk_deleted(*i_chunk_id, true);
        }
    }

    pub fn save_source_state(&self, s_doc_path: &str, o_state: &SourceState) {
        if let Ok(v_buf) = bincode::serialize(o_state) {
            let _ = self.t_source_state.insert(s_doc_path.as_bytes(), v_buf);
            let _ = self.db.flush();
        }
    }

    pub fn get_source_state(&self, s_doc_path: &str) -> Option<SourceState> {
        return self
            .t_source_state
            .get(s_doc_path.as_bytes())
            .ok()
            .flatten()
            .and_then(|v| bincode::deserialize::<SourceState>(v.as_ref()).ok());
    }

    pub fn delete_source_state(&self, s_doc_path: &str) -> Result<(), String> {
        let _ = self
            .t_source_state
            .remove(s_doc_path.as_bytes())
            .map_err(|_| "source_state_delete_failed".to_string())?;
        let _ = self.db.flush();
        Ok(())
    }

    pub fn save_gram_posting_meta(&self, s_gram: &str, o_meta: &GramPostingFileEntry) {
        if let Ok(v_buf) = bincode::serialize(o_meta) {
            let _ = self.t_gram_posting_meta.insert(s_gram.as_bytes(), v_buf);
            let _ = self.db.flush();
        }
    }

    pub fn get_gram_posting_meta(&self, s_gram: &str) -> Option<GramPostingFileEntry> {
        return self
            .t_gram_posting_meta
            .get(s_gram.as_bytes())
            .ok()
            .flatten()
            .and_then(|v| bincode::deserialize::<GramPostingFileEntry>(v.as_ref()).ok());
    }

    pub fn delete_gram_posting_meta(&self, s_gram: &str) -> Result<(), String> {
        let _ = self
            .t_gram_posting_meta
            .remove(s_gram.as_bytes())
            .map_err(|_| "gram_posting_meta_delete_failed".to_string())?;
        let _ = self.db.flush();
        Ok(())
    }

    pub fn clear_gram_posting_meta(&self) -> Result<(), String> {
        self.t_gram_posting_meta
            .clear()
            .map_err(|_| "gram_posting_meta_clear_failed".to_string())?;
        let _ = self.db.flush();
        Ok(())
    }

    pub fn save_chunk_terms(&self, i_chunk_id: ChunkId, v_terms: &[String]) {
        if let Ok(v_buf) = bincode::serialize(v_terms) {
            let _ = self.t_chunk_terms.insert(i_chunk_id.to_le_bytes(), v_buf);
            let _ = self.db.flush();
        }
    }

    pub fn get_chunk_terms(&self, i_chunk_id: ChunkId) -> Vec<String> {
        return self
            .t_chunk_terms
            .get(i_chunk_id.to_le_bytes())
            .ok()
            .flatten()
            .and_then(|v| bincode::deserialize::<Vec<String>>(v.as_ref()).ok())
            .unwrap_or_default();
    }

    pub fn delete_chunk_terms(&self, i_chunk_id: ChunkId) -> Result<(), String> {
        let _ = self
            .t_chunk_terms
            .remove(i_chunk_id.to_le_bytes())
            .map_err(|_| "chunk_terms_delete_failed".to_string())?;
        let _ = self.db.flush();
        Ok(())
    }

    pub fn iter_all_chunk_ids(&self) -> Vec<ChunkId> {
        let mut v_out: Vec<ChunkId> = Vec::new();

        for item in self.t_chunk_by_id.iter() {
            let Ok((k, _)) = item else {
                continue;
            };

            if k.len() == 8 {
                let mut a = [0u8; 8];
                a.copy_from_slice(k.as_ref());
                v_out.push(u64::from_le_bytes(a));
            }
        }

        v_out.sort_unstable();
        v_out
    }

    pub fn iter_all_doc_ids(&self) -> Vec<DocId> {
        let mut v_out: Vec<DocId> = Vec::new();

        for item in self.t_doc_by_id.iter() {
            let Ok((k, _)) = item else {
                continue;
            };

            if k.len() == 8 {
                let mut a = [0u8; 8];
                a.copy_from_slice(k.as_ref());
                v_out.push(u64::from_le_bytes(a));
            }
        }

        v_out.sort_unstable();
        v_out
    }

    pub fn compute_source_hash(s_text: &str) -> [u8; 32] {
        Sha256::digest(s_text.as_bytes()).into()
    }
}

pub struct VectorIndex {
    doc_store: Arc<DocStore>,
    inv_idx_store: Arc<InvertedIndexStore>,
    embedding_store: Arc<EmbeddingStore>,
    embedding_backend: Arc<dyn EmbeddingBackend>,
    chunk_cfg: ChunkingConfig,
    o_bg: BackgroundIndexer,
    o_worker_join: Mutex<Option<thread::JoinHandle<()>>>,
    h_synonyms: Arc<RwSynonymMap>,
    h_dictionary_terms: Arc<RwDictionarySet>,
    h_replacements: Arc<RwReplacementMap>,
    o_norm_cfg: Arc<Mutex<NormalizationConfig>>,
}

type RwSynonymMap = Mutex<HashMap<String, Vec<String>>>;
type RwDictionarySet = Mutex<HashSet<String>>;
type RwReplacementMap = Mutex<HashMap<String, String>>;

impl VectorIndex {
    pub fn new(p_root: &Path) -> Arc<Self> {
        let doc_store = Arc::new(DocStore::new(p_root));

        let mut p_inv_idx = p_root.to_path_buf();
        p_inv_idx.push(S_INV_IDX_DIR);

        let inv_idx_store = Arc::new(InvertedIndexStore::new(p_inv_idx));
        let embedding_store = Arc::new(EmbeddingStore::new(doc_store.db()));
        let embedding_backend: Arc<dyn EmbeddingBackend> =
            Arc::new(SimpleHashEmbeddingBackend::new(I_EMBEDDING_DIM_DEFAULT, 1));

        let (o_bg, rx) = BackgroundIndexer::new();

        let o_self = Arc::new(Self {
            doc_store,
            inv_idx_store,
            embedding_store,
            embedding_backend,
            chunk_cfg: ChunkingConfig::default(),
            o_bg,
            o_worker_join: Mutex::new(None),
            h_synonyms: Arc::new(Mutex::new(HashMap::new())),
            h_dictionary_terms: Arc::new(Mutex::new(HashSet::new())),
            h_replacements: Arc::new(Mutex::new(HashMap::new())),
            o_norm_cfg: Arc::new(Mutex::new(NormalizationConfig::default())),
        });

        let _ = o_self.load_language_resources_from_dir(Path::new("config"));

        let o_clone = Arc::clone(&o_self);
        let h = thread::spawn(move || {
            o_clone.background_worker(rx);
        });

        *o_self
            .o_worker_join
            .lock()
            .expect("worker_join_lock_failed") = Some(h);

        o_self
    }

    pub fn load_synonyms_json(&self, p_file: &Path) -> Result<(), String> {
        let s_json =
            fs::read_to_string(p_file).map_err(|_| "synonyms_json_read_failed".to_string())?;
        let o_cfg: SynonymConfig =
            serde_json::from_str(&s_json).map_err(|_| "synonyms_json_parse_failed".to_string())?;

        let mut h_syn = self.h_synonyms.lock().expect("synonyms_lock_failed");
        h_syn.clear();

        for (s_key, v_vals) in o_cfg.synonyms.into_iter() {
            let s_key_norm = self.normalize_text_cfg(&s_key);
            if s_key_norm.is_empty() {
                continue;
            }

            let mut v_norm_vals: Vec<String> = Vec::new();
            for s_val in v_vals.into_iter() {
                let s_val_norm = self.normalize_text_cfg(&s_val);
                if !s_val_norm.is_empty() && !v_norm_vals.contains(&s_val_norm) {
                    v_norm_vals.push(s_val_norm);
                }
            }

            if !v_norm_vals.is_empty() {
                h_syn.insert(s_key_norm, v_norm_vals);
            }
        }

        Ok(())
    }

    pub fn load_dictionary_json(&self, p_file: &Path) -> Result<(), String> {
        let s_json =
            fs::read_to_string(p_file).map_err(|_| "dictionary_json_read_failed".to_string())?;
        let o_cfg: DictionaryConfig = serde_json::from_str(&s_json)
            .map_err(|_| "dictionary_json_parse_failed".to_string())?;

        let mut h_terms = self
            .h_dictionary_terms
            .lock()
            .expect("dictionary_terms_lock_failed");
        let mut h_replacements = self
            .h_replacements
            .lock()
            .expect("dictionary_replacements_lock_failed");

        h_terms.clear();
        h_replacements.clear();

        for s_term in o_cfg.dictionary_terms.into_iter() {
            let s_norm = self.normalize_text_cfg(&s_term);
            if !s_norm.is_empty() {
                h_terms.insert(s_norm);
            }
        }

        for (s_key, s_val) in o_cfg.replacements.into_iter() {
            let s_key_norm = self.normalize_text_cfg(&s_key);
            let s_val_norm = self.normalize_text_cfg(&s_val);
            if !s_key_norm.is_empty() && !s_val_norm.is_empty() {
                h_replacements.insert(s_key_norm, s_val_norm);
            }
        }

        Ok(())
    }

    pub fn load_normalization_json(&self, p_file: &Path) -> Result<(), String> {
        let s_json =
            fs::read_to_string(p_file).map_err(|_| "normalization_json_read_failed".to_string())?;

        let mut o_cfg: NormalizationConfig = serde_json::from_str(&s_json)
            .map_err(|_| "normalization_json_parse_failed".to_string())?;

        let mut v_stopwords_norm: Vec<String> = Vec::new();
        for s_word in o_cfg.v_stopwords.into_iter() {
            let s_norm = normalize_text_with_config(
                &s_word,
                &NormalizationConfig {
                    b_to_lowercase: true,
                    b_ascii_only: true,
                    b_collapse_whitespace: true,
                    b_keep_alphanumeric_only: true,
                    b_map_umlauts: true,
                    v_stopwords: Vec::new(),
                },
            );

            if !s_norm.is_empty() && !v_stopwords_norm.contains(&s_norm) {
                v_stopwords_norm.push(s_norm);
            }
        }

        o_cfg.v_stopwords = v_stopwords_norm;

        let mut o_guard = self.o_norm_cfg.lock().expect("normalization_lock_failed");
        *o_guard = o_cfg;

        Ok(())
    }

    pub fn load_language_resources_from_dir(&self, p_dir: &Path) -> Result<(), String> {
        if !p_dir.exists() {
            return Err("language_resource_dir_missing".to_string());
        }

        let mut p_syn = p_dir.to_path_buf();
        p_syn.push("synonyms.json");

        let mut p_dict = p_dir.to_path_buf();
        p_dict.push("dictionary.json");

        let mut p_norm = p_dir.to_path_buf();
        p_norm.push("normalization.json");

        if p_syn.exists() {
            self.load_synonyms_json(&p_syn)?;
        }
        if p_dict.exists() {
            self.load_dictionary_json(&p_dict)?;
        }
        if p_norm.exists() {
            self.load_normalization_json(&p_norm)?;
        }

        Ok(())
    }

    fn normalize_text_cfg(&self, s_text: &str) -> String {
        let o_cfg = self
            .o_norm_cfg
            .lock()
            .expect("normalization_lock_failed")
            .clone();
        normalize_text_with_config(s_text, &o_cfg)
    }

    fn apply_dictionary_replacements(&self, s_text: &str) -> String {
        let s_norm = self.normalize_text_cfg(s_text);
        if s_norm.is_empty() {
            return String::new();
        }

        let h_replacements = self
            .h_replacements
            .lock()
            .expect("dictionary_replacements_lock_failed");

        let mut v_out: Vec<String> = Vec::new();
        for s_token in s_norm.split_whitespace() {
            if let Some(s_rep) = h_replacements.get(s_token) {
                v_out.push(s_rep.clone());
            } else {
                v_out.push(s_token.to_string());
            }
        }

        v_out.join(" ")
    }

    fn expand_term_with_synonyms(&self, s_term: &str) -> Vec<String> {
        let s_norm = self.normalize_text_cfg(s_term);
        if s_norm.is_empty() {
            return Vec::new();
        }

        let h_syn = self.h_synonyms.lock().expect("synonyms_lock_failed");
        let mut v_out: Vec<String> = vec![s_norm.clone()];

        if let Some(v_syn) = h_syn.get(&s_norm) {
            for s_val in v_syn.iter() {
                if !v_out.contains(s_val) {
                    v_out.push(s_val.clone());
                }
            }
        }

        v_out
    }

    fn background_worker(self: Arc<Self>, rx: Receiver<IndexJob>) {
        while let Ok(job) = rx.recv() {
            match job {
                IndexJob::UpsertPath { p_path, payload } => {
                    let _ = self.upsert_path_now(&p_path, payload);
                }
                IndexJob::DeletePath { s_doc_path } => {
                    let _ = self.delete_document_now(&s_doc_path);
                }
                IndexJob::RebuildAll { p_root } => {
                    self.rebuild_now(&p_root);
                }
                IndexJob::ReprojectDirty { v_chunk_ids } => {
                    self.reproject_chunks_now(&v_chunk_ids);
                }
            }
        }
    }

    pub fn encode_query(&self, s_text: &str) -> Vec<f32> {
        let v_grams = self.build_five_grams_cfg(s_text);
        let mut h_freq: HashMap<String, usize> = HashMap::new();

        for s_gram in v_grams.into_iter() {
            *h_freq.entry(s_gram).or_insert(0) += 1;
        }

        let mut v_pairs: Vec<(String, usize)> = h_freq.into_iter().collect();
        v_pairs.sort_by(|a, b| a.0.cmp(&b.0));

        let mut v_out: Vec<f32> = Vec::with_capacity(v_pairs.len() * 2);
        for (_, i_tf) in v_pairs.into_iter() {
            v_out.push(i_tf as f32);
            v_out.push(1.0);
        }

        if v_out.is_empty() {
            v_out.push(0.0);
        }

        v_out
    }

    pub fn encode_text_embedding(&self, s_text: &str) -> Result<Vec<f32>, String> {
        let s_trim = s_text.trim();
        if s_trim.is_empty() {
            return Err("embedding_input_empty".to_string());
        }

        let s_limited: String = s_trim.chars().take(I_EMBEDDING_TEXT_LIMIT).collect();
        let v_embedding = self.embedding_backend.encode(&s_limited)?;

        if v_embedding.len() != self.embedding_backend.embedding_dim() {
            return Err("embedding_backend_dim_mismatch".to_string());
        }

        Ok(v_embedding)
    }

    pub fn save_chunk_embedding(
        &self,
        i_chunk_id: ChunkId,
        v_embedding: Vec<f32>,
    ) -> Result<(), String> {
        if v_embedding.is_empty() {
            return Err("embedding_empty".to_string());
        }

        let i_now = now_ts();
        let o_old = self.embedding_store.get_chunk_embedding(i_chunk_id);

        let o_record = EmbeddingRecord {
            i_chunk_id,
            i_embedding_dim: v_embedding.len() as u32,
            i_model_version: self.embedding_backend.model_version(),
            i_created_ts: o_old.as_ref().map(|o| o.i_created_ts).unwrap_or(i_now),
            i_updated_ts: i_now,
            v_embedding,
        };

        self.embedding_store.save_chunk_embedding(&o_record)
    }

    pub fn get_chunk_embedding(&self, i_chunk_id: ChunkId) -> Option<EmbeddingRecord> {
        self.embedding_store.get_chunk_embedding(i_chunk_id)
    }

    pub fn ingest_batch_paths(&self, v_paths: Vec<(PathBuf, PayloadMap)>) {
        for (p_path, payload) in v_paths.into_iter() {
            let _ = self.o_bg.tx.send(IndexJob::UpsertPath { p_path, payload });
        }
    }

    pub fn delete_document_by_path(&self, s_doc_path: &str) {
        let _ = self.o_bg.tx.send(IndexJob::DeletePath {
            s_doc_path: s_doc_path.to_string(),
        });
    }

    pub fn rebuild_async(&self, p_root: &Path) {
        let _ = self.o_bg.tx.send(IndexJob::RebuildAll {
            p_root: p_root.to_path_buf(),
        });
    }

    pub fn reproject_dirty_async(&self, i_limit: usize) {
        let v_chunk_ids = self
            .doc_store
            .iter_all_chunk_ids()
            .into_iter()
            .take(i_limit)
            .collect::<Vec<ChunkId>>();

        if !v_chunk_ids.is_empty() {
            let _ = self.o_bg.tx.send(IndexJob::ReprojectDirty { v_chunk_ids });
        }
    }

    pub fn sync(self: &Arc<Self>, root: &Path) {
        /*
        Beschreibung:
        - Dateisystem Sync arbeitet delta basiert.
        - Nur neue oder geaenderte Dokumente werden neu indexiert.
        - Unveraenderte Dokumente bleiben unangetastet.
        - Fehlende Dokumente werden soft geloescht und aus den betroffenen Teilindizes entfernt.

        Historie:
        - 17.05.2026   Marcus Schlieper   - Zyklisches Delta Sync statt Vollrebuild
        */

        let mut v_jobs: Vec<(PathBuf, PayloadMap)> = Vec::new();
        Self::crawl_collect(root, &mut v_jobs);

        let h_seen: HashSet<String> = self.collect_paths_from_fs(root).into_iter().collect();

        for (p_path, payload) in v_jobs.into_iter() {
            let _ = self.o_bg.tx.send(IndexJob::UpsertPath { p_path, payload });
        }

        self.soft_delete_missing_docs(&h_seen);
    }

    pub fn upsert_path_now(&self, p_path: &Path, payload: PayloadMap) -> Result<(), String> {
        let s_doc_path = canonicalize_best_effort(p_path);
        let md = fs::metadata(p_path).map_err(|_| "metadata_failed".to_string())?;

        let i_modified_ts = md
            .modified()
            .unwrap_or(SystemTime::UNIX_EPOCH)
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let s_text = extract_doc_text(p_path).map_err(|_| "extract_doc_text_failed".to_string())?;
        if s_text.trim().is_empty() {
            return Err("empty_document".to_string());
        }

        let a_sha256 = DocStore::compute_source_hash(&s_text);

        if let Some(o_old) = self.doc_store.get_source_state(&s_doc_path) {
            if o_old.i_last_modified_ts == i_modified_ts && o_old.a_sha256 == a_sha256 {
                return Ok(());
            }
        }

        let o_doc = self.doc_store.upsert_document_meta(&s_doc_path, payload.clone());

        let v_old_chunk_ids = self.doc_store.list_chunk_ids_by_doc(o_doc.i_doc_id);
        let v_old_chunk_ids_active: Vec<ChunkId> = v_old_chunk_ids
            .iter()
            .copied()
            .filter(|i_chunk_id| {
                self.doc_store
                    .get_chunk(*i_chunk_id)
                    .map(|o_chunk| !o_chunk.b_deleted)
                    .unwrap_or(false)
            })
            .collect();

        let h_old_grams = self.collect_grams_for_chunk_ids(&v_old_chunk_ids_active);

        self.doc_store.replace_document_chunks_soft_delete(o_doc.i_doc_id);

        for i_old_chunk_id in v_old_chunk_ids.iter().copied() {
            let _ = self.embedding_store.delete_chunk_embedding(i_old_chunk_id);
            let _ = self.doc_store.delete_chunk_terms(i_old_chunk_id);
        }

        let v_chunks = chunk_text(&s_text, &self.chunk_cfg);
        let mut v_new_chunk_ids: Vec<ChunkId> = Vec::new();

        for (i_idx, s_chunk) in v_chunks.into_iter().enumerate() {
            let s_chunk_norm = self.apply_dictionary_replacements(&s_chunk);

            let o_chunk = self.doc_store.create_chunk(
                o_doc.i_doc_id,
                i_idx as u32,
                s_chunk_norm.clone(),
                payload.clone(),
                self.embedding_backend.model_version(),
            );

            let v_terms = self.build_five_grams_cfg(&s_chunk_norm);
            self.doc_store.save_chunk_terms(o_chunk.i_chunk_id, &v_terms);
            v_new_chunk_ids.push(o_chunk.i_chunk_id);

            if let Ok(v_embedding) = self.encode_text_embedding(&s_chunk_norm) {
                let _ = self.save_chunk_embedding(o_chunk.i_chunk_id, v_embedding);
            }
        }

        self.doc_store.save_source_state(
            &s_doc_path,
            &SourceState {
                i_doc_id: o_doc.i_doc_id,
                i_last_modified_ts: i_modified_ts,
                a_sha256,
            },
        );

        let h_new_grams = self.collect_grams_for_chunk_ids(&v_new_chunk_ids);
        let mut h_dirty_grams: HashSet<String> = HashSet::new();
        h_dirty_grams.extend(h_old_grams.into_iter());
        h_dirty_grams.extend(h_new_grams.into_iter());

        self.refresh_grams_incremental(&h_dirty_grams)?;
        Ok(())
    }

    pub fn delete_document_now(&self, s_doc_path: &str) -> Result<(), String> {
        if let Some(i_doc_id) = self.doc_store.get_doc_id_by_path(s_doc_path) {
            let v_chunk_ids = self.doc_store.list_chunk_ids_by_doc(i_doc_id);
            let h_dirty_grams = self.collect_grams_for_chunk_ids(&v_chunk_ids);

            self.doc_store.mark_document_deleted(i_doc_id);

            for i_chunk_id in v_chunk_ids.iter() {
                self.doc_store.update_chunk_deleted(*i_chunk_id, true);
                let _ = self.embedding_store.delete_chunk_embedding(*i_chunk_id);
                let _ = self.doc_store.delete_chunk_terms(*i_chunk_id);
            }

            let _ = self.doc_store.delete_source_state(s_doc_path);
            self.refresh_grams_incremental(&h_dirty_grams)?;
        }

        Ok(())
    }

    pub fn query_with_options(&self, s_query: &str, opts: QueryOptions) -> Vec<VecSearchHit> {
        if s_query.trim().is_empty() || opts.i_k == 0 {
            return Vec::new();
        }

        let o_bool_query = self.parse_bool_query_cfg(s_query);
        let b_has_explicit_bool_ops = has_explicit_bool_ops(s_query);
        let s_lexical_query = self.build_lexical_query_from_bool_cfg(&o_bool_query);

        if s_lexical_query.trim().is_empty() {
            return Vec::new();
        }

        let v_query_grams = self.build_five_grams_cfg(&s_lexical_query);
        if v_query_grams.is_empty() {
            return Vec::new();
        }

        let mut h_query_tf: HashMap<String, usize> = HashMap::new();
        for s_gram in v_query_grams.iter() {
            *h_query_tf.entry(s_gram.clone()).or_insert(0) += 1;
        }

        let v_all_chunk_ids = self.doc_store.iter_all_chunk_ids();
        let i_chunk_count = v_all_chunk_ids.len().max(1);

        let mut h_candidate_score: HashMap<ChunkId, f32> = HashMap::new();
        let mut h_candidate_ids: HashSet<ChunkId> = HashSet::new();

        for (s_gram, i_q_tf) in h_query_tf.iter() {
            let Some(o_meta) = self.doc_store.get_gram_posting_meta(s_gram) else {
                continue;
            };

            let v_postings = match self
                .inv_idx_store
                .read_posting_list(&o_meta.s_rel_file, I_POSTING_PER_GRAM_LIMIT)
            {
                Ok(v) => v,
                Err(_) => continue,
            };

            let d_idf = compute_bm25_idf(o_meta.i_doc_freq as usize, i_chunk_count);

            for o_posting in v_postings.into_iter() {
                if h_candidate_ids.len() >= I_TARGET_CANDIDATES
                    && !h_candidate_ids.contains(&o_posting.i_chunk_id)
                {
                    continue;
                }

                h_candidate_ids.insert(o_posting.i_chunk_id);
                let d_add = (*i_q_tf as f32) * (o_posting.i_tf as f32) * d_idf.max(0.0);
                *h_candidate_score.entry(o_posting.i_chunk_id).or_insert(0.0) += d_add;
            }
        }

        let mut v_preselected: Vec<(ChunkId, f32)> = Vec::new();

        for (i_chunk_id, d_posting_score_raw) in h_candidate_score.into_iter() {
            let Some(o_chunk) = self.doc_store.get_chunk(i_chunk_id) else {
                continue;
            };
            if o_chunk.b_deleted {
                continue;
            }

            let Some(o_doc) = self.doc_store.get_document_meta(o_chunk.i_doc_id) else {
                continue;
            };
            if o_doc.b_deleted {
                continue;
            }

            if !matches_filters(&o_doc.payload, &opts.v_filters)
                && !matches_filters(&o_chunk.payload, &opts.v_filters)
            {
                continue;
            }

            let d_bool_soft_score = self.compute_bool_soft_score(&o_chunk.s_text, &o_bool_query);

            if b_has_explicit_bool_ops && d_bool_soft_score < D_BOOL_FILTER_THRESHOLD {
                continue;
            }

            let d_posting_score = d_posting_score_raw / (1.0 + d_posting_score_raw);
            let d_soft_score_base =
                self.compute_soft_gram_score(&s_lexical_query, &o_chunk.s_text, d_posting_score);

            let d_soft_score = if b_has_explicit_bool_ops {
                ((1.0 - D_EXPLICIT_BOOL_SEARCH_BOOL_WEIGHT) * d_soft_score_base)
                    + (D_EXPLICIT_BOOL_SEARCH_BOOL_WEIGHT * d_bool_soft_score)
            } else {
                ((1.0 - D_NORMAL_SEARCH_BOOL_WEIGHT) * d_soft_score_base)
                    + (D_NORMAL_SEARCH_BOOL_WEIGHT * d_bool_soft_score)
            };

            v_preselected.push((i_chunk_id, d_soft_score));
        }

        if v_preselected.is_empty() {
            for i_chunk_id in self.doc_store.iter_all_chunk_ids().into_iter() {
                let Some(o_chunk) = self.doc_store.get_chunk(i_chunk_id) else {
                    continue;
                };
                if o_chunk.b_deleted {
                    continue;
                }

                let Some(o_doc) = self.doc_store.get_document_meta(o_chunk.i_doc_id) else {
                    continue;
                };
                if o_doc.b_deleted {
                    continue;
                }

                if !matches_filters(&o_doc.payload, &opts.v_filters)
                    && !matches_filters(&o_chunk.payload, &opts.v_filters)
                {
                    continue;
                }

                let d_bool_soft_score = self.compute_bool_soft_score(&o_chunk.s_text, &o_bool_query);

                if b_has_explicit_bool_ops && d_bool_soft_score < D_BOOL_FILTER_THRESHOLD {
                    continue;
                }

                let d_soft_score_base =
                    self.compute_soft_gram_score(&s_lexical_query, &o_chunk.s_text, 0.0);

                let d_soft_score = if b_has_explicit_bool_ops {
                    ((1.0 - D_EXPLICIT_BOOL_SEARCH_BOOL_WEIGHT) * d_soft_score_base)
                        + (D_EXPLICIT_BOOL_SEARCH_BOOL_WEIGHT * d_bool_soft_score)
                } else {
                    ((1.0 - D_NORMAL_SEARCH_BOOL_WEIGHT) * d_soft_score_base)
                        + (D_NORMAL_SEARCH_BOOL_WEIGHT * d_bool_soft_score)
                };

                v_preselected.push((i_chunk_id, d_soft_score));
            }
        }

        v_preselected.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(Ordering::Equal));
        v_preselected.truncate(I_BM25_TOP_CANDIDATES.max(opts.i_k * 4));

        let mut v_texts: Vec<(u64, String)> = Vec::new();
        let mut h_vec_score: HashMap<ChunkId, f32> = HashMap::new();

        for (i_chunk_id, d_score) in v_preselected.into_iter() {
            let Some(o_chunk) = self.doc_store.get_chunk(i_chunk_id) else {
                continue;
            };
            if o_chunk.b_deleted {
                continue;
            }

            h_vec_score.insert(i_chunk_id, d_score);
            v_texts.push((i_chunk_id, o_chunk.s_text.clone()));
        }

        let v_bm25 = bm25_rerank_top_k(&v_texts, &s_lexical_query, I_BM25_TOP_CANDIDATES);
        let mut h_bm25_score: HashMap<ChunkId, f32> = HashMap::new();

        for (i_chunk_id, d_bm25) in v_bm25.into_iter() {
            h_bm25_score.insert(i_chunk_id, d_bm25);
        }

        let o_query_embedding = if opts.b_enable_embedding_rescore {
            self.encode_text_embedding(&s_lexical_query).ok()
        } else {
            None
        };

        let mut h_doc_best: HashMap<DocId, VecSearchHit> = HashMap::new();

        for (i_chunk_id, d_soft) in h_vec_score.into_iter() {
            let Some(o_chunk) = self.doc_store.get_chunk(i_chunk_id) else {
                continue;
            };
            let Some(o_doc) = self.doc_store.get_document_meta(o_chunk.i_doc_id) else {
                continue;
            };

            let d_bm25 = *h_bm25_score.get(&i_chunk_id).unwrap_or(&0.0);

            let d_embedding = if let Some(v_query_embedding) = o_query_embedding.as_ref() {
                if let Some(o_embedding) = self.get_chunk_embedding(i_chunk_id) {
                    cosine_similarity(v_query_embedding, &o_embedding.v_embedding)
                } else {
                    0.0
                }
            } else {
                0.0
            };

            let d_final = if o_query_embedding.is_some() {
                D_HYBRID_LEXICAL_WEIGHT * d_soft
                    + D_HYBRID_BM25_WEIGHT * d_bm25
                    + D_HYBRID_EMBEDDING_WEIGHT * d_embedding
            } else {
                0.50 * d_soft + 0.50 * d_bm25
            };

            let o_hit = VecSearchHit {
                s_doc: o_doc.s_doc_path.clone(),
                d_score: d_final,
                s_snippet: build_snippet_for_query(&o_chunk.s_text, &s_lexical_query),
            };

            match h_doc_best.get(&o_doc.i_doc_id) {
                None => {
                    h_doc_best.insert(o_doc.i_doc_id, o_hit);
                }
                Some(o_old) => {
                    if d_final > o_old.d_score {
                        h_doc_best.insert(o_doc.i_doc_id, o_hit);
                    }
                }
            }
        }

        let mut v_hits: Vec<VecSearchHit> = h_doc_best.into_values().collect();
        v_hits.sort_by(|a, b| b.d_score.partial_cmp(&a.d_score).unwrap_or(Ordering::Equal));
        v_hits.truncate(opts.i_k);
        v_hits
    }

    pub fn query_with_snippets(self: &Arc<Self>, s_query: &str, i_k: usize) -> Vec<VecSearchHit> {
        self.query_with_options(
            s_query,
            QueryOptions {
                i_k,
                v_filters: Vec::new(),
                b_enable_token_level_rescore: false,
                b_enable_embedding_rescore: true,
            },
        )
    }

    pub fn query(self: &Arc<Self>, s_query: &str, i_k: usize) -> Vec<(String, f32)> {
        self.query_with_snippets(s_query, i_k)
            .into_iter()
            .map(|h| (h.s_doc, h.d_score))
            .collect()
    }

    pub fn rebuild_now(&self, p_root: &Path) {
        let _ = p_root;
        let _ = self.rebuild_posting_store();
        let v_chunk_ids = self.doc_store.iter_all_chunk_ids();
        let _ = self.rebuild_embeddings(&v_chunk_ids);
    }

    pub fn reproject_chunks_now(&self, v_chunk_ids: &[ChunkId]) {
        let _ = self.rebuild_posting_store();
        let _ = self.rebuild_embeddings(v_chunk_ids);
    }

    pub fn save(&self, p_root: &Path) {
        let _ = p_root;
        let _ = self.doc_store.db().flush();
    }

    pub fn load(&self, p_root: &Path) {
        let _ = p_root;
    }

    pub fn repair_five_gram_postings(&self) -> Result<(), String> {
        for i_chunk_id in self.doc_store.iter_all_chunk_ids().into_iter() {
            let Some(o_chunk) = self.doc_store.get_chunk(i_chunk_id) else {
                continue;
            };

            if o_chunk.b_deleted {
                continue;
            }

            let v_terms = self.build_five_grams_cfg(&o_chunk.s_text);
            self.doc_store.save_chunk_terms(i_chunk_id, &v_terms);
        }

        self.rebuild_posting_store()?;
        Ok(())
    }

    pub fn rebuild_embeddings(&self, v_chunk_ids: &[ChunkId]) -> Result<(), String> {
        let v_targets: Vec<ChunkId> = if v_chunk_ids.is_empty() {
            self.doc_store.iter_all_chunk_ids()
        } else {
            v_chunk_ids.to_vec()
        };

        for i_chunk_id in v_targets.into_iter() {
            let Some(o_chunk) = self.doc_store.get_chunk(i_chunk_id) else {
                continue;
            };

            if o_chunk.b_deleted {
                let _ = self.embedding_store.delete_chunk_embedding(i_chunk_id);
                continue;
            }

            let Some(o_doc) = self.doc_store.get_document_meta(o_chunk.i_doc_id) else {
                continue;
            };

            if o_doc.b_deleted {
                let _ = self.embedding_store.delete_chunk_embedding(i_chunk_id);
                continue;
            }

            let v_embedding = self.encode_text_embedding(&o_chunk.s_text)?;
            self.save_chunk_embedding(i_chunk_id, v_embedding)?;
        }

        Ok(())
    }

    fn collect_grams_for_chunk_ids(&self, v_chunk_ids: &[ChunkId]) -> HashSet<String> {
        let mut h_grams: HashSet<String> = HashSet::new();

        for i_chunk_id in v_chunk_ids.iter() {
            let v_terms = self.doc_store.get_chunk_terms(*i_chunk_id);
            for s_term in v_terms.into_iter() {
                h_grams.insert(s_term);
            }
        }

        h_grams
    }

    fn collect_postings_for_gram(&self, s_gram: &str) -> Vec<GramPostingRecord> {
        let mut v_postings: Vec<GramPostingRecord> = Vec::new();

        for i_chunk_id in self.doc_store.iter_all_chunk_ids().into_iter() {
            let Some(o_chunk) = self.doc_store.get_chunk(i_chunk_id) else {
                continue;
            };
            if o_chunk.b_deleted {
                continue;
            }

            let Some(o_doc) = self.doc_store.get_document_meta(o_chunk.i_doc_id) else {
                continue;
            };
            if o_doc.b_deleted {
                continue;
            }

            let v_terms = self.doc_store.get_chunk_terms(i_chunk_id);
            if v_terms.is_empty() {
                continue;
            }

            let mut i_tf: u32 = 0;
            for s_term in v_terms.into_iter() {
                if s_term == s_gram {
                    i_tf = i_tf.saturating_add(1);
                }
            }

            if i_tf > 0 {
                v_postings.push(GramPostingRecord {
                    i_chunk_id,
                    i_tf,
                });
            }
        }

        v_postings.sort_by(|a, b| a.i_chunk_id.cmp(&b.i_chunk_id));
        v_postings.dedup_by(|a, b| a.i_chunk_id == b.i_chunk_id);
        v_postings
    }

    fn refresh_grams_incremental(&self, h_dirty_grams: &HashSet<String>) -> Result<(), String> {
        /*
        Beschreibung:
        - Aktualisiert nur die Posting Dateien der betroffenen 5 gram Terme.
        - Neue Dokumente ergaenzen bestehende Indizes.
        - Geaenderte Dokumente ersetzen nur ihre eigenen Chunk Eintraege innerhalb der betroffenen Terme.
        - Leere Posting Listen loeschen die zugehoerige Posting Datei und Metadaten.

        Historie:
        - 17.05.2026   Marcus Schlieper   - Delta Update fuer invertierten Dateindex
        */

        if h_dirty_grams.is_empty() {
            return Ok(());
        }

        let mut v_grams: Vec<String> = h_dirty_grams.iter().cloned().collect();
        v_grams.sort();

        for s_gram in v_grams.into_iter() {
            if s_gram.is_empty() {
                continue;
            }

            let v_postings = self.collect_postings_for_gram(&s_gram);

            if v_postings.is_empty() {
                if let Some(o_old_meta) = self.doc_store.get_gram_posting_meta(&s_gram) {
                    let _ = self
                        .inv_idx_store
                        .delete_posting_file_by_rel(&o_old_meta.s_rel_file);
                }

                self.doc_store.delete_gram_posting_meta(&s_gram)?;
                continue;
            }

            let o_old_meta = self.doc_store.get_gram_posting_meta(&s_gram);

            let (s_rel_file, i_byte_len) = self
                .inv_idx_store
                .write_posting_list(&s_gram, &v_postings)
                .map_err(|_| "inverted_index_write_failed".to_string())?;

            if let Some(o_old) = o_old_meta {
                if o_old.s_rel_file != s_rel_file {
                    let _ = self.inv_idx_store.delete_posting_file_by_rel(&o_old.s_rel_file);
                }
            }

            let i_expected_byte_len =
                4u64.saturating_add((v_postings.len() as u64).saturating_mul(12));

            if i_byte_len != i_expected_byte_len {
                return Err("posting_store_record_count_mismatch".to_string());
            }

            self.doc_store.save_gram_posting_meta(
                &s_gram,
                &GramPostingFileEntry {
                    s_rel_file,
                    i_doc_freq: v_postings.len() as u32,
                    i_byte_len,
                },
            );
        }

        Ok(())
    }

    fn parse_bool_query_cfg(&self, s_query: &str) -> ParsedBoolQuery {
        let v_tokens_raw: Vec<&str> = s_query.split_whitespace().collect();

        let mut v_required_terms: Vec<String> = Vec::new();
        let mut v_optional_terms: Vec<String> = Vec::new();
        let mut v_excluded_terms: Vec<String> = Vec::new();
        let mut o_pending_op: Option<BoolOp> = None;

        for s_token_raw in v_tokens_raw.into_iter() {
            let s_token_upper = s_token_raw.trim().to_ascii_uppercase();

            if s_token_upper == "AND" {
                o_pending_op = Some(BoolOp::And);
                continue;
            }
            if s_token_upper == "OR" {
                o_pending_op = Some(BoolOp::Or);
                continue;
            }
            if s_token_upper == "NOT" {
                o_pending_op = Some(BoolOp::Not);
                continue;
            }

            let s_term = self.apply_dictionary_replacements(s_token_raw);
            if s_term.is_empty() {
                continue;
            }

            match o_pending_op {
                Some(BoolOp::And) => {
                    let v_expanded = self.expand_term_with_synonyms(&s_term);
                    if v_expanded.len() > 1 {
                        for s_part in v_expanded.into_iter() {
                            if !v_optional_terms.contains(&s_part) {
                                v_optional_terms.push(s_part);
                            }
                        }

                        let s_first = self.normalize_text_cfg(&s_term);
                        if !s_first.is_empty() && !v_required_terms.contains(&s_first) {
                            v_required_terms.push(s_first);
                        }
                    } else {
                        let s_norm = self.normalize_text_cfg(&s_term);
                        if !s_norm.is_empty() {
                            v_required_terms.push(s_norm);
                        }
                    }
                }
                Some(BoolOp::Or) => {
                    for s_expanded in self.expand_term_with_synonyms(&s_term).into_iter() {
                        if !v_optional_terms.contains(&s_expanded) {
                            v_optional_terms.push(s_expanded);
                        }
                    }
                }
                Some(BoolOp::Not) => {
                    let s_norm = self.normalize_text_cfg(&s_term);
                    if !s_norm.is_empty() {
                        v_excluded_terms.push(s_norm);
                    }
                }
                None => {
                    let s_norm = self.normalize_text_cfg(&s_term);
                    if !s_norm.is_empty() {
                        v_required_terms.push(s_norm.clone());
                    }

                    for s_expanded in self.expand_term_with_synonyms(&s_term).into_iter() {
                        if s_expanded != s_norm && !v_optional_terms.contains(&s_expanded) {
                            v_optional_terms.push(s_expanded);
                        }
                    }
                }
            }

            o_pending_op = None;
        }

        v_required_terms.sort();
        v_required_terms.dedup();

        v_optional_terms.sort();
        v_optional_terms.dedup();

        v_excluded_terms.sort();
        v_excluded_terms.dedup();

        ParsedBoolQuery {
            v_required_terms,
            v_optional_terms,
            v_excluded_terms,
        }
    }

    fn build_lexical_query_from_bool_cfg(&self, o_bool_query: &ParsedBoolQuery) -> String {
        let mut v_terms: Vec<String> = Vec::new();

        for s_term in o_bool_query.v_required_terms.iter() {
            v_terms.push(s_term.clone());
        }

        for s_term in o_bool_query.v_optional_terms.iter() {
            if !v_terms.contains(s_term) {
                v_terms.push(s_term.clone());
            }
        }

        v_terms.join(" ")
    }

    fn compute_bool_soft_score(&self, s_text: &str, o_bool_query: &ParsedBoolQuery) -> f32 {
        /*
        Beschreibung:
        - Berechnet einen weichen Bool Score fuer normale Suche und explizite Bool Query.
        - Der Score liegt zwischen 0.0 und 1.0.
        - Required Treffer erhoehen den Score.
        - Fehlende Required Begriffe und ausgeschlossene Begriffe senken den Score.

        Historie:
        - 17.05.2026   Marcus Schlieper   - Erste Version fuer weiches Bool Ranking
        */

        let s_norm = self.apply_dictionary_replacements(s_text);
        if s_norm.is_empty() {
            return 0.0;
        }

        let mut i_required_hits: usize = 0;
        let mut i_optional_hits: usize = 0;
        let mut i_excluded_hits: usize = 0;

        for s_term in o_bool_query.v_required_terms.iter() {
            if contains_term_soft(&s_norm, s_term) {
                i_required_hits += 1;
            }
        }

        for s_term in o_bool_query.v_optional_terms.iter() {
            if contains_term_soft(&s_norm, s_term) {
                i_optional_hits += 1;
            }
        }

        for s_term in o_bool_query.v_excluded_terms.iter() {
            if contains_term_soft(&s_norm, s_term) {
                i_excluded_hits += 1;
            }
        }

        let d_required_score = if o_bool_query.v_required_terms.is_empty() {
            1.0
        } else {
            (i_required_hits as f32) / (o_bool_query.v_required_terms.len() as f32)
        };

        let d_optional_score = if o_bool_query.v_optional_terms.is_empty() {
            0.0
        } else {
            (i_optional_hits as f32) / (o_bool_query.v_optional_terms.len() as f32)
        };

        let d_excluded_penalty = if o_bool_query.v_excluded_terms.is_empty() {
            0.0
        } else {
            (i_excluded_hits as f32) / (o_bool_query.v_excluded_terms.len() as f32)
        };

        let d_score =
            0.75 * d_required_score + 0.25 * d_optional_score - 0.60 * d_excluded_penalty;

        d_score.clamp(0.0, 1.0)
    }

    fn build_five_grams_cfg(&self, s_text: &str) -> Vec<String> {
        let s_norm = self.apply_dictionary_replacements(s_text);
        if s_norm.is_empty() {
            return Vec::new();
        }

        let s_joined = s_norm.replace(' ', "_");
        let v_chars: Vec<char> = s_joined.chars().collect();

        if v_chars.is_empty() {
            return Vec::new();
        }

        if v_chars.len() < I_FIVE_GRAM_SIZE {
            let s_single: String = v_chars.iter().collect();
            return vec![s_single];
        }

        let mut v_out: Vec<String> =
            Vec::with_capacity(v_chars.len().saturating_sub(I_FIVE_GRAM_SIZE) + 1);

        for i_pos in 0..=(v_chars.len() - I_FIVE_GRAM_SIZE) {
            let s_part: String = v_chars[i_pos..i_pos + I_FIVE_GRAM_SIZE].iter().collect();
            v_out.push(s_part);
        }

        v_out
    }

    fn compute_soft_gram_score(
        &self,
        s_query: &str,
        s_chunk_text: &str,
        d_posting_score: f32,
    ) -> f32 {
        let v_query_grams = self.build_five_grams_cfg(s_query);
        let v_doc_grams = self.build_five_grams_cfg(s_chunk_text);

        let d_dice_score = dice_similarity(&v_query_grams, &v_doc_grams);
        let d_prefix_score = prefix_match_score(s_query, s_chunk_text);
        let d_exact_score = exact_match_score(s_query, s_chunk_text);

        let d_final_score = 0.65 * d_dice_score
            + 0.20 * d_prefix_score
            + 0.15 * d_exact_score
            + 0.10 * d_posting_score.min(1.0);

        d_final_score
    }

    fn rebuild_posting_store(&self) -> Result<(), String> {
        self.inv_idx_store.reset_dir()?;
        self.doc_store.clear_gram_posting_meta()?;

        let mut h_gram_to_postings: HashMap<String, Vec<GramPostingRecord>> = HashMap::new();

        for i_chunk_id in self.doc_store.iter_all_chunk_ids().into_iter() {
            let Some(o_chunk) = self.doc_store.get_chunk(i_chunk_id) else {
                continue;
            };
            if o_chunk.b_deleted {
                continue;
            }

            let Some(o_doc) = self.doc_store.get_document_meta(o_chunk.i_doc_id) else {
                continue;
            };
            if o_doc.b_deleted {
                continue;
            }

            let v_terms = self.doc_store.get_chunk_terms(i_chunk_id);
            if v_terms.is_empty() {
                continue;
            }

            let mut h_tf: HashMap<String, u32> = HashMap::new();
            for s_term in v_terms.into_iter() {
                let o_entry = h_tf.entry(s_term).or_insert(0);
                *o_entry = o_entry.saturating_add(1);
            }

            for (s_gram, i_tf) in h_tf.into_iter() {
                h_gram_to_postings
                    .entry(s_gram)
                    .or_insert_with(Vec::new)
                    .push(GramPostingRecord {
                        i_chunk_id,
                        i_tf,
                    });
            }
        }

        let mut v_grams: Vec<(String, Vec<GramPostingRecord>)> =
            h_gram_to_postings.into_iter().collect();
        v_grams.sort_by(|a, b| a.0.cmp(&b.0));

        for (_, v_postings) in v_grams.iter_mut() {
            v_postings.sort_by(|a, b| a.i_chunk_id.cmp(&b.i_chunk_id));
            v_postings.dedup_by(|a, b| a.i_chunk_id == b.i_chunk_id);
        }

        for (s_gram, v_postings) in v_grams.into_iter() {
            if v_postings.is_empty() {
                continue;
            }

            let (s_rel_file, i_byte_len) = self
                .inv_idx_store
                .write_posting_list(&s_gram, &v_postings)
                .map_err(|_| "inverted_index_write_failed".to_string())?;

            let i_expected_byte_len =
                4u64.saturating_add((v_postings.len() as u64).saturating_mul(12));

            if i_byte_len != i_expected_byte_len {
                return Err("posting_store_record_count_mismatch".to_string());
            }

            self.doc_store.save_gram_posting_meta(
                &s_gram,
                &GramPostingFileEntry {
                    s_rel_file,
                    i_doc_freq: v_postings.len() as u32,
                    i_byte_len,
                },
            );
        }

        Ok(())
    }

    fn collect_paths_from_fs(&self, p_root: &Path) -> Vec<String> {
        let mut v_out: Vec<String> = Vec::new();
        self.collect_paths_recursive(p_root, &mut v_out);
        v_out
    }

    fn collect_paths_recursive(&self, p_dir: &Path, v_out: &mut Vec<String>) {
        let _ = &self;

        if let Ok(rd) = fs::read_dir(p_dir) {
            for entry in rd.flatten() {
                let p_path = entry.path();

                if p_path.is_dir() {
                    self.collect_paths_recursive(&p_path, v_out);
                    continue;
                }

                let s_ext = p_path
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();

                let a_ok_ext = [
                    "txt", "md", "rs", "py", "json", "pdf", "docx", "xlsx", "xls", "csv", "pptx",
                ];

                if a_ok_ext.contains(&s_ext.as_str()) {
                    v_out.push(canonicalize_best_effort(&p_path));
                }
            }
        }
    }

    fn soft_delete_missing_docs(&self, h_seen: &HashSet<String>) {
        for i_doc_id in self.doc_store.iter_all_doc_ids().into_iter() {
            let Some(o_doc) = self.doc_store.get_document_meta(i_doc_id) else {
                continue;
            };

            if o_doc.b_deleted {
                continue;
            }

            if !h_seen.contains(&o_doc.s_doc_path) {
                let _ = self.delete_document_now(&o_doc.s_doc_path);
            }
        }
    }

    fn crawl_collect(p_dir: &Path, v_jobs: &mut Vec<(PathBuf, PayloadMap)>) {
        if let Ok(rd) = fs::read_dir(p_dir) {
            for entry in rd.flatten() {
                let p_path = entry.path();

                if p_path.is_dir() {
                    Self::crawl_collect(&p_path, v_jobs);
                    continue;
                }

                let a_ok_ext = [
                    "txt", "md", "rs", "py", "json", "pdf", "docx", "xlsx", "xls", "csv", "pptx",
                ];

                let s_ext = p_path
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();

                if !a_ok_ext.contains(&s_ext.as_str()) {
                    continue;
                }

                let mut payload = PayloadMap::new();
                payload.insert("source_type".to_string(), s_ext.clone());
                payload.insert("indexed_at".to_string(), now_ts().to_string());

                v_jobs.push((p_path, payload));
            }
        }
    }
}

pub fn load_or_init_index(p_root: &Path, _p_tracker_dir: &Path) -> Arc<VectorIndex> {
    let idx = VectorIndex::new(p_root);
    idx.load(p_root);
    idx
}

pub fn persist_index(idx: &VectorIndex, p_root: &Path) {
    idx.save(p_root);
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn canonicalize_best_effort(p_in: &Path) -> String {
    match fs::canonicalize(p_in) {
        Ok(p) => p.to_string_lossy().into_owned(),
        Err(_) => p_in.to_string_lossy().into_owned(),
    }
}

fn chunk_text(s_text: &str, cfg: &ChunkingConfig) -> Vec<String> {
    let s_trim = s_text.trim();
    if s_trim.is_empty() {
        return Vec::new();
    }

    let i_chunk_chars = cfg.i_chunk_chars.max(200);
    let i_overlap = cfg.i_chunk_overlap_chars.min(i_chunk_chars / 2);

    let v_chars: Vec<char> = s_trim.chars().collect();
    let mut v_out: Vec<String> = Vec::new();
    let mut i_start: usize = 0;

    while i_start < v_chars.len() {
        let i_end = (i_start + i_chunk_chars).min(v_chars.len());
        let s_chunk: String = v_chars[i_start..i_end].iter().collect();
        let s_chunk = s_chunk.trim().to_string();

        if !s_chunk.is_empty() {
            v_out.push(s_chunk);
        }

        if i_end >= v_chars.len() {
            break;
        }

        let i_next = i_end.saturating_sub(i_overlap);
        if i_next <= i_start {
            break;
        }

        i_start = i_next;
    }

    v_out
}

fn matches_filters(payload: &PayloadMap, v_filters: &[PayloadFilter]) -> bool {
    for f in v_filters.iter() {
        let s_val = payload
            .get(&f.s_field)
            .map(|s| s.as_str())
            .unwrap_or("");

        let b_ok = match f.op {
            PayloadFilterOp::Eq => s_val == f.s_value,
            PayloadFilterOp::Ne => s_val != f.s_value,
            PayloadFilterOp::Contains => s_val.contains(&f.s_value),
        };

        if !b_ok {
            return false;
        }
    }

    true
}

fn normalize_text_default(s_in: &str) -> String {
    normalize_text_with_config(s_in, &NormalizationConfig::default())
}

fn normalize_text_with_config(s_in: &str, o_cfg: &NormalizationConfig) -> String {
    let mut s_work = s_in.to_string();

    if o_cfg.b_to_lowercase {
        s_work = s_work.to_lowercase();
    }

    if o_cfg.b_map_umlauts {
        s_work = s_work
            .replace("ae", "ae")
            .replace("oe", "oe")
            .replace("ue", "ue")
            .replace("ss", "ss");
    }

    let mut s_out = String::with_capacity(s_work.len().min(I_SNIPPET_SCAN_MAX_LEN));
    let mut b_prev_space = false;

    for ch in s_work.chars().take(I_SNIPPET_SCAN_MAX_LEN) {
        let b_keep = if o_cfg.b_keep_alphanumeric_only {
            ch.is_ascii_alphanumeric()
        } else {
            !ch.is_control()
        };

        if b_keep {
            if o_cfg.b_ascii_only {
                if ch.is_ascii() {
                    s_out.push(ch);
                    b_prev_space = false;
                } else if !b_prev_space {
                    s_out.push(' ');
                    b_prev_space = true;
                }
            } else {
                s_out.push(ch);
                b_prev_space = false;
            }
        } else if !b_prev_space {
            s_out.push(' ');
            b_prev_space = true;
        }
    }

    let mut v_tokens: Vec<String> = s_out.split_whitespace().map(|s| s.to_string()).collect();

    if !o_cfg.v_stopwords.is_empty() {
        let h_stop: HashSet<&str> = o_cfg.v_stopwords.iter().map(|s| s.as_str()).collect();
        v_tokens.retain(|s| !h_stop.contains(s.as_str()));
    }

    if o_cfg.b_collapse_whitespace {
        return v_tokens.join(" ");
    }

    s_out
}

fn build_five_grams(s_text: &str) -> Vec<String> {
    let s_norm = normalize_text_default(s_text);
    if s_norm.is_empty() {
        return Vec::new();
    }

    let s_joined = s_norm.replace(' ', "_");
    let v_chars: Vec<char> = s_joined.chars().collect();

    if v_chars.is_empty() {
        return Vec::new();
    }

    if v_chars.len() < I_FIVE_GRAM_SIZE {
        let s_single: String = v_chars.iter().collect();
        return vec![s_single];
    }

    let mut v_out: Vec<String> =
        Vec::with_capacity(v_chars.len().saturating_sub(I_FIVE_GRAM_SIZE) + 1);

    for i_pos in 0..=(v_chars.len() - I_FIVE_GRAM_SIZE) {
        let s_part: String = v_chars[i_pos..i_pos + I_FIVE_GRAM_SIZE].iter().collect();
        v_out.push(s_part);
    }

    v_out
}

fn extract_query_tokens(s_query: &str) -> Vec<String> {
    let s_norm = normalize_text_default(s_query);
    let mut v_out: Vec<String> = Vec::new();

    for s_t in s_norm.split_whitespace() {
        if s_t.len() >= 2 {
            v_out.push(s_t.to_string());
        }
    }

    v_out
}

fn build_snippet_for_query(s_text: &str, s_query: &str) -> String {
    let s_text_trim = s_text.trim();
    if s_text_trim.is_empty() {
        return String::new();
    }

    let s_norm = normalize_text_default(s_text_trim);
    if s_norm.is_empty() {
        return s_text_trim.chars().take(I_SNIPPET_MAX_LEN).collect::<String>();
    }

    let v_q = extract_query_tokens(s_query);
    if v_q.is_empty() {
        return s_text_trim.chars().take(I_SNIPPET_MAX_LEN).collect::<String>();
    }

    let mut i_best_pos: Option<usize> = None;
    for s_t in &v_q {
        if let Some(i_pos) = s_norm.find(s_t) {
            i_best_pos = match i_best_pos {
                None => Some(i_pos),
                Some(i_old) => Some(i_old.min(i_pos)),
            };
        }
    }

    let Some(i_pos_norm) = i_best_pos else {
        return s_text_trim.chars().take(I_SNIPPET_MAX_LEN).collect::<String>();
    };

    let d_ratio = (s_text_trim.len().max(1) as f64) / (s_norm.len().max(1) as f64);
    let i_pos_orig = ((i_pos_norm as f64) * d_ratio) as usize;
    let i_half = I_SNIPPET_MAX_LEN / 2;
    let i_start = i_pos_orig.saturating_sub(i_half);

    let s_slice: String = s_text_trim
        .chars()
        .skip(i_start)
        .take(I_SNIPPET_MAX_LEN)
        .collect();

    s_slice
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ")
}

fn dice_similarity(v_query_grams: &[String], v_doc_grams: &[String]) -> f32 {
    if v_query_grams.is_empty() || v_doc_grams.is_empty() {
        return 0.0;
    }

    let h_query: HashSet<&str> = v_query_grams.iter().map(|s| s.as_str()).collect();
    let h_doc: HashSet<&str> = v_doc_grams.iter().map(|s| s.as_str()).collect();

    let i_intersection = h_query.intersection(&h_doc).count() as f32;
    let i_total = (h_query.len() + h_doc.len()) as f32;

    if i_total <= 0.0 {
        0.0
    } else {
        (2.0 * i_intersection) / i_total
    }
}

fn prefix_match_score(s_query: &str, s_chunk_text: &str) -> f32 {
    let s_query_norm = normalize_text_default(s_query);
    let s_chunk_norm = normalize_text_default(s_chunk_text);

    if s_query_norm.is_empty() || s_chunk_norm.is_empty() {
        return 0.0;
    }

    for s_word in s_chunk_norm.split_whitespace() {
        if s_word.starts_with(&s_query_norm) || s_query_norm.starts_with(s_word) {
            return 1.0;
        }
    }

    0.0
}

fn exact_match_score(s_query: &str, s_chunk_text: &str) -> f32 {
    let s_query_norm = normalize_text_default(s_query);
    let s_chunk_norm = normalize_text_default(s_chunk_text);

    if s_query_norm.is_empty() || s_chunk_norm.is_empty() {
        return 0.0;
    }

    for s_word in s_chunk_norm.split_whitespace() {
        if s_word == s_query_norm {
            return 1.0;
        }
    }

    0.0
}

fn bm25_ngram_from_env() -> usize {
    5
}

fn to_char_ngrams(s_text: &str, i_n: usize, s_boundary: &str) -> Vec<String> {
    let s_norm = normalize_text_default(s_text);
    if s_norm.trim().is_empty() {
        return Vec::new();
    }

    let i_n_eff = i_n.max(1);
    let mut v_out: Vec<String> = Vec::new();

    for s_word in s_norm.split_whitespace() {
        if s_word.is_empty() {
            continue;
        }

        let s_w = format!("{}{}{}", s_boundary, s_word, s_boundary);
        let v_chars: Vec<char> = s_w.chars().collect();

        if v_chars.len() < i_n_eff {
            v_out.push(s_w);
            continue;
        }

        for i_pos in 0..=(v_chars.len() - i_n_eff) {
            let s_part: String = v_chars[i_pos..i_pos + i_n_eff].iter().collect();
            v_out.push(s_part);
        }
    }

    v_out
}

fn tokenize_bm25_char_ngrams(s_text: &str, i_n: usize) -> Vec<String> {
    to_char_ngrams(s_text, i_n, "_")
}

fn bm25_scores(
    v_docs_tokens: &[Vec<String>],
    v_query_tokens: &[String],
    d_k1: f32,
    d_b: f32,
) -> Vec<f32> {
    let i_n_docs = v_docs_tokens.len().max(1) as f32;
    let v_doc_lens: Vec<usize> = v_docs_tokens.iter().map(|d| d.len()).collect();
    let i_sum_len: usize = v_doc_lens.iter().sum();
    let d_avgdl = (i_sum_len.max(1) as f32) / (v_doc_lens.len().max(1) as f32);

    let mut h_df: HashMap<String, usize> = HashMap::new();
    for v_doc in v_docs_tokens.iter() {
        let mut h_seen: HashSet<&str> = HashSet::new();

        for s_term in v_doc.iter() {
            if h_seen.insert(s_term.as_str()) {
                *h_df.entry(s_term.clone()).or_insert(0) += 1;
            }
        }
    }

    let mut h_idf: HashMap<String, f32> = HashMap::new();
    for (s_term, i_df) in h_df.iter() {
        let d_df = *i_df as f32;
        let d_idf = ((i_n_docs - d_df + 0.5) / (d_df + 0.5) + 1.0).ln();
        h_idf.insert(s_term.clone(), d_idf);
    }

    let mut v_tf: Vec<HashMap<&str, usize>> = Vec::with_capacity(v_docs_tokens.len());
    for v_doc in v_docs_tokens.iter() {
        let mut h_tf: HashMap<&str, usize> = HashMap::new();

        for s_t in v_doc.iter() {
            *h_tf.entry(s_t.as_str()).or_insert(0) += 1;
        }

        v_tf.push(h_tf);
    }

    let mut v_scores: Vec<f32> = Vec::with_capacity(v_docs_tokens.len());

    for (i_idx, h_tf) in v_tf.iter().enumerate() {
        let i_dl = v_doc_lens[i_idx].max(1) as f32;
        let mut d_score: f32 = 0.0;

        for s_term in v_query_tokens.iter() {
            let i_f = *h_tf.get(s_term.as_str()).unwrap_or(&0) as f32;
            if i_f <= 0.0 {
                continue;
            }

            let d_idf_t = *h_idf.get(s_term).unwrap_or(&0.0);
            let d_den = i_f + d_k1 * (1.0 - d_b + d_b * (i_dl / d_avgdl));
            if d_den <= 0.0 {
                continue;
            }

            let d_num = d_idf_t * i_f * (d_k1 + 1.0);
            d_score += d_num / d_den;
        }

        v_scores.push(d_score);
    }

    v_scores
}

fn bm25_rerank_top_k(v_texts: &[(u64, String)], s_query: &str, i_k: usize) -> Vec<(u64, f32)> {
    if v_texts.is_empty() {
        return Vec::new();
    }

    let i_ngram = bm25_ngram_from_env();
    let v_q_tokens = tokenize_bm25_char_ngrams(s_query, i_ngram);

    if v_q_tokens.is_empty() {
        return v_texts
            .iter()
            .take(i_k)
            .map(|(i_id, _)| (*i_id, 0.0))
            .collect();
    }

    let v_doc_tokens: Vec<Vec<String>> = v_texts
        .iter()
        .map(|(_, s_text)| tokenize_bm25_char_ngrams(s_text, i_ngram))
        .collect();

    let v_scores = bm25_scores(&v_doc_tokens, &v_q_tokens, D_BM25_K1, D_BM25_B);

    let mut v_out: Vec<(u64, f32)> = v_texts
        .iter()
        .zip(v_scores.into_iter())
        .map(|((i_id, _), d_score)| (*i_id, d_score))
        .collect();

    v_out.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(Ordering::Equal));
    v_out.truncate(i_k);
    v_out
}

fn compute_bm25_idf(i_df: usize, i_doc_count: usize) -> f32 {
    let d_df = i_df.max(1) as f32;
    let d_n = i_doc_count.max(1) as f32;
    ((d_n - d_df + 0.5) / (d_df + 0.5) + 1.0).ln()
}

pub fn cosine_similarity(v_left: &[f32], v_right: &[f32]) -> f32 {
    if v_left.is_empty() || v_right.is_empty() {
        return 0.0;
    }

    if v_left.len() != v_right.len() {
        return 0.0;
    }

    let mut d_dot: f32 = 0.0;
    let mut d_norm_left: f32 = 0.0;
    let mut d_norm_right: f32 = 0.0;

    for (d_l, d_r) in v_left.iter().zip(v_right.iter()) {
        d_dot += d_l * d_r;
        d_norm_left += d_l * d_l;
        d_norm_right += d_r * d_r;
    }

    if d_norm_left <= 0.0 || d_norm_right <= 0.0 {
        return 0.0;
    }

    d_dot / (d_norm_left.sqrt() * d_norm_right.sqrt())
}

fn contains_term(s_text_norm: &str, s_term_norm: &str) -> bool {
    if s_text_norm.is_empty() || s_term_norm.is_empty() {
        return false;
    }

    for s_word in s_text_norm.split_whitespace() {
        if s_word == s_term_norm {
            return true;
        }
    }

    false
}

fn contains_term_soft(s_text_norm: &str, s_term_norm: &str) -> bool {
    /*
    Beschreibung:
    - Weiche Termpruefung fuer Bool Scoring.
    - Exakter Worttreffer ist positiv.
    - Prefix Treffer ist positiv.
    - Gemeinsame 5 gram Treffer sind positiv.
    - So bleiben Angebot und Angebote in der Bool Bewertung verwandt.
    */

    if s_text_norm.is_empty() || s_term_norm.is_empty() {
        return false;
    }

    if contains_term(s_text_norm, s_term_norm) {
        return true;
    }

    for s_word in s_text_norm.split_whitespace() {
        if s_word.starts_with(s_term_norm) || s_term_norm.starts_with(s_word) {
            return true;
        }

        let v_left = build_five_grams(s_word);
        let v_right = build_five_grams(s_term_norm);
        let d_dice = dice_similarity(&v_left, &v_right);

        if d_dice >= 0.45 {
            return true;
        }
    }

    false
}

fn has_explicit_bool_ops(s_query: &str) -> bool {
    for s_token in s_query.split_whitespace() {
        let s_upper = s_token.trim().to_ascii_uppercase();
        if s_upper == "AND" || s_upper == "OR" || s_upper == "NOT" {
            return true;
        }
    }

    false
}

fn nibble_to_hex(i_val: u8) -> char {
    match i_val {
        0..=9 => (b'0' + i_val) as char,
        10..=15 => (b'a' + (i_val - 10)) as char,
        _ => '0',
    }
}
