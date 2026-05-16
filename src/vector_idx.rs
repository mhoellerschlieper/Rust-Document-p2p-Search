/**********************************************************************************************
 * Modulname : vector_idx
 * Datei     : vector_idx.rs
 * Autor     : Marcus Schlieper
 *---------------------------------------------------------------------------------------------
 * Beschreibung
 * - MUVERA orientierte Retrieval Implementierung in einer Datei.
 * - Persistente Dokumente, Chunks, Token Daten, MUVERA Vektoren und Metadaten.
 * - Inkrementelles Insert und Delete.
 * - Stabile Dokument IDs und Chunk IDs.
 * - Chunking Strategie.
 * - Persistente Metadaten.
 * - Filter auf Payload.
 * - Batch Ingestion.
 * - Hintergrund Indexierung.
 * - Sauberer Rebuild Prozess.
 * - Kein erneutes Dateilesen im Query Pfad.
 * - BM25 Re Ranking auf Top Kandidaten nach MUVERA und Token Recall.
 * - Persistenter Token Posting Index fuer lexikalischen Recall.
 * - Robusteres MUVERA mit:
 *   - erweiterter Tokenisierung
 *   - Soft Assignment Top 2
 *   - speziellem Query Pooling fuer kurze Queries
 *   - multilingualem Subword Recall ueber char 3 bis 5 grams
 *
 * Historie
 * 13.11.2025   MS   - Ausgangsmodul fuer einfachen Vektor Index
 * 08.05.2026   MS   - Embedding Backend Abstraktion
 * 16.05.2026   MS   - MUVERA Version 1 ohne ANN
 * 16.05.2026   MS   - MUVERA Version 2 mit Modell Swap, Reprojektion und SimHash Buckets
 * 16.05.2026   MS   - Persistenter Token Posting Index fuer lexikalischen Recall
 * 16.05.2026   MS   - Erweiterte MUVERA Tokenisierung und Soft Assignment Top 2
 * 16.05.2026   MS   - Multilingualer Subword Recall ueber char 3 bis 5 grams
 **********************************************************************************************/

#![allow(clippy::needless_return)]
#![allow(clippy::type_complexity)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sled::{Db, Tree};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    mpsc::{channel, Receiver, Sender},
    Arc, Mutex,
};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::embedding_backend::{create_backend_from_env, EmbeddingBackend, I_VEC_DIM_DEFAULT};
use crate::extract_doc_text;

const I_BM25_TOP_CANDIDATES: usize = 40;
const D_BM25_K1: f32 = 1.5;
const D_BM25_B: f32 = 0.75;
const I_BM25_NGRAM_DEFAULT: usize = 5;
const I_BM25_NGRAM_MIN: usize = 3;
const I_BM25_NGRAM_MAX: usize = 6;

const I_SNIPPET_MAX_LEN: usize = 320;
const I_SNIPPET_SCAN_MAX_LEN: usize = 32_000;

const I_DEFAULT_CHUNK_CHARS: usize = 1200;
const I_DEFAULT_CHUNK_OVERLAP_CHARS: usize = 200;

const I_DEFAULT_MUVERA_CLUSTER_COUNT: usize = 32;
const I_DEFAULT_SIMHASH_BITS: usize = 64;
const I_DEFAULT_QUERY_PRESELECT: usize = 2000;
const I_DEFAULT_BUCKET_PREFIX_BITS: usize = 12;
const I_DEFAULT_FINE_SCORE_TOP_K: usize = 24;

const I_TOKEN_POSTING_PER_TERM_LIMIT: usize = 20_000;
const I_TOKEN_POSTING_TARGET_CANDIDATES: usize = 20_000;

const I_MUVERA_ASSIGN_TOP_K: usize = 2;
const I_MUVERA_CHAR_NGRAM_MIN: usize = 3;
const I_MUVERA_CHAR_NGRAM_MAX: usize = 5;
const I_MUVERA_SHORT_QUERY_WORD_THRESHOLD: usize = 3;

const D_MUVERA_QUERY_MAX_POOL_WEIGHT_SHORT: f32 = 0.55;
const D_MUVERA_QUERY_MEAN_POOL_WEIGHT_SHORT: f32 = 0.45;
const D_MUVERA_DOC_MAX_POOL_WEIGHT: f32 = 0.20;
const D_MUVERA_DOC_MEAN_POOL_WEIGHT: f32 = 0.80;

const D_SUBWORD_CANDIDATE_WEIGHT_SHORT_QUERY: f32 = 0.45;
const D_SUBWORD_CANDIDATE_WEIGHT_NORMAL_QUERY: f32 = 0.30;
const D_WORD_CANDIDATE_WEIGHT_SHORT_QUERY: f32 = 0.15;
const D_WORD_CANDIDATE_WEIGHT_NORMAL_QUERY: f32 = 0.10;

const S_DOC_STORE_DB_DIR: &str = "doc_store_db";
const S_MODEL_ACTIVE_FILE: &str = "muvera_model_active.bin";
const S_MODEL_STAGING_FILE: &str = "muvera_model_staging.bin";
const S_TOKEN_STORE_FILE: &str = "token_vectors_compact.bin";
const S_MUVERA_STORE_FILE: &str = "muvera_vectors.bin";

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
}

impl Default for QueryOptions {
    fn default() -> Self {
        Self {
            i_k: 10,
            v_filters: Vec::new(),
            b_enable_token_level_rescore: false,
        }
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
        Self {
            i_chunk_chars: I_DEFAULT_CHUNK_CHARS,
            i_chunk_overlap_chars: I_DEFAULT_CHUNK_OVERLAP_CHARS,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MuveraConfig {
    pub i_token_dim: usize,
    pub i_cluster_count: usize,
    pub i_simhash_bits: usize,
    pub i_bucket_prefix_bits: usize,
    pub i_query_preselect: usize,
    pub i_bm25_top_k: usize,
    pub i_fine_score_top_k: usize,
    pub i_model_version: u32,
}

impl Default for MuveraConfig {
    fn default() -> Self {
        Self {
            i_token_dim: I_VEC_DIM_DEFAULT.max(64),
            i_cluster_count: I_DEFAULT_MUVERA_CLUSTER_COUNT,
            i_simhash_bits: I_DEFAULT_SIMHASH_BITS,
            i_bucket_prefix_bits: I_DEFAULT_BUCKET_PREFIX_BITS,
            i_query_preselect: I_DEFAULT_QUERY_PRESELECT,
            i_bm25_top_k: I_BM25_TOP_CANDIDATES,
            i_fine_score_top_k: I_DEFAULT_FINE_SCORE_TOP_K,
            i_model_version: 1,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClusterCentroid {
    pub i_cluster_id: u32,
    pub v_center: Vec<f32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MuveraModel {
    pub cfg: MuveraConfig,
    pub v_centroids: Vec<ClusterCentroid>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TokenVectorRecord {
    pub i_chunk_id: ChunkId,
    pub i_token_count: u32,
    pub i_vector_dim: u32,
    pub i_file_offset: u64,
    pub i_byte_len: u64,
    pub b_quantized_i8: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MuveraVectorRecord {
    pub i_chunk_id: ChunkId,
    pub i_dim: u32,
    pub i_model_version: u32,
    pub i_file_offset: u64,
    pub i_byte_len: u64,
    pub a_simhash: Vec<u64>,
    pub i_bucket_key: u32,
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

struct BackgroundIndexer {
    tx: Sender<IndexJob>,
}

impl BackgroundIndexer {
    fn new() -> (Self, Receiver<IndexJob>) {
        let (tx, rx) = channel::<IndexJob>();
        (Self { tx }, rx)
    }
}

pub struct VectorMatrixStore {
    p_file: PathBuf,
    o_lock: Mutex<()>,
}

impl VectorMatrixStore {
    pub fn new(p_file: PathBuf) -> Self {
        if let Some(p_parent) = p_file.parent() {
            let _ = fs::create_dir_all(p_parent);
        }
        Self {
            p_file,
            o_lock: Mutex::new(()),
        }
    }

    pub fn append_vector_f32(&self, v_vec: &[f32]) -> std::io::Result<(u64, u64)> {
        let _g = self
            .o_lock
            .lock()
            .expect("vector_matrix_store_lock_failed");
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&self.p_file)?;
        let i_offset = f.seek(SeekFrom::End(0))?;
        let mut v_buf: Vec<u8> = Vec::with_capacity(v_vec.len() * 4);
        for d_val in v_vec.iter() {
            v_buf.extend_from_slice(&d_val.to_le_bytes());
        }
        f.write_all(&v_buf)?;
        f.flush()?;
        Ok((i_offset, v_buf.len() as u64))
    }

    pub fn read_vector_f32(&self, i_offset: u64, i_dim: usize) -> std::io::Result<Vec<f32>> {
        let _g = self
            .o_lock
            .lock()
            .expect("vector_matrix_store_lock_failed");
        let mut f = OpenOptions::new()
            .create(true)
            .read(true)
            .open(&self.p_file)?;
        let mut v_buf = vec![0u8; i_dim.saturating_mul(4)];
        f.seek(SeekFrom::Start(i_offset))?;
        f.read_exact(&mut v_buf)?;
        let mut v_out: Vec<f32> = Vec::with_capacity(i_dim);
        for i_idx in 0..i_dim {
            let i_pos = i_idx * 4;
            let a = [
                v_buf[i_pos],
                v_buf[i_pos + 1],
                v_buf[i_pos + 2],
                v_buf[i_pos + 3],
            ];
            v_out.push(f32::from_le_bytes(a));
        }
        Ok(v_out)
    }

    pub fn append_matrix_i8_quantized(
        &self,
        v_matrix: &[Vec<f32>],
        i_dim: usize,
    ) -> std::io::Result<(u64, u64)> {
        let _g = self
            .o_lock
            .lock()
            .expect("vector_matrix_store_lock_failed");
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&self.p_file)?;
        let i_offset = f.seek(SeekFrom::End(0))?;
        let mut v_buf: Vec<u8> = Vec::new();
        for v_row in v_matrix.iter() {
            for i_idx in 0..i_dim {
                let d_val = *v_row.get(i_idx).unwrap_or(&0.0);
                let d_clamped = d_val.clamp(-1.0, 1.0);
                let i_q = (d_clamped * 127.0).round() as i8;
                v_buf.push(i_q as u8);
            }
        }
        f.write_all(&v_buf)?;
        f.flush()?;
        Ok((i_offset, v_buf.len() as u64))
    }

    pub fn read_matrix_i8_quantized(
        &self,
        i_offset: u64,
        i_rows: usize,
        i_dim: usize,
    ) -> std::io::Result<Vec<Vec<f32>>> {
        let _g = self
            .o_lock
            .lock()
            .expect("vector_matrix_store_lock_failed");
        let mut f = OpenOptions::new()
            .create(true)
            .read(true)
            .open(&self.p_file)?;
        let i_byte_len = i_rows.saturating_mul(i_dim);
        let mut v_buf = vec![0u8; i_byte_len];
        f.seek(SeekFrom::Start(i_offset))?;
        f.read_exact(&mut v_buf)?;
        let mut v_out: Vec<Vec<f32>> = Vec::with_capacity(i_rows);
        let mut i_pos = 0usize;
        for _ in 0..i_rows {
            let mut v_row: Vec<f32> = Vec::with_capacity(i_dim);
            for _ in 0..i_dim {
                if i_pos >= v_buf.len() {
                    v_row.push(0.0);
                } else {
                    let i_q = v_buf[i_pos] as i8;
                    v_row.push((i_q as f32) / 127.0);
                }
                i_pos += 1;
            }
            v_out.push(v_row);
        }
        Ok(v_out)
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
    t_token_record_by_chunk: Tree,
    t_muvera_record_by_chunk: Tree,
    t_dirty_reproject: Tree,
    t_bucket_by_prefix: Tree,
    t_postings_by_token: Tree,
}

impl DocStore {
    pub fn new(p_root: &Path) -> Self {
        let mut p_db = p_root.to_path_buf();
        p_db.push(S_DOC_STORE_DB_DIR);
        let _ = fs::create_dir_all(&p_db);
        let db = sled::open(&p_db).expect("doc_store_db_open_failed");
        Self {
            t_doc_by_id: db
                .open_tree("doc_by_id")
                .expect("doc_by_id_open_failed"),
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
            t_token_record_by_chunk: db
                .open_tree("token_record_by_chunk")
                .expect("token_record_by_chunk_open_failed"),
            t_muvera_record_by_chunk: db
                .open_tree("muvera_record_by_chunk")
                .expect("muvera_record_by_chunk_open_failed"),
            t_dirty_reproject: db
                .open_tree("dirty_reproject")
                .expect("dirty_reproject_open_failed"),
            t_bucket_by_prefix: db
                .open_tree("bucket_by_prefix")
                .expect("bucket_by_prefix_open_failed"),
            t_postings_by_token: db
                .open_tree("postings_by_token")
                .expect("postings_by_token_open_failed"),
            db,
        }
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

    pub fn get_doc_id_by_path(&self, s_doc_path: &str) -> Option<u64> {
        self.t_doc_id_by_path
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
            })
    }

    pub fn get_document_meta(&self, i_doc_id: DocId) -> Option<DocumentMeta> {
        self.t_doc_by_id
            .get(i_doc_id.to_le_bytes())
            .ok()
            .flatten()
            .and_then(|v| bincode::deserialize::<DocumentMeta>(v.as_ref()).ok())
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
        self.t_chunk_by_id
            .get(i_chunk_id.to_le_bytes())
            .ok()
            .flatten()
            .and_then(|v| bincode::deserialize::<ChunkMeta>(v.as_ref()).ok())
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

    pub fn list_chunk_ids_by_doc(&self, i_doc_id: DocId) -> Vec<u64> {
        let a_prefix = i_doc_id.to_be_bytes();
        let mut v_out: Vec<u64> = Vec::new();
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
        self.t_source_state
            .get(s_doc_path.as_bytes())
            .ok()
            .flatten()
            .and_then(|v| bincode::deserialize::<SourceState>(v.as_ref()).ok())
    }

    pub fn save_token_record(&self, o_rec: &TokenVectorRecord) {
        if let Ok(v_buf) = bincode::serialize(o_rec) {
            let _ = self
                .t_token_record_by_chunk
                .insert(o_rec.i_chunk_id.to_le_bytes(), v_buf);
            let _ = self.db.flush();
        }
    }

    pub fn get_token_record(&self, i_chunk_id: ChunkId) -> Option<TokenVectorRecord> {
        self.t_token_record_by_chunk
            .get(i_chunk_id.to_le_bytes())
            .ok()
            .flatten()
            .and_then(|v| bincode::deserialize::<TokenVectorRecord>(v.as_ref()).ok())
    }

    pub fn save_muvera_record(&self, o_rec: &MuveraVectorRecord) {
        if let Ok(v_buf) = bincode::serialize(o_rec) {
            let _ = self
                .t_muvera_record_by_chunk
                .insert(o_rec.i_chunk_id.to_le_bytes(), v_buf);
            let _ = self.db.flush();
        }
    }

    pub fn get_muvera_record(&self, i_chunk_id: ChunkId) -> Option<MuveraVectorRecord> {
        self.t_muvera_record_by_chunk
            .get(i_chunk_id.to_le_bytes())
            .ok()
            .flatten()
            .and_then(|v| bincode::deserialize::<MuveraVectorRecord>(v.as_ref()).ok())
    }

    pub fn mark_chunk_dirty_for_reproject(&self, i_chunk_id: ChunkId) {
        let _ = self.t_dirty_reproject.insert(i_chunk_id.to_le_bytes(), &[1u8]);
        let _ = self.db.flush();
    }

    pub fn clear_chunk_dirty_for_reproject(&self, i_chunk_id: ChunkId) {
        let _ = self.t_dirty_reproject.remove(i_chunk_id.to_le_bytes());
        let _ = self.db.flush();
    }

    pub fn list_dirty_reproject_chunks(&self, i_limit: usize) -> Vec<u64> {
        let mut v_out: Vec<u64> = Vec::new();
        for item in self.t_dirty_reproject.iter() {
            let Ok((k, _)) = item else {
                continue;
            };
            if k.len() == 8 {
                let mut a = [0u8; 8];
                a.copy_from_slice(k.as_ref());
                v_out.push(u64::from_le_bytes(a));
            }
            if v_out.len() >= i_limit {
                break;
            }
        }
        v_out
    }

    fn bucket_key_prefix_to_bytes(i_bucket_key: u32, i_chunk_id: ChunkId) -> [u8; 12] {
        let mut a = [0u8; 12];
        a[0..4].copy_from_slice(&i_bucket_key.to_be_bytes());
        a[4..12].copy_from_slice(&i_chunk_id.to_be_bytes());
        a
    }

    pub fn bucket_remove_chunk(&self, i_bucket_key: u32, i_chunk_id: ChunkId) {
        let a_key = Self::bucket_key_prefix_to_bytes(i_bucket_key, i_chunk_id);
        let _ = self.t_bucket_by_prefix.remove(a_key);
        let _ = self.db.flush();
    }

    pub fn bucket_insert_chunk(&self, i_bucket_key: u32, i_chunk_id: ChunkId) {
        let a_key = Self::bucket_key_prefix_to_bytes(i_bucket_key, i_chunk_id);
        let _ = self.t_bucket_by_prefix.insert(a_key, &[1u8]);
        let _ = self.db.flush();
    }

    pub fn bucket_list_chunks(&self, i_bucket_key: u32, i_limit: usize) -> Vec<u64> {
        let mut v_out: Vec<u64> = Vec::new();
        let a_prefix = i_bucket_key.to_be_bytes();
        for item in self.t_bucket_by_prefix.scan_prefix(a_prefix) {
            let Ok((k, _)) = item else {
                continue;
            };
            if k.len() == 12 {
                let mut a = [0u8; 8];
                a.copy_from_slice(&k[4..12]);
                v_out.push(u64::from_be_bytes(a));
            }
            if v_out.len() >= i_limit {
                break;
            }
        }
        v_out
    }

    fn posting_key_prefix_for_token(s_token: &str) -> Vec<u8> {
        let a_token = s_token.as_bytes();
        let i_len = a_token.len().min(u16::MAX as usize) as u16;
        let mut v_key = Vec::with_capacity(2 + a_token.len());
        v_key.extend_from_slice(&i_len.to_be_bytes());
        v_key.extend_from_slice(a_token);
        v_key
    }

    fn posting_key_for_token_chunk(s_token: &str, i_chunk_id: ChunkId) -> Vec<u8> {
        let mut v_key = Self::posting_key_prefix_for_token(s_token);
        v_key.extend_from_slice(&i_chunk_id.to_be_bytes());
        v_key
    }

    pub fn token_postings_insert(&self, s_token: &str, i_chunk_id: ChunkId) {
        if s_token.is_empty() {
            return;
        }
        let v_key = Self::posting_key_for_token_chunk(s_token, i_chunk_id);
        let _ = self.t_postings_by_token.insert(v_key, &[1u8]);
    }

    pub fn token_postings_remove(&self, s_token: &str, i_chunk_id: ChunkId) {
        if s_token.is_empty() {
            return;
        }
        let v_key = Self::posting_key_for_token_chunk(s_token, i_chunk_id);
        let _ = self.t_postings_by_token.remove(v_key);
    }

    pub fn token_postings_list_chunks(&self, s_token: &str, i_limit: usize) -> Vec<u64> {
        if s_token.is_empty() || i_limit == 0 {
            return Vec::new();
        }
        let v_prefix = Self::posting_key_prefix_for_token(s_token);
        let mut v_out: Vec<u64> = Vec::new();
        for item in self.t_postings_by_token.scan_prefix(v_prefix) {
            let Ok((k, _)) = item else {
                continue;
            };
            if k.len() < 10 {
                continue;
            }
            let i_pos = k.len().saturating_sub(8);
            let mut a = [0u8; 8];
            a.copy_from_slice(&k[i_pos..]);
            v_out.push(u64::from_be_bytes(a));
            if v_out.len() >= i_limit {
                break;
            }
        }
        v_out
    }

    pub fn token_postings_remove_chunk_tokens(&self, i_chunk_id: ChunkId, v_tokens: &[String]) {
        let mut h_seen: HashSet<&str> = HashSet::new();
        for s_token in v_tokens.iter() {
            if h_seen.insert(s_token.as_str()) {
                self.token_postings_remove(s_token, i_chunk_id);
            }
        }
        let _ = self.db.flush();
    }

    pub fn token_postings_insert_chunk_tokens(&self, i_chunk_id: ChunkId, v_tokens: &[String]) {
        let mut h_seen: HashSet<&str> = HashSet::new();
        for s_token in v_tokens.iter() {
            if h_seen.insert(s_token.as_str()) {
                self.token_postings_insert(s_token, i_chunk_id);
            }
        }
        let _ = self.db.flush();
    }

    pub fn iter_all_chunk_ids(&self) -> Vec<u64> {
        let mut v_out: Vec<u64> = Vec::new();
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

    pub fn iter_all_doc_ids(&self) -> Vec<u64> {
        let mut v_out: Vec<u64> = Vec::new();
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
    backend: Arc<dyn EmbeddingBackend + Send + Sync>,
    doc_store: Arc<DocStore>,
    token_store: Arc<VectorMatrixStore>,
    muvera_store: Arc<VectorMatrixStore>,
    model: Mutex<MuveraModel>,
    chunk_cfg: ChunkingConfig,
    o_bg: BackgroundIndexer,
    o_worker_join: Mutex<Option<thread::JoinHandle<()>>>,
}

impl VectorIndex {
    pub fn new(p_root: &Path) -> Arc<Self> {
        let backend = create_backend_from_env();
        let i_token_dim = backend.dim().max(I_VEC_DIM_DEFAULT);
        let doc_store = Arc::new(DocStore::new(p_root));

        let mut p_token = p_root.to_path_buf();
        p_token.push(S_TOKEN_STORE_FILE);

        let mut p_muvera = p_root.to_path_buf();
        p_muvera.push(S_MUVERA_STORE_FILE);

        let token_store = Arc::new(VectorMatrixStore::new(p_token));
        let muvera_store = Arc::new(VectorMatrixStore::new(p_muvera));
        let model = load_or_create_model_active(p_root, i_token_dim);

        let (o_bg, rx) = BackgroundIndexer::new();

        let o_self = Arc::new(Self {
            backend,
            doc_store,
            token_store,
            muvera_store,
            model: Mutex::new(model),
            chunk_cfg: ChunkingConfig::default(),
            o_bg,
            o_worker_join: Mutex::new(None),
        });

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

    fn background_worker(self: Arc<Self>, rx: Receiver<IndexJob>) {
        while let Ok(job) = rx.recv() {
            match job {
                IndexJob::UpsertPath { p_path, payload } => {
                    let _ = self.upsert_path_now(&p_path, payload);
                }
                IndexJob::DeletePath { s_doc_path } => {
                    self.delete_document_now(&s_doc_path);
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
        let v_token_vectors = self.encode_text_to_token_vectors(s_text);
        self.project_query_token_vectors_to_muvera(s_text, &v_token_vectors)
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
        let v_chunk_ids = self.doc_store.list_dirty_reproject_chunks(i_limit);
        if !v_chunk_ids.is_empty() {
            let _ = self.o_bg.tx.send(IndexJob::ReprojectDirty { v_chunk_ids });
        }
    }

    pub fn sync(self: &Arc<Self>, root: &Path) {
        let mut v_jobs: Vec<(PathBuf, PayloadMap)> = Vec::new();
        Self::crawl_collect(root, &mut v_jobs);
        for (p_path, payload) in v_jobs.into_iter() {
            let _ = self.o_bg.tx.send(IndexJob::UpsertPath { p_path, payload });
        }
        let h_seen: HashSet<String> = self.collect_paths_from_fs(root).into_iter().collect();
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

        for i_old_chunk_id in self.doc_store.list_chunk_ids_by_doc(o_doc.i_doc_id).iter() {
            if let Some(o_old_chunk) = self.doc_store.get_chunk(*i_old_chunk_id) {
                let v_old_tokens = tokenize_for_postings(&o_old_chunk.s_text);
                self.doc_store
                    .token_postings_remove_chunk_tokens(*i_old_chunk_id, &v_old_tokens);
                if let Some(o_old_muv) = self.doc_store.get_muvera_record(*i_old_chunk_id) {
                    self.doc_store
                        .bucket_remove_chunk(o_old_muv.i_bucket_key, *i_old_chunk_id);
                }
            }
        }

        self.doc_store.replace_document_chunks_soft_delete(o_doc.i_doc_id);

        let v_chunks = chunk_text(&s_text, &self.chunk_cfg);
        let i_model_version = self
            .model
            .lock()
            .expect("muvera_model_lock_failed")
            .cfg
            .i_model_version;

        for (i_idx, s_chunk) in v_chunks.into_iter().enumerate() {
            let o_chunk = self.doc_store.create_chunk(
                o_doc.i_doc_id,
                i_idx as u32,
                s_chunk.clone(),
                payload.clone(),
                i_model_version,
            );

            let v_posting_tokens = tokenize_for_postings(&s_chunk);
            self.doc_store
                .token_postings_insert_chunk_tokens(o_chunk.i_chunk_id, &v_posting_tokens);

            let v_token_vectors = self.encode_text_to_token_vectors(&s_chunk);
            let (i_token_offset, i_token_len) = self
                .token_store
                .append_matrix_i8_quantized(&v_token_vectors, self.token_dim())
                .map_err(|_| "token_store_write_failed".to_string())?;

            let o_token_rec = TokenVectorRecord {
                i_chunk_id: o_chunk.i_chunk_id,
                i_token_count: v_token_vectors.len() as u32,
                i_vector_dim: self.token_dim() as u32,
                i_file_offset: i_token_offset,
                i_byte_len: i_token_len,
                b_quantized_i8: true,
            };
            self.doc_store.save_token_record(&o_token_rec);

            self.write_chunk_projection(&o_chunk, &v_token_vectors)?;
        }

        self.doc_store.save_source_state(
            &s_doc_path,
            &SourceState {
                i_doc_id: o_doc.i_doc_id,
                i_last_modified_ts: i_modified_ts,
                a_sha256,
            },
        );

        Ok(())
    }

    fn write_chunk_projection(
        &self,
        o_chunk: &ChunkMeta,
        v_token_vectors: &[Vec<f32>],
    ) -> Result<(), String> {
        let v_muvera = self.project_token_vectors_to_muvera(v_token_vectors);
        let a_simhash = self.simhash_for_vector(&v_muvera);
        let i_bucket_key = self.bucket_key_from_simhash(&a_simhash);

        if let Some(o_old) = self.doc_store.get_muvera_record(o_chunk.i_chunk_id) {
            self.doc_store
                .bucket_remove_chunk(o_old.i_bucket_key, o_chunk.i_chunk_id);
        }

        let (i_muvera_offset, i_muvera_len) = self
            .muvera_store
            .append_vector_f32(&v_muvera)
            .map_err(|_| "muvera_store_write_failed".to_string())?;

        let i_model_version = self
            .model
            .lock()
            .expect("muvera_model_lock_failed")
            .cfg
            .i_model_version;

        let o_muvera_rec = MuveraVectorRecord {
            i_chunk_id: o_chunk.i_chunk_id,
            i_dim: v_muvera.len() as u32,
            i_model_version,
            i_file_offset: i_muvera_offset,
            i_byte_len: i_muvera_len,
            a_simhash,
            i_bucket_key,
        };

        self.doc_store.save_muvera_record(&o_muvera_rec);
        self.doc_store
            .bucket_insert_chunk(i_bucket_key, o_chunk.i_chunk_id);
        self.doc_store
            .clear_chunk_dirty_for_reproject(o_chunk.i_chunk_id);

        Ok(())
    }

    pub fn delete_document_now(&self, s_doc_path: &str) {
        if let Some(i_doc_id) = self.doc_store.get_doc_id_by_path(s_doc_path) {
            self.doc_store.mark_document_deleted(i_doc_id);
            for i_chunk_id in self.doc_store.list_chunk_ids_by_doc(i_doc_id).iter() {
                if let Some(o_chunk) = self.doc_store.get_chunk(*i_chunk_id) {
                    let v_tokens = tokenize_for_postings(&o_chunk.s_text);
                    self.doc_store
                        .token_postings_remove_chunk_tokens(*i_chunk_id, &v_tokens);
                }
                self.doc_store.update_chunk_deleted(*i_chunk_id, true);
                if let Some(o_rec) = self.doc_store.get_muvera_record(*i_chunk_id) {
                    self.doc_store
                        .bucket_remove_chunk(o_rec.i_bucket_key, *i_chunk_id);
                }
            }
        }
    }

    pub fn query_with_options(&self, s_query: &str, opts: QueryOptions) -> Vec<VecSearchHit> {
        if s_query.trim().is_empty() || opts.i_k == 0 {
            return Vec::new();
        }

        let v_query_posting_tokens = tokenize_for_postings(s_query);
        let v_query_token_vectors = self.encode_text_to_token_vectors(s_query);
        let v_query_muvera =
            self.project_query_token_vectors_to_muvera(s_query, &v_query_token_vectors);
        let a_query_simhash = self.simhash_for_vector(&v_query_muvera);
        let i_query_bucket_key = self.bucket_key_from_simhash(&a_query_simhash);

        let cfg = self
            .model
            .lock()
            .expect("muvera_model_lock_failed")
            .cfg
            .clone();

        let b_short_query = is_short_query_text(s_query);

        let mut h_candidate_ids: HashSet<ChunkId> = HashSet::new();
        let mut h_subword_match_count: HashMap<ChunkId, usize> = HashMap::new();
        let mut h_word_match_count: HashMap<ChunkId, usize> = HashMap::new();

        for s_token in v_query_posting_tokens.iter() {
            let b_is_subword = s_token.starts_with("g:");
            let b_is_word = s_token.starts_with("w:");

            for i_chunk_id in self
                .doc_store
                .token_postings_list_chunks(s_token, I_TOKEN_POSTING_PER_TERM_LIMIT)
                .into_iter()
            {
                h_candidate_ids.insert(i_chunk_id);

                if b_is_subword {
                    *h_subword_match_count.entry(i_chunk_id).or_insert(0) += 1;
                }
                if b_is_word {
                    *h_word_match_count.entry(i_chunk_id).or_insert(0) += 1;
                }

                if h_candidate_ids.len() >= I_TOKEN_POSTING_TARGET_CANDIDATES {
                    break;
                }
            }

            if h_candidate_ids.len() >= I_TOKEN_POSTING_TARGET_CANDIDATES {
                break;
            }
        }

        let v_bucket_keys = self.expand_bucket_keys_near(i_query_bucket_key);
        for i_bucket_key in v_bucket_keys.iter() {
            for i_chunk_id in self
                .doc_store
                .bucket_list_chunks(*i_bucket_key, cfg.i_query_preselect)
                .into_iter()
            {
                h_candidate_ids.insert(i_chunk_id);
                if h_candidate_ids.len() >= cfg.i_query_preselect.saturating_mul(3) {
                    break;
                }
            }
        }

        if h_candidate_ids.is_empty() {
            for i_chunk_id in self
                .doc_store
                .iter_all_chunk_ids()
                .into_iter()
                .take(cfg.i_query_preselect)
            {
                h_candidate_ids.insert(i_chunk_id);
            }
        }

        let mut v_preselected: Vec<(ChunkId, f32)> = Vec::new();

        for i_chunk_id in h_candidate_ids.into_iter() {
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

            let Some(o_muvera_rec) = self.doc_store.get_muvera_record(i_chunk_id) else {
                continue;
            };

            let v_chunk_muvera = match self
                .muvera_store
                .read_vector_f32(o_muvera_rec.i_file_offset, o_muvera_rec.i_dim as usize)
            {
                Ok(v) => v,
                Err(_) => continue,
            };

            let d_cos = cosine(&v_query_muvera, &v_chunk_muvera);
            let d_hash = simhash_similarity(&a_query_simhash, &o_muvera_rec.a_simhash);

            let i_subword_hits = *h_subword_match_count.get(&i_chunk_id).unwrap_or(&0) as f32;
            let i_word_hits = *h_word_match_count.get(&i_chunk_id).unwrap_or(&0) as f32;

            let d_subword_bonus = if i_subword_hits > 0.0 {
                i_subword_hits.min(12.0) / 12.0
            } else {
                0.0
            };

            let d_word_bonus = if i_word_hits > 0.0 {
                i_word_hits.min(6.0) / 6.0
            } else {
                0.0
            };

            let d_candidate_bonus = if b_short_query {
                D_SUBWORD_CANDIDATE_WEIGHT_SHORT_QUERY * d_subword_bonus
                    + D_WORD_CANDIDATE_WEIGHT_SHORT_QUERY * d_word_bonus
            } else {
                D_SUBWORD_CANDIDATE_WEIGHT_NORMAL_QUERY * d_subword_bonus
                    + D_WORD_CANDIDATE_WEIGHT_NORMAL_QUERY * d_word_bonus
            };

            let mut d_score = if b_short_query {
                0.45 * d_cos + 0.10 * d_hash + d_candidate_bonus
            } else {
                0.60 * d_cos + 0.15 * d_hash + d_candidate_bonus
            };

            if opts.b_enable_token_level_rescore && v_preselected.len() < cfg.i_fine_score_top_k {
                let d_fine = self.token_level_rescore(i_chunk_id, &v_query_token_vectors);
                d_score = 0.60 * d_score + 0.40 * d_fine;
            }

            v_preselected.push((i_chunk_id, d_score));
        }

        v_preselected.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(Ordering::Equal));
        v_preselected.truncate(cfg.i_query_preselect.max(cfg.i_bm25_top_k));

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

        let v_bm25 = bm25_rerank_top_k(&v_texts, s_query, cfg.i_bm25_top_k);

        let mut h_doc_best: HashMap<DocId, VecSearchHit> = HashMap::new();

        for (i_chunk_id, d_bm25) in v_bm25.into_iter() {
            let Some(o_chunk) = self.doc_store.get_chunk(i_chunk_id) else {
                continue;
            };
            let Some(o_doc) = self.doc_store.get_document_meta(o_chunk.i_doc_id) else {
                continue;
            };

            let d_vec = *h_vec_score.get(&i_chunk_id).unwrap_or(&0.0);
            let d_final = 0.45 * d_vec + 0.55 * d_bm25;

            let o_hit = VecSearchHit {
                s_doc: o_doc.s_doc_path.clone(),
                d_score: d_final,
                s_snippet: build_snippet_for_query(&o_chunk.s_text, s_query),
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
        let v_samples = self.collect_token_sample_vectors(p_root, 2000, 8);
        let i_token_dim = self.token_dim();

        let mut cfg = self
            .model
            .lock()
            .expect("muvera_model_lock_failed")
            .cfg
            .clone();

        cfg.i_token_dim = i_token_dim;
        cfg.i_model_version = cfg.i_model_version.saturating_add(1);

        let v_centroids = train_kmeans_centroids(&v_samples, cfg.i_cluster_count, 6, i_token_dim);

        let o_new_model = MuveraModel {
            cfg: cfg.clone(),
            v_centroids,
        };

        if save_model_staging(p_root, &o_new_model).is_ok() {
            if atomic_activate_staging_model(p_root).is_ok() {
                let mut g = self.model.lock().expect("muvera_model_lock_failed");
                *g = o_new_model;
            }
        }

        for i_chunk_id in self.doc_store.iter_all_chunk_ids().into_iter() {
            self.doc_store.mark_chunk_dirty_for_reproject(i_chunk_id);
        }

        self.reproject_dirty_async(50_000);
    }

    pub fn reproject_chunks_now(&self, v_chunk_ids: &[ChunkId]) {
        let i_model_version = self
            .model
            .lock()
            .expect("muvera_model_lock_failed")
            .cfg
            .i_model_version;

        for i_chunk_id in v_chunk_ids.iter() {
            let Some(mut o_chunk) = self.doc_store.get_chunk(*i_chunk_id) else {
                continue;
            };

            if o_chunk.b_deleted {
                self.doc_store.clear_chunk_dirty_for_reproject(*i_chunk_id);
                continue;
            }

            let Some(o_token_rec) = self.doc_store.get_token_record(*i_chunk_id) else {
                continue;
            };

            let v_token_vectors = if o_token_rec.b_quantized_i8 {
                match self.token_store.read_matrix_i8_quantized(
                    o_token_rec.i_file_offset,
                    o_token_rec.i_token_count as usize,
                    o_token_rec.i_vector_dim as usize,
                ) {
                    Ok(v) => v,
                    Err(_) => continue,
                }
            } else {
                continue;
            };

            o_chunk.i_model_version = i_model_version;
            self.doc_store.save_chunk(&o_chunk);
            let _ = self.write_chunk_projection(&o_chunk, &v_token_vectors);
        }
    }

    pub fn save(&self, p_root: &Path) {
        let g = self.model.lock().expect("muvera_model_lock_failed");
        let _ = save_model_active(p_root, &g);
    }

    pub fn load(&self, p_root: &Path) {
        let i_token_dim = self.token_dim();
        let o_model = load_or_create_model_active(p_root, i_token_dim);
        let mut g = self.model.lock().expect("muvera_model_lock_failed");
        *g = o_model;
    }

    fn token_dim(&self) -> usize {
        self.backend.dim().max(I_VEC_DIM_DEFAULT)
    }

    fn encode_text_to_token_vectors(&self, s_text: &str) -> Vec<Vec<f32>> {
        let v_segments = split_text_for_token_vectors(s_text);
        if v_segments.is_empty() {
            return vec![vec![0.0; self.token_dim()]];
        }
        match self.backend.encode_many(&v_segments) {
            Ok(vs) if !vs.is_empty() => vs,
            _ => v_segments
                .iter()
                .map(|_| vec![0.0; self.token_dim()])
                .collect(),
        }
    }

    fn project_token_vectors_to_muvera(&self, v_token_vectors: &[Vec<f32>]) -> Vec<f32> {
        let g = self.model.lock().expect("muvera_model_lock_failed");
        project_token_vectors_to_muvera_doc(&g, v_token_vectors)
    }

    fn project_query_token_vectors_to_muvera(
        &self,
        s_query: &str,
        v_query_token_vectors: &[Vec<f32>],
    ) -> Vec<f32> {
        let g = self.model.lock().expect("muvera_model_lock_failed");
        let b_short_query = is_short_query_text(s_query);
        project_token_vectors_to_muvera_query(&g, v_query_token_vectors, b_short_query)
    }

    fn simhash_for_vector(&self, v_vec: &[f32]) -> Vec<u64> {
        let i_bits = self
            .model
            .lock()
            .expect("muvera_model_lock_failed")
            .cfg
            .i_simhash_bits
            .max(8);
        compute_simhash(v_vec, i_bits)
    }

    fn bucket_key_from_simhash(&self, a_simhash: &[u64]) -> u32 {
        let i_prefix_bits = self
            .model
            .lock()
            .expect("muvera_model_lock_failed")
            .cfg
            .i_bucket_prefix_bits
            .clamp(1, 32);
        let i_first = *a_simhash.get(0).unwrap_or(&0u64);
        let i_shift = 64usize.saturating_sub(i_prefix_bits);
        (i_first >> i_shift) as u32
    }

    fn expand_bucket_keys_near(&self, i_bucket_key: u32) -> Vec<u32> {
        let i_prefix_bits = self
            .model
            .lock()
            .expect("muvera_model_lock_failed")
            .cfg
            .i_bucket_prefix_bits
            .clamp(1, 32);

        let i_mask: u32 = if i_prefix_bits >= 32 {
            u32::MAX
        } else {
            (1u32 << i_prefix_bits) - 1
        };

        let mut v_out: Vec<u32> = Vec::new();
        let mut h_seen: HashSet<u32> = HashSet::new();

        let mut add_bucket = |i_val: u32| {
            let i_masked = i_val & i_mask;
            if h_seen.insert(i_masked) {
                v_out.push(i_masked);
            }
        };

        add_bucket(i_bucket_key);

        for i_bit in 0..i_prefix_bits {
            add_bucket(i_bucket_key ^ (1u32 << i_bit));
        }

        let i_max_two_bit = 16usize;
        let mut i_count = 0usize;
        'outer: for i_a in 0..i_prefix_bits {
            for i_b in (i_a + 1)..i_prefix_bits {
                add_bucket(i_bucket_key ^ ((1u32 << i_a) | (1u32 << i_b)));
                i_count = i_count.saturating_add(1);
                if i_count >= i_max_two_bit {
                    break 'outer;
                }
            }
        }

        v_out
    }

    fn token_level_rescore(&self, i_chunk_id: ChunkId, v_query_tokens: &[Vec<f32>]) -> f32 {
        let Some(o_token_rec) = self.doc_store.get_token_record(i_chunk_id) else {
            return 0.0;
        };

        let v_doc_tokens = if o_token_rec.b_quantized_i8 {
            match self.token_store.read_matrix_i8_quantized(
                o_token_rec.i_file_offset,
                o_token_rec.i_token_count as usize,
                o_token_rec.i_vector_dim as usize,
            ) {
                Ok(v) => v,
                Err(_) => return 0.0,
            }
        } else {
            return 0.0;
        };

        if v_doc_tokens.is_empty() || v_query_tokens.is_empty() {
            return 0.0;
        }

        let mut d_sum_best = 0.0f32;
        let mut i_cnt = 0usize;

        for v_q in v_query_tokens.iter() {
            let mut d_best = f32::MIN;
            for v_d in v_doc_tokens.iter() {
                let d = cosine(v_q, v_d);
                if d > d_best {
                    d_best = d;
                }
            }
            if d_best.is_finite() {
                d_sum_best += d_best.max(0.0);
                i_cnt = i_cnt.saturating_add(1);
            }
        }

        if i_cnt == 0 {
            0.0
        } else {
            d_sum_best / (i_cnt as f32)
        }
    }

    fn collect_token_sample_vectors(
        &self,
        p_root: &Path,
        i_doc_limit: usize,
        i_chunks_per_doc: usize,
    ) -> Vec<Vec<f32>> {
        let mut v_jobs: Vec<(PathBuf, PayloadMap)> = Vec::new();
        Self::crawl_collect(p_root, &mut v_jobs);

        let mut v_out: Vec<Vec<f32>> = Vec::new();

        for (p_path, _) in v_jobs.into_iter().take(i_doc_limit) {
            let Ok(s_text) = extract_doc_text(&p_path) else {
                continue;
            };
            let v_chunks = chunk_text(&s_text, &self.chunk_cfg);
            for s_chunk in v_chunks.into_iter().take(i_chunks_per_doc) {
                let v_token_vectors = self.encode_text_to_token_vectors(&s_chunk);
                for v in v_token_vectors.into_iter().take(4) {
                    v_out.push(v);
                }
            }
        }

        if v_out.is_empty() {
            v_out.push(vec![0.0; self.token_dim()]);
        }

        v_out
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
            if !h_seen.contains(&o_doc.s_doc_path) {
                self.delete_document_now(&o_doc.s_doc_path);
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

fn split_text_for_token_vectors(s_text: &str) -> Vec<String> {
    let s_norm = normalize_for_match(s_text);
    if s_norm.is_empty() {
        return Vec::new();
    }

    let v_words: Vec<&str> = s_norm.split_whitespace().collect();
    if v_words.is_empty() {
        return Vec::new();
    }

    let mut h_seen: HashSet<String> = HashSet::new();
    let mut v_out: Vec<String> = Vec::new();

    let i_window = 6usize;
    let i_stride = 3usize;
    let mut i_pos = 0usize;

    while i_pos < v_words.len() {
        let i_end = (i_pos + i_window).min(v_words.len());
        let s_part = v_words[i_pos..i_end].join(" ");
        if !s_part.is_empty() && h_seen.insert(s_part.clone()) {
            v_out.push(s_part);
        }
        if i_end >= v_words.len() {
            break;
        }
        let i_next = i_pos.saturating_add(i_stride);
        if i_next <= i_pos {
            break;
        }
        i_pos = i_next;
    }

    for s_word in v_words.iter() {
        if s_word.len() >= 2 {
            let s_word_owned = (*s_word).to_string();
            if h_seen.insert(s_word_owned.clone()) {
                v_out.push(s_word_owned);
            }
        }
    }

    for s_word in v_words.iter() {
        if s_word.len() < 3 {
            continue;
        }
        for i_n in I_MUVERA_CHAR_NGRAM_MIN..=I_MUVERA_CHAR_NGRAM_MAX {
            for s_ng in to_char_ngrams(s_word, i_n, "") {
                if s_ng.len() >= 3 {
                    let s_token = format!("cg {}", s_ng);
                    if h_seen.insert(s_token.clone()) {
                        v_out.push(s_token);
                    }
                }
            }
        }
    }

    if v_out.is_empty() {
        v_out.push(s_norm);
    }

    v_out
}

fn tokenize_for_postings(s_text: &str) -> Vec<String> {
    let s_norm = normalize_for_match(s_text);
    if s_norm.is_empty() {
        return Vec::new();
    }

    let mut h_seen: HashSet<String> = HashSet::new();
    let mut v_out: Vec<String> = Vec::new();

    for s_word in s_norm.split_whitespace() {
        if s_word.len() < 2 {
            continue;
        }

        let s_word_token = format!("w:{}", s_word);
        if h_seen.insert(s_word_token.clone()) {
            v_out.push(s_word_token);
        }

        for i_n in 3..=5 {
            for s_ng in to_char_ngrams(s_word, i_n, "") {
                if s_ng.len() < 3 {
                    continue;
                }
                let s_ng_token = format!("g:{}", s_ng);
                if h_seen.insert(s_ng_token.clone()) {
                    v_out.push(s_ng_token);
                }
            }
        }
    }

    v_out
}

fn is_short_query_text(s_text: &str) -> bool {
    let s_norm = normalize_for_match(s_text);
    if s_norm.is_empty() {
        return true;
    }
    let v_words: Vec<&str> = s_norm.split_whitespace().collect();
    v_words.len() <= I_MUVERA_SHORT_QUERY_WORD_THRESHOLD
}

fn matches_filters(payload: &PayloadMap, v_filters: &[PayloadFilter]) -> bool {
    for f in v_filters.iter() {
        let s_val = payload.get(&f.s_field).map(|s| s.as_str()).unwrap_or("");
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

fn model_active_path(p_root: &Path) -> PathBuf {
    let mut p = p_root.to_path_buf();
    p.push(S_MODEL_ACTIVE_FILE);
    p
}

fn model_staging_path(p_root: &Path) -> PathBuf {
    let mut p = p_root.to_path_buf();
    p.push(S_MODEL_STAGING_FILE);
    p
}

fn load_or_create_model_active(p_root: &Path, i_token_dim: usize) -> MuveraModel {
    let p_model = model_active_path(p_root);
    if let Ok(v_buf) = fs::read(&p_model) {
        if let Ok(o_model) = bincode::deserialize::<MuveraModel>(&v_buf) {
            return o_model;
        }
    }

    let cfg = MuveraConfig {
        i_token_dim,
        ..MuveraConfig::default()
    };

    let mut v_centroids: Vec<ClusterCentroid> = Vec::new();
    for i_idx in 0..cfg.i_cluster_count {
        let mut v_center = vec![0.0f32; i_token_dim];
        if i_idx < i_token_dim {
            v_center[i_idx] = 1.0;
        } else if !v_center.is_empty() {
            let i_len = v_center.len();
            let i_pos = i_idx % i_len;
            v_center[i_pos] = 1.0;
        }
        v_centroids.push(ClusterCentroid {
            i_cluster_id: i_idx as u32,
            v_center,
        });
    }

    let o_model = MuveraModel { cfg, v_centroids };
    let _ = save_model_active(p_root, &o_model);
    o_model
}

fn save_model_active(p_root: &Path, o_model: &MuveraModel) -> Result<(), String> {
    let p_model = model_active_path(p_root);
    if let Some(p_parent) = p_model.parent() {
        let _ = fs::create_dir_all(p_parent);
    }
    let v_buf = bincode::serialize(o_model).map_err(|_| "model_serialize_failed".to_string())?;
    fs::write(p_model, v_buf).map_err(|_| "model_write_failed".to_string())
}

fn save_model_staging(p_root: &Path, o_model: &MuveraModel) -> Result<(), String> {
    let p_model = model_staging_path(p_root);
    if let Some(p_parent) = p_model.parent() {
        let _ = fs::create_dir_all(p_parent);
    }
    let v_buf = bincode::serialize(o_model).map_err(|_| "model_serialize_failed".to_string())?;
    fs::write(p_model, v_buf).map_err(|_| "model_staging_write_failed".to_string())
}

fn atomic_activate_staging_model(p_root: &Path) -> Result<(), String> {
    let p_staging = model_staging_path(p_root);
    let p_active = model_active_path(p_root);
    if !p_staging.exists() {
        return Err("model_staging_missing".to_string());
    }
    let p_backup = {
        let mut p = p_root.to_path_buf();
        p.push("muvera_model_backup.bin");
        p
    };
    if p_active.exists() {
        let _ = fs::rename(&p_active, &p_backup);
    }
    fs::rename(&p_staging, &p_active).map_err(|_| "model_atomic_swap_failed".to_string())?;
    let _ = fs::remove_file(&p_backup);
    Ok(())
}

fn nearest_centroid_index(v_vec: &[f32], v_centroids: &[ClusterCentroid]) -> usize {
    if v_centroids.is_empty() {
        return 0;
    }
    let mut i_best = 0usize;
    let mut d_best = f32::MIN;
    for (i_idx, c) in v_centroids.iter().enumerate() {
        let d_score = cosine(v_vec, &c.v_center);
        if d_score > d_best {
            d_best = d_score;
            i_best = i_idx;
        }
    }
    i_best
}

fn nearest_centroid_indices_weighted(
    v_vec: &[f32],
    v_centroids: &[ClusterCentroid],
    i_top_k: usize,
) -> Vec<(usize, f32)> {
    if v_centroids.is_empty() || i_top_k == 0 {
        return Vec::new();
    }

    let mut v_scores: Vec<(usize, f32)> = v_centroids
        .iter()
        .enumerate()
        .map(|(i_idx, c)| (i_idx, cosine(v_vec, &c.v_center)))
        .collect();

    v_scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(Ordering::Equal));
    v_scores.truncate(i_top_k.min(v_scores.len()));

    let mut d_sum_pos = 0.0f32;
    for (_, d_score) in v_scores.iter() {
        d_sum_pos += d_score.max(0.0);
    }

    if d_sum_pos <= 0.0 {
        let d_uniform = 1.0 / (v_scores.len().max(1) as f32);
        return v_scores
            .into_iter()
            .map(|(i_idx, _)| (i_idx, d_uniform))
            .collect();
    }

    v_scores
        .into_iter()
        .map(|(i_idx, d_score)| (i_idx, d_score.max(0.0) / d_sum_pos))
        .collect()
}

fn train_kmeans_centroids(
    v_samples: &[Vec<f32>],
    i_cluster_count: usize,
    i_iterations: usize,
    i_dim: usize,
) -> Vec<ClusterCentroid> {
    if v_samples.is_empty() {
        let mut v_centroids: Vec<ClusterCentroid> = Vec::new();
        for i_idx in 0..i_cluster_count.max(1) {
            let mut v = vec![0.0; i_dim.max(1)];
            if !v.is_empty() {
                let i_len = v.len();
                let i_pos = i_idx % i_len;
                v[i_pos] = 1.0;
            }
            v_centroids.push(ClusterCentroid {
                i_cluster_id: i_idx as u32,
                v_center: v,
            });
        }
        return v_centroids;
    }

    let i_k = i_cluster_count.min(v_samples.len()).max(1);
    let mut v_centers: Vec<Vec<f32>> = v_samples.iter().take(i_k).cloned().collect();

    while v_centers.len() < i_cluster_count {
        let i_len = v_centers.len();
        let i_src = i_len % i_k;
        let v_clone = v_centers[i_src].clone();
        v_centers.push(v_clone);
    }

    for _ in 0..i_iterations.max(1) {
        let mut v_sum = vec![vec![0.0f32; i_dim]; i_cluster_count];
        let mut v_cnt = vec![0usize; i_cluster_count];

        for v_s in v_samples.iter() {
            let mut i_best = 0usize;
            let mut d_best = f32::MIN;
            for (i_idx, v_c) in v_centers.iter().enumerate() {
                let d = cosine(v_s, v_c);
                if d > d_best {
                    d_best = d;
                    i_best = i_idx;
                }
            }
            add_in_place(&mut v_sum[i_best], v_s);
            v_cnt[i_best] = v_cnt[i_best].saturating_add(1);
        }

        for i_idx in 0..i_cluster_count {
            if v_cnt[i_idx] > 0 {
                scale_in_place(&mut v_sum[i_idx], 1.0 / (v_cnt[i_idx] as f32));
                l2_normalize_in_place(&mut v_sum[i_idx]);
                v_centers[i_idx] = v_sum[i_idx].clone();
            }
        }
    }

    v_centers
        .into_iter()
        .enumerate()
        .map(|(i_idx, v_center)| ClusterCentroid {
            i_cluster_id: i_idx as u32,
            v_center,
        })
        .collect()
}

fn project_token_vectors_to_muvera_doc(
    o_model: &MuveraModel,
    v_token_vectors: &[Vec<f32>],
) -> Vec<f32> {
    let i_cluster_count = o_model.cfg.i_cluster_count.max(1);
    let i_token_dim = o_model.cfg.i_token_dim.max(1);

    let mut v_bucket_sum = vec![vec![0.0f32; i_token_dim]; i_cluster_count];
    let mut v_bucket_max = vec![vec![f32::MIN; i_token_dim]; i_cluster_count];
    let mut v_bucket_weight = vec![0.0f32; i_cluster_count];

    for v_tok in v_token_vectors.iter() {
        let v_assign =
            nearest_centroid_indices_weighted(v_tok, &o_model.v_centroids, I_MUVERA_ASSIGN_TOP_K);

        for (i_cluster, d_weight) in v_assign.into_iter() {
            if i_cluster >= i_cluster_count || d_weight <= 0.0 {
                continue;
            }
            for i_dim in 0..i_token_dim {
                let d_val = *v_tok.get(i_dim).unwrap_or(&0.0);
                v_bucket_sum[i_cluster][i_dim] += d_val * d_weight;
                let d_weighted = d_val * d_weight;
                if d_weighted > v_bucket_max[i_cluster][i_dim] {
                    v_bucket_max[i_cluster][i_dim] = d_weighted;
                }
            }
            v_bucket_weight[i_cluster] += d_weight;
        }
    }

    let mut v_out: Vec<f32> = Vec::with_capacity(i_cluster_count * i_token_dim);

    for i_cluster in 0..i_cluster_count {
        let mut v_mean = v_bucket_sum[i_cluster].clone();
        if v_bucket_weight[i_cluster] > 0.0 {
            scale_in_place(&mut v_mean, 1.0 / v_bucket_weight[i_cluster]);
        }

        let mut v_max = v_bucket_max[i_cluster].clone();
        for d_val in v_max.iter_mut() {
            if !d_val.is_finite() || *d_val == f32::MIN {
                *d_val = 0.0;
            }
        }

        l2_normalize_in_place(&mut v_mean);
        l2_normalize_in_place(&mut v_max);

        let mut v_mix = vec![0.0f32; i_token_dim];
        for i_dim in 0..i_token_dim {
            v_mix[i_dim] = D_MUVERA_DOC_MEAN_POOL_WEIGHT * v_mean[i_dim]
                + D_MUVERA_DOC_MAX_POOL_WEIGHT * v_max[i_dim];
        }

        l2_normalize_in_place(&mut v_mix);
        v_out.extend_from_slice(&v_mix);
    }

    l2_normalize_in_place(&mut v_out);
    v_out
}

fn project_token_vectors_to_muvera_query(
    o_model: &MuveraModel,
    v_token_vectors: &[Vec<f32>],
    b_short_query: bool,
) -> Vec<f32> {
    let i_cluster_count = o_model.cfg.i_cluster_count.max(1);
    let i_token_dim = o_model.cfg.i_token_dim.max(1);

    let mut v_bucket_sum = vec![vec![0.0f32; i_token_dim]; i_cluster_count];
    let mut v_bucket_max = vec![vec![f32::MIN; i_token_dim]; i_cluster_count];
    let mut v_bucket_weight = vec![0.0f32; i_cluster_count];

    for v_tok in v_token_vectors.iter() {
        let v_assign =
            nearest_centroid_indices_weighted(v_tok, &o_model.v_centroids, I_MUVERA_ASSIGN_TOP_K);

        for (i_cluster, d_weight) in v_assign.into_iter() {
            if i_cluster >= i_cluster_count || d_weight <= 0.0 {
                continue;
            }
            for i_dim in 0..i_token_dim {
                let d_val = *v_tok.get(i_dim).unwrap_or(&0.0);
                v_bucket_sum[i_cluster][i_dim] += d_val * d_weight;
                let d_weighted = d_val * d_weight;
                if d_weighted > v_bucket_max[i_cluster][i_dim] {
                    v_bucket_max[i_cluster][i_dim] = d_weighted;
                }
            }
            v_bucket_weight[i_cluster] += d_weight;
        }
    }

    let d_mean_w = if b_short_query {
        D_MUVERA_QUERY_MEAN_POOL_WEIGHT_SHORT
    } else {
        D_MUVERA_DOC_MEAN_POOL_WEIGHT
    };

    let d_max_w = if b_short_query {
        D_MUVERA_QUERY_MAX_POOL_WEIGHT_SHORT
    } else {
        D_MUVERA_DOC_MAX_POOL_WEIGHT
    };

    let mut v_out: Vec<f32> = Vec::with_capacity(i_cluster_count * i_token_dim);

    for i_cluster in 0..i_cluster_count {
        let mut v_mean = v_bucket_sum[i_cluster].clone();
        if v_bucket_weight[i_cluster] > 0.0 {
            scale_in_place(&mut v_mean, 1.0 / v_bucket_weight[i_cluster]);
        }

        let mut v_max = v_bucket_max[i_cluster].clone();
        for d_val in v_max.iter_mut() {
            if !d_val.is_finite() || *d_val == f32::MIN {
                *d_val = 0.0;
            }
        }

        l2_normalize_in_place(&mut v_mean);
        l2_normalize_in_place(&mut v_max);

        let mut v_mix = vec![0.0f32; i_token_dim];
        for i_dim in 0..i_token_dim {
            v_mix[i_dim] = d_mean_w * v_mean[i_dim] + d_max_w * v_max[i_dim];
        }

        l2_normalize_in_place(&mut v_mix);
        v_out.extend_from_slice(&v_mix);
    }

    l2_normalize_in_place(&mut v_out);
    v_out
}

fn add_in_place(v_target: &mut [f32], v_add: &[f32]) {
    for (d_t, d_a) in v_target.iter_mut().zip(v_add.iter()) {
        *d_t += *d_a;
    }
}

fn scale_in_place(v_target: &mut [f32], d_scale: f32) {
    for d in v_target.iter_mut() {
        *d *= d_scale;
    }
}

fn l2_normalize_in_place(v_vec: &mut [f32]) {
    let d_norm = v_vec.iter().map(|x| x * x).sum::<f32>().sqrt();
    if d_norm > 0.0 {
        for d in v_vec.iter_mut() {
            *d /= d_norm;
        }
    }
}

fn compute_simhash(v_vec: &[f32], i_bits: usize) -> Vec<u64> {
    let i_bits_eff = i_bits.max(8);
    let i_word_count = i_bits_eff.div_ceil(64);
    let mut v_acc = vec![0.0f32; i_word_count * 64];

    for (i_idx, d_val) in v_vec.iter().enumerate() {
        for i_bit in 0..(i_word_count * 64) {
            let i_mix = ((i_idx as u64).wrapping_mul(0x9E3779B185EBCA87u64))
                ^ ((i_bit as u64).wrapping_mul(0xC2B2AE3D27D4EB4Fu64));
            let b_pos = (i_mix.count_ones() & 1) == 0;
            if b_pos {
                v_acc[i_bit] += *d_val;
            } else {
                v_acc[i_bit] -= *d_val;
            }
        }
    }

    let mut v_out = vec![0u64; i_word_count];
    for i_bit in 0..i_bits_eff {
        if v_acc[i_bit] >= 0.0 {
            let i_word = i_bit / 64;
            let i_off = i_bit % 64;
            v_out[i_word] |= 1u64 << i_off;
        }
    }

    v_out
}

fn simhash_similarity(a: &[u64], b: &[u64]) -> f32 {
    let i_len = a.len().min(b.len());
    if i_len == 0 {
        return 0.0;
    }

    let mut i_same_bits = 0u32;
    let mut i_total_bits = 0u32;

    for i_idx in 0..i_len {
        let i_xor = a[i_idx] ^ b[i_idx];
        let i_diff = i_xor.count_ones();
        let i_bits = 64u32;
        i_same_bits = i_same_bits.saturating_add(i_bits.saturating_sub(i_diff));
        i_total_bits = i_total_bits.saturating_add(i_bits);
    }

    if i_total_bits == 0 {
        0.0
    } else {
        (i_same_bits as f32) / (i_total_bits as f32)
    }
}

pub fn cosine(a: &[f32], b: &[f32]) -> f32 {
    let d_dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let d_n1 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let d_n2 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if d_n1 == 0.0 || d_n2 == 0.0 {
        0.0
    } else {
        d_dot / (d_n1 * d_n2)
    }
}

fn normalize_for_match(s_in: &str) -> String {
    let mut s_out = String::with_capacity(s_in.len().min(I_SNIPPET_SCAN_MAX_LEN));
    let mut b_prev_space = false;

    for ch in s_in.chars().take(I_SNIPPET_SCAN_MAX_LEN) {
        let ch_l = ch.to_ascii_lowercase();
        if ch_l.is_ascii_alphanumeric() {
            s_out.push(ch_l);
            b_prev_space = false;
        } else if !b_prev_space {
            s_out.push(' ');
            b_prev_space = true;
        }
    }

    s_out.split_whitespace().collect::<Vec<&str>>().join(" ")
}

fn extract_query_tokens(s_query: &str) -> Vec<String> {
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
    let s_text_trim = s_text.trim();
    if s_text_trim.is_empty() {
        return String::new();
    }

    let s_norm = normalize_for_match(s_text_trim);
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

    s_slice.split_whitespace().collect::<Vec<&str>>().join(" ")
}

fn bm25_ngram_from_env() -> usize {
    let s_val = std::env::var("BM25_NGRAM").unwrap_or_else(|_| String::new());
    let mut i_n = s_val.trim().parse::<usize>().unwrap_or(I_BM25_NGRAM_DEFAULT);
    if i_n < I_BM25_NGRAM_MIN {
        i_n = I_BM25_NGRAM_MIN;
    }
    if i_n > I_BM25_NGRAM_MAX {
        i_n = I_BM25_NGRAM_MAX;
    }
    i_n
}

fn normalize_heuristic(s_text: &str) -> String {
    let mut s_out = String::with_capacity(s_text.len());
    let mut b_prev_space = false;

    for ch in s_text.chars() {
        let ch_l = ch.to_ascii_lowercase();
        if ch_l.is_ascii_alphanumeric() {
            s_out.push(ch_l);
            b_prev_space = false;
        } else if !b_prev_space {
            s_out.push(' ');
            b_prev_space = true;
        }
    }

    s_out.split_whitespace().collect::<Vec<&str>>().join(" ")
}

fn to_char_ngrams(s_text: &str, i_n: usize, s_boundary: &str) -> Vec<String> {
    let s_norm = normalize_heuristic(s_text);
    if s_norm.trim().is_empty() {
        return Vec::new();
    }

    let i_n_eff = i_n.clamp(I_BM25_NGRAM_MIN, I_BM25_NGRAM_MAX);
    let mut v_out: Vec<String> = Vec::new();

    for s_word in s_norm.split_whitespace() {
        if s_word.is_empty() {
            continue;
        }

        let s_w = format!("{}{}{}", s_boundary, s_word, s_boundary);
        let i_len = s_w.len();

        if i_len < i_n_eff {
            v_out.push(s_w);
            continue;
        }

        for i_pos in 0..=(i_len - i_n_eff) {
            v_out.push(s_w[i_pos..i_pos + i_n_eff].to_string());
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
