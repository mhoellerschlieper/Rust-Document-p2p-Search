/**********************************************************************************************
 *  Modulname : vector_idx
 *
 *  Datei     : vector_idx.rs
 *  Autor     : Marcus Schlieper
 *------------------------------------------------------------------------------------------------
 *  Historie
 *  13.11.2025   MS   - Neufassung: semantischer Vektor-Index ohne ANN-Bibliothek
 *  07.01.2026   MS   - Erweiterung: Re-Ranking der Top-K Vektor-Kandidaten via BM25
 *  07.01.2026   MS   - Anpassung: BM25 Tokenisierung via Char-N-Grams (BM25_NGRAM 3..6, Default 5)
 *
 *  Beschreibung
 *  - query(): 2-stufiges Retrieval
 *    1) Vektor-Aehnlichkeit (Kosinus) auf allen Eintraegen
 *    2) BM25 Re-Ranking auf einer Kurzliste (Top-N) mit Char-N-Gram Tokenisierung
 *
 *  Konfiguration
 *  - BM25_NGRAM: Umgebungsvariable, gueltig 3..6, Default 5
 *
 *  Sicherheit
 *  - Defensive Defaults, Validierung, keine Panics in Re-Ranking Pfaden, Fehlerbehandlung per Fallback
 **********************************************************************************************/

#![allow(clippy::type_complexity)]
#![allow(clippy::needless_return)]
#![allow(warnings)]

use std::{
    fs,
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::extract_doc_text;
use bincode;
use rust_bert::pipelines::sentence_embeddings::{
    SentenceEmbeddingsBuilder, SentenceEmbeddingsModel, SentenceEmbeddingsModelType,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sled::IVec;

/* ------------------------------- Konstanten ----------------------------------------------- */
const VEC_DIM: usize = 384;
const ANN_CAPACITY: usize = 30_000;
const TRACKER_DB: &str = "vec_tracker";
const GRAPH_FILE: &str = "ann_graph.bin";

/* BM25 Parameter */
const BM25_K1: f32 = 1.5;
const BM25_B: f32 = 0.75;

/* Re-Ranking Parameter: Kurzliste = min(len, k * mult) */
const BM25_CANDIDATE_MULT: usize = 10;

/* BM25 N-Gram Defaults */
const BM25_NGRAM_DEFAULT: usize = 5;
const BM25_NGRAM_MIN: usize = 3;
const BM25_NGRAM_MAX: usize = 6;

const I_SNIPPET_MAX_LEN: usize = 320;
const I_SNIPPET_SCAN_MAX_LEN: usize = 32_000;

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct VecSearchHit {
    pub s_doc: String,
    pub d_score: f32,
    pub s_snippet: String,
}

/* ----------------------- Aenderungs-Tracker (sled) --------------------------------------- */
struct VecTracker {
    db: sled::Db,
}
impl VecTracker {
    fn new() -> Self {
        Self {
            db: sled::open(TRACKER_DB).expect("Tracker-DB"),
        }
    }

    fn state(&self, s_path: &str) -> Option<(u64, [u8; 32])> {
        self.db.get(s_path).ok().flatten().and_then(|v| {
            if v.len() == 40 {
                let (t, h) = v.split_at(8);
                let mut a_t = [0u8; 8];
                let mut a_h = [0u8; 32];
                a_t.copy_from_slice(t);
                a_h.copy_from_slice(h);
                Some((u64::from_le_bytes(a_t), a_h))
            } else {
                None
            }
        })
    }

    fn set(&self, s_path: &str, i_ts: u64, a_hash: [u8; 32]) {
        let mut v_buf = Vec::with_capacity(40);
        v_buf.extend_from_slice(&i_ts.to_le_bytes());
        v_buf.extend_from_slice(&a_hash);
        let _ = self.db.insert(s_path, IVec::from(v_buf));
    }

    fn remove(&self, s_path: &str) {
        let _ = self.db.remove(s_path);
    }

    fn all(&self) -> Vec<String> {
        self.db
            .iter()
            .keys()
            .flatten()
            .map(|k| String::from_utf8_lossy(&k).into_owned())
            .collect()
    }
}

/* ----------------------------- Datenstruktur --------------------------------------------- */
#[derive(Serialize, Deserialize)]
struct StoredEntry {
    path: String,
    vec: Vec<f32>,
}

pub struct VectorIndex {
    model: SentenceEmbeddingsModel,
    entries: Mutex<Vec<StoredEntry>>,
    tracker: VecTracker,
}

fn normalize_for_match(s_in: &str) -> String {
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

    let mut i_best_pos: Option<usize> = None;
    for s_t in &v_q {
        if let Some(i_pos) = s_norm.find(s_t) {
            i_best_pos = match i_best_pos {
                None => Some(i_pos),
                Some(old) => Some(old.min(i_pos)),
            };
        }
    }

    let Some(i_pos_norm) = i_best_pos else {
        return s_text_trim
            .chars()
            .take(I_SNIPPET_MAX_LEN)
            .collect::<String>();
    };

    let d_ratio = (s_text_trim.len().max(1) as f64) / (s_norm.len().max(1) as f64);
    let i_pos_orig = ((i_pos_norm as f64) * d_ratio) as usize;

    let i_half = I_SNIPPET_MAX_LEN / 2;
    let i_start = i_pos_orig.saturating_sub(i_half);
    let i_end = (i_start + I_SNIPPET_MAX_LEN).min(s_text_trim.len());

    let s_slice = &s_text_trim[i_start..i_end];
    s_slice.split_whitespace().collect::<Vec<&str>>().join(" ")
}
/* ----------------------------- Implementierung ------------------------------------------- */
impl VectorIndex {
    pub fn new() -> Arc<Self> {
        let model = SentenceEmbeddingsBuilder::remote(SentenceEmbeddingsModelType::AllMiniLmL6V2)
            .create_model()
            .expect("Sentence-Transformer");

        Arc::new(Self {
            model,
            entries: Mutex::new(Vec::with_capacity(ANN_CAPACITY)),
            tracker: VecTracker::new(),
        })
    }

    pub fn encode_query(&self, s_text: &str) -> Vec<f32> {
        self.model
            .encode(&[s_text.to_owned()])
            .map(|mut v| v.pop().unwrap_or_else(|| vec![0.0; VEC_DIM]))
            .unwrap_or_else(|_| vec![0.0; VEC_DIM])
    }

    pub fn vec_of(&self, s_path: &str) -> Option<Vec<f32>> {
        let g = self.entries.lock().unwrap();
        g.iter().find(|e| e.path == s_path).map(|e| e.vec.clone())
    }

    pub fn sync(self: &Arc<Self>, root: &Path) {
        let mut v_seen: Vec<String> = Vec::new();
        Self::crawl(root, self, &mut v_seen);

        let mut guard = self.entries.lock().unwrap();
        guard.retain(|e| {
            if v_seen.contains(&e.path) {
                true
            } else {
                self.tracker.remove(&e.path);
                false
            }
        });
    }

    /******************************************************************************************
     *  Funktion : query_with_snippets
     *-----------------------------------------------------------------------------------------
     *  Zweck    : Liefert Top-K Treffer mit Score und Text Snippet (query-biased).
     *            Snippet ist laengenbegrenzt und verarbeitet maximal I_SNIPPET_SCAN_MAX_LEN Zeichen.
     *
     *  Historie
     *  08.01.2026   MS   - Neu: Snippet Ausgabe fuer vec_search lokal und remote
     ******************************************************************************************/
    pub fn query_with_snippets(self: &Arc<Self>, s_query: &str, i_k: usize) -> Vec<VecSearchHit> {
        if s_query.trim().is_empty() {
            return Vec::new();
        }
        if i_k == 0 {
            return Vec::new();
        }

        // Reuse existing retrieval (vector + bm25 rerank) to get ordered paths and scores.
        // NOTE: query() currently returns (path, score) after BM25 rerank; keep it as ranking baseline.
        let v_ranked: Vec<(String, f32)> = self.query(s_query, i_k);

        let mut v_out: Vec<VecSearchHit> = Vec::with_capacity(v_ranked.len());
        for (s_path, d_score) in v_ranked {
            // Defensive: bounded extraction. extract_doc_text already handles formats.
            let s_txt = extract_doc_text(Path::new(&s_path)).unwrap_or_else(|_| String::new());
            let s_snip = if s_txt.is_empty() {
                String::new()
            } else {
                build_snippet_for_query(&s_txt, s_query)
            };

            v_out.push(VecSearchHit {
                s_doc: s_path,
                d_score,
                s_snippet: s_snip,
            });
        }

        v_out
    }

    /******************************************************************************************
     *  Funktion : query
     *-----------------------------------------------------------------------------------------
     *  Zweck    : 2-Phasen Retrieval
     *            (1) Vektor: Kosinus Aehnlichkeit
     *            (2) BM25: Char-N-Gram Re-Ranking auf Kurzliste
     *
     *  Historie
     *  07.01.2026   MS   - Umstellung der BM25 Tokenisierung auf Char-N-Grams (3..6, Default 5)
     ******************************************************************************************/
    pub fn query(self: &Arc<Self>, q: &str, k: usize) -> Vec<(String, f32)> {
        if q.trim().is_empty() {
            return Vec::new();
        }
        if k == 0 {
            return Vec::new();
        }

        let q_vec = self
            .model
            .encode(&[q.to_owned()])
            .ok()
            .and_then(|mut v| v.pop())
            .unwrap_or_else(|| vec![0.0; VEC_DIM]);

        let guard = self.entries.lock().unwrap();
        if guard.is_empty() {
            return Vec::new();
        }

        let i_target = k.saturating_mul(BM25_CANDIDATE_MULT).max(k);
        let i_limit = i_target.min(guard.len());

        let mut v_scored: Vec<(String, f32)> = guard
            .iter()
            .map(|e| (e.path.clone(), cosine(&q_vec, &e.vec)))
            .collect();

        v_scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        v_scored.truncate(i_limit);

        /* BM25 Re-Ranking (Char-N-Grams) */
        let v_scored = Self::bm25_rerank_char_ngrams(&v_scored, q, k);
        v_scored
    }

    pub fn save(&self, dir: &Path) {
        if let Ok(buf) = bincode::serialize(&*self.entries.lock().unwrap()) {
            let _ = fs::write(dir.join(GRAPH_FILE), buf);
        }
    }

    pub fn load(&self, dir: &Path) {
        if let Ok(buf) = fs::read(dir.join(GRAPH_FILE)) {
            if let Ok(v) = bincode::deserialize::<Vec<StoredEntry>>(&buf) {
                *self.entries.lock().unwrap() = v;
            }
        }
    }

    fn crawl(p_dir: &Path, o_self: &Arc<Self>, v_seen: &mut Vec<String>) {
        if let Ok(rd) = fs::read_dir(p_dir) {
            for entry in rd.flatten() {
                let p_path = entry.path();
                if p_path.is_dir() {
                    Self::crawl(&p_path, o_self, v_seen);
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

                let s_path = p_path.display().to_string();
                v_seen.push(s_path.clone());

                if let Ok(md) = entry.metadata() {
                    let i_ts = md
                        .modified()
                        .unwrap_or(SystemTime::UNIX_EPOCH)
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    let s_text = match extract_doc_text(&p_path) {
                        Ok(t) if !t.trim().is_empty() => t,
                        _ => continue,
                    };

                    let a_hash: [u8; 32] = Sha256::digest(s_text.as_bytes()).into();

                    let b_changed = o_self
                        .tracker
                        .state(&s_path)
                        .map_or(true, |(i_old_ts, a_old_h)| {
                            i_old_ts != i_ts || a_old_h != a_hash
                        });

                    if b_changed {
                        let v_vec = o_self
                            .model
                            .encode(&[s_text])
                            .ok()
                            .and_then(|mut v| v.pop())
                            .unwrap_or_else(|| vec![0.0; VEC_DIM]);

                        let mut g = o_self.entries.lock().unwrap();
                        if let Some(pos) = g.iter().position(|e| e.path == s_path) {
                            g[pos].vec = v_vec;
                        } else {
                            g.push(StoredEntry {
                                path: s_path.clone(),
                                vec: v_vec,
                            });
                        }
                        o_self.tracker.set(&s_path, i_ts, a_hash);
                    }
                }
            }
        }
    }

    /* ------------------------------ BM25: Char N-Grams ----------------------------------- */

    fn bm25_rerank_char_ngrams(
        v_candidates: &[(String, f32)],
        s_query: &str,
        k: usize,
    ) -> Vec<(String, f32)> {
        if v_candidates.is_empty() {
            return Vec::new();
        }

        let i_ngram = Self::bm25_ngram_from_env();
        let v_q_tokens = Self::tokenize_bm25_char_ngrams(s_query, i_ngram);
        if v_q_tokens.is_empty() {
            let mut v_out: Vec<(String, f32)> = v_candidates.to_vec();
            v_out.truncate(k);
            return v_out;
        }

        /* Dokumente laden und tokenisieren (nur Kurzliste) */
        let mut v_doc_tokens: Vec<Vec<String>> = Vec::with_capacity(v_candidates.len());
        let mut v_paths: Vec<String> = Vec::with_capacity(v_candidates.len());

        for (s_path, _) in v_candidates.iter() {
            let s_txt = extract_doc_text(Path::new(s_path)).unwrap_or_else(|_| String::new());
            let v_toks = Self::tokenize_bm25_char_ngrams(&s_txt, i_ngram);
            v_paths.push(s_path.clone());
            v_doc_tokens.push(v_toks);
        }

        /* Fallback, falls Inhalte nicht verwertbar sind */
        if v_doc_tokens.iter().all(|t| t.is_empty()) {
            let mut v_out: Vec<(String, f32)> = v_candidates.to_vec();
            v_out.truncate(k);
            return v_out;
        }

        let v_scores = Self::bm25_scores(&v_doc_tokens, &v_q_tokens, BM25_K1, BM25_B);

        let mut v_scored: Vec<(String, f32)> =
            v_paths.into_iter().zip(v_scores.into_iter()).collect();

        v_scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        v_scored.truncate(k);
        v_scored
    }

    fn bm25_ngram_from_env() -> usize {
        let s_val = std::env::var("BM25_NGRAM").unwrap_or_else(|_| "".to_string());
        let mut i_n = s_val.trim().parse::<usize>().unwrap_or(BM25_NGRAM_DEFAULT);

        if i_n < BM25_NGRAM_MIN {
            i_n = BM25_NGRAM_MIN;
        }
        if i_n > BM25_NGRAM_MAX {
            i_n = BM25_NGRAM_MAX;
        }
        i_n
    }

    fn normalize_heuristic(s_text: &str) -> String {
        /* ASCII-only, lower, nicht-alnum als Space, Whitespace normalisieren */
        let mut s_out = String::with_capacity(s_text.len());
        let mut b_prev_space = false;

        for ch in s_text.chars() {
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

    fn to_char_ngrams(s_text: &str, i_n: usize, s_boundary: &str) -> Vec<String> {
        let s_norm = Self::normalize_heuristic(s_text);
        if s_norm.trim().is_empty() {
            return Vec::new();
        }

        let mut i_n_eff = i_n;
        if i_n_eff < BM25_NGRAM_MIN {
            i_n_eff = BM25_NGRAM_MIN;
        }
        if i_n_eff > BM25_NGRAM_MAX {
            i_n_eff = BM25_NGRAM_MAX;
        }

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
        Self::to_char_ngrams(s_text, i_n, "_")
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

        /* df */
        let mut h_df: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for v_doc in v_docs_tokens.iter() {
            let mut h_seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
            for s_term in v_doc.iter() {
                if h_seen.insert(s_term.as_str()) {
                    *h_df.entry(s_term.clone()).or_insert(0) += 1;
                }
            }
        }

        /* idf */
        let mut h_idf: std::collections::HashMap<String, f32> = std::collections::HashMap::new();
        for (s_term, i_df) in h_df.iter() {
            let d_df = *i_df as f32;
            let d_idf = ((i_n_docs - d_df + 0.5) / (d_df + 0.5) + 1.0).ln();
            h_idf.insert(s_term.clone(), d_idf);
        }

        /* tf je Dokument */
        let mut v_tf: Vec<std::collections::HashMap<&str, usize>> =
            Vec::with_capacity(v_docs_tokens.len());
        for v_doc in v_docs_tokens.iter() {
            let mut h_tf: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
            for s_t in v_doc.iter() {
                *h_tf.entry(s_t.as_str()).or_insert(0) += 1;
            }
            v_tf.push(h_tf);
        }

        /* scoring */
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
}

/* ----------------------------- Hilfsfunktion Kosinus ------------------------------------- */
pub fn cosine(a: &[f32], b: &[f32]) -> f32 {
    let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let n1 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let n2 = b.iter().map(|x| x * x).sum::<f32>().sqrt();

    if n1 == 0.0 || n2 == 0.0 {
        0.0
    } else {
        dot / (n1 * n2)
    }
}

/* ------------------------- Oeffentliche Convenience-Funktionen ---------------------------- */
pub fn load_or_init_index(root: &Path) -> Arc<VectorIndex> {
    let idx = VectorIndex::new();
    idx.load(root);
    idx
}

pub fn persist_index(idx: &VectorIndex, root: &Path) {
    idx.save(root);
}
