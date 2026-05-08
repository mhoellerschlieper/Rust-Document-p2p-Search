/**********************************************************************************************
 * Modulname : embedding_backend
 * Datei     : embedding_backend.rs
 * Autor     : Marcus Schlieper
 *------------------------------------------------------------------------------------------------
 * Beschreibung
 * - Abstraktion fuer Embedding Backends ohne harte Build Abhaengigkeit zu torch-sys.
 * - Standard ist ein lokales, deterministisches Fallback Backend.
 * - Optional kann ein HTTP Dienst genutzt werden.
 *
 * Historie
 * 08.05.2026   MS   - Neufassung fuer plattformstabilen Betrieb auf Windows, Linux und macOS
 **********************************************************************************************/

#![allow(clippy::needless_return)]

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::sync::Arc;

pub const I_VEC_DIM_DEFAULT: usize = 384;

pub trait EmbeddingBackend: Send + Sync {
    fn encode_one(&self, s_text: &str) -> Result<Vec<f32>>;

    fn encode_many(&self, v_texts: &[String]) -> Result<Vec<Vec<f32>>> {
        let mut v_out: Vec<Vec<f32>> = Vec::with_capacity(v_texts.len());
        for s_text in v_texts {
            v_out.push(self.encode_one(s_text)?);
        }
        return Ok(v_out);
    }

    fn dim(&self) -> usize;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EmbeddingBackendKind {
    LocalFallback,
    Http,
}

pub fn create_backend_from_env() -> Arc<dyn EmbeddingBackend> {
    let s_kind = env::var("EMBEDDING_BACKEND")
        .unwrap_or_else(|_| "local".to_string())
        .to_ascii_lowercase();

    if s_kind == "http" {
        let s_url = env::var("EMBEDDING_HTTP_URL").unwrap_or_else(|_| String::new());
        let s_token = env::var("EMBEDDING_HTTP_TOKEN").unwrap_or_else(|_| String::new());

        if !s_url.trim().is_empty() {
            return Arc::new(HttpEmbeddingBackend::new(&s_url, &s_token, I_VEC_DIM_DEFAULT));
        }
    }

    return Arc::new(LocalFallbackEmbeddingBackend::new(I_VEC_DIM_DEFAULT));
}

pub struct LocalFallbackEmbeddingBackend {
    i_dim: usize,
}

impl LocalFallbackEmbeddingBackend {
    pub fn new(i_dim: usize) -> Self {
        let i_dim_safe = if i_dim == 0 { I_VEC_DIM_DEFAULT } else { i_dim };
        return Self { i_dim: i_dim_safe };
    }

    fn normalize_text(&self, s_text: &str) -> String {
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

        return s_out.split_whitespace().collect::<Vec<_>>().join(" ");
    }
}

impl EmbeddingBackend for LocalFallbackEmbeddingBackend {
    fn encode_one(&self, s_text: &str) -> Result<Vec<f32>> {
        let s_norm = self.normalize_text(s_text);
        let mut v_out = vec![0.0_f32; self.i_dim];

        if s_norm.is_empty() {
            return Ok(v_out);
        }

        for s_token in s_norm.split_whitespace() {
            let a_hash = Sha256::digest(s_token.as_bytes());
            for i_idx in 0..self.i_dim {
                let i_hash_idx = i_idx % a_hash.len();
                let i_val = a_hash[i_hash_idx] as f32;
                v_out[i_idx] += (i_val / 255.0_f32) - 0.5_f32;
            }
        }

        let d_norm = v_out.iter().map(|x| x * x).sum::<f32>().sqrt();
        if d_norm > 0.0 {
            for d_val in &mut v_out {
                *d_val /= d_norm;
            }
        }

        return Ok(v_out);
    }

    fn dim(&self) -> usize {
        return self.i_dim;
    }
}

pub struct HttpEmbeddingBackend {
    s_url: String,
    s_token: String,
    i_dim: usize,
}

impl HttpEmbeddingBackend {
    pub fn new(s_url: &str, s_token: &str, i_dim: usize) -> Self {
        return Self {
            s_url: s_url.trim().to_string(),
            s_token: s_token.trim().to_string(),
            i_dim: if i_dim == 0 { I_VEC_DIM_DEFAULT } else { i_dim },
        };
    }
}

#[derive(Serialize)]
struct HttpEmbeddingRequest {
    input: String,
}

#[derive(Deserialize)]
struct HttpEmbeddingResponse {
    embedding: Vec<f32>,
}

impl EmbeddingBackend for HttpEmbeddingBackend {
    fn encode_one(&self, s_text: &str) -> Result<Vec<f32>> {
        let o_rt = tokio::runtime::Runtime::new()
            .map_err(|e| anyhow!("runtime_create_failed: {}", e))?;

        let s_url = self.s_url.clone();
        let s_token = self.s_token.clone();
        let s_input = s_text.to_string();
        let i_dim = self.i_dim;

        let v_res = o_rt.block_on(async move {
            let o_client = reqwest::Client::new();
            let mut o_req = o_client.post(&s_url).json(&HttpEmbeddingRequest { input: s_input });

            if !s_token.is_empty() {
                o_req = o_req.bearer_auth(s_token);
            }

            let o_resp = o_req.send().await.map_err(|e| anyhow!("http_send_failed: {}", e))?;
            if !o_resp.status().is_success() {
                return Err(anyhow!("http_status_not_success: {}", o_resp.status()));
            }

            let o_data: HttpEmbeddingResponse = o_resp
                .json()
                .await
                .map_err(|e| anyhow!("http_json_parse_failed: {}", e))?;

            if o_data.embedding.len() != i_dim {
                return Err(anyhow!(
                    "embedding_dim_mismatch: expected={}, got={}",
                    i_dim,
                    o_data.embedding.len()
                ));
            }

            Ok(o_data.embedding)
        })?;

        return Ok(v_res);
    }

    fn dim(&self) -> usize {
        return self.i_dim;
    }
}
