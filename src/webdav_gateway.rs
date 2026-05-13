/**********************************************************************************************
 *  Modulname : secure_p2p_ext
 *  Datei     : webdav_gateway.rs
 *  Autor     : Marcus Schlieper
 *---------------------------------------------------------------------------------------------
 *  Beschreibung
 *  - Read only WebDAV Gateway fuer das verteilte Dokumentensystem.
 *  - Stellt virtuelle Pfade unter /local, /peers und /search bereit.
 *  - Unterstuetzt OPTIONS, PROPFIND, GET und HEAD.
 *  - IAM Leserechte werden zentral geprueft.
 *  - Metadaten Cache und Dateicache sind enthalten.
 *  - Hybrid Suche wird als virtuelle Trefferliste unter /search/hybrid/<query>/ angeboten.
 *  - Snippets werden als virtuelle Datei snippet.txt je Treffer bereitgestellt.
 *
 *  Historie
 *  13.05.2026  MS  - Initiale Version fuer Phase 1 und Phase 2
 *  13.05.2026  MS  - Erweiterung: Windows WebDAV Basis Support mit HEAD und Depth
 *  13.05.2026  MS  - Erweiterung: saubere XML Ausgabe fuer PROPFIND
 **********************************************************************************************/

#![allow(clippy::needless_return)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use percent_encoding::{percent_decode_str, utf8_percent_encode, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};

use crate::config::cfg_get;
use crate::iam::{iam_store, right_read};
use crate::{combi_search_with_snippets, TantivyIndex};
use crate::vector_idx::VectorIndex;

/* ========================================================================================== */
/* Types                                                                                      */
/* ========================================================================================== */

pub type HttpBody = Full<Bytes>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebDavEntry {
    pub s_name: String,
    pub s_path: String,
    pub b_dir: bool,
    pub i_size: u64,
    pub i_mtime_unix: u64,
}

#[derive(Clone, Debug)]
pub struct WebDavFileData {
    pub v_bytes: Vec<u8>,
    pub i_mtime_unix: u64,
    pub s_mime: String,
}

#[derive(Clone, Debug)]
struct MetaCacheEntry {
    i_created_ms: u64,
    v_entries: Vec<WebDavEntry>,
}

#[derive(Clone, Debug)]
struct FileCacheEntry {
    i_created_ms: u64,
    data: WebDavFileData,
}

#[derive(Clone)]
pub struct WebDavGateway {
    pub iam: Arc<iam_store>,
    pub idx_tan: Arc<TantivyIndex>,
    pub idx_vec: Arc<VectorIndex>,
    pub h_meta_cache: Arc<Mutex<HashMap<String, MetaCacheEntry>>>,
    pub h_file_cache: Arc<Mutex<HashMap<String, FileCacheEntry>>>,
    pub h_peer_docs: Arc<Mutex<HashMap<String, Vec<WebDavEntry>>>>,
}

/* ========================================================================================== */
/* Const                                                                                      */
/* ========================================================================================== */

const I_META_CACHE_TTL_MS: u64 = 20_000;
const I_FILE_CACHE_TTL_MS: u64 = 60_000;
const I_SEARCH_RESULT_LIMIT: usize = 25;
const I_SNIPPET_FILE_LIMIT: usize = 4096;

/* ========================================================================================== */
/* Impl                                                                                       */
/* ========================================================================================== */

impl WebDavGateway {
    /******************************************************************************************
     *  Beschreibung
     *  - Zentrale Initialisierung des WebDAV Gateways.
     *
     *  Historie
     *  13.05.2026  MS  - Initiale Version
     ******************************************************************************************/
    pub fn new(
        iam: Arc<iam_store>,
        idx_tan: Arc<TantivyIndex>,
        idx_vec: Arc<VectorIndex>,
    ) -> Self {
        Self {
            iam,
            idx_tan,
            idx_vec,
            h_meta_cache: Arc::new(Mutex::new(HashMap::new())),
            h_file_cache: Arc::new(Mutex::new(HashMap::new())),
            h_peer_docs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn register_peer_entries(&self, s_peer_id: &str, v_entries: Vec<WebDavEntry>) {
        let mut g = self.h_peer_docs.lock().unwrap();
        g.insert(s_peer_id.to_string(), v_entries);
    }

    pub async fn handle_request(
        &self,
        req: Request<Incoming>,
        s_session: Option<String>,
    ) -> Response<HttpBody> {
        let method = req.method().clone();
        let headers = req.headers().clone();
        let s_uri_path = req.uri().path().to_string();
        let s_path = normalize_webdav_path(&decode_path(&s_uri_path));

        match method {
            Method::OPTIONS => self.handle_options(),
            Method::GET => self.handle_get(&s_path, s_session).await,
            Method::HEAD => self.handle_head(&s_path, s_session).await,
            _ => {
                let s_m = method.as_str().to_string();
                if s_m == "PROPFIND" {
                    self.handle_propfind(&s_path, s_session, &headers).await
                } else {
                    response_text(StatusCode::METHOD_NOT_ALLOWED, "read_only_webdav")
                }
            }
        }
    }

    fn handle_options(&self) -> Response<HttpBody> {
        Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header("DAV", "1")
            .header("Allow", "OPTIONS, PROPFIND, GET, HEAD")
            .header("MS-Author-Via", "DAV")
            .header("Content-Length", "0")
            .body(Full::new(Bytes::new()))
            .unwrap_or_else(|_| response_text(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"))
    }

    async fn handle_propfind(
        &self,
        s_path: &str,
        s_session: Option<String>,
        headers: &http::HeaderMap,
    ) -> Response<HttpBody> {
        let s_depth = headers
            .get("Depth")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("1")
            .to_string();

        let b_include_children = match s_depth.as_str() {
            "0" => false,
            "1" => true,
            "infinity" => true,
            _ => true,
        };

        let v_entries = match self.list_entries(s_path, s_session.as_deref(), b_include_children) {
            Ok(v) => v,
            Err(s_err) if s_err == "forbidden" => {
                return response_text(StatusCode::FORBIDDEN, "forbidden");
            }
            Err(s_err) if s_err == "not_found" => {
                return response_text(StatusCode::NOT_FOUND, "not_found");
            }
            Err(_) => {
                return response_text(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
            }
        };

        let s_xml = build_propfind_xml(s_path, &v_entries);

        Response::builder()
            .status(StatusCode::from_u16(207).unwrap_or(StatusCode::OK))
            .header("Content-Type", "application/xml; charset=utf-8")
            .header("Content-Length", s_xml.len().to_string())
            .body(Full::new(Bytes::from(s_xml)))
            .unwrap_or_else(|_| response_text(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"))
    }

    async fn handle_get(
        &self,
        s_path: &str,
        s_session: Option<String>,
    ) -> Response<HttpBody> {
        match self.read_file(s_path, s_session.as_deref()) {
            Ok(data) => Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", data.s_mime)
                .header("Content-Length", data.v_bytes.len().to_string())
                .body(Full::new(Bytes::from(data.v_bytes)))
                .unwrap_or_else(|_| {
                    response_text(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
                }),
            Err(s_err) if s_err == "forbidden" => {
                response_text(StatusCode::FORBIDDEN, "forbidden")
            }
            Err(s_err) if s_err == "not_found" => {
                response_text(StatusCode::NOT_FOUND, "not_found")
            }
            Err(_) => response_text(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        }
    }

    async fn handle_head(
        &self,
        s_path: &str,
        s_session: Option<String>,
    ) -> Response<HttpBody> {
        match self.read_file(s_path, s_session.as_deref()) {
            Ok(data) => Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", data.s_mime)
                .header("Content-Length", data.v_bytes.len().to_string())
                .body(Full::new(Bytes::new()))
                .unwrap_or_else(|_| {
                    response_text(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
                }),
            Err(s_err) if s_err == "forbidden" => {
                response_text(StatusCode::FORBIDDEN, "forbidden")
            }
            Err(s_err) if s_err == "not_found" => {
                response_text(StatusCode::NOT_FOUND, "not_found")
            }
            Err(_) => response_text(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        }
    }

    fn list_entries(
        &self,
        s_path: &str,
        o_session: Option<&str>,
        b_include_children: bool,
    ) -> Result<Vec<WebDavEntry>, String> {
        if !self.path_exists(s_path, o_session)? {
            return Err("not_found".to_string());
        }

        if !b_include_children {
            return Ok(Vec::new());
        }

        if let Some(v_cached) = self.meta_cache_get(s_path) {
            return Ok(v_cached);
        }

        let v_entries = if s_path == "/" {
            vec![
                dir_entry("local", "/local/"),
                dir_entry("peers", "/peers/"),
                dir_entry("search", "/search/"),
            ]
        } else if s_path == "/local/" {
            vec![dir_entry("docs", "/local/docs/")]
        } else if s_path == "/local/docs/" {
            self.list_local_docs(o_session)?
        } else if s_path == "/peers/" {
            self.list_peer_roots()
        } else if s_path.starts_with("/peers/") {
            self.list_peer_branch(s_path, o_session)?
        } else if s_path == "/search/" {
            vec![dir_entry("hybrid", "/search/hybrid/")]
        } else if s_path == "/search/hybrid/" {
            Vec::new()
        } else if s_path.starts_with("/search/hybrid/") {
            self.list_search_branch(s_path, o_session)?
        } else {
            return Err("not_found".to_string());
        };

        self.meta_cache_put(s_path, &v_entries);
        Ok(v_entries)
    }

    fn read_file(
        &self,
        s_path: &str,
        o_session: Option<&str>,
    ) -> Result<WebDavFileData, String> {
        if let Some(data) = self.file_cache_get(s_path) {
            return Ok(data);
        }

        let data = if s_path.starts_with("/local/docs/") {
            self.read_local_file(s_path, o_session)?
        } else if s_path.starts_with("/peers/") {
            self.read_peer_virtual_file(s_path, o_session)?
        } else if s_path.starts_with("/search/hybrid/") {
            self.read_search_virtual_file(s_path, o_session)?
        } else {
            return Err("not_found".to_string());
        };

        self.file_cache_put(s_path, &data);
        Ok(data)
    }

    fn path_exists(
        &self,
        s_path: &str,
        o_session: Option<&str>,
    ) -> Result<bool, String> {
        if s_path == "/" || s_path == "/local/" || s_path == "/peers/" || s_path == "/search/" {
            return Ok(true);
        }

        if s_path == "/local/docs/" {
            return Ok(true);
        }

        if s_path == "/search/hybrid/" {
            return Ok(true);
        }

        if s_path.starts_with("/peers/") {
            let v_parts = split_clean_path(s_path);
            let g = self.h_peer_docs.lock().unwrap();

            if v_parts.len() == 2 {
                return Ok(g.contains_key(&v_parts[1]));
            }

            if v_parts.len() == 3 && v_parts[2] == "docs" {
                return Ok(g.contains_key(&v_parts[1]));
            }

            if v_parts.len() == 4 && v_parts[2] == "docs" {
                if let Some(v_entries) = g.get(&v_parts[1]) {
                    let b_found = v_entries.iter().any(|x| x.s_name == v_parts[3]);
                    return Ok(b_found);
                }
            }

            return Ok(false);
        }

        if s_path.starts_with("/search/hybrid/") {
            let v_parts = split_clean_path(s_path);

            if v_parts.len() == 3 {
                return Ok(true);
            }

            if v_parts.len() == 4 {
                return Ok(true);
            }

            if v_parts.len() == 5 {
                return Ok(parse_hit_dir_index(&v_parts[4]).is_some());
            }

            if v_parts.len() == 6 {
                let b_file_ok = matches!(
                    v_parts[5].as_str(),
                    "document_path.txt" | "score.txt" | "snippet.txt" | "open_local.txt"
                );
                return Ok(b_file_ok);
            }

            return Ok(false);
        }

        if s_path.starts_with("/local/docs/") {
            let s_rel = s_path.trim_start_matches("/local/docs/");
            let s_name = decode_segment(s_rel);
            let p = PathBuf::from(cfg_get().s_doc_dir.clone()).join(&s_name);

            if let Ok(md) = std::fs::metadata(&p) {
                let s_real = p.to_string_lossy().into_owned();
                if md.is_file() && self.check_read_access(o_session, &s_real)? {
                    return Ok(true);
                }
            }

            return Ok(false);
        }

        Ok(false)
    }

    fn list_local_docs(&self, o_session: Option<&str>) -> Result<Vec<WebDavEntry>, String> {
        let p_root = PathBuf::from(cfg_get().s_doc_dir.clone());
        let mut v_out: Vec<WebDavEntry> = Vec::new();

        let rd = std::fs::read_dir(&p_root).map_err(|_| "not_found".to_string())?;

        for entry_res in rd {
            let entry = match entry_res {
                Ok(x) => x,
                Err(_) => continue,
            };

            let p = entry.path();
            let md = match entry.metadata() {
                Ok(x) => x,
                Err(_) => continue,
            };

            let s_real = p.to_string_lossy().into_owned();
            if !self.check_read_access(o_session, &s_real)? {
                continue;
            }

            let s_name = entry.file_name().to_string_lossy().into_owned();

            if md.is_dir() {
                continue;
            }

            let s_path = format!("/local/docs/{}", encode_segment(&s_name));

            v_out.push(WebDavEntry {
                s_name,
                s_path,
                b_dir: false,
                i_size: md.len(),
                i_mtime_unix: system_time_to_unix(md.modified().ok()),
            });
        }

        Ok(v_out)
    }

    fn list_peer_roots(&self) -> Vec<WebDavEntry> {
        let g = self.h_peer_docs.lock().unwrap();
        let mut v_out: Vec<WebDavEntry> = Vec::new();

        for s_peer_id in g.keys() {
            v_out.push(dir_entry(
                s_peer_id,
                &format!("/peers/{}/", encode_segment(s_peer_id)),
            ));
        }

        v_out
    }

    fn list_peer_branch(
        &self,
        s_path: &str,
        o_session: Option<&str>,
    ) -> Result<Vec<WebDavEntry>, String> {
        let v_parts = split_clean_path(s_path);

        if v_parts.len() == 2 {
            let s_peer_id = &v_parts[1];
            return Ok(vec![dir_entry(
                "docs",
                &format!("/peers/{}/docs/", encode_segment(s_peer_id)),
            )]);
        }

        if v_parts.len() == 3 && v_parts[2] == "docs" {
            let s_peer_id = &v_parts[1];
            let g = self.h_peer_docs.lock().unwrap();
            let v_src = g.get(s_peer_id).ok_or_else(|| "not_found".to_string())?;
            let mut v_out: Vec<WebDavEntry> = Vec::new();

            for e in v_src {
                if !self.check_read_access(o_session, &e.s_name)? {
                    continue;
                }

                v_out.push(WebDavEntry {
                    s_name: e.s_name.clone(),
                    s_path: format!(
                        "/peers/{}/docs/{}",
                        encode_segment(s_peer_id),
                        encode_segment(&e.s_name)
                    ),
                    b_dir: false,
                    i_size: e.i_size,
                    i_mtime_unix: e.i_mtime_unix,
                });
            }

            return Ok(v_out);
        }

        Err("not_found".to_string())
    }

    fn list_search_branch(
        &self,
        s_path: &str,
        o_session: Option<&str>,
    ) -> Result<Vec<WebDavEntry>, String> {
        let v_parts = split_clean_path(s_path);

        if v_parts.len() == 3 {
            return Ok(Vec::new());
        }

        if v_parts.len() == 4 {
            let s_query = &v_parts[3];
            let v_hits = combi_search_with_snippets(
                &self.idx_tan,
                &self.idx_vec,
                s_query,
                I_SEARCH_RESULT_LIMIT,
            );

            let mut v_out: Vec<WebDavEntry> = Vec::new();

            for (i_idx, h) in v_hits.iter().enumerate() {
                if !self.check_read_access(o_session, &h.s_doc)? {
                    continue;
                }

                let s_hit_dir_name = format!("hit_{:03}", i_idx + 1);
                v_out.push(dir_entry(
                    &s_hit_dir_name,
                    &format!(
                        "/search/hybrid/{}/{}/",
                        encode_segment(s_query),
                        encode_segment(&s_hit_dir_name)
                    ),
                ));
            }

            return Ok(v_out);
        }

        if v_parts.len() == 5 {
            let s_query = &v_parts[3];
            let s_hit_dir = &v_parts[4];
            let i_hit_idx = parse_hit_dir_index(s_hit_dir).ok_or_else(|| "not_found".to_string())?;
            let h = self.search_hit_by_index(s_query, i_hit_idx, o_session)?;
            let s_base = format!(
                "/search/hybrid/{}/{}",
                encode_segment(s_query),
                encode_segment(s_hit_dir)
            );

            let v_out = vec![
                file_entry("document_path.txt", &format!("{}/document_path.txt", s_base), 256),
                file_entry("score.txt", &format!("{}/score.txt", s_base), 32),
                file_entry(
                    "snippet.txt",
                    &format!("{}/snippet.txt", s_base),
                    I_SNIPPET_FILE_LIMIT as u64,
                ),
                file_entry(
                    "open_local.txt",
                    &format!("{}/open_local.txt", s_base),
                    h.s_doc.len() as u64 + 2,
                ),
            ];

            return Ok(v_out);
        }

        Err("not_found".to_string())
    }

    fn read_local_file(
        &self,
        s_path: &str,
        o_session: Option<&str>,
    ) -> Result<WebDavFileData, String> {
        let s_rel = s_path.trim_start_matches("/local/docs/");
        let s_name = decode_segment(s_rel);
        let p = PathBuf::from(cfg_get().s_doc_dir.clone()).join(&s_name);
        let s_real = p.to_string_lossy().into_owned();

        if !self.check_read_access(o_session, &s_real)? {
            return Err("forbidden".to_string());
        }

        let md = std::fs::metadata(&p).map_err(|_| "not_found".to_string())?;
        if md.is_dir() {
            return Err("not_found".to_string());
        }

        let v_bytes = std::fs::read(&p).map_err(|_| "not_found".to_string())?;

        Ok(WebDavFileData {
            v_bytes,
            i_mtime_unix: system_time_to_unix(md.modified().ok()),
            s_mime: mime_from_name(&s_name),
        })
    }

    fn read_peer_virtual_file(
        &self,
        s_path: &str,
        o_session: Option<&str>,
    ) -> Result<WebDavFileData, String> {
        let v_parts = split_clean_path(s_path);

        if v_parts.len() != 4 || v_parts[2] != "docs" {
            return Err("not_found".to_string());
        }

        let s_peer_id = &v_parts[1];
        let s_file_name = &v_parts[3];

        let g = self.h_peer_docs.lock().unwrap();
        let v_entries = g.get(s_peer_id).ok_or_else(|| "not_found".to_string())?;

        let e = v_entries
            .iter()
            .find(|x| x.s_name == *s_file_name)
            .ok_or_else(|| "not_found".to_string())?;

        if !self.check_read_access(o_session, &e.s_name)? {
            return Err("forbidden".to_string());
        }

        let s_payload = format!(
            "remote_placeholder peer={} file={}\n",
            s_peer_id, s_file_name
        );

        Ok(WebDavFileData {
            v_bytes: s_payload.into_bytes(),
            i_mtime_unix: e.i_mtime_unix,
            s_mime: "text/plain; charset=utf-8".to_string(),
        })
    }

    fn read_search_virtual_file(
        &self,
        s_path: &str,
        o_session: Option<&str>,
    ) -> Result<WebDavFileData, String> {
        let v_parts = split_clean_path(s_path);

        if v_parts.len() != 6 {
            return Err("not_found".to_string());
        }

        let s_query = &v_parts[3];
        let s_hit_dir = &v_parts[4];
        let s_file = &v_parts[5];

        let i_hit_idx = parse_hit_dir_index(s_hit_dir).ok_or_else(|| "not_found".to_string())?;
        let h = self.search_hit_by_index(s_query, i_hit_idx, o_session)?;

        let (s_content, s_mime) = match s_file.as_str() {
            "document_path.txt" => (
                h.s_doc.clone(),
                "text/plain; charset=utf-8".to_string(),
            ),
            "score.txt" => (
                format!("{:.6}", h.d_score),
                "text/plain; charset=utf-8".to_string(),
            ),
            "snippet.txt" => (
                truncate_ascii_safe(&h.s_snippet, I_SNIPPET_FILE_LIMIT),
                "text/plain; charset=utf-8".to_string(),
            ),
            "open_local.txt" => (
                format!("{}\n", h.s_doc),
                "text/plain; charset=utf-8".to_string(),
            ),
            _ => return Err("not_found".to_string()),
        };

        Ok(WebDavFileData {
            v_bytes: s_content.into_bytes(),
            i_mtime_unix: system_time_to_unix(Some(SystemTime::now())),
            s_mime,
        })
    }

    fn search_hit_by_index(
        &self,
        s_query: &str,
        i_hit_idx: usize,
        o_session: Option<&str>,
    ) -> Result<crate::CombiSearchHit, String> {
        let v_hits = combi_search_with_snippets(
            &self.idx_tan,
            &self.idx_vec,
            s_query,
            I_SEARCH_RESULT_LIMIT,
        );

        let mut v_allowed: Vec<crate::CombiSearchHit> = Vec::new();

        for h in v_hits {
            if self.check_read_access(o_session, &h.s_doc)? {
                v_allowed.push(h);
            }
        }

        v_allowed
            .into_iter()
            .nth(i_hit_idx)
            .ok_or_else(|| "not_found".to_string())
    }

    fn check_read_access(
        &self,
        o_session: Option<&str>,
        s_path: &str,
    ) -> Result<bool, String> {
        let s_session = o_session.unwrap_or("");

        match self.iam.check_access(
            s_session,
            s_path,
            right_read,
            cfg_get().b_iam_remote_scope_public,
        ) {
            Ok(dec) => Ok(dec.b_allowed),
            Err(_) => Ok(false),
        }
    }

    fn meta_cache_get(&self, s_key: &str) -> Option<Vec<WebDavEntry>> {
        let mut g = self.h_meta_cache.lock().unwrap();
        let now = now_ms();

        g.retain(|_, v| now.saturating_sub(v.i_created_ms) <= I_META_CACHE_TTL_MS);

        g.get(s_key).map(|x| x.v_entries.clone())
    }

    fn meta_cache_put(&self, s_key: &str, v_entries: &[WebDavEntry]) {
        let mut g = self.h_meta_cache.lock().unwrap();
        g.insert(
            s_key.to_string(),
            MetaCacheEntry {
                i_created_ms: now_ms(),
                v_entries: v_entries.to_vec(),
            },
        );
    }

    fn file_cache_get(&self, s_key: &str) -> Option<WebDavFileData> {
        let mut g = self.h_file_cache.lock().unwrap();
        let now = now_ms();

        g.retain(|_, v| now.saturating_sub(v.i_created_ms) <= I_FILE_CACHE_TTL_MS);

        g.get(s_key).map(|x| x.data.clone())
    }

    fn file_cache_put(&self, s_key: &str, data: &WebDavFileData) {
        let mut g = self.h_file_cache.lock().unwrap();
        g.insert(
            s_key.to_string(),
            FileCacheEntry {
                i_created_ms: now_ms(),
                data: data.clone(),
            },
        );
    }
}

/* ========================================================================================== */
/* Public server bootstrap                                                                    */
/* ========================================================================================== */

pub async fn run_webdav_server(
    s_bind: &str,
    gateway: Arc<WebDavGateway>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind(s_bind).await?;
    println!("webdav: listening on http://{}", s_bind);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let gateway_cloned = gateway.clone();

        tokio::spawn(async move {
            let service = service_fn(move |req: Request<Incoming>| {
                let gateway_inner = gateway_cloned.clone();

                async move {
                    let s_session = req
                        .headers()
                        .get("x-iam-session")
                        .and_then(|x| x.to_str().ok())
                        .map(|x| x.to_string());

                    let resp = gateway_inner.handle_request(req, s_session).await;
                    Ok::<_, hyper::Error>(resp)
                }
            });

            let _ = http1::Builder::new()
                .serve_connection(io, service)
                .with_upgrades()
                .await;
        });
    }
}

/* ========================================================================================== */
/* Helpers                                                                                    */
/* ========================================================================================== */

fn build_propfind_xml(s_base_path: &str, v_entries: &[WebDavEntry]) -> String {
    /*
     * Defensive:
     * - Gueltige WebDAV Multi-Status XML Antwort
     * - Root Eintrag zuerst
     * - Danach Kind Elemente
     * - Ordner erhalten einen Slash am Ende im href
     */
    let mut s_xml = String::new();

    s_xml.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
    s_xml.push_str("<D:multistatus xmlns:D=\"DAV:\">");

    s_xml.push_str("<D:response>");
    s_xml.push_str(&format!(
        "<D:href>{}</D:href>",
        escape_xml(&href_for_collection(s_base_path, true))
    ));
    s_xml.push_str("<D:propstat><D:prop>");
    s_xml.push_str(&format!(
        "<D:displayname>{}</D:displayname>",
        escape_xml(last_name_of_path(s_base_path))
    ));
    s_xml.push_str("<D:resourcetype><D:collection/></D:resourcetype>");
    s_xml.push_str("</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>");
    s_xml.push_str("</D:response>");

    for e in v_entries {
        s_xml.push_str("<D:response>");
        s_xml.push_str(&format!(
            "<D:href>{}</D:href>",
            escape_xml(&href_for_collection(&e.s_path, e.b_dir))
        ));
        s_xml.push_str("<D:propstat><D:prop>");
        s_xml.push_str(&format!(
            "<D:displayname>{}</D:displayname>",
            escape_xml(&e.s_name)
        ));

        if e.b_dir {
            s_xml.push_str("<D:resourcetype><D:collection/></D:resourcetype>");
            s_xml.push_str("<D:getcontentlength>0</D:getcontentlength>");
        } else {
            s_xml.push_str("<D:resourcetype/>");
            s_xml.push_str(&format!(
                "<D:getcontentlength>{}</D:getcontentlength>",
                e.i_size
            ));
        }

        s_xml.push_str(&format!(
            "<D:getlastmodified>{}</D:getlastmodified>",
            http_date_from_unix(e.i_mtime_unix)
        ));
        s_xml.push_str("</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>");
        s_xml.push_str("</D:response>");
    }

    s_xml.push_str("</D:multistatus>");
    s_xml
}

fn dir_entry(s_name: &str, s_path: &str) -> WebDavEntry {
    let s_norm_path = if s_path.ends_with('/') {
        s_path.to_string()
    } else {
        format!("{}/", s_path)
    };

    WebDavEntry {
        s_name: s_name.to_string(),
        s_path: s_norm_path,
        b_dir: true,
        i_size: 0,
        i_mtime_unix: now_unix(),
    }
}

fn file_entry(s_name: &str, s_path: &str, i_size: u64) -> WebDavEntry {
    let s_norm_path = s_path.trim_end_matches('/').to_string();

    WebDavEntry {
        s_name: s_name.to_string(),
        s_path: s_norm_path,
        b_dir: false,
        i_size,
        i_mtime_unix: now_unix(),
    }
}

fn response_text(status: StatusCode, s_text: &str) -> Response<HttpBody> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain; charset=utf-8")
        .header("Content-Length", s_text.len().to_string())
        .body(Full::new(Bytes::from(s_text.to_string())))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("internal_error"))))
}

fn split_clean_path(s_path: &str) -> Vec<String> {
    s_path
        .split('/')
        .filter(|x| !x.trim().is_empty())
        .map(decode_segment)
        .collect()
}

fn parse_hit_dir_index(s_hit_dir: &str) -> Option<usize> {
    let s_num = s_hit_dir.strip_prefix("hit_")?;
    let i_val = s_num.parse::<usize>().ok()?;
    i_val.checked_sub(1)
}

fn decode_path(s_path: &str) -> String {
    percent_decode_str(s_path).decode_utf8_lossy().into_owned()
}

fn decode_segment(s_in: &str) -> String {
    percent_decode_str(s_in).decode_utf8_lossy().into_owned()
}

fn encode_segment(s_in: &str) -> String {
    utf8_percent_encode(s_in, NON_ALPHANUMERIC).to_string()
}

fn normalize_webdav_path(s_path: &str) -> String {
    let s_trim = s_path.trim();

    if s_trim.is_empty() || s_trim == "/" {
        return "/".to_string();
    }

    let mut s_norm = if s_trim.starts_with('/') {
        s_trim.to_string()
    } else {
        format!("/{}", s_trim)
    };

    if s_norm == "/local" || s_norm == "/peers" || s_norm == "/search" || s_norm == "/search/hybrid" {
        s_norm.push('/');
        return s_norm;
    }

    if s_norm == "/local/docs" {
        s_norm.push('/');
        return s_norm;
    }

    if s_norm.starts_with("/peers/") {
        let v_parts = split_clean_path(&s_norm);
        if v_parts.len() == 2 || (v_parts.len() == 3 && v_parts[2] == "docs") {
            if !s_norm.ends_with('/') {
                s_norm.push('/');
            }
        }
        return s_norm;
    }

    if s_norm.starts_with("/search/hybrid/") {
        let v_parts = split_clean_path(&s_norm);
        if v_parts.len() == 4 || v_parts.len() == 5 {
            if !s_norm.ends_with('/') {
                s_norm.push('/');
            }
        }
        return s_norm;
    }

    s_norm
}

fn href_for_collection(s_path: &str, b_dir: bool) -> String {
    if b_dir {
        if s_path == "/" {
            "/".to_string()
        } else if s_path.ends_with('/') {
            s_path.to_string()
        } else {
            format!("{}/", s_path)
        }
    } else {
        s_path.trim_end_matches('/').to_string()
    }
}

fn now_ms() -> u64 {
    let d = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0));
    d.as_millis() as u64
}

fn now_unix() -> u64 {
    let d = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0));
    d.as_secs()
}

fn system_time_to_unix(o_t: Option<SystemTime>) -> u64 {
    o_t.and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn mime_from_name(s_name: &str) -> String {
    let s_ext = Path::new(s_name)
        .extension()
        .and_then(|x| x.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    match s_ext.as_str() {
        "txt" => "text/plain; charset=utf-8".to_string(),
        "json" => "application/json".to_string(),
        "pdf" => "application/pdf".to_string(),
        "html" | "htm" => "text/html; charset=utf-8".to_string(),
        "csv" => "text/csv; charset=utf-8".to_string(),
        "png" => "image/png".to_string(),
        "jpg" | "jpeg" => "image/jpeg".to_string(),
        "gif" => "image/gif".to_string(),
        "svg" => "image/svg+xml".to_string(),
        _ => "application/octet-stream".to_string(),
    }
}

fn truncate_ascii_safe(s_in: &str, i_limit: usize) -> String {
    s_in.chars().take(i_limit).collect::<String>()
}

fn last_name_of_path(s_path: &str) -> &str {
    if s_path == "/" {
        return "/";
    }

    s_path
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or("/")
}

fn escape_xml(s_in: &str) -> String {
    s_in
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&apos;")
}

fn http_date_from_unix(i_unix: u64) -> String {
    use chrono::{DateTime, Utc};

    let dt: DateTime<Utc> =
        DateTime::<Utc>::from(SystemTime::UNIX_EPOCH + Duration::from_secs(i_unix));

    dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}
