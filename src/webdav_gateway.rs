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
 *  - Hybrid Suche wird als virtuelle Trefferliste unter /search/hybrid/ angeboten.
 *  - Snippets werden als virtuelle Datei snippet.txt je Treffer bereitgestellt.
 *  - Erweiterung:
 *    - Alle Peers inklusive des eigenen Peers werden unter /peers angezeigt.
 *    - Der eigene Peer wird unter /local/docs aus lokalen Dateien dargestellt.
 *    - Peer Dateien werden in den Peer Endpunkten direkt angezeigt.
 *    - Letzte Hybrid Suche wird unter /search/hybrid/ als virtuelle Trefferliste angezeigt.
 *    - Umfangreiche println! Debug Ausgaben fuer Windows WebDAV Analyse.
 *
 *  Historie
 *  13.05.2026  MS  - Initiale Version fuer Phase 1 und Phase 2
 *  13.05.2026  MS  - Erweiterung: Windows WebDAV Basis Support mit HEAD und Depth
 *  13.05.2026  MS  - Erweiterung: saubere XML Ausgabe fuer PROPFIND
 *  14.05.2026  MS  - Erweiterung: alle Peers inkl local im Endpoint /peers
 *  14.05.2026  MS  - Erweiterung: letzte Hybrid Suche unter /search/hybrid/
 *  14.05.2026  MS  - Debug Version mit println! fuer Request Flow und Dateilisten
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

use crate::{
    collect_local_doc_entries,
    combi_search_with_snippets,
    CombiSearchHit,
    TantivyIndex,
};

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

#[derive(Clone, Debug)]
struct LastSearchState {
    s_query: String,
    v_hits: Vec<CombiSearchHit>,
    i_created_ms: u64,
}

#[derive(Clone)]
pub struct WebDavGateway {
    pub iam: Arc<iam_store>,
    pub idx_tan: Arc<TantivyIndex>,
    pub idx_vec: Arc<VectorIndex>,
    pub h_meta_cache: Arc<Mutex<HashMap<String, MetaCacheEntry>>>,
    pub h_file_cache: Arc<Mutex<HashMap<String, FileCacheEntry>>>,
    pub h_peer_docs: Arc<Mutex<HashMap<String, Vec<WebDavEntry>>>>,
    pub s_local_peer_id: Arc<Mutex<String>>,
    pub o_last_search: Arc<Mutex<Option<LastSearchState>>>,
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
     *  14.05.2026  MS  - local peer id und last search state hinzugefuegt
     ******************************************************************************************/
    pub fn new(
        iam: Arc<iam_store>,
        idx_tan: Arc<TantivyIndex>,
        idx_vec: Arc<VectorIndex>,
    ) -> Self {
        println!("webdav dbg: gateway new");

        Self {
            iam,
            idx_tan,
            idx_vec,
            h_meta_cache: Arc::new(Mutex::new(HashMap::new())),
            h_file_cache: Arc::new(Mutex::new(HashMap::new())),
            h_peer_docs: Arc::new(Mutex::new(HashMap::new())),
            s_local_peer_id: Arc::new(Mutex::new(String::new())),
            o_last_search: Arc::new(Mutex::new(None)),
        }
    }

    pub fn set_local_peer_id(&self, s_peer_id: &str) {
        println!("webdav dbg: set_local_peer_id={}", s_peer_id);
        let mut g = self.s_local_peer_id.lock().unwrap();
        *g = s_peer_id.to_string();
    }

    pub fn register_peer_entries(&self, s_peer_id: &str, v_entries: Vec<WebDavEntry>) {
        println!(
            "webdav dbg: register_peer_entries peer={} count={}",
            s_peer_id,
            v_entries.len()
        );

        for e in v_entries.iter() {
            println!(
                "webdav dbg:   peer_entry name={} path={} dir={} size={}",
                e.s_name, e.s_path, e.b_dir, e.i_size
            );
        }

        let mut g = self.h_peer_docs.lock().unwrap();
        g.insert(s_peer_id.to_string(), v_entries);
    }

    pub fn update_last_search(&self, s_query: &str) {
        println!("webdav dbg: update_last_search query={}", s_query);

        let v_hits = combi_search_with_snippets(
            &self.idx_tan,
            &self.idx_vec,
            s_query,
            I_SEARCH_RESULT_LIMIT,
        );

        println!("webdav dbg: update_last_search hits={}", v_hits.len());

        let mut g = self.o_last_search.lock().unwrap();
        *g = Some(LastSearchState {
            s_query: s_query.to_string(),
            v_hits,
            i_created_ms: now_ms(),
        });
    }

    fn get_local_peer_id(&self) -> String {
        let s_peer_id = self.s_local_peer_id.lock().unwrap().clone();
        println!("webdav dbg: get_local_peer_id={}", s_peer_id);
        s_peer_id
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

        println!(
            "webdav dbg: handle_request method={} uri_path={} norm_path={} session_present={}",
            method.as_str(),
            s_uri_path,
            s_path,
            s_session.is_some()
        );

        for (k, v) in headers.iter() {
            let s_val = v.to_str().unwrap_or("header_to_str_failed");
            println!("webdav dbg: header {}={}", k.as_str(), s_val);
        }

        match method {
            Method::OPTIONS => self.handle_options(),
            Method::GET => self.handle_get(&s_path, s_session).await,
            Method::HEAD => self.handle_head(&s_path, s_session).await,
            _ => {
                let s_m = method.as_str().to_string();
                if s_m == "PROPFIND" {
                    self.handle_propfind(&s_path, s_session, &headers).await
                } else {
                    println!("webdav dbg: method_not_allowed method={}", s_m);
                    response_text(StatusCode::METHOD_NOT_ALLOWED, "read_only_webdav")
                }
            }
        }
    }

    fn handle_options(&self) -> Response<HttpBody> {
        println!("webdav dbg: handle_options");

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

        println!(
            "webdav dbg: handle_propfind path={} depth={} include_children={}",
            s_path, s_depth, b_include_children
        );

        let v_entries = match self.list_entries(s_path, s_session.as_deref(), b_include_children) {
            Ok(v) => v,
            Err(s_err) if s_err == "forbidden" => {
                println!("webdav dbg: propfind forbidden path={}", s_path);
                return response_text(StatusCode::FORBIDDEN, "forbidden");
            }
            Err(s_err) if s_err == "not_found" => {
                println!("webdav dbg: propfind not_found path={}", s_path);
                return response_text(StatusCode::NOT_FOUND, "not_found");
            }
            Err(s_err) => {
                println!("webdav dbg: propfind internal_error path={} err={}", s_path, s_err);
                return response_text(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
            }
        };

        println!(
            "webdav dbg: propfind entries_count={} path={}",
            v_entries.len(),
            s_path
        );

        for e in v_entries.iter() {
            println!(
                "webdav dbg:   propfind_entry name={} path={} dir={} size={}",
                e.s_name, e.s_path, e.b_dir, e.i_size
            );
        }

        let s_xml = build_propfind_xml(s_path, &v_entries);
        println!("webdav dbg: propfind xml_len={}", s_xml.len());

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
        println!("webdav dbg: handle_get path={}", s_path);

        match self.read_file(s_path, s_session.as_deref()) {
            Ok(data) => {
                println!(
                    "webdav dbg: get ok path={} mime={} bytes={}",
                    s_path,
                    data.s_mime,
                    data.v_bytes.len()
                );

                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", data.s_mime)
                    .header("Content-Length", data.v_bytes.len().to_string())
                    .body(Full::new(Bytes::from(data.v_bytes)))
                    .unwrap_or_else(|_| {
                        response_text(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
                    })
            }
            Err(s_err) if s_err == "forbidden" => {
                println!("webdav dbg: get forbidden path={}", s_path);
                response_text(StatusCode::FORBIDDEN, "forbidden")
            }
            Err(s_err) if s_err == "not_found" => {
                println!("webdav dbg: get not_found path={}", s_path);
                response_text(StatusCode::NOT_FOUND, "not_found")
            }
            Err(s_err) => {
                println!("webdav dbg: get internal_error path={} err={}", s_path, s_err);
                response_text(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
            }
        }
    }

    async fn handle_head(
        &self,
        s_path: &str,
        s_session: Option<String>,
    ) -> Response<HttpBody> {
        println!("webdav dbg: handle_head path={}", s_path);

        match self.read_file(s_path, s_session.as_deref()) {
            Ok(data) => {
                println!(
                    "webdav dbg: head ok path={} mime={} bytes={}",
                    s_path,
                    data.s_mime,
                    data.v_bytes.len()
                );

                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", data.s_mime)
                    .header("Content-Length", data.v_bytes.len().to_string())
                    .body(Full::new(Bytes::new()))
                    .unwrap_or_else(|_| {
                        response_text(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
                    })
            }
            Err(s_err) if s_err == "forbidden" => {
                println!("webdav dbg: head forbidden path={}", s_path);
                response_text(StatusCode::FORBIDDEN, "forbidden")
            }
            Err(s_err) if s_err == "not_found" => {
                println!("webdav dbg: head not_found path={}", s_path);
                response_text(StatusCode::NOT_FOUND, "not_found")
            }
            Err(s_err) => {
                println!("webdav dbg: head internal_error path={} err={}", s_path, s_err);
                response_text(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
            }
        }
    }

    /**********************************************************************************************
    *  Historie
    *  14.05.2026  MS  - local/<peer_id>/ fuer eigenes Verzeichnis ergaenzt
    **********************************************************************************************/
    fn path_exists(
    &self,
    s_path: &str,
    o_session: Option<&str>,
) -> Result<bool, String> {
    println!("webdav dbg: path_exists path={}", s_path);

    if s_path == "/" || s_path == "/local/" || s_path == "/peers/" || s_path == "/search/" {
        return Ok(true);
    }

    if s_path == "/search/hybrid/" {
        return Ok(true);
    }

    if s_path.starts_with("/local/") {
        let s_rel = s_path.trim_start_matches("/local/");
        if s_rel.trim().is_empty() {
            return Ok(true);
        }

        let s_name = decode_path(s_rel);
        let p = PathBuf::from(cfg_get().s_doc_dir.clone()).join(&s_name);

        println!(
            "webdav dbg: path_exists local rel={} file_path={}",
            s_name,
            p.to_string_lossy()
        );

        if let Ok(md) = std::fs::metadata(&p) {
            return Ok(md.is_file() && self.check_read_access(o_session, &s_name)?);
        }

        return Ok(false);
    }

    if s_path.starts_with("/peers/") {
        let v_parts = split_clean_path(s_path);
        println!("webdav dbg: path_exists peers parts={:?}", v_parts);

        if v_parts.len() == 2 {
            let s_peer_id = &v_parts[1];
            if s_peer_id == &self.get_local_peer_id() {
                return Ok(true);
            }

            let g = self.h_peer_docs.lock().unwrap();
            return Ok(g.contains_key(s_peer_id));
        }

        if v_parts.len() == 3 && v_parts[2] == "docs" {
            let s_peer_id = &v_parts[1];
            if s_peer_id == &self.get_local_peer_id() {
                return Ok(true);
            }

            let g = self.h_peer_docs.lock().unwrap();
            return Ok(g.contains_key(s_peer_id));
        }

        if v_parts.len() >= 4 && v_parts[2] == "docs" {
            let s_peer_id = &v_parts[1];
            let s_rel_file = v_parts[3..].join("/");

            println!(
                "webdav dbg: path_exists peer file peer={} rel_file={}",
                s_peer_id, s_rel_file
            );

            if s_peer_id == &self.get_local_peer_id() {
                let p = PathBuf::from(cfg_get().s_doc_dir.clone()).join(&s_rel_file);
                if let Ok(md) = std::fs::metadata(&p) {
                    return Ok(md.is_file() && self.check_read_access(o_session, &s_rel_file)?);
                }
                return Ok(false);
            }

            let g = self.h_peer_docs.lock().unwrap();
            if let Some(v_entries) = g.get(s_peer_id) {
                let b_found = v_entries.iter().any(|x| x.s_name == s_rel_file);
                return Ok(b_found);
            }

            return Ok(false);
        }

        return Ok(false);
    }

    if s_path.starts_with("/search/hybrid/") {
        let v_parts = split_clean_path(s_path);
        println!("webdav dbg: path_exists search parts={:?}", v_parts);

        if v_parts.len() == 3 {
            return Ok(self.o_last_search.lock().unwrap().is_some());
        }

        if v_parts.len() == 4 {
            return Ok(parse_hit_dir_index(&v_parts[3]).is_some());
        }

        if v_parts.len() == 5 {
            let b_file_ok = matches!(
                v_parts[4].as_str(),
                "document_path.txt" | "score.txt" | "snippet.txt" | "open_local.txt"
            );
            return Ok(b_file_ok);
        }

        return Ok(false);
    }

    Ok(false)
}

    /**********************************************************************************************
     *  Historie
     *  14.05.2026  MS  - Initiale Umstellung auf parent_path gesteuerte Pfadauflosung
     **********************************************************************************************/
    fn direct_parent_path(s_path: &str) -> String {
        /*
         * Defensive:
         * - Erwartet bereits normalisierte WebDAV Pfade
         * - Gibt bei root einen leeren String zurueck
         */
        let v_parts = split_clean_path(s_path);

        if v_parts.len() <= 1 {
            return String::new();
        }

        v_parts[v_parts.len() - 2].clone()
    }

    fn last_path_segment(s_path: &str) -> String {
        /*
         * Defensive:
         * - Liefert das letzte Segment eines Pfades
         * - Bei root wird ein leerer String geliefert
         */
        let v_parts = split_clean_path(s_path);

        if let Some(s_last) = v_parts.last() {
            return s_last.clone();
        }

        String::new()
    }
    // ===============================================
    fn list_entries(
        &self,
        s_path: &str,
        o_session: Option<&str>,
        b_include_children: bool,
    ) -> Result<Vec<WebDavEntry>, String> {
        println!(
            "webdav dbg: list_entries path={} include_children={}",
            s_path, b_include_children
        );

        if !self.path_exists(s_path, o_session)? {
            println!("webdav dbg: list_entries path_not_exists path={}", s_path);
            return Err("not_found".to_string());
        }

        if !b_include_children {
            println!("webdav dbg: list_entries depth_zero path={}", s_path);
            return Ok(Vec::new());
        }

        if let Some(v_cached) = self.meta_cache_get(s_path) {
            println!(
                "webdav dbg: list_entries cache_hit path={} count={}",
                s_path,
                v_cached.len()
            );
            return Ok(v_cached);
        }

        let v_entries = if s_path == "/" {
            vec![
                dir_entry("local", "/local/"),
                dir_entry("peers", "/peers/"),
                dir_entry("search", "/search/"),
            ]
        } else if s_path == "/local/" {
            /*
             * Wichtig:
             * - /local/ bedeutet: alle lokalen Dokumente des lokalen Peers
             * - Quelle ist dieselbe Logik wie fuer den CLI Befehl dir in main.rs
             */
            let v_src = collect_local_doc_entries().map_err(|_| "internal_error".to_string())?;
            let mut v_out: Vec<WebDavEntry> = Vec::with_capacity(v_src.len());

            for e in v_src {
                if !self.check_read_access(o_session, &e.s_name)? { 
                    println!(
                        "webdav dbg: list_entries local access_denied file={}",
                        e.s_name
                    );
                    continue;
                }

                v_out.push(WebDavEntry {
                    s_name: e.s_name.clone(),
                    s_path: format!("/local/{}", encode_segment_path(&e.s_name)),
                    b_dir: false,
                    i_size: e.i_size,
                    i_mtime_unix: e.i_mtime_unix,
                });
            }

            v_out
        } else if s_path == "/peers/" {
            self.list_all_peers()?
        } else if s_path.starts_with("/peers/") {
            self.list_peer_branch(s_path, o_session)?
        } else if s_path == "/search/" {
            vec![dir_entry("hybrid", "/search/hybrid/")]
        } else if s_path == "/search/hybrid/" {
            self.list_last_search_root()
        } else if s_path.starts_with("/search/hybrid/") {
            self.list_search_branch(s_path, o_session)?
        } else {
            println!("webdav dbg: list_entries unknown_path={}", s_path);
            return Err("not_found".to_string());
        };

        println!(
            "webdav dbg: list_entries resolved path={} count={}",
            s_path,
            v_entries.len()
        );

        self.meta_cache_put(s_path, &v_entries);
        Ok(v_entries)
    }
    // ===============================================
    fn read_file(
        &self,
        s_path: &str,
        o_session: Option<&str>,
    ) -> Result<WebDavFileData, String> {
        println!("webdav dbg: read_file path={}", s_path);

        if let Some(data) = self.file_cache_get(s_path) {
            println!(
                "webdav dbg: read_file cache_hit path={} bytes={}",
                s_path,
                data.v_bytes.len()
            );
            return Ok(data);
        }

        let data = if s_path.starts_with("/local/docs/") {
            self.read_local_file(s_path, o_session)?
        } else if s_path.starts_with("/peers/") {
            self.read_peer_virtual_file(s_path, o_session)?
        } else if s_path.starts_with("/search/hybrid/") {
            self.read_search_virtual_file(s_path, o_session)?
        } else {
            println!("webdav dbg: read_file unsupported_path={}", s_path);
            return Err("not_found".to_string());
        };

        println!(
            "webdav dbg: read_file resolved path={} bytes={}",
            s_path,
            data.v_bytes.len()
        );

        self.file_cache_put(s_path, &data);
        Ok(data)
    }

    fn list_local_docs(&self, o_session: Option<&str>) -> Result<Vec<WebDavEntry>, String> {
        let p_root = PathBuf::from(cfg_get().s_doc_dir.clone());
        let mut v_out: Vec<WebDavEntry> = Vec::new();

        println!(
            "webdav dbg: list_local_docs root={}",
            p_root.to_string_lossy()
        );

        self.collect_local_doc_entries_recursive(
            p_root.as_path(),
            p_root.as_path(),
            o_session,
            &mut v_out,
        )?;

        println!("webdav dbg: list_local_docs count={}", v_out.len());

        for e in v_out.iter() {
            println!(
                "webdav dbg:   local_doc name={} path={} size={}",
                e.s_name, e.s_path, e.i_size
            );
        }

        Ok(v_out)
    }

    /**********************************************************************************************
     *  Modulname : secure_p2p_ext
     *  Datei     : webdav_gateway.rs
     *  Autor     : Marcus Schlieper
     *---------------------------------------------------------------------------------------------
     *  Beschreibung
     *  - Listet lokale Dokumente rekursiv.
     *  - Dadurch erscheinen auch Dateien aus Unterordnern im WebDAV.
     *
     *  Historie
     *  14.05.2026  MS  - Rekursive Dateiliste fuer Windows Explorer
     **********************************************************************************************/
    fn collect_local_doc_entries_recursive(
        &self,
        p_root: &Path,
        p_current: &Path,
        o_session: Option<&str>,
        v_out: &mut Vec<WebDavEntry>,
    ) -> Result<(), String> {
        println!(
            "webdav dbg: scan_dir current={}",
            p_current.to_string_lossy()
        );

        let rd = std::fs::read_dir(p_current).map_err(|_| "not_found".to_string())?;

        for entry_res in rd {
            let entry = match entry_res {
                Ok(x) => x,
                Err(_) => {
                    println!("webdav dbg: scan_dir entry read failed");
                    continue;
                }
            };

            let p = entry.path();
            let md = match entry.metadata() {
                Ok(x) => x,
                Err(_) => {
                    println!(
                        "webdav dbg: metadata failed path={}",
                        p.to_string_lossy()
                    );
                    continue;
                }
            };

            if md.is_dir() {
                println!("webdav dbg: scan_dir recurse={}", p.to_string_lossy());
                self.collect_local_doc_entries_recursive(p_root, &p, o_session, v_out)?;
                continue;
            }

            if !md.is_file() {
                println!("webdav dbg: scan_dir skip_non_file={}", p.to_string_lossy());
                continue;
            }

            let s_real = p.to_string_lossy().into_owned();
            if !self.check_read_access(o_session, &s_real)? {
                println!("webdav dbg: scan_dir access_denied={}", s_real);
                continue;
            }

            let p_rel = match p.strip_prefix(p_root) {
                Ok(x) => x,
                Err(_) => {
                    println!(
                        "webdav dbg: strip_prefix failed root={} path={}",
                        p_root.to_string_lossy(),
                        p.to_string_lossy()
                    );
                    continue;
                }
            };

            let s_name = p_rel.to_string_lossy().replace("\\", "/");
            let s_path = format!("/local/docs/{}", encode_segment_path(&s_name));

            println!(
                "webdav dbg: scan_dir add_file name={} webdav_path={} size={}",
                s_name,
                s_path,
                md.len()
            );

            v_out.push(WebDavEntry {
                s_name,
                s_path,
                b_dir: false,
                i_size: md.len(),
                i_mtime_unix: system_time_to_unix(md.modified().ok()),
            });
        }

        Ok(())
    }

    fn list_all_peers(&self) -> Result<Vec<WebDavEntry>, String> {
        let mut v_out: Vec<WebDavEntry> = Vec::new();

        let s_local_peer_id = self.get_local_peer_id();
        if !s_local_peer_id.trim().is_empty() {
            v_out.push(dir_entry(
                &s_local_peer_id,
                &format!("/peers/{}/", encode_segment(&s_local_peer_id)),
            ));
        }

        let g = self.h_peer_docs.lock().unwrap();
        for s_peer_id in g.keys() {
            if *s_peer_id == s_local_peer_id {
                continue;
            }

            v_out.push(dir_entry(
                s_peer_id,
                &format!("/peers/{}/", encode_segment(s_peer_id)),
            ));
        }

        println!("webdav dbg: list_all_peers count={}", v_out.len());
        for e in v_out.iter() {
            println!("webdav dbg:   peer_root name={} path={}", e.s_name, e.s_path);
        }

        Ok(v_out)
    }

    fn list_peer_branch(
        &self,
        s_path: &str,
        o_session: Option<&str>,
    ) -> Result<Vec<WebDavEntry>, String> {
        let v_parts = split_clean_path(s_path);

        println!("webdav dbg: list_peer_branch path={} parts={:?}", s_path, v_parts);

        if v_parts.len() == 2 {
            let s_peer_id = &v_parts[1];
            return Ok(vec![dir_entry(
                "docs",
                &format!("/peers/{}/docs/", encode_segment(s_peer_id)),
            )]);
        }

        if v_parts.len() == 3 && v_parts[2] == "docs" {
            let s_peer_id = &v_parts[1];

            if *s_peer_id == self.get_local_peer_id() {
                let v_local = self.list_local_docs(o_session)?;
                let mut v_out: Vec<WebDavEntry> = Vec::with_capacity(v_local.len());

                for e in v_local {
                    v_out.push(WebDavEntry {
                        s_name: e.s_name.clone(),
                        s_path: format!(
                            "/peers/{}/docs/{}",
                            encode_segment(s_peer_id),
                            encode_segment_path(&e.s_name)
                        ),
                        b_dir: false,
                        i_size: e.i_size,
                        i_mtime_unix: e.i_mtime_unix,
                    });
                }

                println!(
                    "webdav dbg: list_peer_branch local_peer_docs peer={} count={}",
                    s_peer_id,
                    v_out.len()
                );

                return Ok(v_out);
            }

            let g = self.h_peer_docs.lock().unwrap();
            let v_src = g.get(s_peer_id).ok_or_else(|| "not_found".to_string())?;
            let mut v_out: Vec<WebDavEntry> = Vec::new();

            for e in v_src {
                if !self.check_read_access(o_session, &e.s_name)? {
                    println!(
                        "webdav dbg: list_peer_branch access_denied peer={} file={}",
                        s_peer_id, e.s_name
                    );
                    continue;
                }

                v_out.push(WebDavEntry {
                    s_name: e.s_name.clone(),
                    s_path: format!(
                        "/peers/{}/docs/{}",
                        encode_segment(s_peer_id),
                        encode_segment_path(&e.s_name)
                    ),
                    b_dir: false,
                    i_size: e.i_size,
                    i_mtime_unix: e.i_mtime_unix,
                });
            }

            println!(
                "webdav dbg: list_peer_branch remote_peer_docs peer={} count={}",
                s_peer_id,
                v_out.len()
            );

            return Ok(v_out);
        }

        Err("not_found".to_string())
    }

    fn list_last_search_root(&self) -> Vec<WebDavEntry> {
        let g = self.o_last_search.lock().unwrap();

        match g.as_ref() {
            Some(st) => {
                println!(
                    "webdav dbg: list_last_search_root query={} hits={} age_ms={}",
                    st.s_query,
                    st.v_hits.len(),
                    now_ms().saturating_sub(st.i_created_ms)
                );

                vec![dir_entry(
                    &st.s_query,
                    &format!("/search/hybrid/{}/", encode_segment(&st.s_query)),
                )]
            }
            None => {
                println!("webdav dbg: list_last_search_root empty");
                Vec::new()
            }
        }
    }

    fn list_search_branch(
        &self,
        s_path: &str,
        o_session: Option<&str>,
    ) -> Result<Vec<WebDavEntry>, String> {
        let v_parts = split_clean_path(s_path);

        println!("webdav dbg: list_search_branch path={} parts={:?}", s_path, v_parts);

        if v_parts.len() == 3 {
            return Ok(self.list_last_search_root());
        }

        if v_parts.len() == 4 {
            let s_query = &v_parts[3];
            let v_hits = self.get_last_search_hits_for_query(s_query)?;

            let mut v_out: Vec<WebDavEntry> = Vec::new();

            for (i_idx, h) in v_hits.iter().enumerate() {
                if !self.check_read_access(o_session, &h.s_doc)? {
                    println!(
                        "webdav dbg: search_branch access_denied hit_doc={}",
                        h.s_doc
                    );
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

            println!(
                "webdav dbg: list_search_branch query={} count={}",
                s_query,
                v_out.len()
            );

            return Ok(v_out);
        }

        if v_parts.len() == 5 {
            let s_query = &v_parts[3];
            let s_hit_dir = &v_parts[4];
            let i_hit_idx =
                parse_hit_dir_index(s_hit_dir).ok_or_else(|| "not_found".to_string())?;
            let h = self.search_hit_by_index(s_query, i_hit_idx, o_session)?;
            let s_base = format!(
                "/search/hybrid/{}/{}",
                encode_segment(s_query),
                encode_segment(s_hit_dir)
            );

            let v_out = vec![
                file_entry(
                    "document_path.txt",
                    &format!("{}/document_path.txt", s_base),
                    h.s_doc.len() as u64,
                ),
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

            println!(
                "webdav dbg: list_search_branch hit_files query={} hit_dir={} count={}",
                s_query,
                s_hit_dir,
                v_out.len()
            );

            return Ok(v_out);
        }

        Err("not_found".to_string())
    }

    fn read_local_file(
    &self,
    s_path: &str,
    o_session: Option<&str>,
) -> Result<WebDavFileData, String> {
    let s_rel = s_path.trim_start_matches("/local/");
    let s_name = decode_path(s_rel);
    let p = PathBuf::from(cfg_get().s_doc_dir.clone()).join(&s_name);
    let s_real = p.to_string_lossy().into_owned();

    println!(
        "webdav dbg: read_local_file webdav_path={} rel={} real={}",
        s_path, s_name, s_real
    );

    if !self.check_read_access(o_session, &s_name)? {
        println!("webdav dbg: read_local_file forbidden real={}", s_real);
        return Err("forbidden".to_string());
    }

    let md = std::fs::metadata(&p).map_err(|_| "not_found".to_string())?;
    if md.is_dir() {
        println!("webdav dbg: read_local_file is_dir real={}", s_real);
        return Err("not_found".to_string());
    }

    let v_bytes = std::fs::read(&p).map_err(|_| "not_found".to_string())?;

    println!(
        "webdav dbg: read_local_file ok real={} bytes={}",
        s_real,
        v_bytes.len()
    );

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

        println!(
            "webdav dbg: read_peer_virtual_file path={} parts={:?}",
            s_path, v_parts
        );

        if v_parts.len() < 4 || v_parts[2] != "docs" {
            return Err("not_found".to_string());
        }

        let s_peer_id = &v_parts[1];
        let s_file_name = v_parts[3..].join("/");

        println!(
            "webdav dbg: read_peer_virtual_file peer={} file={}",
            s_peer_id, s_file_name
        );

        if *s_peer_id == self.get_local_peer_id() {
            let p = PathBuf::from(cfg_get().s_doc_dir.clone()).join(&s_file_name);
            let s_real = p.to_string_lossy().into_owned();

            if !self.check_read_access(o_session, &s_real)? {
                println!("webdav dbg: read_peer_virtual_file local forbidden real={}", s_real);
                return Err("forbidden".to_string());
            }

            let md = std::fs::metadata(&p).map_err(|_| "not_found".to_string())?;
            if !md.is_file() {
                println!("webdav dbg: read_peer_virtual_file local not_file real={}", s_real);
                return Err("not_found".to_string());
            }

            let v_bytes = std::fs::read(&p).map_err(|_| "not_found".to_string())?;

            println!(
                "webdav dbg: read_peer_virtual_file local ok real={} bytes={}",
                s_real,
                v_bytes.len()
            );

            return Ok(WebDavFileData {
                v_bytes,
                i_mtime_unix: system_time_to_unix(md.modified().ok()),
                s_mime: mime_from_name(&s_file_name),
            });
        }

        let g = self.h_peer_docs.lock().unwrap();
        let v_entries = g.get(s_peer_id).ok_or_else(|| "not_found".to_string())?;

        let e = v_entries
            .iter()
            .find(|x| x.s_name == s_file_name)
            .ok_or_else(|| "not_found".to_string())?;

        if !self.check_read_access(o_session, &e.s_name)? {
            println!(
                "webdav dbg: read_peer_virtual_file remote forbidden peer={} file={}",
                s_peer_id, e.s_name
            );
            return Err("forbidden".to_string());
        }

        let s_payload = format!(
            "remote_placeholder peer={} file={}\n",
            s_peer_id, s_file_name
        );

        println!(
            "webdav dbg: read_peer_virtual_file remote placeholder peer={} file={}",
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

        println!(
            "webdav dbg: read_search_virtual_file path={} parts={:?}",
            s_path, v_parts
        );

        if v_parts.len() != 5 {
            return Err("not_found".to_string());
        }

        let s_query = &v_parts[2];
        let s_hit_dir = &v_parts[3];
        let s_file = &v_parts[4];

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

        println!(
            "webdav dbg: read_search_virtual_file ok query={} hit_dir={} file={} bytes={}",
            s_query,
            s_hit_dir,
            s_file,
            s_content.len()
        );

        Ok(WebDavFileData {
            v_bytes: s_content.into_bytes(),
            i_mtime_unix: system_time_to_unix(Some(SystemTime::now())),
            s_mime,
        })
    }

    fn get_last_search_hits_for_query(&self, s_query: &str) -> Result<Vec<CombiSearchHit>, String> {
        let g = self.o_last_search.lock().unwrap();

        let Some(st) = g.as_ref() else {
            println!("webdav dbg: get_last_search_hits_for_query empty");
            return Err("not_found".to_string());
        };

        if st.s_query != *s_query {
            println!(
                "webdav dbg: get_last_search_hits_for_query mismatch wanted={} actual={}",
                s_query, st.s_query
            );
            return Err("not_found".to_string());
        }

        println!(
            "webdav dbg: get_last_search_hits_for_query query={} hits={}",
            s_query,
            st.v_hits.len()
        );

        Ok(st.v_hits.clone())
    }

    fn search_hit_by_index(
        &self,
        s_query: &str,
        i_hit_idx: usize,
        o_session: Option<&str>,
    ) -> Result<CombiSearchHit, String> {
        let v_hits = self.get_last_search_hits_for_query(s_query)?;
        let mut v_allowed: Vec<CombiSearchHit> = Vec::new();

        for h in v_hits {
            if self.check_read_access(o_session, &h.s_doc)? {
                v_allowed.push(h);
            } else {
                println!("webdav dbg: search_hit_by_index access_denied doc={}", h.s_doc);
            }
        }

        println!(
            "webdav dbg: search_hit_by_index query={} idx={} allowed_hits={}",
            s_query,
            i_hit_idx,
            v_allowed.len()
        );

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
        Ok(true)
       /* 
        let s_session = o_session.unwrap_or("");

        println!(
            "webdav dbg: check_read_access session_present={} path={}",
            !s_session.is_empty(),
            s_path
        );

        match self.iam.check_access(
            s_session,
            s_path,
            right_read,
            cfg_get().b_iam_remote_scope_public,
        ) {
            Ok(dec) => {
                println!(
                    "webdav dbg: check_read_access allowed={} reason={} path={}",
                    dec.b_allowed,
                    dec.s_reason,
                    s_path
                );
                Ok(dec.b_allowed)
            }
            Err(_) => {
                println!("webdav dbg: check_read_access error path={}", s_path);
                Ok(false)
            }
        }*/
    }

    fn meta_cache_get(&self, s_key: &str) -> Option<Vec<WebDavEntry>> {
        let mut g = self.h_meta_cache.lock().unwrap();
        let now = now_ms();

        g.retain(|_, v| now.saturating_sub(v.i_created_ms) <= I_META_CACHE_TTL_MS);

        let o = g.get(s_key).map(|x| x.v_entries.clone());

        println!(
            "webdav dbg: meta_cache_get key={} hit={}",
            s_key,
            o.is_some()
        );

        o
    }

    fn meta_cache_put(&self, s_key: &str, v_entries: &[WebDavEntry]) {
        println!(
            "webdav dbg: meta_cache_put key={} count={}",
            s_key,
            v_entries.len()
        );

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

        let o = g.get(s_key).map(|x| x.data.clone());

        println!(
            "webdav dbg: file_cache_get key={} hit={}",
            s_key,
            o.is_some()
        );

        o
    }

    fn file_cache_put(&self, s_key: &str, data: &WebDavFileData) {
        println!(
            "webdav dbg: file_cache_put key={} bytes={}",
            s_key,
            data.v_bytes.len()
        );

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
        let (stream, addr) = listener.accept().await?;
        println!("webdav dbg: accepted connection from={}", addr);

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
    let mut s_xml = String::new();

    s_xml.push_str(r#"<?xml version="1.0" encoding="utf-8"?>"#);
    s_xml.push_str(r#"<D:multistatus xmlns:D="DAV:">"#);

    s_xml.push_str(r#"<D:response>"#);
    s_xml.push_str(&format!(
        r#"<D:href>{}</D:href>"#,
        escape_xml(&href_for_collection(s_base_path, true))
    ));
    s_xml.push_str(r#"<D:propstat><D:prop>"#);
    s_xml.push_str(&format!(
        r#"<D:displayname>{}</D:displayname>"#,
        escape_xml(last_name_of_path(s_base_path))
    ));
    s_xml.push_str(r#"<D:resourcetype><D:collection/></D:resourcetype>"#);
    s_xml.push_str(r#"<D:getcontentlength>0</D:getcontentlength>"#);
    s_xml.push_str(&format!(
        r#"<D:getlastmodified>{}</D:getlastmodified>"#,
        http_date_from_unix(now_unix())
    ));
    s_xml.push_str(r#"</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>"#);
    s_xml.push_str(r#"</D:response>"#);

    for e in v_entries {
        s_xml.push_str(r#"<D:response>"#);
        s_xml.push_str(&format!(
            r#"<D:href>{}</D:href>"#,
            escape_xml(&href_for_collection(&e.s_path, e.b_dir))
        ));
        s_xml.push_str(r#"<D:propstat><D:prop>"#);
        s_xml.push_str(&format!(
            r#"<D:displayname>{}</D:displayname>"#,
            escape_xml(&e.s_name)
        ));

        if e.b_dir {
            s_xml.push_str(r#"<D:resourcetype><D:collection/></D:resourcetype>"#);
            s_xml.push_str(r#"<D:getcontentlength>0</D:getcontentlength>"#);
        } else {
            s_xml.push_str(r#"<D:resourcetype></D:resourcetype>"#);
            s_xml.push_str(&format!(
                r#"<D:getcontentlength>{}</D:getcontentlength>"#,
                e.i_size
            ));
        }

        s_xml.push_str(&format!(
            r#"<D:getlastmodified>{}</D:getlastmodified>"#,
            http_date_from_unix(e.i_mtime_unix)
        ));
        s_xml.push_str(r#"</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>"#);
        s_xml.push_str(r#"</D:response>"#);
    }

    s_xml.push_str(r#"</D:multistatus>"#);

    println!(
        "webdav dbg: build_propfind_xml base={} entries={} xml_len={}",
        s_base_path,
        v_entries.len(),
        s_xml.len()
    );

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

fn encode_segment_path(s_in: &str) -> String {
    s_in
        .split('/')
        .map(encode_segment)
        .collect::<Vec<String>>()
        .join("/")
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

    if s_norm == "/local" || s_norm == "/peers" || s_norm == "/search" || s_norm == "/search/hybrid"
    {
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
        if v_parts.len() == 3 || v_parts.len() == 4 {
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
