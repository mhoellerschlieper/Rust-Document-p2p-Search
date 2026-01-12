/**********************************************************************************************
 *  Module name : web_server
 *  File        : web_server.rs
 *  Author      : Marcus Schlieper
 *---------------------------------------------------------------------------------------------
 *  Description
 *  - Axum based web server for secure_p2p_ext web UI.
 *  - Provides a small REST API used by app.js and serves the static UI assets.
 *  - Uses a command bridge (tokio mpsc) to forward requests into the main event loop.
 *  - Adds IAM groups listing endpoint GET /api/iam/groups (JSON array).
 *
 *  History
 *  2026-01-11  Marcus Schlieper  - Initial web server module: API endpoints + static files
 *  2026-01-11  Marcus Schlieper  - Add: /api/iam/groups and unified router state type
 **********************************************************************************************/

#![allow(dead_code)]
#![allow(warnings)]

use axum::{
    extract::{Path as AxumPath, State},
    http::{header, HeaderMap, StatusCode,HeaderValue},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};

use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, oneshot};
use tokio::net::TcpListener;

/* ============================================================================================
 * Constants
 * ============================================================================================
 */

pub const I_EVENT_RING_MAX: usize = 200;

/* ============================================================================================
 * DTOs (web views)
 * ============================================================================================
 */

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct web_ok_resp {
    pub b_ok: bool,
    pub s_error: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct web_login_resp {
    pub b_ok: bool,
    pub s_session: String,
    pub s_error: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct web_status_view {
    pub s_node_peer_id: String,
    pub i_known_peers: usize,
    pub s_chat_peer: String,
    pub s_chat_topic: String,
    pub i_event_ring_len: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct web_peer_view {
    pub s_peer_id: String,
    pub b_online: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct web_search_dispatch_resp {
    pub b_ok: bool,
    pub s_error: String,
    pub i_search_id: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct web_search_hit {
    pub s_peer_id: String,
    pub s_doc: String,
    pub d_score: f32,
    pub s_snippet: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct web_search_resp {
    pub b_ok: bool,
    pub s_error: String,
    pub i_search_id: u64,
    pub v_hits: Vec<web_search_hit>,
    pub b_partial: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct web_iam_group_view {
    pub s_group: String,
    pub s_rights: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct web_doc_text_resp {
    pub b_ok: bool,
    pub s_error: String,
    pub s_peer_id: String,
    pub s_path: String,
    pub s_text: String,
}

/* --- NEW request DTO --------------------------------------------------------------------- */
#[derive(Serialize, Deserialize, Debug)]
pub struct req_doc_text_get {
    pub s_peer_id: String,
    pub s_path: String,
}


/* ============================================================================================
 * Shared state (owned by main, mirrored for web UI)
 * ============================================================================================
 */

#[derive(Clone, Debug)]
pub struct web_search_state {
    pub i_search_id: u64,
    pub s_query: String,
    pub i_limit: usize,
    pub i_created_ms: u64,
    pub b_partial: bool,
    pub v_hits: Vec<web_search_hit>,
}

#[derive(Clone, Debug)]
pub struct web_doc_state {
    pub i_req_id: u64,
    pub s_peer_id: String,
    pub s_path: String,
    pub i_created_ms: u64,
    pub b_done: bool,
    pub s_text: String,
    pub s_error: String,
}

#[derive(Clone, Debug)]
pub struct web_shared_state {
    pub s_node_peer_id: String,
    pub v_peers: Vec<web_peer_view>,
    pub s_chat_peer: Option<String>,
    pub s_chat_topic: Option<String>,
    pub v_event_ring: VecDeque<String>,
    pub h_search_cache: HashMap<u64, web_search_state>,
    pub h_doc_cache: HashMap<u64, web_doc_state>,
}

impl web_shared_state {
    pub fn new(s_node_peer_id: String) -> Self {
        Self {
            s_node_peer_id,
            v_peers: Vec::new(),
            s_chat_peer: None,
            s_chat_topic: None,
            v_event_ring: VecDeque::new(),
            h_search_cache: HashMap::new(),
            h_doc_cache: HashMap::new(),
        }
    }

    pub fn push_event(&mut self, s_event: String) {
        self.v_event_ring.push_back(s_event);
        while self.v_event_ring.len() > I_EVENT_RING_MAX {
            self.v_event_ring.pop_front();
        }
    }

    pub fn search_cache_hits_len(&self, i_search_id: u64) -> Option<usize> {
        self.h_search_cache.get(&i_search_id).map(|st| st.v_hits.len())
    }

    pub fn search_cache_insert_new(&mut self, i_search_id: u64, s_query: String, i_limit: usize, i_now_ms: u64) {
        let st = web_search_state {
            i_search_id,
            s_query,
            i_limit,
            i_created_ms: i_now_ms,
            b_partial: true,
            v_hits: Vec::new(),
        };
        self.h_search_cache.insert(i_search_id, st);
    }

    pub fn search_cache_add_hits(&mut self, i_search_id: u64, mut v_hits: Vec<web_search_hit>) {
        if let Some(st) = self.h_search_cache.get_mut(&i_search_id) {
            st.v_hits.append(&mut v_hits);
            st.v_hits.sort_by(|a, b| b.d_score.partial_cmp(&a.d_score).unwrap_or(std::cmp::Ordering::Equal));
            if st.v_hits.len() > st.i_limit {
                st.v_hits.truncate(st.i_limit);
            }
            st.b_partial = true;
        }
    }

    pub fn search_cache_get(&mut self, i_search_id: u64) -> Option<web_search_state> {
        self.h_search_cache.get(&i_search_id).cloned()
    }

    /* Doc cache helpers */
    pub fn doc_cache_insert_pending(&mut self, i_req_id: u64, s_peer_id: String, s_path: String, i_now_ms: u64) {
        self.h_doc_cache.insert(i_req_id, web_doc_state {
            i_req_id,
            s_peer_id,
            s_path,
            i_created_ms: i_now_ms,
            b_done: false,
            s_text: "".to_string(),
            s_error: "pending".to_string(),
        });
    }

    pub fn doc_cache_set_result(&mut self, i_req_id: u64, s_peer_id: String, s_path: String, s_text: String, s_error: String) {
        if let Some(st) = self.h_doc_cache.get_mut(&i_req_id) {
            st.b_done = true;
            st.s_peer_id = s_peer_id;
            st.s_path = s_path;
            st.s_text = s_text;
            st.s_error = s_error;
        } else {
            self.h_doc_cache.insert(i_req_id, web_doc_state {
                i_req_id,
                s_peer_id,
                s_path,
                i_created_ms: now_ms(),
                b_done: true,
                s_text,
                s_error,
            });
        }
    }

    pub fn doc_cache_get(&self, i_req_id: u64) -> Option<web_doc_state> {
        self.h_doc_cache.get(&i_req_id).cloned()
    }
}

/* ============================================================================================
 * Command bridge (web -> main)
 * ============================================================================================
 */

#[derive(Debug)]
pub enum web_command {
    status_get {
        tx: tokio::sync::oneshot::Sender<web_status_view>,
    },
    peers_get {
        tx: tokio::sync::oneshot::Sender<Vec<web_peer_view>>,
    },
    events_get {
        tx: tokio::sync::oneshot::Sender<Vec<String>>,
    },

    p2p_connect_by_peer_id {
        s_peer_id: String,
        tx: tokio::sync::oneshot::Sender<web_ok_resp>,
    },
    p2p_send_text {
        s_text: String,
        tx: tokio::sync::oneshot::Sender<web_ok_resp>,
    },

    search_network_combi_dispatch {
        s_query: String,
        i_limit: usize,
        tx: tokio::sync::oneshot::Sender<web_search_dispatch_resp>,
    },
    search_network_combi_get {
        i_search_id: u64,
        tx: tokio::sync::oneshot::Sender<web_search_resp>,
    },

    doc_text_get {
        s_peer_id: String,
        s_path: String,
        tx: tokio::sync::oneshot::Sender<web_doc_text_resp>,
    },

    iam_login_local {
        s_user: String,
        s_password: String,
        tx: tokio::sync::oneshot::Sender<web_login_resp>,
    },
    iam_group_add {
        s_actor: String,
        s_group: String,
        s_rights: String,
        tx: tokio::sync::oneshot::Sender<web_ok_resp>,
    },
    iam_user_add {
        s_actor: String,
        s_user: String,
        s_password: String,
        s_group: String,
        tx: tokio::sync::oneshot::Sender<web_ok_resp>,
    },
    iam_path_add {
        s_actor: String,
        s_path: String,
        s_group_or_dash: String,
        b_public: bool,
        s_rights: String,
        tx: tokio::sync::oneshot::Sender<web_ok_resp>,
    },

    iam_groups_get {
        tx: tokio::sync::oneshot::Sender<Vec<web_iam_group_view>>,
    },
}
/* ============================================================================================
 * Router state (axum state must be consistent)
 * ============================================================================================
 */


#[derive(Clone)]
pub struct web_server_ctx {
    pub tx_web_cmd: mpsc::Sender<web_command>,
    pub st_web: Arc<Mutex<web_shared_state>>,
}


/* ============================================================================================
 * Request DTOs
 * ============================================================================================
 */

#[derive(Serialize, Deserialize, Debug)]
pub struct req_p2p_connect {
    pub s_peer_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct req_p2p_send_text {
    pub s_text: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct req_search_dispatch {
    pub s_query: String,
    pub i_limit: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct req_iam_login {
    pub s_user: String,
    pub s_password: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct req_iam_group_add {
    pub s_group: String,
    pub s_rights: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct req_iam_user_add {
    pub s_user: String,
    pub s_password: String,
    pub s_group: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct req_iam_path_add {
    pub s_path: String,
    pub s_group_or_dash: String,
    pub b_public: bool,
    pub s_rights: String,
}

/* ============================================================================================
 * Utilities
 * ============================================================================================
 */

fn now_ms() -> u64 {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0));
    d.as_millis() as u64
}

fn safe_trim(s_in: &str, i_max_len: usize) -> String {
    let s_t = s_in.trim();
    if s_t.len() > i_max_len {
        return s_t[..i_max_len].to_string();
    }
    s_t.to_string()
}

fn is_reasonable_ascii(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    if s.len() > 4096 {
        return false;
    }
    s.chars().all(|c| c.is_ascii() && (c.is_ascii_graphic() || c == ' '))
}

fn parse_limit_clamped(i_limit: i64, i_min: i64, i_max: i64, i_fallback: i64) -> i64 {
    if i_limit < i_min {
        return i_min;
    }
    if i_limit > i_max {
        return i_max;
    }
    if i_limit == 0 {
        return i_fallback;
    }
    i_limit
}

fn json_err(s_error: &str, i_status: StatusCode) -> Response {
    let resp = web_ok_resp {
        b_ok: false,
        s_error: safe_trim(s_error, 128),
    };
    (i_status, Json(resp)).into_response()
}

async fn cmd_roundtrip<T: Send + 'static>(
    tx_web_cmd: &mpsc::Sender<web_command>,
    mk_cmd: impl FnOnce(oneshot::Sender<T>) -> web_command,
) -> Result<T, String> {
    let (tx, rx) = oneshot::channel::<T>();
    tx_web_cmd
        .send(mk_cmd(tx))
        .await
        .map_err(|_| "web_cmd_send_failed".to_string())?;
    rx.await.map_err(|_| "web_cmd_recv_failed".to_string())
}

/* ============================================================================================
 * Static files (embedded placeholders)
 *
 * NOTE:
 * - In a production setup, these should be served from disk or embedded via include_str!.
 * - This module provides minimal placeholders to keep the server self contained.
 * ============================================================================================
 */
/* ==========================================================================================
 * Cache control helper
 * ========================================================================================== */

fn no_cache_headers() -> HeaderMap {
    // Defensive caching strategy for dev consoles:
    // - no-store: do not store in any cache
    // - no-cache: must revalidate
    // - max-age=0: immediately stale
    // - pragma/expires: legacy compatibility
    let mut h = HeaderMap::new();
    h.insert(
        "Cache-Control",
        HeaderValue::from_static("no-store, no-cache, max-age=0, must-revalidate"),
    );
    h.insert("Pragma", HeaderValue::from_static("no-cache"));
    h.insert("Expires", HeaderValue::from_static("0"));
    h
}

/* ==========================================================================================
 * Static endpoints (requested to be re-integrated)
 * ========================================================================================== */

async fn api_static_index() -> impl IntoResponse {
    // text/html is set by Html wrapper
    (no_cache_headers(), Html(include_str!("./web/index.html"))).into_response()
}

async fn api_static_app_js() -> impl IntoResponse {
    let mut h = no_cache_headers();
    h.insert(
        "Content-Type",
        HeaderValue::from_static("application/javascript; charset=utf-8"),
    );

    (h, (StatusCode::OK, include_str!("./web/app.js"))).into_response()
}

async fn api_static_app_css() -> impl IntoResponse {
    let mut h = no_cache_headers();
    h.insert("Content-Type", HeaderValue::from_static("text/css; charset=utf-8"));

    (h, (StatusCode::OK, include_str!("./web/app.css"))).into_response()
}

/* ============================================================================================
 * Route handlers: API
 * ============================================================================================
 */

async fn route_api_status(State(ctx): State<web_server_ctx>) -> Response {
    match cmd_roundtrip(&ctx.tx_web_cmd, |tx| web_command::status_get { tx }).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(_) => json_err("status_failed", StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn route_api_peers(State(ctx): State<web_server_ctx>) -> Response {
    match cmd_roundtrip(&ctx.tx_web_cmd, |tx| web_command::peers_get { tx }).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(_) => json_err("peers_failed", StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn route_api_events(State(ctx): State<web_server_ctx>) -> Response {
    match cmd_roundtrip(&ctx.tx_web_cmd, |tx| web_command::events_get { tx }).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(_) => json_err("events_failed", StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn route_api_p2p_connect(State(ctx): State<web_server_ctx>, Json(req): Json<req_p2p_connect>) -> Response {
    let s_peer_id = safe_trim(&req.s_peer_id, 256);
    if s_peer_id.len() < 4 || !is_reasonable_ascii(&s_peer_id) {
        return json_err("invalid_peer_id", StatusCode::BAD_REQUEST);
    }

    match cmd_roundtrip(&ctx.tx_web_cmd, |tx| web_command::p2p_connect_by_peer_id {
        s_peer_id: s_peer_id.clone(),
        tx,
    })
    .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(_) => json_err("connect_failed", StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn route_api_p2p_send_text(State(ctx): State<web_server_ctx>, Json(req): Json<req_p2p_send_text>) -> Response {
    let s_text = safe_trim(&req.s_text, 10000);
    if s_text.is_empty() || !is_reasonable_ascii(&s_text) {
        return json_err("invalid_text", StatusCode::BAD_REQUEST);
    }

    match cmd_roundtrip(&ctx.tx_web_cmd, |tx| web_command::p2p_send_text { s_text: s_text.clone(), tx }).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(_) => json_err("send_failed", StatusCode::INTERNAL_SERVER_ERROR),
    }
}

#[derive(Debug, Clone, Deserialize)]
struct web_search_dispatch_req {
    pub s_query: String,
    pub i_limit: Option<u32>,
}

fn validate_search_query_or_err(s_query: &str) -> Result<String, String> {
    let s_t = s_query.trim();
    if s_t.is_empty() {
        return Err("empty_query".to_string());
    }

    /* Defensive: bound by chars, not bytes; unicode allowed. */
    let i_max_chars: usize = 4096;
    if s_t.chars().count() > i_max_chars {
        return Err("query_too_long".to_string());
    }

    /* Defensive: reject control chars. */
    for ch in s_t.chars() {
        if ch.is_control() {
            return Err("query_has_control_chars".to_string());
        }
    }

    Ok(s_t.to_string())
}

fn clamp_limit(o_limit: Option<u32>) -> usize {
    let i_default: u32 = 10;
    let i_min: u32 = 1;
    let i_max: u32 = 50;

    let mut i_v = o_limit.unwrap_or(i_default);
    if i_v < i_min {
        i_v = i_min;
    }
    if i_v > i_max {
        i_v = i_max;
    }

    i_v as usize
}

pub async fn route_api_search_combi_dispatch(
    State(ctx): State<web_server_ctx>,
    Json(req): Json<web_search_dispatch_req>,
) -> impl IntoResponse {
    let s_query = match validate_search_query_or_err(&req.s_query) {
        Ok(s) => s,
        Err(s_err) => {
            let resp = web_search_dispatch_resp {
                b_ok: false,
                s_error: s_err,
                i_search_id: 0,
            };
            return (StatusCode::BAD_REQUEST, Json(resp));
        }
    };

    let i_limit: usize = clamp_limit(req.i_limit);

    /* Optional diagnostic event; keep ASCII-only log message. */
    {
        let mut g = match ctx.st_web.lock() {
            Ok(guard) => guard,
            Err(_) => {
                let resp = web_search_dispatch_resp {
                    b_ok: false,
                    s_error: "state_lock_failed".to_string(),
                    i_search_id: 0,
                };
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(resp));
            }
        };

        g.push_event(format!(
            "api: search_combi_dispatch q_len={} limit={}",
            s_query.chars().count(),
            i_limit
        ));
    }

    /* Bridge to main via web_command. */
    let (tx, rx) = tokio::sync::oneshot::channel::<web_search_dispatch_resp>();

    let cmd = web_command::search_network_combi_dispatch {
        s_query,
        i_limit,
        tx,
    };

    if ctx.tx_web_cmd.send(cmd).await.is_err() {
        let resp = web_search_dispatch_resp {
            b_ok: false,
            s_error: "command_channel_closed".to_string(),
            i_search_id: 0,
        };
        return (StatusCode::SERVICE_UNAVAILABLE, Json(resp));
    }

    match rx.await {
        Ok(resp) => {
            if resp.b_ok {
                (StatusCode::OK, Json(resp))
            } else {
                (StatusCode::BAD_REQUEST, Json(resp))
            }
        }
        Err(_) => {
            let resp = web_search_dispatch_resp {
                b_ok: false,
                s_error: "command_response_failed".to_string(),
                i_search_id: 0,
            };
            (StatusCode::GATEWAY_TIMEOUT, Json(resp))
        }
    }
}

async fn route_api_search_combi_result(
    State(ctx): State<web_server_ctx>,
    AxumPath(i_search_id): AxumPath<u64>,
) -> Response {
    match cmd_roundtrip(&ctx.tx_web_cmd, |tx| web_command::search_network_combi_get { i_search_id, tx }).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(_) => json_err("search_get_failed", StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn route_api_iam_login(State(ctx): State<web_server_ctx>, Json(req): Json<req_iam_login>) -> Response {
    let s_user = safe_trim(&req.s_user, 64);
    let s_password = safe_trim(&req.s_password, 256);

    if s_user.is_empty() || !is_reasonable_ascii(&s_user) {
        return json_err("invalid_user", StatusCode::BAD_REQUEST);
    }
    if s_password.is_empty() {
        return json_err("invalid_password", StatusCode::BAD_REQUEST);
    }

    match cmd_roundtrip(&ctx.tx_web_cmd, |tx| web_command::iam_login_local {
        s_user: s_user.clone(),
        s_password: s_password.clone(),
        tx,
    })
    .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(_) => json_err("login_failed", StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn route_api_iam_group_add(State(ctx): State<web_server_ctx>, Json(req): Json<req_iam_group_add>) -> Response {
    let s_group = safe_trim(&req.s_group, 64);
    let s_rights = safe_trim(&req.s_rights, 32);

    if s_group.is_empty() || !is_reasonable_ascii(&s_group) {
        return json_err("invalid_group", StatusCode::BAD_REQUEST);
    }
    if s_rights.is_empty() || !is_reasonable_ascii(&s_rights) {
        return json_err("invalid_rights", StatusCode::BAD_REQUEST);
    }

    let s_actor = "web".to_string();

    match cmd_roundtrip(&ctx.tx_web_cmd, |tx| web_command::iam_group_add {
        s_actor: s_actor.clone(),
        s_group: s_group.clone(),
        s_rights: s_rights.clone(),
        tx,
    })
    .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(_) => json_err("group_add_failed", StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn route_api_iam_user_add(State(ctx): State<web_server_ctx>, Json(req): Json<req_iam_user_add>) -> Response {
    let s_user = safe_trim(&req.s_user, 64);
    let s_password = safe_trim(&req.s_password, 256);
    let s_group = safe_trim(&req.s_group, 64);

    if s_user.is_empty() || !is_reasonable_ascii(&s_user) {
        return json_err("invalid_user", StatusCode::BAD_REQUEST);
    }
    if s_password.is_empty() {
        return json_err("invalid_password", StatusCode::BAD_REQUEST);
    }
    if s_group.is_empty() || !is_reasonable_ascii(&s_group) {
        return json_err("invalid_group", StatusCode::BAD_REQUEST);
    }

    let s_actor = "web".to_string();

    match cmd_roundtrip(&ctx.tx_web_cmd, |tx| web_command::iam_user_add {
        s_actor: s_actor.clone(),
        s_user: s_user.clone(),
        s_password: s_password.clone(),
        s_group: s_group.clone(),
        tx,
    })
    .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(_) => json_err("user_add_failed", StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn route_api_iam_path_add(State(ctx): State<web_server_ctx>, Json(req): Json<req_iam_path_add>) -> Response {
    let s_path = safe_trim(&req.s_path, 512);
    let s_group_or_dash = safe_trim(&req.s_group_or_dash, 64);
    let s_rights = safe_trim(&req.s_rights, 32);

    if s_path.is_empty() || !is_reasonable_ascii(&s_path) {
        return json_err("invalid_path", StatusCode::BAD_REQUEST);
    }
    if s_group_or_dash.is_empty() || !is_reasonable_ascii(&s_group_or_dash) {
        return json_err("invalid_group", StatusCode::BAD_REQUEST);
    }
    if s_rights.is_empty() || !is_reasonable_ascii(&s_rights) {
        return json_err("invalid_rights", StatusCode::BAD_REQUEST);
    }

    let s_actor = "web".to_string();

    match cmd_roundtrip(&ctx.tx_web_cmd, |tx| web_command::iam_path_add {
        s_actor: s_actor.clone(),
        s_path: s_path.clone(),
        s_group_or_dash: s_group_or_dash.clone(),
        b_public: req.b_public,
        s_rights: s_rights.clone(),
        tx,
    })
    .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(_) => json_err("path_add_failed", StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn route_api_iam_groups(State(ctx): State<web_server_ctx>) -> Response {
    match cmd_roundtrip(&ctx.tx_web_cmd, |tx| web_command::iam_groups_get { tx }).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(_) => (StatusCode::OK, Json(Vec::<web_iam_group_view>::new())).into_response(),
    }
}

async fn route_api_doc_text_get(
    State(ctx): State<web_server_ctx>,
    Json(req): Json<req_doc_text_get>,
) -> Response {
    let s_peer_id = safe_trim(&req.s_peer_id, 256);
    let s_path = safe_trim(&req.s_path, 1024);

    if s_peer_id.len() < 4 || !is_reasonable_ascii(&s_peer_id) {
        return json_err("invalid_peer_id", StatusCode::BAD_REQUEST);
    }
    if s_path.is_empty() {
        return json_err("invalid_path", StatusCode::BAD_REQUEST);
    }

    match cmd_roundtrip(&ctx.tx_web_cmd, |tx| web_command::doc_text_get {
        s_peer_id: s_peer_id.clone(),
        s_path: s_path.clone(),
        tx,
    })
    .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(_) => json_err("doc_text_get_failed", StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/* ============================================================================================
 * Router build + server run
 * ============================================================================================
 */

fn build_router(ctx: web_server_ctx) -> Router {
    Router::new()
        /* Static */
        .route("/", get(api_static_index))
        .route("/app.js", get(api_static_app_js))
        .route("/app.css", get(api_static_app_css))
        /* API */
        .route("/api/status", get(route_api_status))
        .route("/api/peers", get(route_api_peers))
        .route("/api/events", get(route_api_events))
        .route("/api/p2p/connect", post(route_api_p2p_connect))
        .route("/api/p2p/send_text", post(route_api_p2p_send_text))
        .route("/api/search/combi/dispatch", post(route_api_search_combi_dispatch))
        .route("/api/search/combi/result/:i_search_id", get(route_api_search_combi_result))
        .route("/api/doc/text_get", post(route_api_doc_text_get))

        .route("/api/iam/login", post(route_api_iam_login))
        .route("/api/iam/group_add", post(route_api_iam_group_add))
        .route("/api/iam/user_add", post(route_api_iam_user_add))
        .route("/api/iam/path_add", post(route_api_iam_path_add))
        .route("/api/iam/groups", get(route_api_iam_groups))
        .with_state(ctx)
}

pub async fn run_web_server(
    s_bind: &str,
    tx_web_cmd: mpsc::Sender<web_command>,
    st_web: Arc<Mutex<web_shared_state>>,
) -> Result<(), String> {
    /* History
     * 2026-01-11 Marcus Schlieper - Web server entry: build router, bind and serve.
     */

    let addr: SocketAddr = s_bind
        .parse()
        .map_err(|_| "invalid_bind_addr".to_string())?;

    let ctx = web_server_ctx { tx_web_cmd, st_web };

    let app = build_router(ctx);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|_| "bind_failed".to_string())?;

    axum::serve(listener, app)
        .await
        .map_err(|_| "serve_failed".to_string())?;

    Ok(())
}
