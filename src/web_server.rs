/**********************************************************************************************
 *  Modulname : web_server
 *  Datei     : web_server.rs
 *  Autor     : Marcus Schlieper
 *---------------------------------------------------------------------------------------------
 *  Beschreibung
 *  - HTTP Webserver fuer secure_p2p_ext.
 *  - Stellt JSON API Endpunkte bereit, die Funktionen der CLI abbilden und ueber eine
 *    Command Bridge an den libp2p Swarm Event Loop delegieren.
 *  - Liefert statische Assets (index.html, app.js, app.css) aus.
 *
 *  Historie
 *  11.01.2026  MS  - Initiale Version: REST API, statische Dateien, Command Bridge
 **********************************************************************************************/

#![allow(dead_code)]
#![allow(warnings)]

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode, HeaderValue},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};

pub const I_EVENT_RING_MAX: usize = 400;

/* -------------------------------- Shared State ------------------------------------------ */

#[derive(Debug, Clone, Serialize)]
pub struct web_peer_view {
    pub s_peer_id: String,
    pub b_online: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct web_status_view {
    pub s_node_peer_id: String,
    pub i_known_peers: usize,
    pub s_chat_peer: String,
    pub s_chat_topic: String,
    pub i_event_ring_len: usize,
}

#[derive(Debug, Clone)]
pub struct web_shared_state {
    pub s_node_peer_id: String,
    pub v_peers: Vec<web_peer_view>,
    pub s_chat_peer: Option<String>,
    pub s_chat_topic: Option<String>,
    pub v_event_ring: VecDeque<String>,
}

impl web_shared_state {
    pub fn new(s_node_peer_id: String) -> Self {
        Self {
            s_node_peer_id,
            v_peers: Vec::new(),
            s_chat_peer: None,
            s_chat_topic: None,
            v_event_ring: VecDeque::with_capacity(I_EVENT_RING_MAX),
        }
    }

    pub fn push_event(&mut self, s_event: String) {
        if self.v_event_ring.len() >= I_EVENT_RING_MAX {
            let _ = self.v_event_ring.pop_front();
        }
        self.v_event_ring.push_back(s_event);
    }
}

/* -------------------------------- Command Bridge ---------------------------------------- */

#[derive(Debug, Clone, Deserialize)]
pub struct web_login_req {
    pub s_user: String,
    pub s_password: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct web_login_resp {
    pub b_ok: bool,
    pub s_session: String,
    pub s_error: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct web_group_add_req {
    pub s_group: String,
    pub s_rights: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct web_user_add_req {
    pub s_user: String,
    pub s_password: String,
    pub s_group: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct web_path_add_req {
    pub s_path: String,
    pub s_group_or_dash: String,
    pub b_public: bool,
    pub s_rights: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct web_send_text_req {
    pub s_text: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct web_connect_req {
    pub s_peer_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct web_search_req {
    pub s_query: String,
    pub i_limit: u32,
    pub b_network: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct web_search_hit {
    pub s_doc: String,
    pub d_score: f32,
    pub s_snippet: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct web_search_resp {
    pub b_ok: bool,
    pub s_error: String,
    pub v_hits: Vec<web_search_hit>,
}

#[derive(Debug, Clone, Serialize)]
pub struct web_ok_resp {
    pub b_ok: bool,
    pub s_error: String,
}

#[derive(Debug)]
pub enum web_command {
    status_get {
        tx: oneshot::Sender<web_status_view>,
    },

    peers_get {
        tx: oneshot::Sender<Vec<web_peer_view>>,
    },

    events_get {
        tx: oneshot::Sender<Vec<String>>,
    },

    iam_login_local {
        s_user: String,
        s_password: String,
        tx: oneshot::Sender<web_login_resp>,
    },

    iam_group_add {
        s_actor: String,
        s_group: String,
        s_rights: String,
        tx: oneshot::Sender<web_ok_resp>,
    },

    iam_user_add {
        s_actor: String,
        s_user: String,
        s_password: String,
        s_group: String,
        tx: oneshot::Sender<web_ok_resp>,
    },

    iam_path_add {
        s_actor: String,
        s_path: String,
        s_group_or_dash: String,
        b_public: bool,
        s_rights: String,
        tx: oneshot::Sender<web_ok_resp>,
    },

    p2p_connect_by_peer_id {
        s_peer_id: String,
        tx: oneshot::Sender<web_ok_resp>,
    },

    p2p_send_text {
        s_text: String,
        tx: oneshot::Sender<web_ok_resp>,
    },

    search_local_tantivy {
        s_query: String,
        i_limit: usize,
        tx: oneshot::Sender<web_search_resp>,
    },

    search_local_vector {
        s_query: String,
        i_limit: usize,
        tx: oneshot::Sender<web_search_resp>,
    },

    search_local_combi {
        s_query: String,
        i_limit: usize,
        tx: oneshot::Sender<web_search_resp>,
    },

    search_network_tantivy {
        s_query: String,
        i_limit: usize,
        tx: oneshot::Sender<web_ok_resp>,
    },

    search_network_vector {
        s_query: String,
        i_limit: usize,
        tx: oneshot::Sender<web_ok_resp>,
    },

    search_network_combi {
        s_query: String,
        i_limit: usize,
        tx: oneshot::Sender<web_ok_resp>,
    },
}

#[derive(Clone)]
pub struct web_server_ctx {
    pub tx_cmd: mpsc::Sender<web_command>,
    pub st: Arc<Mutex<web_shared_state>>,
}

/* -------------------------------- HTTP Handlers ----------------------------------------- */

fn no_cache_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("Cache-Control", "no-store".parse().unwrap());
    h
}

async fn api_status(State(ctx): State<web_server_ctx>) -> impl IntoResponse {
    let (tx, rx) = oneshot::channel::<web_status_view>();
    let cmd = web_command::status_get { tx };
    if ctx.tx_cmd.send(cmd).await.is_err() {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(web_status_view {
            s_node_peer_id: "na".to_string(),
            i_known_peers: 0,
            s_chat_peer: "".to_string(),
            s_chat_topic: "".to_string(),
            i_event_ring_len: 0,
        })).into_response();
    }
    match rx.await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, StatusCode::SERVICE_UNAVAILABLE).into_response(),
    }
}

async fn api_peers(State(ctx): State<web_server_ctx>) -> impl IntoResponse {
    let (tx, rx) = oneshot::channel::<Vec<web_peer_view>>();
    let cmd = web_command::peers_get { tx };
    if ctx.tx_cmd.send(cmd).await.is_err() {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(Vec::<web_peer_view>::new())).into_response();
    }
    match rx.await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, Json(Vec::<web_peer_view>::new())).into_response(),
    }
}

async fn api_events(State(ctx): State<web_server_ctx>) -> impl IntoResponse {
    let (tx, rx) = oneshot::channel::<Vec<String>>();
    let cmd = web_command::events_get { tx };
    if ctx.tx_cmd.send(cmd).await.is_err() {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(Vec::<String>::new())).into_response();
    }
    match rx.await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, Json(Vec::<String>::new())).into_response(),
    }
}

async fn api_login(State(ctx): State<web_server_ctx>, Json(req): Json<web_login_req>) -> impl IntoResponse {
    let s_user = req.s_user.trim().to_string();
    if s_user.is_empty() || s_user.len() > 64 {
        return (StatusCode::BAD_REQUEST, Json(web_login_resp {
            b_ok: false,
            s_session: "".to_string(),
            s_error: "invalid_user".to_string(),
        })).into_response();
    }
    if req.s_password.len() > 256 {
        return (StatusCode::BAD_REQUEST, Json(web_login_resp {
            b_ok: false,
            s_session: "".to_string(),
            s_error: "invalid_password".to_string(),
        })).into_response();
    }

    let (tx, rx) = oneshot::channel::<web_login_resp>();
    let cmd = web_command::iam_login_local {
        s_user: s_user.clone(),
        s_password: req.s_password.clone(),
        tx,
    };
    if ctx.tx_cmd.send(cmd).await.is_err() {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(web_login_resp {
            b_ok: false,
            s_session: "".to_string(),
            s_error: "cmd_channel_down".to_string(),
        })).into_response();
    }
    match rx.await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, Json(web_login_resp {
            b_ok: false,
            s_session: "".to_string(),
            s_error: "cmd_timeout".to_string(),
        })).into_response(),
    }
}

async fn api_group_add(State(ctx): State<web_server_ctx>, Json(req): Json<web_group_add_req>) -> impl IntoResponse {
    let (tx, rx) = oneshot::channel::<web_ok_resp>();
    let cmd = web_command::iam_group_add {
        s_actor: "web".to_string(),
        s_group: req.s_group.trim().to_string(),
        s_rights: req.s_rights.trim().to_string(),
        tx,
    };
    if ctx.tx_cmd.send(cmd).await.is_err() {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(web_ok_resp { b_ok: false, s_error: "cmd_channel_down".to_string() })).into_response();
    }
    match rx.await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, Json(web_ok_resp { b_ok: false, s_error: "cmd_timeout".to_string() })).into_response(),
    }
}

async fn api_user_add(State(ctx): State<web_server_ctx>, Json(req): Json<web_user_add_req>) -> impl IntoResponse {
    let (tx, rx) = oneshot::channel::<web_ok_resp>();
    let cmd = web_command::iam_user_add {
        s_actor: "web".to_string(),
        s_user: req.s_user.trim().to_string(),
        s_password: req.s_password.clone(),
        s_group: req.s_group.trim().to_string(),
        tx,
    };
    if ctx.tx_cmd.send(cmd).await.is_err() {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(web_ok_resp { b_ok: false, s_error: "cmd_channel_down".to_string() })).into_response();
    }
    match rx.await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, Json(web_ok_resp { b_ok: false, s_error: "cmd_timeout".to_string() })).into_response(),
    }
}

async fn api_path_add(State(ctx): State<web_server_ctx>, Json(req): Json<web_path_add_req>) -> impl IntoResponse {
    let (tx, rx) = oneshot::channel::<web_ok_resp>();
    let cmd = web_command::iam_path_add {
        s_actor: "web".to_string(),
        s_path: req.s_path.trim().to_string(),
        s_group_or_dash: req.s_group_or_dash.trim().to_string(),
        b_public: req.b_public,
        s_rights: req.s_rights.trim().to_string(),
        tx,
    };
    if ctx.tx_cmd.send(cmd).await.is_err() {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(web_ok_resp { b_ok: false, s_error: "cmd_channel_down".to_string() })).into_response();
    }
    match rx.await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, Json(web_ok_resp { b_ok: false, s_error: "cmd_timeout".to_string() })).into_response(),
    }
}

async fn api_connect(State(ctx): State<web_server_ctx>, Json(req): Json<web_connect_req>) -> impl IntoResponse {
    let s_peer_id = req.s_peer_id.trim().to_string();
    if s_peer_id.is_empty() || s_peer_id.len() > 128 {
        return (StatusCode::BAD_REQUEST, Json(web_ok_resp { b_ok: false, s_error: "invalid_peer_id".to_string() })).into_response();
    }
    let (tx, rx) = oneshot::channel::<web_ok_resp>();
    let cmd = web_command::p2p_connect_by_peer_id { s_peer_id, tx };
    if ctx.tx_cmd.send(cmd).await.is_err() {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(web_ok_resp { b_ok: false, s_error: "cmd_channel_down".to_string() })).into_response();
    }
    match rx.await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, Json(web_ok_resp { b_ok: false, s_error: "cmd_timeout".to_string() })).into_response(),
    }
}

async fn api_send_text(State(ctx): State<web_server_ctx>, Json(req): Json<web_send_text_req>) -> impl IntoResponse {
    let s_text = req.s_text.trim().to_string();
    if s_text.is_empty() || s_text.len() > 10_000 {
        return (StatusCode::BAD_REQUEST, Json(web_ok_resp { b_ok: false, s_error: "invalid_text".to_string() })).into_response();
    }
    let (tx, rx) = oneshot::channel::<web_ok_resp>();
    let cmd = web_command::p2p_send_text { s_text, tx };
    if ctx.tx_cmd.send(cmd).await.is_err() {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(web_ok_resp { b_ok: false, s_error: "cmd_channel_down".to_string() })).into_response();
    }
    match rx.await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, Json(web_ok_resp { b_ok: false, s_error: "cmd_timeout".to_string() })).into_response(),
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct web_search_route_req {
    pub s_query: String,
    pub i_limit: u32,
}

async fn api_search_tantivy(State(ctx): State<web_server_ctx>, Json(req): Json<web_search_route_req>) -> impl IntoResponse {
    let s_query = req.s_query.trim().to_string();
    let i_limit = req.i_limit.clamp(1, 50) as usize;

    let (tx, rx) = oneshot::channel::<web_search_resp>();
    let cmd = web_command::search_local_tantivy { s_query, i_limit, tx };
    if ctx.tx_cmd.send(cmd).await.is_err() {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(web_search_resp { b_ok: false, s_error: "cmd_channel_down".to_string(), v_hits: Vec::new() })).into_response();
    }
    match rx.await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, Json(web_search_resp { b_ok: false, s_error: "cmd_timeout".to_string(), v_hits: Vec::new() })).into_response(),
    }
}

async fn api_search_vector(State(ctx): State<web_server_ctx>, Json(req): Json<web_search_route_req>) -> impl IntoResponse {
    let s_query = req.s_query.trim().to_string();
    let i_limit = req.i_limit.clamp(1, 50) as usize;

    let (tx, rx) = oneshot::channel::<web_search_resp>();
    let cmd = web_command::search_local_vector { s_query, i_limit, tx };
    if ctx.tx_cmd.send(cmd).await.is_err() {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(web_search_resp { b_ok: false, s_error: "cmd_channel_down".to_string(), v_hits: Vec::new() })).into_response();
    }
    match rx.await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, Json(web_search_resp { b_ok: false, s_error: "cmd_timeout".to_string(), v_hits: Vec::new() })).into_response(),
    }
}

async fn api_search_combi(State(ctx): State<web_server_ctx>, Json(req): Json<web_search_route_req>) -> impl IntoResponse {
    let s_query = req.s_query.trim().to_string();
    let i_limit = req.i_limit.clamp(1, 50) as usize;

    let (tx, rx) = oneshot::channel::<web_search_resp>();
    let cmd = web_command::search_local_combi { s_query, i_limit, tx };
    if ctx.tx_cmd.send(cmd).await.is_err() {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(web_search_resp { b_ok: false, s_error: "cmd_channel_down".to_string(), v_hits: Vec::new() })).into_response();
    }
    match rx.await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, Json(web_search_resp { b_ok: false, s_error: "cmd_timeout".to_string(), v_hits: Vec::new() })).into_response(),
    }
}

async fn api_static_index() -> impl IntoResponse {
    // text/html is set by Html wrapper
    (no_cache_headers(), Html(include_str!("./web/index.html"))).into_response()
}

async fn api_static_app_js() -> impl IntoResponse {
    let mut h = no_cache_headers();
    h.insert("Content-Type", HeaderValue::from_static("application/javascript; charset=utf-8"));

    (h, (StatusCode::OK, include_str!("./web/app.js"))).into_response()
}

async fn api_static_app_css() -> impl IntoResponse {
    let mut h = no_cache_headers();
    h.insert("Content-Type", HeaderValue::from_static("text/css; charset=utf-8"));

    (h, (StatusCode::OK, include_str!("./web/app.css"))).into_response()
}

/* -------------------------------- Server Start ------------------------------------------ */

pub async fn run_web_server(
    s_bind: &str,
    tx_cmd: mpsc::Sender<web_command>,
    st: Arc<Mutex<web_shared_state>>,
) -> Result<(), String> {
    let addr: SocketAddr = s_bind.parse().map_err(|_| "invalid_bind_addr".to_string())?;

    let ctx = web_server_ctx { tx_cmd, st };

    let app = Router::new()
        .route("/", get(api_static_index))
        .route("/app.js", get(api_static_app_js))
        .route("/app.css", get(api_static_app_css))
        .route("/api/status", get(api_status))
        .route("/api/peers", get(api_peers))
        .route("/api/events", get(api_events))
        .route("/api/iam/login", post(api_login))
        .route("/api/iam/group_add", post(api_group_add))
        .route("/api/iam/user_add", post(api_user_add))
        .route("/api/iam/path_add", post(api_path_add))
        .route("/api/p2p/connect", post(api_connect))
        .route("/api/p2p/send_text", post(api_send_text))
        .route("/api/search/tantivy", post(api_search_tantivy))
        .route("/api/search/vector", post(api_search_vector))
        .route("/api/search/combi", post(api_search_combi))
        .with_state(ctx);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|_| "bind_failed".to_string())?;

    axum::serve(listener, app).await.map_err(|_| "serve_failed".to_string())?;
    Ok(())
}

