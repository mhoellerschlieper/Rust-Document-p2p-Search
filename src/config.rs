/**********************************************************************************************
 *  Modulname : secure_p2p_ext
 *  Datei     : config.rs
 *  Autor     : Marcus Schlieper
 *---------------------------------------------------------------------------------------------
 *  Beschreibung
 *  - Zentrale Konfiguration fuer secure_p2p_ext.
 *  - Laedt Einstellungen aus Konfigurationsdatei und Umgebungsvariablen.
 *  - Unterstuetzt Feature Flags fuer WebDAV und WebServer sowie weitere Parameter.
 *  - Validiert Eingaben defensiv und stellt stabile Pfadfunktionen bereit.
 *
 *  Historie
 *  11.01.2026  Marcus Schlieper  - Initiale Version: AppConfig + Env Parsing + Validierung
 *  16.05.2026  Marcus Schlieper  - Merge: JSON Konfigurationsdatei integriert
 *  16.05.2026  Marcus Schlieper  - Erweiterung um b_use_webdav, b_use_web_server, s_webdav_bind
 **********************************************************************************************/

#![allow(dead_code)]
#![allow(warnings)]

use crate::fs;
use crate::Path;
use crate::PathBuf;

use serde::{Deserialize, Serialize};
use std::env;
use std::sync::OnceLock;

static CFG: OnceLock<app_config> = OnceLock::new();

pub fn cfg_get() -> &'static app_config {
    CFG.get_or_init(|| {
        crate::config::app_config::load_from_env().unwrap_or_else(|e| {
            println!("config error: {}", e);
            std::process::exit(2);
        })
    })
}

pub const S_DATA_ROOT_DIR: &str = "data";

/* Unterverzeichnisse unterhalb von ./data */
pub const S_DIR_TANTIVY_IDX: &str = "tantivy_idx";
pub const S_DIR_VEC_TRACKER: &str = "vec_tracker";
pub const S_DIR_VECTOR_IDX: &str = "vector_idx";
pub const S_DIR_QUEUE: &str = "expchat_queue";
pub const S_DIR_PROCESSED_DOCS: &str = "processed_docs";
pub const S_DIR_IAM_DB: &str = "iam_db";

/* Dateien */
pub const S_DIR_ANN: &str = "ann";
pub const S_FILE_ANN_GRAPH: &str = "ann_graph.bin";

/* ===================================== Konstanten ======================================== */

const S_ENV_CONFIG_FILE: &str = "EXPCHAT_CONFIG";
const S_ENV_WEB_BIND: &str = "EXPCHAT_WEB_BIND";
const S_ENV_WEBDAV_BIND: &str = "EXPCHAT_WEBDAV_BIND";
const S_ENV_DOC_DIR: &str = "EXPCHAT_DOC_DIR";
const S_ENV_IDX_DIR: &str = "EXPCHAT_IDX_DIR";
const S_ENV_GLOBAL_TOPIC: &str = "EXPCHAT_GLOBAL_TOPIC";
const S_ENV_IAM_TOPIC: &str = "EXPCHAT_IAM_TOPIC";
const S_ENV_IDX_INTERVAL_SEC: &str = "EXPCHAT_IDX_INTERVAL_SEC";
const S_ENV_PERSIST_INTERVAL_SEC: &str = "EXPCHAT_PERSIST_INTERVAL_SEC";
const S_ENV_MAX_TRANSMIT_SIZE: &str = "EXPCHAT_MAX_TRANSMIT_SIZE";
const S_ENV_CHUNK_SIZE: &str = "EXPCHAT_CHUNK_SIZE";
const S_ENV_IAM_REMOTE_SCOPE_PUBLIC: &str = "EXPCHAT_IAM_REMOTE_SCOPE_PUBLIC";
const S_ENV_USE_WEBDAV: &str = "EXPCHAT_USE_WEBDAV";
const S_ENV_USE_WEBSERVER: &str = "EXPCHAT_USE_WEBSERVER";

const S_DEFAULT_CONFIG_FILE: &str = "config/app_config.json";
const S_DEFAULT_WEB_BIND: &str = "127.0.0.1:8080";
const S_DEFAULT_WEBDAV_BIND: &str = "127.0.0.1:1900";
const S_DEFAULT_DOC_DIR: &str = "Documents";
const S_DEFAULT_IDX_DIR: &str = "./data/tantivy_idx";
const S_DEFAULT_GLOBAL_TOPIC: &str = "expchat-main";
const S_DEFAULT_IAM_TOPIC: &str = "expchat-iam";

const I_MIN_INTERVAL_SEC: u64 = 5;
const I_MAX_INTERVAL_SEC: u64 = 86_400;

const I_MIN_MAX_TRANSMIT_SIZE: usize = 16 * 1024;
const I_MAX_MAX_TRANSMIT_SIZE: usize = 16 * 1024 * 1024;

const I_MIN_CHUNK_SIZE: usize = 4096;
const I_MAX_CHUNK_SIZE: usize = 2 * 1024 * 1024;

/* ===================================== Datenstruktur ===================================== */

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct app_config {
    pub s_web_bind: String,
    pub s_webdav_bind: String,
    pub s_doc_dir: String,
    pub s_idx_dir: String,

    pub s_global_topic: String,
    pub s_iam_topic: String,

    pub i_idx_interval_sec: u64,
    pub i_persist_interval_sec: u64,

    pub i_max_transmit_size: usize,
    pub i_chunk_size: usize,

    pub b_iam_remote_scope_public: bool,
    pub b_use_webdav: bool,
    pub b_use_web_server: bool,
}

/* Helper: join ./data + rel */
fn join_under_data_root(s_rel: &str) -> PathBuf {
    let mut p = PathBuf::from(S_DATA_ROOT_DIR);
    p.push(s_rel);
    p
}

/* Oeffentliche Pfad-Getter */
pub fn path_data_root_dir() -> PathBuf {
    PathBuf::from(S_DATA_ROOT_DIR)
}

pub fn path_tantivy_idx_dir() -> PathBuf {
    join_under_data_root(S_DIR_TANTIVY_IDX)
}

pub fn path_vec_tracker_dir() -> PathBuf {
    join_under_data_root(S_DIR_VEC_TRACKER)
}

pub fn path_vector_idx_dir() -> PathBuf {
    join_under_data_root(S_DIR_VECTOR_IDX)
}

pub fn path_queue_dir() -> PathBuf {
    join_under_data_root(S_DIR_QUEUE)
}

pub fn path_processed_docs_dir() -> PathBuf {
    join_under_data_root(S_DIR_PROCESSED_DOCS)
}

pub fn path_iam_db_dir() -> PathBuf {
    join_under_data_root(S_DIR_IAM_DB)
}

pub fn path_ann_graph_file() -> PathBuf {
    let mut p = join_under_data_root(S_DIR_ANN);
    p.push(S_FILE_ANN_GRAPH);
    p
}

pub fn ensure_data_layout() -> Result<(), String> {
    let cfg = cfg_get();

    let v_dirs = vec![
        path_data_root_dir(),
        path_tantivy_idx_dir(),
        path_vec_tracker_dir(),
        path_vector_idx_dir(),
        path_queue_dir(),
        path_processed_docs_dir(),
        path_iam_db_dir(),
        join_under_data_root(S_DIR_ANN),
        PathBuf::from(&cfg.s_doc_dir),
    ];

    for p in v_dirs {
        fs::create_dir_all(&p).map_err(|_| "data_layout_create_failed".to_string())?;
    }

    Ok(())
}

pub fn ensure_parent_dir(p_file: &Path) -> Result<(), String> {
    if let Some(p_parent) = p_file.parent() {
        fs::create_dir_all(p_parent).map_err(|_| "parent_dir_create_failed".to_string())?;
    }
    Ok(())
}

/* ===================================== Implementierung ==================================== */

impl Default for app_config {
    fn default() -> Self {
        Self {
            s_web_bind: S_DEFAULT_WEB_BIND.to_string(),
            s_webdav_bind: S_DEFAULT_WEBDAV_BIND.to_string(),
            s_doc_dir: S_DEFAULT_DOC_DIR.to_string(),
            s_idx_dir: S_DEFAULT_IDX_DIR.to_string(),
            s_global_topic: S_DEFAULT_GLOBAL_TOPIC.to_string(),
            s_iam_topic: S_DEFAULT_IAM_TOPIC.to_string(),
            i_idx_interval_sec: 30,
            i_persist_interval_sec: 900,
            i_max_transmit_size: 1_048_576,
            i_chunk_size: 65_536,
            b_iam_remote_scope_public: true,
            b_use_webdav: true,
            b_use_web_server: true,
        }
    }
}

impl app_config {
    pub fn load_from_env() -> Result<Self, String> {
        let mut cfg = match Self::load_from_file() {
            Ok(o_cfg) => o_cfg,
            Err(_) => app_config::default(),
        };

        if let Ok(s) = env::var(S_ENV_WEB_BIND) {
            let s_t = s.trim();
            if !s_t.is_empty() && s_t.len() <= 128 {
                cfg.s_web_bind = s_t.to_string();
            }
        }

        if let Ok(s) = env::var(S_ENV_WEBDAV_BIND) {
            let s_t = s.trim();
            if !s_t.is_empty() && s_t.len() <= 128 {
                cfg.s_webdav_bind = s_t.to_string();
            }
        }

        if let Ok(s) = env::var(S_ENV_DOC_DIR) {
            let s_t = s.trim();
            if !s_t.is_empty() && s_t.len() <= 512 {
                cfg.s_doc_dir = s_t.to_string();
            }
        }

        if let Ok(s) = env::var(S_ENV_IDX_DIR) {
            let s_t = s.trim();
            if !s_t.is_empty() && s_t.len() <= 512 {
                cfg.s_idx_dir = s_t.to_string();
            }
        }

        if let Ok(s) = env::var(S_ENV_GLOBAL_TOPIC) {
            let s_t = s.trim();
            if Self::validate_topic_name(s_t) {
                cfg.s_global_topic = s_t.to_string();
            }
        }

        if let Ok(s) = env::var(S_ENV_IAM_TOPIC) {
            let s_t = s.trim();
            if Self::validate_topic_name(s_t) {
                cfg.s_iam_topic = s_t.to_string();
            }
        }

        if let Ok(s) = env::var(S_ENV_IDX_INTERVAL_SEC) {
            if let Some(i_v) = parse_u64_bounded(&s, I_MIN_INTERVAL_SEC, I_MAX_INTERVAL_SEC) {
                cfg.i_idx_interval_sec = i_v;
            }
        }

        if let Ok(s) = env::var(S_ENV_PERSIST_INTERVAL_SEC) {
            if let Some(i_v) = parse_u64_bounded(&s, I_MIN_INTERVAL_SEC, I_MAX_INTERVAL_SEC) {
                cfg.i_persist_interval_sec = i_v;
            }
        }

        if let Ok(s) = env::var(S_ENV_MAX_TRANSMIT_SIZE) {
            if let Some(i_v) = parse_usize_bounded(&s, I_MIN_MAX_TRANSMIT_SIZE, I_MAX_MAX_TRANSMIT_SIZE) {
                cfg.i_max_transmit_size = i_v;
            }
        }

        if let Ok(s) = env::var(S_ENV_CHUNK_SIZE) {
            if let Some(i_v) = parse_usize_bounded(&s, I_MIN_CHUNK_SIZE, I_MAX_CHUNK_SIZE) {
                cfg.i_chunk_size = i_v;
            }
        }

        if let Ok(s) = env::var(S_ENV_IAM_REMOTE_SCOPE_PUBLIC) {
            if let Some(b) = parse_bool_ext(&s) {
                cfg.b_iam_remote_scope_public = b;
            }
        }

        if let Ok(s) = env::var(S_ENV_USE_WEBDAV) {
            if let Some(b) = parse_bool_ext(&s) {
                cfg.b_use_webdav = b;
            }
        }

        if let Ok(s) = env::var(S_ENV_USE_WEBSERVER) {
            if let Some(b) = parse_bool_ext(&s) {
                cfg.b_use_web_server = b;
            }
        }

        cfg.validate()?;
        Ok(cfg)
    }

    fn load_from_file() -> Result<Self, String> {
        let s_cfg_file = env::var(S_ENV_CONFIG_FILE).unwrap_or_else(|_| S_DEFAULT_CONFIG_FILE.to_string());
        let p_cfg_file = PathBuf::from(&s_cfg_file);

        if !p_cfg_file.exists() {
            return Err("config_file_not_found".to_string());
        }

        let s_json = fs::read_to_string(&p_cfg_file).map_err(|_| "config_file_read_failed".to_string())?;
        let cfg: app_config = serde_json::from_str(&s_json).map_err(|_| "config_file_parse_failed".to_string())?;

        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.s_web_bind.trim().is_empty() || self.s_web_bind.len() > 128 {
            return Err("invalid_web_bind".to_string());
        }
        if self.s_webdav_bind.trim().is_empty() || self.s_webdav_bind.len() > 128 {
            return Err("invalid_webdav_bind".to_string());
        }
        if self.s_doc_dir.trim().is_empty() || self.s_doc_dir.len() > 512 {
            return Err("invalid_doc_dir".to_string());
        }
        if self.s_idx_dir.trim().is_empty() || self.s_idx_dir.len() > 512 {
            return Err("invalid_idx_dir".to_string());
        }
        if !Self::validate_topic_name(&self.s_global_topic) {
            return Err("invalid_global_topic".to_string());
        }
        if !Self::validate_topic_name(&self.s_iam_topic) {
            return Err("invalid_iam_topic".to_string());
        }

        if self.i_idx_interval_sec < I_MIN_INTERVAL_SEC || self.i_idx_interval_sec > I_MAX_INTERVAL_SEC {
            return Err("invalid_idx_interval_sec".to_string());
        }
        if self.i_persist_interval_sec < I_MIN_INTERVAL_SEC || self.i_persist_interval_sec > I_MAX_INTERVAL_SEC {
            return Err("invalid_persist_interval_sec".to_string());
        }

        if self.i_max_transmit_size < I_MIN_MAX_TRANSMIT_SIZE || self.i_max_transmit_size > I_MAX_MAX_TRANSMIT_SIZE {
            return Err("invalid_max_transmit_size".to_string());
        }
        if self.i_chunk_size < I_MIN_CHUNK_SIZE || self.i_chunk_size > I_MAX_CHUNK_SIZE {
            return Err("invalid_chunk_size".to_string());
        }

        Ok(())
    }

    fn validate_topic_name(s_in: &str) -> bool {
        let s = s_in.trim();
        if s.is_empty() || s.len() > 128 {
            return false;
        }
        s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    }
}

/* ===================================== Parser Utils ====================================== */

fn parse_bool_01(s_in: &str) -> Option<bool> {
    match s_in.trim() {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    }
}

fn parse_bool_ext(s_in: &str) -> Option<bool> {
    let s = s_in.trim().to_ascii_lowercase();
    match s.as_str() {
        "0" | "false" | "no" | "off" => Some(false),
        "1" | "true" | "yes" | "on" => Some(true),
        _ => None,
    }
}

fn parse_u64_bounded(s_in: &str, i_min: u64, i_max: u64) -> Option<u64> {
    let s = s_in.trim();
    if s.is_empty() {
        return None;
    }
    let i_v = u64::from_str_radix(s, 10).ok()?;
    if i_v < i_min || i_v > i_max {
        return None;
    }
    Some(i_v)
}

fn parse_usize_bounded(s_in: &str, i_min: usize, i_max: usize) -> Option<usize> {
    let s = s_in.trim();
    if s.is_empty() {
        return None;
    }
    let i_v = usize::from_str_radix(s, 10).ok()?;
    if i_v < i_min || i_v > i_max {
        return None;
    }
    Some(i_v)
}
