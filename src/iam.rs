/**********************************************************************************************
 *  Modulname : iam
 *  Datei     : iam.rs
 *  Autor     : Marcus Schlieper
 *---------------------------------------------------------------------------------------------
 *  Beschreibung
 *  - Lokale IAM Verwaltung fuer secure_p2p_ext.
 *  - Passwoerter verlassen den Node niemals. Login erfolgt per Challenge Response.
 *  - Records (User, Group, Membership, Path) sind replizierbar ueber Events.
 *  - Autorisierung ist node-lokal (Pfadregeln + Gruppenrechte + public/local).
 *
 *  Historie
 *  09.01.2026  MS  - Initiale Version: IAM Core + Event Hookpoints fuer Replikation
 **********************************************************************************************/

#![allow(dead_code)]
#![allow(warnings)]

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sled::{Db, Tree};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::iam_net::{iam_event, iam_op, iam_record_type};

pub type rights_mask = u64;

pub const right_read: rights_mask = 1 << 0;
pub const right_write: rights_mask = 1 << 1;
pub const right_create: rights_mask = 1 << 2;
pub const right_publish: rights_mask = 1 << 3;
pub const right_local: rights_mask = 1 << 4;
pub const right_public: rights_mask = 1 << 5;
pub const right_admin: rights_mask = 1 << 63;

const iam_db_dir: &str = "iam_db";
const t_users: &str = "users";
const t_groups: &str = "groups";
const t_memberships: &str = "memberships";
const t_paths: &str = "paths";
const t_sessions: &str = "sessions";
const t_challenges: &str = "challenges";
const t_audit: &str = "audit";

const i_challenge_ttl_sec: u64 = 60;
const i_session_ttl_sec: u64 = 900;

fn now_unix_sec() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut v: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        v |= x ^ y;
    }
    v == 0
}

#[derive(Debug)]
pub enum iam_error {
    invalid_input,
    not_found,
    already_exists,
    locked,
    unauthorized,
    expired,
    storage,
    crypto,
}

pub type iam_result<T> = Result<T, iam_error>;

#[derive(Serialize, Deserialize, Clone)]
pub struct user_record {
    pub s_user: String,
    pub s_pw_hash: String,
    pub b_locked: bool,
    pub i_created_at: u64,
    pub i_updated_at: u64,
    pub i_version: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct group_record {
    pub s_group: String,
    pub i_rights: rights_mask,
    pub i_created_at: u64,
    pub i_updated_at: u64,
    pub i_version: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct membership_record {
    pub s_user: String,
    pub s_group: String,
    pub i_created_at: u64,
    pub i_version: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct path_record {
    pub s_path_id: String,
    pub s_path: String,
    pub s_group: Option<String>,
    pub b_public: bool,
    pub i_rights: rights_mask,
    pub i_created_at: u64,
    pub i_updated_at: u64,
    pub i_version: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct login_challenge {
    pub s_challenge_id: String,
    pub s_user: String,
    pub a_nonce: [u8; 32],
    pub i_issued_at: u64,
    pub i_expires_at: u64,
    pub b_used: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct session_record {
    pub s_session: String,
    pub s_user: String,
    pub i_issued_at: u64,
    pub i_expires_at: u64,
    pub i_version: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct audit_record {
    pub i_ts: u64,
    pub s_actor: String,
    pub s_action: String,
    pub s_target: String,
    pub s_detail: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct access_decision {
    pub b_allowed: bool,
    pub s_reason: String,
    pub i_effective_rights: rights_mask,
}

#[derive(Clone)]
pub struct iam_config {
    pub s_node_id: String,
}

impl Default for iam_config {
    fn default() -> Self {
        Self {
            s_node_id: "node_unknown".to_string(),
        }
    }
}

pub struct iam_store {
    db: Db,
    tr_users: Tree,
    tr_groups: Tree,
    tr_memberships: Tree,
    tr_paths: Tree,
    tr_sessions: Tree,
    tr_challenges: Tree,
    tr_audit: Tree,
    cfg: iam_config,
}

impl iam_store {
    pub fn open(cfg: iam_config) -> iam_result<Self> {
        let db = sled::open(iam_db_dir).map_err(|_| iam_error::storage)?;
        Ok(Self {
            tr_users: db.open_tree(t_users).map_err(|_| iam_error::storage)?,
            tr_groups: db.open_tree(t_groups).map_err(|_| iam_error::storage)?,
            tr_memberships: db.open_tree(t_memberships).map_err(|_| iam_error::storage)?,
            tr_paths: db.open_tree(t_paths).map_err(|_| iam_error::storage)?,
            tr_sessions: db.open_tree(t_sessions).map_err(|_| iam_error::storage)?,
            tr_challenges: db.open_tree(t_challenges).map_err(|_| iam_error::storage)?,
            tr_audit: db.open_tree(t_audit).map_err(|_| iam_error::storage)?,
            db,
            cfg,
        })
    }

    fn audit(&self, s_actor: &str, s_action: &str, s_target: &str, s_detail: &str) {
        let r = audit_record {
            i_ts: now_unix_sec(),
            s_actor: s_actor.to_string(),
            s_action: s_action.to_string(),
            s_target: s_target.to_string(),
            s_detail: s_detail.to_string(),
        };
        if let Ok(v) = serde_json::to_vec(&r) {
            let mut a_key = [0u8; 16];
            OsRng.fill_bytes(&mut a_key);
            let _ = self.tr_audit.insert(a_key, v);
        }
    }

    fn validate_name(s: &str) -> bool {
        let s_t = s.trim();
        if s_t.is_empty() || s_t.len() > 64 {
            return false;
        }
        s_t.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    }

    fn validate_path(s: &str) -> bool {
        let s_t = s.trim();
        if s_t.is_empty() || s_t.len() > 512 {
            return false;
        }
        s_t.chars().all(|c| c.is_ascii_graphic() || c == ' ')
    }

    fn new_id_hex_32() -> String {
        let mut a = [0u8; 16];
        OsRng.fill_bytes(&mut a);
        hex::encode(a)
    }

    fn argon2_hash_password(s_password: &str) -> iam_result<String> {
        if s_password.len() < 8 || s_password.len() > 256 {
            return Err(iam_error::invalid_input);
        }
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(s_password.as_bytes(), &salt)
            .map_err(|_| iam_error::crypto)?
            .to_string();
        Ok(hash)
    }

    fn user_get(&self, s_user: &str) -> iam_result<user_record> {
        let v = self
            .tr_users
            .get(s_user.as_bytes())
            .map_err(|_| iam_error::storage)?;
        let Some(v) = v else { return Err(iam_error::not_found) };
        serde_json::from_slice(&v).map_err(|_| iam_error::storage)
    }

    fn group_get(&self, s_group: &str) -> iam_result<group_record> {
        let v = self
            .tr_groups
            .get(s_group.as_bytes())
            .map_err(|_| iam_error::storage)?;
        let Some(v) = v else { return Err(iam_error::not_found) };
        serde_json::from_slice(&v).map_err(|_| iam_error::storage)
    }

    pub fn add_group(&self, s_actor: &str, s_group: &str, i_rights: rights_mask) -> iam_result<()> {
        if !Self::validate_name(s_group) {
            return Err(iam_error::invalid_input);
        }
        if self
            .tr_groups
            .get(s_group.as_bytes())
            .map_err(|_| iam_error::storage)?
            .is_some()
        {
            return Err(iam_error::already_exists);
        }
        let now = now_unix_sec();
        let g = group_record {
            s_group: s_group.to_string(),
            i_rights,
            i_created_at: now,
            i_updated_at: now,
            i_version: now,
        };
        let v = serde_json::to_vec(&g).map_err(|_| iam_error::storage)?;
        self.tr_groups
            .insert(s_group.as_bytes(), v)
            .map_err(|_| iam_error::storage)?;
        self.audit(s_actor, "add_group", s_group, "ok");
        Ok(())
    }

    pub fn add_user(&self, s_actor: &str, s_user: &str, s_password: &str, s_group: &str) -> iam_result<()> {
        if !Self::validate_name(s_user) || !Self::validate_name(s_group) {
            return Err(iam_error::invalid_input);
        }
        let _ = self.group_get(s_group)?;
        if self
            .tr_users
            .get(s_user.as_bytes())
            .map_err(|_| iam_error::storage)?
            .is_some()
        {
            return Err(iam_error::already_exists);
        }
        let s_hash = Self::argon2_hash_password(s_password)?;
        let now = now_unix_sec();
        let u = user_record {
            s_user: s_user.to_string(),
            s_pw_hash: s_hash,
            b_locked: false,
            i_created_at: now,
            i_updated_at: now,
            i_version: now,
        };
        let v_u = serde_json::to_vec(&u).map_err(|_| iam_error::storage)?;
        self.tr_users
            .insert(s_user.as_bytes(), v_u)
            .map_err(|_| iam_error::storage)?;
        self.add_user_to_group(s_actor, s_user, s_group)?;
        self.audit(s_actor, "add_user", s_user, "ok");
        Ok(())
    }

    pub fn add_user_to_group(&self, s_actor: &str, s_user: &str, s_group: &str) -> iam_result<()> {
        if !Self::validate_name(s_user) || !Self::validate_name(s_group) {
            return Err(iam_error::invalid_input);
        }
        let _ = self.user_get(s_user)?;
        let _ = self.group_get(s_group)?;
        let s_key = format!("{}::{}", s_user, s_group);
        if self
            .tr_memberships
            .get(s_key.as_bytes())
            .map_err(|_| iam_error::storage)?
            .is_some()
        {
            return Err(iam_error::already_exists);
        }
        let now = now_unix_sec();
        let m = membership_record {
            s_user: s_user.to_string(),
            s_group: s_group.to_string(),
            i_created_at: now,
            i_version: now,
        };
        let v = serde_json::to_vec(&m).map_err(|_| iam_error::storage)?;
        self.tr_memberships
            .insert(s_key.as_bytes(), v)
            .map_err(|_| iam_error::storage)?;
        self.audit(s_actor, "add_user_to_group", s_user, s_group);
        Ok(())
    }

    pub fn add_path(
        &self,
        s_actor: &str,
        s_path: &str,
        s_group: Option<&str>,
        b_public: bool,
        i_rights: rights_mask,
    ) -> iam_result<String> {
        if !Self::validate_path(s_path) {
            return Err(iam_error::invalid_input);
        }
        if let Some(g) = s_group {
            if !Self::validate_name(g) {
                return Err(iam_error::invalid_input);
            }
            let _ = self.group_get(g)?;
        }
        let now = now_unix_sec();
        let s_path_id = Self::new_id_hex_32();
        let pr = path_record {
            s_path_id: s_path_id.clone(),
            s_path: s_path.to_string(),
            s_group: s_group.map(|x| x.to_string()),
            b_public,
            i_rights,
            i_created_at: now,
            i_updated_at: now,
            i_version: now,
        };
        let v = serde_json::to_vec(&pr).map_err(|_| iam_error::storage)?;
        self.tr_paths
            .insert(s_path_id.as_bytes(), v)
            .map_err(|_| iam_error::storage)?;
        self.audit(s_actor, "add_path", &s_path_id, s_path);
        Ok(s_path_id)
    }

    pub fn begin_login(&self, s_user: &str) -> iam_result<login_challenge> {
        if !Self::validate_name(s_user) {
            return Err(iam_error::invalid_input);
        }
        let u = self.user_get(s_user)?;
        if u.b_locked {
            return Err(iam_error::locked);
        }

        let mut a_nonce = [0u8; 32];
        OsRng.fill_bytes(&mut a_nonce);

        let i_issued = now_unix_sec();
        let i_expires = i_issued.saturating_add(i_challenge_ttl_sec);
        let s_challenge_id = Self::new_id_hex_32();

        let c = login_challenge {
            s_challenge_id: s_challenge_id.clone(),
            s_user: s_user.to_string(),
            a_nonce,
            i_issued_at: i_issued,
            i_expires_at: i_expires,
            b_used: false,
        };

        let v = serde_json::to_vec(&c).map_err(|_| iam_error::storage)?;
        self.tr_challenges
            .insert(s_challenge_id.as_bytes(), v)
            .map_err(|_| iam_error::storage)?;
        self.audit(s_user, "begin_login", &s_challenge_id, "issued");
        Ok(c)
    }

    pub fn finish_login(&self, s_user: &str, s_challenge_id: &str, a_proof: &[u8; 32]) -> iam_result<String> {
        if !Self::validate_name(s_user) {
            return Err(iam_error::invalid_input);
        }
        if s_challenge_id.trim().len() != 32 {
            return Err(iam_error::invalid_input);
        }

        let v_ch = self
            .tr_challenges
            .get(s_challenge_id.as_bytes())
            .map_err(|_| iam_error::storage)?;
        let Some(v_ch) = v_ch else { return Err(iam_error::not_found) };
        let mut c: login_challenge = serde_json::from_slice(&v_ch).map_err(|_| iam_error::storage)?;

        let now = now_unix_sec();
        if c.b_used || c.s_user != s_user {
            return Err(iam_error::unauthorized);
        }
        if now > c.i_expires_at {
            return Err(iam_error::expired);
        }

        let u = self.user_get(s_user)?;
        if u.b_locked {
            return Err(iam_error::locked);
        }

        let mut h_pw = Sha256::new();
        h_pw.update(u.s_pw_hash.as_bytes());
        let a_pw = h_pw.finalize();

        let mut h = Sha256::new();
        h.update(&a_pw);
        h.update(&c.a_nonce);
        h.update(c.s_challenge_id.as_bytes());
        h.update(self.cfg.s_node_id.as_bytes());
        let a_expected: [u8; 32] = h.finalize().into();

        if !ct_eq(&a_expected, a_proof) {
            self.audit(s_user, "finish_login", s_challenge_id, "bad_proof");
            return Err(iam_error::unauthorized);
        }

        c.b_used = true;
        let v_ch2 = serde_json::to_vec(&c).map_err(|_| iam_error::storage)?;
        self.tr_challenges
            .insert(s_challenge_id.as_bytes(), v_ch2)
            .map_err(|_| iam_error::storage)?;

        let s_session = Self::new_id_hex_32();
        let i_expires = now.saturating_add(i_session_ttl_sec);
        let srec = session_record {
            s_session: s_session.clone(),
            s_user: s_user.to_string(),
            i_issued_at: now,
            i_expires_at: i_expires,
            i_version: now,
        };
        let v_s = serde_json::to_vec(&srec).map_err(|_| iam_error::storage)?;
        self.tr_sessions
            .insert(s_session.as_bytes(), v_s)
            .map_err(|_| iam_error::storage)?;

        self.audit(s_user, "finish_login", &s_session, "ok");
        Ok(s_session)
    }

    fn get_session(&self, s_session: &str) -> iam_result<session_record> {
        if s_session.trim().len() != 32 {
            return Err(iam_error::invalid_input);
        }
        let v = self
            .tr_sessions
            .get(s_session.as_bytes())
            .map_err(|_| iam_error::storage)?;
        let Some(v) = v else { return Err(iam_error::not_found) };
        let srec: session_record = serde_json::from_slice(&v).map_err(|_| iam_error::storage)?;
        if now_unix_sec() > srec.i_expires_at {
            return Err(iam_error::expired);
        }
        Ok(srec)
    }

    pub fn check_access(&self, s_session: &str, s_path: &str, i_right: rights_mask, b_public_scope: bool) -> iam_result<access_decision> {
        if !Self::validate_path(s_path) {
            return Err(iam_error::invalid_input);
        }
        let srec = self.get_session(s_session)?;
        let s_user = srec.s_user;

        let mut i_group_rights: rights_mask = 0;

        for item in self.tr_memberships.iter() {
            let (_k, v) = item.map_err(|_| iam_error::storage)?;
            let m: membership_record = serde_json::from_slice(&v).map_err(|_| iam_error::storage)?;
            if m.s_user == s_user {
                if let Ok(g) = self.group_get(&m.s_group) {
                    i_group_rights |= g.i_rights;
                }
            }
        }

        let mut o_best: Option<path_record> = None;
        for item in self.tr_paths.iter() {
            let (_k, v) = item.map_err(|_| iam_error::storage)?;
            let pr: path_record = serde_json::from_slice(&v).map_err(|_| iam_error::storage)?;
            if s_path.starts_with(&pr.s_path) {
                let take = match &o_best {
                    None => true,
                    Some(old) => pr.s_path.len() > old.s_path.len(),
                };
                if take {
                    o_best = Some(pr);
                }
            }
        }

        let Some(pr) = o_best else {
            return Ok(access_decision {
                b_allowed: false,
                s_reason: "no_path_rule".to_string(),
                i_effective_rights: 0,
            });
        };

        if b_public_scope && !pr.b_public {
            return Ok(access_decision {
                b_allowed: false,
                s_reason: "path_not_public".to_string(),
                i_effective_rights: 0,
            });
        }

        if let Some(req_group) = pr.s_group {
            let mut b_in_group = false;
            for item in self.tr_memberships.iter() {
                let (_k, v) = item.map_err(|_| iam_error::storage)?;
                let m: membership_record = serde_json::from_slice(&v).map_err(|_| iam_error::storage)?;
                if m.s_user == s_user && m.s_group == req_group {
                    b_in_group = true;
                    break;
                }
            }
            if !b_in_group {
                return Ok(access_decision {
                    b_allowed: false,
                    s_reason: "group_mismatch".to_string(),
                    i_effective_rights: 0,
                });
            }
        }

        let i_effective = i_group_rights & pr.i_rights;
        let b_allowed = (i_effective & i_right) == i_right;

        Ok(access_decision {
            b_allowed,
            s_reason: if b_allowed { "allow" } else { "deny" }.to_string(),
            i_effective_rights: i_effective,
        })
    }

    /* -------------------- Replikations-Hilfen: Event erstellen / anwenden -------------------- */

    pub fn export_all_events(&self) -> iam_result<Vec<iam_event>> {
        /* Minimal: full snapshot as upserts. In production: event log with versions. */
        let mut v_out: Vec<iam_event> = Vec::new();
        let i_ts = now_unix_sec();

        for item in self.tr_users.iter() {
            let (k, v) = item.map_err(|_| iam_error::storage)?;
            let s_key = String::from_utf8_lossy(&k).into_owned();
            let s_val = String::from_utf8_lossy(&v).into_owned();
            v_out.push(iam_event {
                s_event_id: Self::new_id_hex_32(),
                s_node_id: self.cfg.s_node_id.clone(),
                i_ts,
                record_type: iam_record_type::user,
                op: iam_op::upsert,
                s_key,
                v_value_json: Some(s_val),
            });
        }

        for item in self.tr_groups.iter() {
            let (k, v) = item.map_err(|_| iam_error::storage)?;
            let s_key = String::from_utf8_lossy(&k).into_owned();
            let s_val = String::from_utf8_lossy(&v).into_owned();
            v_out.push(iam_event {
                s_event_id: Self::new_id_hex_32(),
                s_node_id: self.cfg.s_node_id.clone(),
                i_ts,
                record_type: iam_record_type::group,
                op: iam_op::upsert,
                s_key,
                v_value_json: Some(s_val),
            });
        }

        for item in self.tr_memberships.iter() {
            let (k, v) = item.map_err(|_| iam_error::storage)?;
            let s_key = String::from_utf8_lossy(&k).into_owned();
            let s_val = String::from_utf8_lossy(&v).into_owned();
            v_out.push(iam_event {
                s_event_id: Self::new_id_hex_32(),
                s_node_id: self.cfg.s_node_id.clone(),
                i_ts,
                record_type: iam_record_type::membership,
                op: iam_op::upsert,
                s_key,
                v_value_json: Some(s_val),
            });
        }

        for item in self.tr_paths.iter() {
            let (k, v) = item.map_err(|_| iam_error::storage)?;
            let s_key = String::from_utf8_lossy(&k).into_owned();
            let s_val = String::from_utf8_lossy(&v).into_owned();
            v_out.push(iam_event {
                s_event_id: Self::new_id_hex_32(),
                s_node_id: self.cfg.s_node_id.clone(),
                i_ts,
                record_type: iam_record_type::path,
                op: iam_op::upsert,
                s_key,
                v_value_json: Some(s_val),
            });
        }

        Ok(v_out)
    }

    pub fn apply_event(&self, ev: &iam_event) -> iam_result<()> {
        if ev.s_key.trim().is_empty() || ev.s_key.len() > 512 {
            return Err(iam_error::invalid_input);
        }

        let (tr, _rt) = match ev.record_type {
            iam_record_type::user => (&self.tr_users, "user"),
            iam_record_type::group => (&self.tr_groups, "group"),
            iam_record_type::membership => (&self.tr_memberships, "membership"),
            iam_record_type::path => (&self.tr_paths, "path"),
        };

        match ev.op {
            iam_op::delete => {
                tr.remove(ev.s_key.as_bytes()).map_err(|_| iam_error::storage)?;
                self.audit("replication", "apply_event_delete", &ev.s_key, &ev.s_node_id);
            }
            iam_op::upsert => {
                let Some(s_val) = &ev.v_value_json else { return Err(iam_error::invalid_input) };
                tr.insert(ev.s_key.as_bytes(), s_val.as_bytes())
                    .map_err(|_| iam_error::storage)?;
                self.audit("replication", "apply_event_upsert", &ev.s_key, &ev.s_node_id);
            }
        }

        Ok(())
    }
}
