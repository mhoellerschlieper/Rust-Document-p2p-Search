/**********************************************************************************************
 *  Modulname : iam_net
 *  Datei     : iam_net.rs
 *  Autor     : Marcus Schlieper
 *---------------------------------------------------------------------------------------------
 *  Beschreibung
 *  - Serde-sichere Replikationspayloads fuer IAM Records.
 *  - Keine Passwoerter oder Klartext-Geheimnisse werden uebertragen.
 *  - Replikation erfolgt als Event-Deltas (Upsert/Delete).
 *
 *  Historie
 *  09.01.2026  MS  - Initiale Version: Event Types und Delta Container
 **********************************************************************************************/

#![allow(dead_code)]
#![allow(warnings)]

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum iam_record_type {
    user,
    group,
    membership,
    path,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum iam_op {
    upsert,
    delete,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct iam_event {
    pub s_event_id: String,
    pub s_node_id: String,
    pub i_ts: u64,

    pub record_type: iam_record_type,
    pub op: iam_op,

    pub s_key: String,
    pub v_value_json: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct iam_delta_push {
    pub s_epoch: String,
    pub i_ts: u64,
    pub v_events: Vec<iam_event>,
    pub s_merkle_root_hex: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct iam_delta_request {
    pub s_since_epoch: String,
    pub i_since_ts: u64,
    pub s_known_merkle_root_hex: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct iam_delta_response {
    pub s_epoch: String,
    pub i_ts: u64,
    pub v_events: Vec<iam_event>,
    pub s_merkle_root_hex: String,
}
