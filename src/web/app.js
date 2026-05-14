/* ============================================================================================
Module name : web_ui
File        : app.js
Author      : Marcus Schlieper
------------------------------------------------------------------------------------------------
Description
- Premium SPA logic for ExpChat.ai FileButler.
- Uses known backend endpoints for status, peers, events, p2p, search, files and iam.
- Supports document text loading, file download, pdf preview and elegant navigation.
History
2026-05-14  Marcus Schlieper
- Full rewrite for premium icon driven dashboard
2026-05-14  Marcus Schlieper
- Added safe fetch helpers, doc preview cleanup and jump navigation
============================================================================================ */
"use strict";

/* -------------------------------- API helper ---------------------------------------------- */
const api = {
    async json_get(s_url) {
        return await api._fetch_json(s_url, { method: "GET" });
    },

    async json_post(s_url, o_body) {
        return await api._fetch_json(s_url, {
            method: "POST",
            headers: { "Content-Type": "application/json; charset=utf-8" },
            body: JSON.stringify(o_body || {}),
        });
    },

    async _fetch_json(s_url, o_opts) {
        const ctrl = new AbortController();
        const i_timeout_ms = 10000;
        const o_timer = setTimeout(() => ctrl.abort(), i_timeout_ms);

        try {
            const o_resp = await fetch(s_url, { ...o_opts, signal: ctrl.signal });
            if (!o_resp.ok) {
                let s_body = "";
                try {
                    s_body = await o_resp.text();
                } catch (_e) {
                    s_body = "";
                }
                return {
                    b_ok: false,
                    s_error: "http_error_" + String(o_resp.status) + (s_body ? ": " + s_body.slice(0, 400) : ""),
                };
            }

            const s_ct = String(o_resp.headers.get("content-type") || "").toLowerCase();
            if (s_ct.indexOf("application/json") < 0) {
                return { b_ok: false, s_error: "unexpected_content_type" };
            }

            return await o_resp.json();
        } catch (o_err) {
            return {
                b_ok: false,
                s_error: o_err && o_err.message ? String(o_err.message) : "fetch_failed",
            };
        } finally {
            clearTimeout(o_timer);
        }
    },
};

/* -------------------------------- DOM helpers --------------------------------------------- */
function by_id(s_id) {
    const o_el = document.getElementById(s_id);
    if (!o_el) {
        throw new Error("missing_element_" + String(s_id || ""));
    }
    return o_el;
}

function opt_by_id(s_id) {
    return document.getElementById(s_id);
}

function set_text(s_id, s_text) {
    const o_el = opt_by_id(s_id);
    if (!o_el) {
        return;
    }
    o_el.textContent = s_text === undefined || s_text === null ? "" : String(s_text);
}

function safe_trim(s_value, i_max_len) {
    const s_text = String(s_value || "").trim();
    if (s_text.length > i_max_len) {
        return s_text.slice(0, i_max_len);
    }
    return s_text;
}

function parse_int_clamped(s_value, i_min, i_max, i_fallback) {
    const i_value = parseInt(String(s_value || ""), 10);
    if (!Number.isFinite(i_value)) {
        return i_fallback;
    }
    if (i_value < i_min) {
        return i_min;
    }
    if (i_value > i_max) {
        return i_max;
    }
    return i_value;
}

function toast(s_text) {
    const o_el = opt_by_id("toast");
    if (!o_el) {
        return;
    }

    o_el.textContent = String(s_text || "");
    o_el.classList.remove("hidden");

    window.clearTimeout(toast._timer_id);
    toast._timer_id = window.setTimeout(() => {
        o_el.classList.add("hidden");
    }, 2800);
}

function safe_file_name_from_path(s_path) {
    const s_clean = String(s_path || "").replace(/\\/g, "/");
    const v_parts = s_clean.split("/");
    let s_name = v_parts.length > 0 ? v_parts[v_parts.length - 1] : "download.bin";
    s_name = s_name.replace(/[^a-zA-Z0-9._-]/g, "_");
    if (s_name.length < 1) {
        s_name = "download.bin";
    }
    if (s_name.length > 128) {
        s_name = s_name.slice(0, 128);
    }
    return s_name;
}

/* -------------------------------- Navigation ---------------------------------------------- */
function set_active_view(s_view_id) {
    document.querySelectorAll(".view").forEach((o_view) => o_view.classList.add("hidden"));
    const o_target = by_id(s_view_id);
    o_target.classList.remove("hidden");

    document.querySelectorAll(".nav_item").forEach((o_btn) => o_btn.classList.remove("active"));
    document.querySelectorAll(".nav_item").forEach((o_btn) => {
        if (o_btn.getAttribute("data-view") === s_view_id) {
            o_btn.classList.add("active");
        }
    });
}

function init_jump_buttons() {
    document.querySelectorAll("[data-jump-view]").forEach((o_btn) => {
        o_btn.addEventListener("click", () => {
            const s_view = o_btn.getAttribute("data-jump-view");
            if (s_view) {
                set_active_view(s_view);
            }
        });
    });
}

/* -------------------------------- Status --------------------------------------------------- */
async function refresh_status() {
    const o_st = await api.json_get("/api/status");
    const o_badge = opt_by_id("status_badge");

    if (!o_st || o_st.s_node_peer_id === undefined) {
        set_text("status_badge", "offline");
        if (o_badge) {
            o_badge.classList.remove("badge_on");
            o_badge.classList.add("badge_off");
        }
        return;
    }

    set_text("st_peer_id", o_st.s_node_peer_id || "-");
    set_text("st_known_peers", String(o_st.i_known_peers || 0));
    set_text("st_chat_peer", o_st.s_chat_peer || "-");
    set_text("st_chat_topic", o_st.s_chat_topic || "-");

    set_text("st_peer_id_2", o_st.s_node_peer_id || "-");
    set_text("st_known_peers_2", String(o_st.i_known_peers || 0));
    set_text("st_chat_peer_2", o_st.s_chat_peer || "-");
    set_text("st_chat_topic_2", o_st.s_chat_topic || "-");

    set_text("chat_meta_peer", o_st.s_chat_peer || "-");
    set_text("chat_meta_topic", o_st.s_chat_topic || "-");

    set_text("status_badge", "online");
    if (o_badge) {
        o_badge.classList.remove("badge_off");
        o_badge.classList.add("badge_on");
    }
}

/* -------------------------------- Peers ---------------------------------------------------- */
function render_peers_table(v_peers) {
    const o_tb = by_id("peers_table");
    o_tb.innerHTML = "";

    if (!Array.isArray(v_peers)) {
        toast("peers_refresh_failed");
        return;
    }

    v_peers.forEach((o_peer) => {
        const s_peer_id = String((o_peer && o_peer.s_peer_id) || "");
        const b_online = !!(o_peer && o_peer.b_online);

        const o_tr = document.createElement("tr");

        const o_td_id = document.createElement("td");
        o_td_id.className = "mono";
        o_td_id.textContent = s_peer_id;

        const o_td_online = document.createElement("td");
        o_td_online.textContent = b_online ? "true" : "false";

        const o_td_action = document.createElement("td");

        const o_btn = document.createElement("button");
        o_btn.className = "panel_btn";
        o_btn.type = "button";
        o_btn.textContent = "connect";
        o_btn.addEventListener("click", async () => {
            await do_connect(s_peer_id);
        });

        o_td_action.appendChild(o_btn);
        o_tr.appendChild(o_td_id);
        o_tr.appendChild(o_td_online);
        o_tr.appendChild(o_td_action);
        o_tb.appendChild(o_tr);
    });
}

async function refresh_peers() {
    const v_peers = await api.json_get("/api/peers");
    render_peers_table(v_peers);
}

async function do_connect(s_peer_id) {
    const s_id = safe_trim(s_peer_id, 256);
    if (s_id.length < 4) {
        toast("invalid_peer_id");
        return;
    }

    const o_res = await api.json_post("/api/p2p/connect", { s_peer_id: s_id });
    if (!o_res || o_res.b_ok !== true) {
        toast("connect_failed: " + String((o_res && o_res.s_error) || "na"));
        return;
    }

    toast("connect_sent");
    await refresh_status();
}

/* -------------------------------- Events --------------------------------------------------- */
function render_events(v_events) {
    const s_text = Array.isArray(v_events) ? v_events.map((x) => String(x || "")).join("\n") : "";
    set_text("events_box", s_text);
    set_text("events_box_overview", s_text);
}

async function refresh_events() {
    const v_events = await api.json_get("/api/events");
    if (!Array.isArray(v_events)) {
        toast("events_refresh_failed");
        return;
    }
    render_events(v_events);
}

/* -------------------------------- P2P ------------------------------------------------------ */
async function do_send_text() {
    const s_text = safe_trim(by_id("send_text").value, 10000);
    if (s_text.length < 1) {
        toast("empty_text");
        return;
    }

    const o_res = await api.json_post("/api/p2p/send_text", { s_text: s_text });
    if (!o_res || o_res.b_ok !== true) {
        toast("send_failed: " + String((o_res && o_res.s_error) || "na"));
        return;
    }

    by_id("send_text").value = "";
    toast("sent");
}

/* -------------------------------- Document preview state ---------------------------------- */
let g_search_poll_timer = null;
let g_last_search_id = null;
let g_preview_object_url = null;

/* Central function history entry:
2026-05-14 Marcus Schlieper
- Added robust object url cleanup before every preview state switch.
*/
function revoke_preview_object_url() {
    if (!g_preview_object_url) {
        return;
    }
    try {
        URL.revokeObjectURL(g_preview_object_url);
    } catch (_e) {
        /* ignore cleanup failure */
    }
    g_preview_object_url = null;
}

function hide_doc_text_show_preview() {
    const o_doc_text = opt_by_id("doc_text");
    const o_doc_text_wrap = opt_by_id("doc_text_wrap");
    const o_preview_wrap = opt_by_id("doc_preview_wrap");

    if (o_doc_text) {
        o_doc_text.classList.add("hidden");
    }
    if (o_doc_text_wrap) {
        o_doc_text_wrap.classList.add("hidden");
    }
    if (o_preview_wrap) {
        o_preview_wrap.classList.remove("hidden");
    }
}

function show_doc_text_hide_preview() {
    const o_doc_text = opt_by_id("doc_text");
    const o_doc_text_wrap = opt_by_id("doc_text_wrap");
    const o_preview_wrap = opt_by_id("doc_preview_wrap");
    const o_preview = opt_by_id("doc_file_preview");

    if (o_doc_text) {
        o_doc_text.classList.remove("hidden");
    }
    if (o_doc_text_wrap) {
        o_doc_text_wrap.classList.remove("hidden");
    }
    if (o_preview_wrap) {
        o_preview_wrap.classList.add("hidden");
    }
    if (o_preview) {
        o_preview.setAttribute("src", "");
    }

    revoke_preview_object_url();
}

function clear_doc_view() {
    set_text("doc_title", "-");
    const o_doc_text = opt_by_id("doc_text");
    const o_preview = opt_by_id("doc_file_preview");

    if (o_doc_text) {
        o_doc_text.textContent = "";
    }
    if (o_preview) {
        o_preview.setAttribute("src", "");
    }

    revoke_preview_object_url();
    show_doc_text_hide_preview();
}

function is_pdf_mime(s_mime) {
    return String(s_mime || "").toLowerCase() === "application/pdf";
}

function base64_to_blob(s_base64, s_mime) {
    try {
        const s_bin = atob(String(s_base64 || ""));
        const a_bytes = new Uint8Array(s_bin.length);
        for (let i_i = 0; i_i < s_bin.length; i_i += 1) {
            a_bytes[i_i] = s_bin.charCodeAt(i_i);
        }
        return new Blob([a_bytes], { type: s_mime || "application/octet-stream" });
    } catch (_e) {
        return null;
    }
}

function trigger_blob_download(o_blob, s_name) {
    const s_url = URL.createObjectURL(o_blob);
    const o_link = document.createElement("a");
    o_link.href = s_url;
    o_link.download = s_name || "download.bin";
    o_link.rel = "noopener";
    document.body.appendChild(o_link);
    o_link.click();
    document.body.removeChild(o_link);

    setTimeout(() => {
        try {
            URL.revokeObjectURL(s_url);
        } catch (_e) {
            /* ignore cleanup failure */
        }
    }, 60000);
}

function show_pdf_preview_from_blob(o_blob) {
    const o_preview = opt_by_id("doc_file_preview");
    if (!o_preview) {
        return false;
    }

    revoke_preview_object_url();
    g_preview_object_url = URL.createObjectURL(o_blob);
    o_preview.setAttribute("src", g_preview_object_url);
    hide_doc_text_show_preview();
    return true;
}

function show_text_in_doc_area(s_title, s_text) {
    set_text("doc_title", s_title);
    show_doc_text_hide_preview();
    const o_doc_text = opt_by_id("doc_text");
    if (o_doc_text) {
        o_doc_text.textContent = String(s_text || "");
    }
}

/* -------------------------------- Search --------------------------------------------------- */
function stop_search_polling() {
    if (g_search_poll_timer) {
        clearInterval(g_search_poll_timer);
        g_search_poll_timer = null;
    }
    set_text("search_poll_state", "idle");
}

function render_search_results(v_hits, b_partial) {
    const o_box = by_id("search_results");
    o_box.innerHTML = "";

    const o_head = document.createElement("div");
    o_head.className = "meta_pill";
    o_head.innerHTML =
        '<i class="fa-solid fa-layer-group"></i><span>' +
        (b_partial ? "partial_results" : "final_results") +
        "</span>";
    o_box.appendChild(o_head);

    if (!Array.isArray(v_hits) || v_hits.length === 0) {
        const o_empty = document.createElement("div");
        o_empty.className = "hint_box";
        o_empty.textContent = "no_hits";
        o_box.appendChild(o_empty);
        return;
    }

    v_hits.forEach((o_hit) => {
        const s_doc = String((o_hit && o_hit.s_doc) || "");
        const s_peer = String((o_hit && o_hit.s_peer_id) || "");
        const d_score = Number((o_hit && o_hit.d_score) || 0);
        const s_snip = String((o_hit && o_hit.s_snippet) || "");

        const o_card = document.createElement("div");
        o_card.className = "hit";

        const o_line_1 = document.createElement("div");
        o_line_1.className = "hit_title";
        o_line_1.textContent = (Number.isFinite(d_score) ? d_score : 0).toFixed(4) + "  " + s_doc;

        const o_line_2 = document.createElement("div");
        o_line_2.className = "hit_snippet";
        o_line_2.textContent = "peer=" + (s_peer ? s_peer : "-");

        const o_line_3 = document.createElement("div");
        o_line_3.className = "hit_snippet";
        o_line_3.textContent = s_snip || "";

        const o_actions = document.createElement("div");
        o_actions.className = "hit_actions";

        const o_btn_text = document.createElement("button");
        o_btn_text.className = "panel_btn";
        o_btn_text.type = "button";
        o_btn_text.innerHTML = '<i class="fa-solid fa-file-lines"></i><span>text</span>';
        o_btn_text.addEventListener("click", async (o_ev) => {
            if (o_ev && typeof o_ev.stopPropagation === "function") {
                o_ev.stopPropagation();
            }
            await fetch_doc_text(s_peer, s_doc);
        });

        const o_btn_download = document.createElement("button");
        o_btn_download.className = "panel_btn secondary";
        o_btn_download.type = "button";
        o_btn_download.innerHTML = '<i class="fa-solid fa-download"></i><span>download</span>';
        o_btn_download.addEventListener("click", async (o_ev) => {
            if (o_ev && typeof o_ev.stopPropagation === "function") {
                o_ev.stopPropagation();
            }
            await fetch_file_for_hit(s_peer, s_doc);
        });

        o_card.addEventListener("click", async () => {
            await fetch_doc_text(s_peer, s_doc);
        });

        o_actions.appendChild(o_btn_text);
        o_actions.appendChild(o_btn_download);
        o_card.appendChild(o_line_1);
        o_card.appendChild(o_line_2);
        o_card.appendChild(o_line_3);
        o_card.appendChild(o_actions);
        o_box.appendChild(o_card);
    });
}

async function poll_search_result_once() {
    if (!g_last_search_id || !Number.isFinite(g_last_search_id)) {
        toast("no_search_id");
        return;
    }

    set_text("search_poll_state", "polling");
    const s_url = "/api/search/combi/result/" + encodeURIComponent(String(g_last_search_id));
    const o_res = await api.json_get(s_url);

    if (!o_res || o_res.b_ok !== true) {
        render_search_results([], true);
        return;
    }

    const b_partial = o_res.b_partial === true;
    render_search_results(o_res.v_hits || [], b_partial);

    if (!b_partial) {
        stop_search_polling();
    }
}

async function do_search() {
    stop_search_polling();

    const s_mode = by_id("search_mode").value;
    if (s_mode !== "combi") {
        toast("invalid_mode");
        return;
    }

    const s_query = safe_trim(by_id("search_query").value, 4096);
    if (s_query.length < 1) {
        toast("empty_query");
        return;
    }

    const i_limit = parse_int_clamped(by_id("search_limit").value, 1, 50, 10);

    set_text("search_id", "-");
    render_search_results([], true);
    clear_doc_view();

    const o_res = await api.json_post("/api/search/combi/dispatch", {
        s_query: s_query,
        i_limit: i_limit,
    });

    if (!o_res || o_res.b_ok !== true) {
        toast("dispatch_failed: " + String((o_res && o_res.s_error) || "na"));
        return;
    }

    const i_search_id = Number(o_res.i_search_id);
    if (!Number.isFinite(i_search_id) || i_search_id <= 0) {
        toast("invalid_search_id");
        return;
    }

    g_last_search_id = i_search_id;
    set_text("search_id", String(i_search_id));
    set_text("search_poll_state", "polling");
    toast("search_dispatched");

    let i_ticks = 0;
    const i_max_ticks = 14;

    g_search_poll_timer = setInterval(async () => {
        i_ticks += 1;
        await poll_search_result_once();
        if (i_ticks >= i_max_ticks) {
            stop_search_polling();
            set_text("search_poll_state", "stopped");
        }
    }, 450);

    await poll_search_result_once();
}

/* -------------------------------- Document text ------------------------------------------- */
async function fetch_doc_text(s_peer_id, s_path) {
    const s_peer = safe_trim(s_peer_id, 256);
    const s_doc_path = safe_trim(s_path, 1024);

    if (s_peer.length < 4 || s_doc_path.length < 1) {
        toast("invalid_doc_request");
        return;
    }

    const o_res = await api.json_post("/api/doc/text_get", {
        s_peer_id: s_peer,
        s_path: s_doc_path,
    });

    if (!o_res || o_res.b_ok !== true) {
        show_text_in_doc_area(s_doc_path, "error: " + String((o_res && o_res.s_error) || "na"));
        return;
    }

    const s_text = String((o_res && o_res.s_text) || "");
    const s_err = String((o_res && o_res.s_error) || "");
    const s_title = s_peer + "  " + s_doc_path;

    if (s_text.length > 0) {
        show_text_in_doc_area(s_title, s_text);
        return;
    }

    show_text_in_doc_area(s_title, s_err ? s_err : "pending");
}

/* -------------------------------- File fetch ---------------------------------------------- */
async function api_file_fetch_get(s_peer_id, s_path) {
    const s_peer = safe_trim(s_peer_id, 256);
    const s_doc_path = safe_trim(s_path, 1024);

    if (s_peer.length < 4 || s_doc_path.length < 1) {
        return { b_ok: false, s_error: "invalid_file_request" };
    }

    return await api.json_post("/api/file/fetch_get", {
        s_peer_id: s_peer,
        s_path: s_doc_path,
    });
}

async function api_file_fetch_result(i_req_id) {
    const i_id = Number(i_req_id);
    if (!Number.isFinite(i_id) || i_id <= 0) {
        return { b_ok: false, s_error: "invalid_req_id" };
    }

    return await api.json_get("/api/file/fetch_result/" + encodeURIComponent(String(i_id)));
}

async function present_fetched_file_or_text(o_file, s_peer_id, s_path) {
    const s_mime = String((o_file && o_file.s_mime) || "").toLowerCase();
    const s_title = safe_trim(s_peer_id, 256) + "  " + safe_trim(s_path, 1024);
    const s_name_raw = String((o_file && o_file.s_name) || "");
    const s_name = s_name_raw.length > 0 ? safe_file_name_from_path(s_name_raw) : safe_file_name_from_path(s_path);

    const o_blob = base64_to_blob(String((o_file && o_file.s_base64) || ""), s_mime);
    if (!o_blob) {
        show_text_in_doc_area(s_title, "error: invalid_file_payload");
        return;
    }

    if (is_pdf_mime(s_mime)) {
        set_text("doc_title", s_title);
        const b_preview_ok = show_pdf_preview_from_blob(o_blob);
        if (!b_preview_ok) {
            trigger_blob_download(o_blob, s_name);
            toast("download_started");
        }
        return;
    }

    trigger_blob_download(o_blob, s_name);
    toast("download_started");
    await fetch_doc_text(s_peer_id, s_path);
}

async function fetch_file_for_hit(s_peer_id, s_path) {
    const s_peer = safe_trim(s_peer_id, 256);
    const s_doc_path = safe_trim(s_path, 1024);

    if (s_peer.length < 4 || s_doc_path.length < 1) {
        toast("invalid_file_request");
        return;
    }

    const o_start = await api_file_fetch_get(s_peer, s_doc_path);
    if (!o_start || o_start.b_ok !== true) {
        toast("file_fetch_failed: " + String((o_start && o_start.s_error) || "na"));
        return;
    }

    if (String((o_start && o_start.s_base64) || "").length > 0) {
        await present_fetched_file_or_text(o_start, s_peer, s_doc_path);
        return;
    }

    const i_req_id = Number(o_start.i_req_id);
    if (!Number.isFinite(i_req_id) || i_req_id <= 0) {
        toast("invalid_req_id");
        return;
    }

    let i_try = 0;
    const i_max_try = 40;

    while (i_try < i_max_try) {
        i_try += 1;
        await new Promise((f_resolve) => setTimeout(f_resolve, 500));

        const o_poll = await api_file_fetch_result(i_req_id);
        if (o_poll && String(o_poll.s_error || "") === "pending") {
            continue;
        }

        if (!o_poll || o_poll.b_ok !== true) {
            toast("file_fetch_failed: " + String((o_poll && o_poll.s_error) || "na"));
            return;
        }

        await present_fetched_file_or_text(o_poll, s_peer, s_doc_path);
        return;
    }

    toast("file_fetch_timeout");
}

/* -------------------------------- IAM rights ---------------------------------------------- */
const g_right_bits = {
    right_read: 1n << 0n,
    right_write: 1n << 1n,
    right_create: 1n << 2n,
    right_publish: 1n << 3n,
    right_local: 1n << 4n,
    right_public: 1n << 5n,
    right_admin: 1n << 63n,
};

function compute_rights_mask_from_named_boxes(o_map_name_to_checkbox_id) {
    try {
        if (!o_map_name_to_checkbox_id || typeof o_map_name_to_checkbox_id !== "object") {
            return { b_ok: false, s_rights_dec: "0", s_error: "invalid_map" };
        }

        let bi_mask = 0n;
        let i_seen = 0;

        for (const s_right_name of Object.keys(o_map_name_to_checkbox_id)) {
            i_seen += 1;
            const s_checkbox_id = String(o_map_name_to_checkbox_id[s_right_name] || "");
            const o_el = opt_by_id(s_checkbox_id);

            if (!o_el) {
                return {
                    b_ok: false,
                    s_rights_dec: "0",
                    s_error: "missing_checkbox_" + s_checkbox_id,
                };
            }

            const bi_bit = g_right_bits[s_right_name];
            if (bi_bit === undefined) {
                return {
                    b_ok: false,
                    s_rights_dec: "0",
                    s_error: "unknown_right_" + s_right_name,
                };
            }

            if (o_el.checked === true) {
                bi_mask |= bi_bit;
            }
        }

        if (i_seen < 1) {
            return { b_ok: false, s_rights_dec: "0", s_error: "empty_map" };
        }

        if (bi_mask === 0n) {
            return { b_ok: false, s_rights_dec: "0", s_error: "no_right_selected" };
        }

        return { b_ok: true, s_rights_dec: bi_mask.toString(10), s_error: "" };
    } catch (o_err) {
        return {
            b_ok: false,
            s_rights_dec: "0",
            s_error: o_err && o_err.message ? String(o_err.message) : "mask_compute_failed",
        };
    }
}

function wire_rights_checkboxes(o_map_name_to_checkbox_id, s_preview_id_optional) {
    const f_update = () => {
        const o_res = compute_rights_mask_from_named_boxes(o_map_name_to_checkbox_id);
        if (s_preview_id_optional) {
            set_text(s_preview_id_optional, o_res.s_rights_dec);
        }
    };

    for (const s_right_name of Object.keys(o_map_name_to_checkbox_id)) {
        const s_checkbox_id = String(o_map_name_to_checkbox_id[s_right_name] || "");
        const o_el = opt_by_id(s_checkbox_id);
        if (!o_el) {
            continue;
        }
        o_el.addEventListener("change", f_update);
    }

    f_update();
}

/* -------------------------------- IAM actions --------------------------------------------- */
async function refresh_iam_groups_select() {
    const o_select = opt_by_id("iam_user_group_select");
    if (!o_select) {
        return;
    }

    o_select.innerHTML = "";

    const o_default = document.createElement("option");
    o_default.value = "";
    o_default.textContent = "select_group";
    o_default.disabled = true;
    o_default.selected = true;
    o_select.appendChild(o_default);

    const v_groups = await api.json_get("/api/iam/groups");
    if (!Array.isArray(v_groups)) {
        const s_err = v_groups && v_groups.s_error ? String(v_groups.s_error) : "na";
        toast("groups_list_failed: " + s_err);
        return;
    }

    for (const o_group of v_groups) {
        const s_group = safe_trim((o_group && o_group.s_group) || "", 64);
        if (s_group.length < 1) {
            continue;
        }
        const o_opt = document.createElement("option");
        o_opt.value = s_group;
        o_opt.textContent = s_group;
        o_select.appendChild(o_opt);
    }
}

async function do_iam_login() {
    const s_user = safe_trim(by_id("iam_login_user").value, 64);
    const s_password = String(by_id("iam_login_pass").value || "");

    if (s_user.length < 1) {
        toast("invalid_user");
        return;
    }
    if (s_password.length < 1 || s_password.length > 256) {
        toast("invalid_password");
        return;
    }

    const o_res = await api.json_post("/api/iam/login", { s_user, s_password });
    if (!o_res || o_res.b_ok !== true) {
        toast("login_failed: " + String((o_res && o_res.s_error) || "na"));
        return;
    }

    set_text("iam_session", o_res.s_session || "-");
    by_id("iam_login_pass").value = "";
    toast("login_ok");
    await refresh_iam_groups_select();
}

async function do_iam_group_add() {
    const s_group = safe_trim(by_id("iam_group").value, 64);
    const o_map = {
        right_read: "iam_group_right_read",
        right_write: "iam_group_right_write",
        right_create: "iam_group_right_create",
        right_publish: "iam_group_right_publish",
        right_local: "iam_group_right_local",
        right_public: "iam_group_right_public",
        right_admin: "iam_group_right_admin",
    };

    if (s_group.length < 1) {
        toast("invalid_input");
        return;
    }

    const o_mask = compute_rights_mask_from_named_boxes(o_map);
    if (o_mask.b_ok !== true) {
        toast("invalid_rights: " + String(o_mask.s_error || "na"));
        return;
    }

    const o_res = await api.json_post("/api/iam/group_add", {
        s_group,
        s_rights: o_mask.s_rights_dec,
    });

    if (!o_res || o_res.b_ok !== true) {
        toast("group_add_failed: " + String((o_res && o_res.s_error) || "na"));
        return;
    }

    toast("group_added");
    await refresh_iam_groups_select();
}

async function do_iam_user_add() {
    const s_user = safe_trim(by_id("iam_user").value, 64);
    const s_password = String(by_id("iam_user_pass").value || "");
    const o_select = opt_by_id("iam_user_group_select");

    if (!o_select) {
        toast("missing_group_select");
        return;
    }

    const s_group = safe_trim(o_select.value, 64);
    if (s_user.length < 1 || s_group.length < 1 || s_password.length < 1) {
        toast("invalid_input");
        return;
    }
    if (s_password.length > 256) {
        toast("invalid_password");
        return;
    }

    const o_res = await api.json_post("/api/iam/user_add", {
        s_user,
        s_password,
        s_group,
    });

    if (!o_res || o_res.b_ok !== true) {
        toast("user_add_failed: " + String((o_res && o_res.s_error) || "na"));
        return;
    }

    by_id("iam_user_pass").value = "";
    toast("user_added");
}

async function do_iam_path_add() {
    const s_path = safe_trim(by_id("iam_path").value, 512);
    const s_group_or_dash = safe_trim(by_id("iam_path_group").value, 64);
    const b_public = by_id("iam_path_public").value === "true";

    const o_map = {
        right_read: "iam_path_right_read",
        right_write: "iam_path_right_write",
        right_create: "iam_path_right_create",
        right_publish: "iam_path_right_publish",
        right_local: "iam_path_right_local",
        right_public: "iam_path_right_public",
        right_admin: "iam_path_right_admin",
    };

    if (s_path.length < 1 || s_group_or_dash.length < 1) {
        toast("invalid_input");
        return;
    }

    const o_mask = compute_rights_mask_from_named_boxes(o_map);
    if (o_mask.b_ok !== true) {
        toast("invalid_rights: " + String(o_mask.s_error || "na"));
        return;
    }

    const o_res = await api.json_post("/api/iam/path_add", {
        s_path,
        s_group_or_dash,
        b_public,
        s_rights: o_mask.s_rights_dec,
    });

    if (!o_res || o_res.b_ok !== true) {
        toast("path_add_failed: " + String((o_res && o_res.s_error) || "na"));
        return;
    }

    toast("path_added");
}

/* -------------------------------- Wiring --------------------------------------------------- */
function init_nav() {
    document.querySelectorAll(".nav_item").forEach((o_btn) => {
        o_btn.addEventListener("click", async () => {
            const s_view = o_btn.getAttribute("data-view");
            if (s_view) {
                set_active_view(s_view);
            }
            if (s_view === "view_iam") {
                await refresh_iam_groups_select();
            }
        });
    });
}

function init_actions() {
    by_id("btn_refresh_status").addEventListener("click", refresh_status);
    by_id("btn_status_refresh").addEventListener("click", refresh_status);

    by_id("btn_refresh_peers").addEventListener("click", refresh_peers);
    by_id("btn_copy_local_peer_id").addEventListener("click", async () => {
        try {
            const s_peer_id = String(by_id("st_peer_id").textContent || "");
            if (s_peer_id && navigator.clipboard && navigator.clipboard.writeText) {
                await navigator.clipboard.writeText(s_peer_id);
                toast("copied");
            } else {
                toast("clipboard_unavailable");
            }
        } catch (_e) {
            toast("copy_failed");
        }
    });

    by_id("btn_connect").addEventListener("click", async () => {
        await do_connect(by_id("connect_peer_id").value);
    });

    by_id("btn_send_text").addEventListener("click", do_send_text);
    by_id("btn_send_text_clear").addEventListener("click", () => {
        by_id("send_text").value = "";
    });

    by_id("btn_refresh_events").addEventListener("click", refresh_events);
    by_id("btn_refresh_events_from_overview").addEventListener("click", refresh_events);

    by_id("btn_clear_events_box").addEventListener("click", () => {
        set_text("events_box", "");
    });
    by_id("btn_clear_events_box_from_overview").addEventListener("click", () => {
        set_text("events_box_overview", "");
    });

    by_id("btn_search").addEventListener("click", async (o_ev) => {
        if (o_ev && typeof o_ev.preventDefault === "function") {
            o_ev.preventDefault();
        }
        await do_search();
    });

    by_id("btn_search_clear").addEventListener("click", () => {
        by_id("search_query").value = "";
        set_text("search_id", "-");
        render_search_results([], true);
        stop_search_polling();
        clear_doc_view();
    });

    by_id("btn_search_poll_once").addEventListener("click", poll_search_result_once);
    by_id("btn_search_stop_poll").addEventListener("click", stop_search_polling);

    by_id("btn_doc_clear").addEventListener("click", clear_doc_view);

    by_id("btn_iam_login").addEventListener("click", do_iam_login);
    by_id("btn_iam_group_add").addEventListener("click", do_iam_group_add);
    by_id("btn_iam_user_add").addEventListener("click", do_iam_user_add);
    by_id("btn_iam_path_add").addEventListener("click", do_iam_path_add);

    const o_search_form = opt_by_id("search_form");
    if (o_search_form) {
        o_search_form.addEventListener("submit", async (o_ev) => {
            if (o_ev && typeof o_ev.preventDefault === "function") {
                o_ev.preventDefault();
            }
            await do_search();
        });
    }

    const o_search_query = opt_by_id("search_query");
    if (o_search_query) {
        o_search_query.addEventListener("keydown", async (o_ev) => {
            if (!o_ev) {
                return;
            }
            if (o_ev.isComposing === true) {
                return;
            }
            if (o_ev.key === "Enter") {
                o_ev.preventDefault();
                await do_search();
            }
        });
    }
}

function init_iam_rights_wiring() {
    const o_group_map = {
        right_read: "iam_group_right_read",
        right_write: "iam_group_right_write",
        right_create: "iam_group_right_create",
        right_publish: "iam_group_right_publish",
        right_local: "iam_group_right_local",
        right_public: "iam_group_right_public",
        right_admin: "iam_group_right_admin",
    };

    const o_path_map = {
        right_read: "iam_path_right_read",
        right_write: "iam_path_right_write",
        right_create: "iam_path_right_create",
        right_publish: "iam_path_right_publish",
        right_local: "iam_path_right_local",
        right_public: "iam_path_right_public",
        right_admin: "iam_path_right_admin",
    };

    wire_rights_checkboxes(o_group_map, "iam_group_rights_preview");
    wire_rights_checkboxes(o_path_map, "iam_path_rights_preview");
}

/* -------------------------------- Main ----------------------------------------------------- */
async function main() {
    try {
        init_nav();
        init_jump_buttons();
        init_actions();
        init_iam_rights_wiring();
    } catch (o_err) {
        toast("init_failed: " + String((o_err && o_err.message) || "na"));
        return;
    }

    await refresh_iam_groups_select();
    await refresh_status();
    await refresh_peers();
    await refresh_events();

    setInterval(refresh_status, 5000);
}

document.addEventListener("DOMContentLoaded", main);
