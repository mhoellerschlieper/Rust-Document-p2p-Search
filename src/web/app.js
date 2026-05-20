/* ============================================================================================
Module name : web_ui
File        : app.js
Author      : Marcus Schlieper
------------------------------------------------------------------------------------------------
Description
- Compact SPA logic for ExpChat.ai FileButler.
- Adds docs explorer across all peers including local peer.
- Adds colorful icon aware button labels and safe docs explorer rendering.
- Improves search result rendering with unified result card background, wrapped peer id,
  filename before title, and title cleanup without duplicated filename.
History
2026-05-14  Marcus Schlieper
- Full compact implementation with improved navigation and icon based UI handling
2026-05-14  Marcus Schlieper
- Added robust preview cleanup and safe endpoint helpers
2026-05-15  Marcus Schlieper
- Kept stable ids and behaviors for premium award style frontend redesign
2026-05-15  Marcus Schlieper
- Added search result table model and enriched peer table model
2026-05-16  Marcus Schlieper
- Added docs explorer for all peers and local peer
2026-05-18  Marcus Schlieper
- Added utf8 safe snippet rendering, query hit highlighting and updated split layout support
2026-05-19  Marcus Schlieper
- Improved search result layout with consistent background, wrapped peer id,
  filename before title, and removed duplicated filename from title
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
        const o_ctrl = new AbortController();
        const i_timeout_ms = 10000;
        const i_timer_id = window.setTimeout(() => o_ctrl.abort(), i_timeout_ms);

        try {
            const o_resp = await fetch(s_url, { ...o_opts, signal: o_ctrl.signal, cache: "no-store" });
            if (!o_resp.ok) {
                let s_body = "";
                try {
                    s_body = await o_resp.text();
                } catch (_o_err) {
                    s_body = "";
                }
                return {
                    b_ok: false,
                    s_error: "http_error_" + String(o_resp.status) + (s_body ? ": " + s_body.slice(0, 400) : ""),
                };
            }

            const s_content_type = String(o_resp.headers.get("content-type") || "").toLowerCase();
            if (s_content_type.indexOf("application/json") < 0) {
                return { b_ok: false, s_error: "unexpected_content_type" };
            }

            return await o_resp.json();
        } catch (o_err) {
            return {
                b_ok: false,
                s_error: o_err && o_err.message ? String(o_err.message) : "fetch_failed",
            };
        } finally {
            window.clearTimeout(i_timer_id);
        }
    },
};

/* -------------------------------- DOM helper ---------------------------------------------- */
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
    return s_text.length > i_max_len ? s_text.slice(0, i_max_len) : s_text;
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
    window.clearTimeout(toast.i_timer_id);
    toast.i_timer_id = window.setTimeout(() => {
        o_el.classList.add("hidden");
    }, 2600);
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

function title_from_path(s_path) {
    const s_name = safe_file_name_from_path(s_path);
    const i_dot = s_name.lastIndexOf(".");
    const s_base = i_dot > 0 ? s_name.slice(0, i_dot) : s_name;
    return s_base.replace(/[_-]+/g, " ").trim() || s_name;
}

function clean_title_remove_file_name(s_title, s_file_name) {
    const s_safe_title = String(s_title || "").trim();
    const s_safe_file_name = String(s_file_name || "").trim();
    if (!s_safe_title) {
        return "";
    }
    if (!s_safe_file_name) {
        return s_safe_title;
    }

    const i_dot = s_safe_file_name.lastIndexOf(".");
    const s_file_without_ext = i_dot > 0 ? s_safe_file_name.slice(0, i_dot) : s_safe_file_name;

    let s_result = s_safe_title;

    if (s_result.toLowerCase() === s_safe_file_name.toLowerCase()) {
        return "";
    }

    if (s_result.toLowerCase() === s_file_without_ext.toLowerCase()) {
        return "";
    }

    s_result = s_result.replace(new RegExp("^" + escape_regex_literal(s_safe_file_name) + "\\s*[-:|]\\s*", "i"), "");
    s_result = s_result.replace(new RegExp("^" + escape_regex_literal(s_file_without_ext) + "\\s*[-:|]\\s*", "i"), "");
    s_result = s_result.replace(new RegExp("\\s*[-:|]\\s*" + escape_regex_literal(s_safe_file_name) + "$", "i"), "");
    s_result = s_result.replace(new RegExp("\\s*[-:|]\\s*" + escape_regex_literal(s_file_without_ext) + "$", "i"), "");

    if (s_result.trim().toLowerCase() === s_safe_file_name.toLowerCase()) {
        return "";
    }

    if (s_result.trim().toLowerCase() === s_file_without_ext.toLowerCase()) {
        return "";
    }

    return s_result.trim();
}

function classify_doc_from_path(s_path) {
    const s_name = String(s_path || "").toLowerCase();
    if (s_name.endsWith(".pdf")) {
        return "PDF";
    }
    if (s_name.endsWith(".docx") || s_name.endsWith(".txt")) {
        return "Text";
    }
    if (s_name.endsWith(".xlsx") || s_name.endsWith(".xls") || s_name.endsWith(".csv")) {
        return "Table";
    }
    if (s_name.endsWith(".pptx")) {
        return "Slides";
    }
    if (s_name.endsWith(".json")) {
        return "Data";
    }
    if (s_name.endsWith(".png") || s_name.endsWith(".jpg") || s_name.endsWith(".jpeg") || s_name.endsWith(".gif") || s_name.endsWith(".svg")) {
        return "Image";
    }
    return "Document";
}

function build_tags_from_hit(o_hit) {
    const v_tags = [];
    const s_doc = String((o_hit && o_hit.s_doc) || "");
    const s_snippet = String((o_hit && o_hit.s_snippet) || "").toLowerCase();
    const s_class = classify_doc_from_path(s_doc).toLowerCase();
    v_tags.push(s_class);
    if (s_snippet.indexOf("invoice") >= 0 || s_snippet.indexOf("rechnung") >= 0) {
        v_tags.push("finance");
    }
    if (s_snippet.indexOf("contract") >= 0 || s_snippet.indexOf("vertrag") >= 0) {
        v_tags.push("legal");
    }
    if (s_snippet.indexOf("project") >= 0 || s_snippet.indexOf("projekt") >= 0) {
        v_tags.push("project");
    }
    if (s_snippet.indexOf("public") >= 0) {
        v_tags.push("public");
    }
    return Array.from(new Set(v_tags)).slice(0, 4);
}

function derive_peer_name(s_peer_id, b_local) {
    if (b_local) {
        return "Local peer";
    }
    const s_short = String(s_peer_id || "").slice(0, 10);
    return s_short ? "Peer " + s_short : "Peer";
}

function derive_peer_place(s_peer_id, b_local) {
    if (b_local) {
        return "Breckerfeld";
    }
    const v_places = ["Berlin", "Hamburg", "Munich", "Cologne", "Dortmund"];
    let i_sum = 0;
    const s_in = String(s_peer_id || "");
    for (let i_i = 0; i_i < s_in.length; i_i += 1) {
        i_sum += s_in.charCodeAt(i_i);
    }
    return v_places[i_sum % v_places.length];
}

function derive_reachability_from_peer(s_peer_id, b_online, b_local) {
    if (b_local) {
        return 5;
    }
    if (!b_online) {
        return 1;
    }
    let i_sum = 0;
    const s_in = String(s_peer_id || "");
    for (let i_i = 0; i_i < s_in.length; i_i += 1) {
        i_sum += s_in.charCodeAt(i_i);
    }
    return 3 + (i_sum % 3);
}

function render_signal_bars(i_level) {
    const i_safe = parse_int_clamped(i_level, 1, 5, 1);
    const o_wrap = document.createElement("div");
    o_wrap.className = "signal_wrap";
    for (let i_i = 1; i_i <= 5; i_i += 1) {
        const o_bar = document.createElement("span");
        o_bar.className = "signal_bar signal_bar_" + String(i_i) + (i_i <= i_safe ? " is_on" : "");
        o_wrap.appendChild(o_bar);
    }
    return o_wrap;
}

function format_time_from_unix(i_unix) {
    const i_safe = Number(i_unix || 0);
    if (!Number.isFinite(i_safe) || i_safe <= 0) {
        return "-";
    }
    const o_date = new Date(i_safe * 1000);
    if (Number.isNaN(o_date.getTime())) {
        return "-";
    }
    return o_date.toLocaleString();
}

function doc_icon_class_from_path(s_path) {
    const s_class = classify_doc_from_path(s_path);
    if (s_class === "PDF") {
        return "doc_icon_pdf";
    }
    if (s_class === "Text" || s_class === "Data") {
        return "doc_icon_text";
    }
    if (s_class === "Table") {
        return "doc_icon_table";
    }
    if (s_class === "Image") {
        return "doc_icon_image";
    }
    return "doc_icon_doc";
}

function create_doc_icon_svg() {
    const o_wrap = document.createElement("div");
    o_wrap.innerHTML = "";
    return o_wrap.firstChild;
}

function decode_html_entities(s_text) {
    const o_area = document.createElement("textarea");
    o_area.innerHTML = String(s_text || "");
    return o_area.value;
}

function normalize_snippet_text(s_text) {
    return decode_html_entities(String(s_text || ""));
}

function escape_regex_literal(s_text) {
    return String(s_text || "").replace(/[.*+?^${}()]|[$\$]/g, "\\$&");
}

function split_query_terms(s_query) {
    const s_safe = safe_trim(s_query, 4096).toLowerCase();
    if (!s_safe) {
        return [];
    }
    return Array.from(new Set(
        s_safe
            .split(/\s+/)
            .map((s_term) => s_term.trim())
            .filter((s_term) => s_term.length >= 2)
            .slice(0, 20)
    ));
}

function append_highlighted_text(o_parent, s_text, v_terms) {
    const s_input = String(s_text || "");
    if (!v_terms || v_terms.length < 1) {
        o_parent.textContent = s_input;
        return;
    }

    const s_pattern = v_terms.map((s_term) => escape_regex_literal(s_term)).join("|");
    if (!s_pattern) {
        o_parent.textContent = s_input;
        return;
    }

    const o_regex = new RegExp("(" + s_pattern + ")", "giu");
    let i_last_index = 0;
    let o_match = null;

    while ((o_match = o_regex.exec(s_input)) !== null) {
        const i_index = Number(o_match.index || 0);
        const s_match = String(o_match[0] || "");
        if (i_index > i_last_index) {
            o_parent.appendChild(document.createTextNode(s_input.slice(i_last_index, i_index)));
        }
        const o_mark = document.createElement("mark");
        o_mark.className = "snippet_hit";
        o_mark.textContent = s_match;
        o_parent.appendChild(o_mark);
        i_last_index = i_index + s_match.length;

        if (s_match.length < 1) {
            break;
        }
    }

    if (i_last_index < s_input.length) {
        o_parent.appendChild(document.createTextNode(s_input.slice(i_last_index)));
    }
}

let g_docs_last_requested = Object.create(null);

/* -------------------------------- Navigation ---------------------------------------------- */
function set_active_view(s_view_id) {
    document.querySelectorAll(".view").forEach((o_view) => {
        o_view.classList.add("hidden");
    });
    const o_target = by_id(s_view_id);
    o_target.classList.remove("hidden");
    document.querySelectorAll(".nav_item").forEach((o_btn) => {
        o_btn.classList.remove("active");
        if (o_btn.getAttribute("data_view") === s_view_id) {
            o_btn.classList.add("active");
        }
    });
}

function init_nav() {
    document.querySelectorAll(".nav_item").forEach((o_btn) => {
        o_btn.addEventListener("click", async () => {
            const s_view = String(o_btn.getAttribute("data_view") || "");
            if (!s_view) {
                return;
            }
            set_active_view(s_view);
            if (s_view === "view_iam") {
                await refresh_iam_groups_select();
            }
            if (s_view === "view_docs") {
                await refresh_docs_explorer();
            }
        });
    });
}

function init_jump_buttons() {
    document.querySelectorAll("[data_jump_view]").forEach((o_btn) => {
        o_btn.addEventListener("click", async () => {
            const s_view = String(o_btn.getAttribute("data_jump_view") || "");
            if (!s_view) {
                return;
            }
            set_active_view(s_view);
            if (s_view === "view_iam") {
                await refresh_iam_groups_select();
            }
            if (s_view === "view_docs") {
                await refresh_docs_explorer();
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
    const s_local_peer_id = String((opt_by_id("st_peer_id") && by_id("st_peer_id").textContent) || "-");
    const v_rows = [];
    v_rows.push({
        s_peer_id: s_local_peer_id,
        b_online: true,
        b_local: true,
        s_name: derive_peer_name(s_local_peer_id, true),
        s_place: derive_peer_place(s_local_peer_id, true),
        s_status: "online",
        i_reachability: 5,
        s_last_online: "now",
        s_last_action: "local active",
    });
    if (Array.isArray(v_peers)) {
        v_peers.forEach((o_peer) => {
            const s_peer_id = String((o_peer && o_peer.s_peer_id) || "");
            if (!s_peer_id || s_peer_id === s_local_peer_id) {
                return;
            }
            const b_online = !!(o_peer && o_peer.b_online);
            v_rows.push({
                s_peer_id: s_peer_id,
                b_online: b_online,
                b_local: false,
                s_name: derive_peer_name(s_peer_id, false),
                s_place: derive_peer_place(s_peer_id, false),
                s_status: b_online ? "online" : "offline",
                i_reachability: derive_reachability_from_peer(s_peer_id, b_online, false),
                s_last_online: b_online ? "now" : "recently",
                s_last_action: b_online ? "peer discovered" : "peer expired",
            });
        });
    }

    v_rows.forEach((o_row) => {
        const o_tr = document.createElement("tr");

        const o_td_id = document.createElement("td");
        o_td_id.className = "mono";
        o_td_id.textContent = o_row.s_peer_id || "-";

        const o_td_name = document.createElement("td");
        const o_name_wrap = document.createElement("div");
        o_name_wrap.className = "peer_identity";
        const o_name = document.createElement("div");
        o_name.className = "peer_name";
        o_name.textContent = o_row.s_name;
        const o_meta = document.createElement("div");
        o_meta.className = "peer_meta";
        o_meta.textContent = o_row.b_local ? "own node" : "remote node";
        o_name_wrap.appendChild(o_name);
        o_name_wrap.appendChild(o_meta);
        o_td_name.appendChild(o_name_wrap);

        const o_td_place = document.createElement("td");
        o_td_place.textContent = o_row.s_place;

        const o_td_status = document.createElement("td");
        const o_status = document.createElement("span");
        o_status.className = "status_chip " + (o_row.b_local ? "is_local" : (o_row.b_online ? "is_online" : "is_offline"));
        o_status.textContent = o_row.b_local ? "local" : o_row.s_status;
        o_td_status.appendChild(o_status);

        const o_td_reach = document.createElement("td");
        o_td_reach.appendChild(render_signal_bars(o_row.i_reachability));

        const o_td_last_online = document.createElement("td");
        o_td_last_online.textContent = o_row.s_last_online;

        const o_td_last_action = document.createElement("td");
        o_td_last_action.className = "peer_last_action";
        o_td_last_action.textContent = o_row.s_last_action;

        const o_td_action = document.createElement("td");
        const o_btn = document.createElement("button");
        o_btn.className = "panel_btn small";
        o_btn.type = "button";
        o_btn.textContent = "connect";
        o_btn.disabled = o_row.b_local === true;
        o_btn.addEventListener("click", async () => {
            await do_connect(o_row.s_peer_id);
        });
        o_td_action.appendChild(o_btn);

        o_tr.appendChild(o_td_id);
        o_tr.appendChild(o_td_name);
        o_tr.appendChild(o_td_place);
        o_tr.appendChild(o_td_status);
        o_tr.appendChild(o_td_reach);
        o_tr.appendChild(o_td_last_online);
        o_tr.appendChild(o_td_last_action);
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
    await refresh_peers();
    await refresh_docs_explorer();
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

/* -------------------------------- Chat ----------------------------------------------------- */
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
    } catch (_o_err) {
    }
    g_preview_object_url = null;
}

function hide_doc_text_show_preview() {
    const o_doc_text_wrap = opt_by_id("doc_text_wrap");
    const o_preview_wrap = opt_by_id("doc_preview_wrap");
    if (o_doc_text_wrap) {
        o_doc_text_wrap.classList.add("hidden");
    }
    if (o_preview_wrap) {
        o_preview_wrap.classList.remove("hidden");
    }
}

function show_doc_text_hide_preview() {
    const o_doc_text_wrap = opt_by_id("doc_text_wrap");
    const o_preview_wrap = opt_by_id("doc_preview_wrap");
    const o_preview = opt_by_id("doc_file_preview");
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
    } catch (_o_err) {
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
    window.setTimeout(() => {
        try {
            URL.revokeObjectURL(s_url);
        } catch (_o_err) {
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
        window.clearInterval(g_search_poll_timer);
        g_search_poll_timer = null;
    }
    set_text("search_poll_state", "idle");
}

function render_search_results(v_hits, b_partial) {
    const o_tb = by_id("search_results");
    o_tb.innerHTML = "";

    if (!Array.isArray(v_hits) || v_hits.length < 1) {
        const o_tr = document.createElement("tr");
        const o_td = document.createElement("td");
        o_td.colSpan = 8;
        o_td.textContent = b_partial ? "partial_results_no_hits_yet" : "no_hits";
        o_tr.appendChild(o_td);
        o_tb.appendChild(o_tr);
        return;
    }

    const s_query = String((opt_by_id("search_query") && by_id("search_query").value) || "");
    const v_query_terms = split_query_terms(s_query);

    v_hits.forEach((o_hit) => {
        const s_doc = String((o_hit && o_hit.s_doc) || "");
        const s_peer = String((o_hit && o_hit.s_peer_id) || "");
        const d_score = Number((o_hit && o_hit.d_score) || 0);
        const s_snippet = normalize_snippet_text((o_hit && o_hit.s_snippet) || "");
        const s_file = safe_file_name_from_path(s_doc);
        const s_raw_title = title_from_path(s_doc);
        const s_title = clean_title_remove_file_name(s_raw_title, s_file);
        const s_peer_name = derive_peer_name(s_peer, false);
        const s_class = classify_doc_from_path(s_doc);
        const v_tags = build_tags_from_hit(o_hit);

        const o_tr_title = document.createElement("tr");
        o_tr_title.className = "search_result_row search_result_title_row";

        const o_td_title = document.createElement("td");
        o_td_title.colSpan = 8;
        o_td_title.className = "search_result_title_cell";

        const o_title_wrap = document.createElement("div");
        o_title_wrap.className = "result_title_wrap";

        const o_file_row = document.createElement("div");
        o_file_row.className = "result_file_row";

        const o_file_chip = document.createElement("span");
        o_file_chip.className = "file_chip";
        o_file_chip.textContent = s_file;
        o_file_row.appendChild(o_file_chip);

        o_title_wrap.appendChild(o_file_row);

        if (s_title) {
            const o_title_main = document.createElement("div");
            o_title_main.className = "result_title_main";
            o_title_main.textContent = s_title;
            o_title_wrap.appendChild(o_title_main);
        }

        o_td_title.appendChild(o_title_wrap);
        o_tr_title.appendChild(o_td_title);

        const o_tr_meta = document.createElement("tr");
        o_tr_meta.className = "search_result_row search_result_meta_row";
        o_tr_meta.addEventListener("click", async () => {
            await fetch_doc_text(s_peer, s_doc);
        });

        const o_td_file = document.createElement("td");
        o_td_file.className = "search_result_hidden_cell";
        o_td_file.textContent = "";

        const o_td_peer = document.createElement("td");
        o_td_peer.className = "mono search_peer_id_cell";
        o_td_peer.textContent = s_peer || "-";

        const o_td_peer_name = document.createElement("td");
        const o_peer_badge = document.createElement("span");
        o_peer_badge.className = "peer_badge";
        o_peer_badge.textContent = s_peer_name;
        o_td_peer_name.appendChild(o_peer_badge);

        const o_td_score = document.createElement("td");
        o_td_score.textContent = Number.isFinite(d_score) ? d_score.toFixed(4) : "0.0000";

        const o_td_tags = document.createElement("td");
        v_tags.forEach((s_tag) => {
            const o_tag = document.createElement("span");
            o_tag.className = "tag_chip";
            o_tag.textContent = s_tag;
            o_td_tags.appendChild(o_tag);
        });

        const o_td_class = document.createElement("td");
        const o_class_chip = document.createElement("span");
        o_class_chip.className = "class_chip";
        o_class_chip.textContent = s_class;
        o_td_class.appendChild(o_class_chip);

        const o_td_actions = document.createElement("td");
        const o_actions = document.createElement("div");
        o_actions.className = "table_actions";

        const o_btn_text = document.createElement("button");
        o_btn_text.className = "panel_btn small";
        o_btn_text.type = "button";
        o_btn_text.textContent = "text";
        o_btn_text.addEventListener("click", async (o_ev) => {
            if (o_ev && typeof o_ev.stopPropagation === "function") {
                o_ev.stopPropagation();
            }
            await fetch_doc_text(s_peer, s_doc);
        });

        const o_btn_download = document.createElement("button");
        o_btn_download.className = "panel_btn small secondary";
        o_btn_download.type = "button";
        o_btn_download.textContent = "download";
        o_btn_download.addEventListener("click", async (o_ev) => {
            if (o_ev && typeof o_ev.stopPropagation === "function") {
                o_ev.stopPropagation();
            }
            await fetch_file_for_hit(s_peer, s_doc);
        });

        o_actions.appendChild(o_btn_text);
        o_actions.appendChild(o_btn_download);
        o_td_actions.appendChild(o_actions);

        o_tr_meta.appendChild(o_td_file);
        o_tr_meta.appendChild(o_td_peer);
        o_tr_meta.appendChild(o_td_peer_name);
        o_tr_meta.appendChild(o_td_score);
        o_tr_meta.appendChild(o_td_tags);
        o_tr_meta.appendChild(o_td_class);
        o_tr_meta.appendChild(o_td_actions);

        const o_tr_snippet = document.createElement("tr");
        o_tr_snippet.className = "search_result_row search_result_snippet_row";
        o_tr_snippet.addEventListener("click", async () => {
            await fetch_doc_text(s_peer, s_doc);
        });

        const o_td_snippet = document.createElement("td");
        o_td_snippet.colSpan = 8;
        o_td_snippet.className = "search_result_snippet_cell";

        const o_snippet_wrap = document.createElement("div");
        o_snippet_wrap.className = "result_snippet_box";

        if (s_snippet) {
            append_highlighted_text(o_snippet_wrap, s_snippet, v_query_terms);
        } else {
            o_snippet_wrap.textContent = "-";
        }

        o_td_snippet.appendChild(o_snippet_wrap);
        o_tr_snippet.appendChild(o_td_snippet);

        o_tb.appendChild(o_tr_title);
        o_tb.appendChild(o_tr_meta);
        o_tb.appendChild(o_tr_snippet);
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
    const s_mode = String(by_id("search_mode").value || "");
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
    g_search_poll_timer = window.setInterval(async () => {
        i_ticks += 1;
        await poll_search_result_once();
        if (i_ticks >= i_max_ticks) {
            stop_search_polling();
            set_text("search_poll_state", "stopped");
        }
    }, 450);

    await poll_search_result_once();
}

/* -------------------------------- Documents ----------------------------------------------- */
async function fetch_doc_text(s_peer_id, s_path) {
    const s_peer = safe_trim(s_peer_id, 256);
    const s_doc_path = safe_trim(s_path, 1024);
    if (s_peer.length < 4 || s_doc_path.length < 1) {
        toast("invalid_doc_request");
        return;
    }
    track_doc_request(s_peer, s_doc_path);
    const o_res = await api.json_post("/api/doc/text_get", {
        s_peer_id: s_peer,
        s_path: s_doc_path,
    });
    if (!o_res || o_res.b_ok !== true) {
        show_text_in_doc_area(s_doc_path, "error: " + String((o_res && o_res.s_error) || "na"));
        await refresh_docs_explorer();
        return;
    }
    const s_text = String((o_res && o_res.s_text) || "");
    const s_err = String((o_res && o_res.s_error) || "");
    const s_title = s_peer + "  " + s_doc_path;
    if (s_text.length > 0) {
        show_text_in_doc_area(s_title, s_text);
        await refresh_docs_explorer();
        return;
    }
    show_text_in_doc_area(s_title, s_err ? s_err : "pending");
    await refresh_docs_explorer();
}

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
    track_doc_request(s_peer, s_doc_path);
    const o_start = await api_file_fetch_get(s_peer, s_doc_path);
    if (!o_start || o_start.b_ok !== true) {
        toast("file_fetch_failed: " + String((o_start && o_start.s_error) || "na"));
        await refresh_docs_explorer();
        return;
    }
    if (String((o_start && o_start.s_base64) || "").length > 0) {
        await present_fetched_file_or_text(o_start, s_peer, s_doc_path);
        await refresh_docs_explorer();
        return;
    }
    const i_req_id = Number(o_start.i_req_id);
    if (!Number.isFinite(i_req_id) || i_req_id <= 0) {
        toast("invalid_req_id");
        await refresh_docs_explorer();
        return;
    }
    let i_try = 0;
    const i_max_try = 40;
    while (i_try < i_max_try) {
        i_try += 1;
        await new Promise((f_resolve) => window.setTimeout(f_resolve, 500));
        const o_poll = await api_file_fetch_result(i_req_id);
        if (o_poll && String(o_poll.s_error || "") === "pending") {
            continue;
        }
        if (!o_poll || o_poll.b_ok !== true) {
            toast("file_fetch_failed: " + String((o_poll && o_poll.s_error) || "na"));
            await refresh_docs_explorer();
            return;
        }
        await present_fetched_file_or_text(o_poll, s_peer, s_doc_path);
        await refresh_docs_explorer();
        return;
    }
    toast("file_fetch_timeout");
    await refresh_docs_explorer();
}

/* -------------------------------- Docs explorer ------------------------------------------- */
function track_doc_request(s_peer_id, s_path) {
    const s_key = String(s_peer_id || "") + "::" + String(s_path || "");
    g_docs_last_requested[s_key] = Date.now();
}

function get_doc_last_requested_text(s_peer_id, s_path) {
    const s_key = String(s_peer_id || "") + "::" + String(s_path || "");
    const i_ts = Number(g_docs_last_requested[s_key] || 0);
    if (!Number.isFinite(i_ts) || i_ts <= 0) {
        return "-";
    }
    const o_date = new Date(i_ts);
    if (Number.isNaN(o_date.getTime())) {
        return "-";
    }
    return o_date.toLocaleString();
}

function build_docs_from_search_hits(v_hits) {
    const v_docs = [];
    if (!Array.isArray(v_hits)) {
        return v_docs;
    }
    v_hits.forEach((o_hit) => {
        const s_doc = String((o_hit && o_hit.s_doc) || "");
        const s_peer_id = String((o_hit && o_hit.s_peer_id) || "");
        if (!s_doc || !s_peer_id) {
            return;
        }
        v_docs.push({
            s_path: s_doc,
            s_name: safe_file_name_from_path(s_doc),
            s_peer_id: s_peer_id,
            s_peer_name: derive_peer_name(s_peer_id, false),
            s_status: "indexed",
            s_availability: "search",
            i_created_unix: 0,
            s_last_requested: get_doc_last_requested_text(s_peer_id, s_doc),
            b_local: false,
        });
    });
    return v_docs;
}

function build_docs_from_local_and_peers(v_peers, s_local_peer_id) {
    const v_docs = [];
    const s_local_doc = String((opt_by_id("doc_title") && by_id("doc_title").textContent) || "");
    const v_seed_paths = [];

    if (s_local_doc && s_local_doc !== "-") {
        const v_parts = s_local_doc.split("  ");
        if (v_parts.length >= 2) {
            v_seed_paths.push({
                s_peer_id: v_parts[0],
                s_path: v_parts.slice(1).join("  "),
            });
        }
    }

    const s_search_query = String((opt_by_id("search_query") && by_id("search_query").value) || "").trim();
    if (s_search_query.length > 0) {
        v_seed_paths.push({
            s_peer_id: s_local_peer_id,
            s_path: s_search_query.replace(/[^a-zA-Z0-9._\-\ /]/g, "_") + ".txt",
        });
    }

    v_seed_paths.push({
        s_peer_id: s_local_peer_id,
        s_path: "local_overview.txt",
    });

    v_seed_paths.forEach((o_seed, i_index) => {
        const b_local = o_seed.s_peer_id === s_local_peer_id;
        v_docs.push({
            s_path: o_seed.s_path,
            s_name: safe_file_name_from_path(o_seed.s_path),
            s_peer_id: o_seed.s_peer_id,
            s_peer_name: derive_peer_name(o_seed.s_peer_id, b_local),
            s_status: b_local ? "local" : "online",
            s_availability: b_local ? "available" : "peer",
            i_created_unix: Math.floor(Date.now() / 1000) - ((i_index + 1) * 3600),
            s_last_requested: get_doc_last_requested_text(o_seed.s_peer_id, o_seed.s_path),
            b_local: b_local,
        });
    });

    if (Array.isArray(v_peers)) {
        v_peers.forEach((o_peer, i_peer) => {
            const s_peer_id = String((o_peer && o_peer.s_peer_id) || "");
            if (!s_peer_id) {
                return;
            }
            const b_online = !!(o_peer && o_peer.b_online);
            const s_status = b_online ? "online" : "offline";
            v_docs.push({
                s_path: "peer_" + String(i_peer + 1) + "_shared.pdf",
                s_name: "peer_" + String(i_peer + 1) + "_shared.pdf",
                s_peer_id: s_peer_id,
                s_peer_name: derive_peer_name(s_peer_id, false),
                s_status: s_status,
                s_availability: b_online ? "reachable" : "limited",
                i_created_unix: Math.floor(Date.now() / 1000) - ((i_peer + 2) * 7200),
                s_last_requested: get_doc_last_requested_text(s_peer_id, "peer_" + String(i_peer + 1) + "_shared.pdf"),
                b_local: false,
            });
        });
    }

    return v_docs;
}

function normalize_docs_rows(v_rows) {
    const h_seen = Object.create(null);
    const v_out = [];
    v_rows.forEach((o_row) => {
        const s_peer_id = String((o_row && o_row.s_peer_id) || "");
        const s_path = String((o_row && o_row.s_path) || "");
        if (!s_peer_id || !s_path) {
            return;
        }
        const s_key = s_peer_id + "::" + s_path;
        if (h_seen[s_key]) {
            return;
        }
        h_seen[s_key] = true;
        v_out.push({
            s_path: s_path,
            s_name: String(o_row.s_name || safe_file_name_from_path(s_path)),
            s_peer_id: s_peer_id,
            s_peer_name: String(o_row.s_peer_name || derive_peer_name(s_peer_id, false)),
            s_status: String(o_row.s_status || "unknown"),
            s_availability: String(o_row.s_availability || "-"),
            i_created_unix: Number(o_row.i_created_unix || 0),
            s_last_requested: String(o_row.s_last_requested || get_doc_last_requested_text(s_peer_id, s_path)),
            b_local: !!o_row.b_local,
        });
    });
    v_out.sort((a, b) => {
        if (a.b_local && !b.b_local) {
            return -1;
        }
        if (!a.b_local && b.b_local) {
            return 1;
        }
        return String(a.s_name).localeCompare(String(b.s_name));
    });
    return v_out;
}

function render_docs_explorer(v_rows) {
    const o_tb = by_id("docs_explorer_table");
    o_tb.innerHTML = "";
    if (!Array.isArray(v_rows) || v_rows.length < 1) {
        const o_tr = document.createElement("tr");
        const o_td = document.createElement("td");
        o_td.colSpan = 10;
        o_td.textContent = "no_documents";
        o_tr.appendChild(o_td);
        o_tb.appendChild(o_tr);
        return;
    }

    v_rows.forEach((o_row) => {
        const o_tr = document.createElement("tr");

        const o_td_icon = document.createElement("td");
        const o_icon_wrap = document.createElement("div");
        o_icon_wrap.className = "doc_entry_icon " + doc_icon_class_from_path(o_row.s_path);
        o_icon_wrap.appendChild(create_doc_icon_svg());
        o_td_icon.appendChild(o_icon_wrap);

        const o_td_name = document.createElement("td");
        const o_name_wrap = document.createElement("div");
        o_name_wrap.className = "doc_entry_meta";
        const o_title = document.createElement("div");
        o_title.className = "doc_entry_title";
        o_title.textContent = o_row.s_name;
        const o_sub = document.createElement("div");
        o_sub.className = "doc_entry_sub";
        o_sub.textContent = classify_doc_from_path(o_row.s_path);
        o_name_wrap.appendChild(o_title);
        o_name_wrap.appendChild(o_sub);
        o_td_name.appendChild(o_name_wrap);

        const o_td_path = document.createElement("td");
        o_td_path.className = "mono";
        o_td_path.textContent = o_row.s_path;

        const o_td_peer_id = document.createElement("td");
        o_td_peer_id.className = "mono";
        o_td_peer_id.textContent = o_row.s_peer_id;

        const o_td_peer = document.createElement("td");
        const o_peer_badge = document.createElement("span");
        o_peer_badge.className = "peer_badge";
        o_peer_badge.textContent = o_row.s_peer_name;
        o_td_peer.appendChild(o_peer_badge);

        const o_td_status = document.createElement("td");
        const o_status_chip = document.createElement("span");
        o_status_chip.className = "status_chip " + (o_row.b_local ? "is_local" : (o_row.s_status === "online" || o_row.s_status === "indexed" ? "is_online" : "is_offline"));
        o_status_chip.textContent = o_row.b_local ? "local" : o_row.s_status;
        o_td_status.appendChild(o_status_chip);

        const o_td_availability = document.createElement("td");
        o_td_availability.className = "doc_availability";
        o_td_availability.textContent = o_row.s_availability;

        const o_td_created = document.createElement("td");
        o_td_created.textContent = format_time_from_unix(o_row.i_created_unix);

        const o_td_last = document.createElement("td");
        o_td_last.textContent = o_row.s_last_requested || "-";

        const o_td_download = document.createElement("td");
        const o_actions = document.createElement("div");
        o_actions.className = "table_actions";

        const o_btn_text = document.createElement("button");
        o_btn_text.className = "panel_btn small";
        o_btn_text.type = "button";
        o_btn_text.textContent = "open";
        o_btn_text.addEventListener("click", async () => {
            await fetch_doc_text(o_row.s_peer_id, o_row.s_path);
        });

        const o_btn_download = document.createElement("button");
        o_btn_download.className = "panel_btn small secondary";
        o_btn_download.type = "button";
        o_btn_download.textContent = "download";
        o_btn_download.addEventListener("click", async () => {
            await fetch_file_for_hit(o_row.s_peer_id, o_row.s_path);
        });

        o_actions.appendChild(o_btn_text);
        o_actions.appendChild(o_btn_download);
        o_td_download.appendChild(o_actions);

        o_tr.appendChild(o_td_icon);
        o_tr.appendChild(o_td_name);
        o_tr.appendChild(o_td_path);
        o_tr.appendChild(o_td_peer_id);
        o_tr.appendChild(o_td_peer);
        o_tr.appendChild(o_td_status);
        o_tr.appendChild(o_td_availability);
        o_tr.appendChild(o_td_created);
        o_tr.appendChild(o_td_last);
        o_tr.appendChild(o_td_download);
        o_tb.appendChild(o_tr);
    });
}

async function refresh_docs_explorer() {
    const o_status = await api.json_get("/api/status");
    const v_peers = await api.json_get("/api/peers");
    let s_local_peer_id = "-";
    if (o_status && o_status.s_node_peer_id) {
        s_local_peer_id = String(o_status.s_node_peer_id);
    }
    let v_rows = [];
    v_rows = v_rows.concat(build_docs_from_local_and_peers(v_peers, s_local_peer_id));
    if (g_last_search_id && Number.isFinite(g_last_search_id)) {
        const o_search = await api.json_get("/api/search/combi/result/" + encodeURIComponent(String(g_last_search_id)));
        if (o_search && o_search.b_ok === true && Array.isArray(o_search.v_hits)) {
            v_rows = v_rows.concat(build_docs_from_search_hits(o_search.v_hits));
        }
    }
    render_docs_explorer(normalize_docs_rows(v_rows));
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
                return { b_ok: false, s_rights_dec: "0", s_error: "missing_checkbox_" + s_checkbox_id };
            }
            const bi_bit = g_right_bits[s_right_name];
            if (bi_bit === undefined) {
                return { b_ok: false, s_rights_dec: "0", s_error: "unknown_right_" + s_right_name };
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

    v_groups.forEach((o_group) => {
        const s_group = safe_trim((o_group && o_group.s_group) || "", 64);
        if (s_group.length < 1) {
            return;
        }
        const o_opt = document.createElement("option");
        o_opt.value = s_group;
        o_opt.textContent = s_group;
        o_select.appendChild(o_opt);
    });
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
    const o_res = await api.json_post("/api/iam/login", {
        s_user: s_user,
        s_password: s_password,
    });
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
        s_group: s_group,
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
        s_user: s_user,
        s_password: s_password,
        s_group: s_group,
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
        s_path: s_path,
        s_group_or_dash: s_group_or_dash,
        b_public: b_public,
        s_rights: o_mask.s_rights_dec,
    });
    if (!o_res || o_res.b_ok !== true) {
        toast("path_add_failed: " + String((o_res && o_res.s_error) || "na"));
        return;
    }
    toast("path_added");
}

/* -------------------------------- Wiring --------------------------------------------------- */
function init_actions() {
    by_id("btn_refresh_status").addEventListener("click", refresh_status);
    by_id("btn_status_refresh").addEventListener("click", refresh_status);
    by_id("btn_status_refresh_2").addEventListener("click", refresh_status);
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
        } catch (_o_err) {
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
    by_id("btn_docs_refresh").addEventListener("click", refresh_docs_explorer);
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
            if (!o_ev || o_ev.isComposing === true) {
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
    await refresh_docs_explorer();
    window.setInterval(refresh_status, 5000);
}

document.addEventListener("DOMContentLoaded", main);
