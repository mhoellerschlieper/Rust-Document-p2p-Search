/* ============================================================================================
Module name : web_ui
File        : app.js
Author      : Marcus Schlieper
------------------------------------------------------------------------------------------------
Description
- Client side SPA logic for secure_p2p_ext dashboard UI.
- Dashboard navigation, status, peers, events, p2p, search and iam actions.
- Search result handling:
  - click hit or text button loads extracted text into doc_text
  - download button fetches file
  - pdf is shown in document_preview
  - non pdf is downloaded and text view is shown in doc_text
- Defensive handling:
  - safe input trimming
  - timeout protected fetch wrappers
  - optional DOM elements do not break init
  - preview and text areas are switched mutually exclusive

History
2026-01-11  Marcus Schlieper
- Rewritten dashboard navigation and network combi search polling
2026-01-11  Marcus Schlieper
- Fix view navigation reads data-view attribute consistently
2026-01-11  Marcus Schlieper
- Update rights checkboxes compute s_rights mask via BigInt
2026-01-11  Marcus Schlieper
- Update user add group selection via /api/iam/groups
2026-01-11  Marcus Schlieper
- Fix robust checkbox wiring without hard dependency on preview elements
2026-05-13  Marcus Schlieper
- Integrated search result download and document preview handling
- Non pdf files are downloaded and text is shown in doc_text
- Pdf files are shown in document_preview and text area is hidden
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
        const i_timeout_ms = 8000;
        const t = setTimeout(() => ctrl.abort(), i_timeout_ms);

        try {
            const r = await fetch(s_url, { ...o_opts, signal: ctrl.signal });

            if (!r.ok) {
                let s_body = "";
                try {
                    s_body = await r.text();
                    if (s_body.length > 512) {
                        s_body = s_body.slice(0, 512);
                    }
                } catch (_e) {
                    s_body = "";
                }

                const s_err =
                    "http_error_" + String(r.status) + (s_body ? ": " + s_body : "");
                return { b_ok: false, s_error: s_err };
            }

            const s_ct = (r.headers.get("content-type") || "").toLowerCase();
            if (s_ct.indexOf("application/json") < 0) {
                return { b_ok: false, s_error: "unexpected_content_type" };
            }

            return await r.json();
        } catch (e) {
            const s_msg = e && e.message ? String(e.message) : "fetch_failed";
            return { b_ok: false, s_error: s_msg };
        } finally {
            clearTimeout(t);
        }
    },
};

/* -------------------------------- DOM helpers --------------------------------------------- */
function by_id(s_id) {
    const el = document.getElementById(s_id);
    if (!el) {
        throw new Error("missing_element_" + String(s_id || ""));
    }
    return el;
}

function opt_by_id(s_id) {
    return document.getElementById(s_id);
}

function set_text(s_id, s_text) {
    const el = opt_by_id(s_id);
    if (!el) {
        return;
    }
    el.textContent = s_text === null || s_text === undefined ? "" : String(s_text);
}

function toast(s_text) {
    const el = opt_by_id("toast");
    if (!el) {
        return;
    }
    el.textContent = String(s_text || "");
    el.classList.remove("hidden");
    setTimeout(() => el.classList.add("hidden"), 2600);
}

function safe_trim(s_value, i_max_len) {
    const s = String(s_value || "").trim();
    if (s.length > i_max_len) {
        return s.slice(0, i_max_len);
    }
    return s;
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
    document.querySelectorAll(".view").forEach((v) => v.classList.add("hidden"));
    by_id(s_view_id).classList.remove("hidden");

    document.querySelectorAll(".nav_item").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".nav_item").forEach((b) => {
        if (b.getAttribute("data-view") === s_view_id) {
            b.classList.add("active");
        }
    });
}

/* -------------------------------- Status, peers, events ----------------------------------- */
async function refresh_status() {
    const st = await api.json_get("/api/status");

    if (!st || st.s_node_peer_id === undefined) {
        set_text("status_badge", "offline");
        const el = opt_by_id("status_badge");
        if (el) {
            el.classList.remove("badge_on");
            el.classList.add("badge_off");
        }
        return;
    }

    set_text("st_peer_id", st.s_node_peer_id || "-");
    set_text("st_known_peers", String(st.i_known_peers || 0));
    set_text("st_chat_peer", st.s_chat_peer || "-");
    set_text("st_chat_topic", st.s_chat_topic || "-");

    set_text("st_peer_id_2", st.s_node_peer_id || "-");
    set_text("st_known_peers_2", String(st.i_known_peers || 0));
    set_text("st_chat_peer_2", st.s_chat_peer || "-");
    set_text("st_chat_topic_2", st.s_chat_topic || "-");

    set_text("status_badge", "online");
    const el = opt_by_id("status_badge");
    if (el) {
        el.classList.remove("badge_off");
        el.classList.add("badge_on");
    }
}

async function refresh_peers() {
    const tb = by_id("peers_table");
    tb.innerHTML = "";

    const v = await api.json_get("/api/peers");
    if (!Array.isArray(v)) {
        toast("peers_refresh_failed");
        return;
    }

    v.forEach((p) => {
        const s_peer_id = String((p && p.s_peer_id) || "");
        const b_online = !!(p && p.b_online);

        const tr = document.createElement("tr");

        const td_id = document.createElement("td");
        td_id.textContent = s_peer_id;
        td_id.className = "mono";

        const td_on = document.createElement("td");
        td_on.textContent = b_online ? "true" : "false";

        const td_act = document.createElement("td");
        const btn = document.createElement("button");
        btn.className = "btn small";
        btn.textContent = "connect";
        btn.addEventListener("click", async () => {
            await do_connect(s_peer_id);
        });

        td_act.appendChild(btn);
        tr.appendChild(td_id);
        tr.appendChild(td_on);
        tr.appendChild(td_act);
        tb.appendChild(tr);
    });
}

async function refresh_events() {
    const v = await api.json_get("/api/events");
    if (!Array.isArray(v)) {
        toast("events_refresh_failed");
        return;
    }
    by_id("events_box").textContent = v.map((x) => String(x || "")).join("\n");
}

/* -------------------------------- P2P ----------------------------------------------------- */
async function do_connect(s_peer_id) {
    const s_id = safe_trim(s_peer_id, 256);
    if (s_id.length < 4) {
        toast("invalid_peer_id");
        return;
    }

    const r = await api.json_post("/api/p2p/connect", { s_peer_id: s_id });
    if (!r || r.b_ok !== true) {
        toast("connect_failed: " + String((r && r.s_error) || "na"));
        return;
    }

    toast("connect_sent");
    await refresh_status();
}

async function do_send_text() {
    const s_text = safe_trim(by_id("send_text").value, 10000);
    if (s_text.length < 1) {
        toast("empty_text");
        return;
    }

    const r = await api.json_post("/api/p2p/send_text", { s_text });
    if (!r || r.b_ok !== true) {
        toast("send_failed: " + String((r && r.s_error) || "na"));
        return;
    }

    by_id("send_text").value = "";
    toast("sent");
}

/* -------------------------------- Document preview state ---------------------------------- */
let g_search_poll_timer = null;
let g_last_search_id = null;
let g_preview_object_url = null;

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
    const el_doc_text = opt_by_id("doc_text");
    const el_doc_text_wrap = opt_by_id("doc_text_wrap");
    const el_preview_wrap = opt_by_id("doc_preview_wrap");

    if (el_doc_text) {
        el_doc_text.classList.add("hidden");
    }
    if (el_doc_text_wrap) {
        el_doc_text_wrap.classList.add("hidden");
    }
    if (el_preview_wrap) {
        el_preview_wrap.classList.remove("hidden");
    }
}

function show_doc_text_hide_preview() {
    const el_doc_text = opt_by_id("doc_text");
    const el_doc_text_wrap = opt_by_id("doc_text_wrap");
    const el_preview_wrap = opt_by_id("doc_preview_wrap");
    const el_preview = opt_by_id("doc_file_preview");

    if (el_doc_text) {
        el_doc_text.classList.remove("hidden");
    }
    if (el_doc_text_wrap) {
        el_doc_text_wrap.classList.remove("hidden");
    }
    if (el_preview_wrap) {
        el_preview_wrap.classList.add("hidden");
    }

    if (el_preview) {
        if (el_preview.tagName === "IFRAME" || el_preview.tagName === "IMG") {
            el_preview.setAttribute("src", "");
        } else {
            el_preview.innerHTML = "";
        }
    }

    revoke_preview_object_url();
}

function clear_doc_view() {
    set_text("doc_title", "-");

    const el_doc_text = opt_by_id("doc_text");
    if (el_doc_text) {
        el_doc_text.textContent = "";
    }

    const el_preview = opt_by_id("doc_file_preview");
    if (el_preview) {
        if (el_preview.tagName === "IFRAME" || el_preview.tagName === "IMG") {
            el_preview.setAttribute("src", "");
        } else {
            el_preview.innerHTML = "";
        }
    }

    revoke_preview_object_url();
    show_doc_text_hide_preview();
}

function is_pdf_mime(s_mime) {
    return String(s_mime || "").toLowerCase() === "application/pdf";
}

function can_inline_show(s_mime) {
    return is_pdf_mime(s_mime);
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

    const el_link = document.createElement("a");
    el_link.href = s_url;
    el_link.download = s_name || "download.bin";
    el_link.rel = "noopener";

    document.body.appendChild(el_link);
    el_link.click();
    document.body.removeChild(el_link);

    setTimeout(() => {
        try {
            URL.revokeObjectURL(s_url);
        } catch (_e) {
            /* ignore cleanup failure */
        }
    }, 60000);
}

function show_pdf_preview_from_blob(o_blob) {
    const el_preview = opt_by_id("doc_file_preview");
    if (!el_preview) {
        return false;
    }

    revoke_preview_object_url();
    g_preview_object_url = URL.createObjectURL(o_blob);

    if (el_preview.tagName === "IFRAME" || el_preview.tagName === "IMG") {
        el_preview.setAttribute("src", g_preview_object_url);
    } else {
        el_preview.innerHTML = "";
        const el_iframe = document.createElement("iframe");
        el_iframe.setAttribute("src", g_preview_object_url);
        el_iframe.setAttribute("title", "document_preview");
        el_iframe.style.width = "100%";
        el_iframe.style.minHeight = "480px";
        el_iframe.style.border = "0";
        el_preview.appendChild(el_iframe);
    }

    hide_doc_text_show_preview();
    return true;
}

function show_text_in_doc_area(s_title, s_text) {
    set_text("doc_title", s_title);
    show_doc_text_hide_preview();

    const el_doc_text = opt_by_id("doc_text");
    if (el_doc_text) {
        el_doc_text.textContent = String(s_text || "");
    }
}

/* -------------------------------- Network combi search ------------------------------------ */
function stop_search_polling() {
    if (g_search_poll_timer) {
        clearInterval(g_search_poll_timer);
        g_search_poll_timer = null;
    }
    set_text("search_poll_state", "idle");
}

function render_search_results(v_hits, b_partial) {
    const box = by_id("search_results");
    box.innerHTML = "";

    const head = document.createElement("div");
    head.className = "muted";
    head.textContent = b_partial ? "partial_results" : "final_results";
    box.appendChild(head);

    if (!Array.isArray(v_hits) || v_hits.length === 0) {
        const empty = document.createElement("div");
        empty.className = "muted";
        empty.textContent = "no_hits";
        box.appendChild(empty);
        return;
    }

    v_hits.forEach((h) => {
        const s_doc = String((h && h.s_doc) || "");
        const s_peer = String((h && h.s_peer_id) || "");
        const d_score = Number((h && h.d_score) || 0);
        const s_snip = String((h && h.s_snippet) || "");

        const card = document.createElement("div");
        card.className = "hit";

        const line1 = document.createElement("div");
        line1.className = "hit_title";
        line1.textContent =
            (Number.isFinite(d_score) ? d_score : 0).toFixed(4) + "  " + s_doc;

        const line2 = document.createElement("div");
        line2.className = "hit_snippet";
        line2.textContent = "peer=" + (s_peer ? s_peer : "-");

        const line3 = document.createElement("div");
        line3.className = "hit_snippet";
        line3.textContent = s_snip ? s_snip : "";

        const actions = document.createElement("div");
        actions.className = "hit_actions";

        const btn_text = document.createElement("button");
        btn_text.className = "btn small";
        btn_text.textContent = "text";
        btn_text.addEventListener("click", async (ev) => {
            if (ev && typeof ev.stopPropagation === "function") {
                ev.stopPropagation();
            }
            await fetch_doc_text(s_peer, s_doc);
        });

        const btn_download = document.createElement("button");
        btn_download.className = "btn small";
        btn_download.textContent = "download";
        btn_download.addEventListener("click", async (ev) => {
            if (ev && typeof ev.stopPropagation === "function") {
                ev.stopPropagation();
            }
            await fetch_file_for_hit(s_peer, s_doc);
        });

        card.addEventListener("click", async () => {
            await fetch_doc_text(s_peer, s_doc);
        });

        actions.appendChild(btn_text);
        actions.appendChild(btn_download);

        card.appendChild(line1);
        card.appendChild(line2);
        card.appendChild(line3);
        card.appendChild(actions);

        box.appendChild(card);
    });
}

async function poll_search_result_once() {
    if (!g_last_search_id || !Number.isFinite(g_last_search_id)) {
        toast("no_search_id");
        return;
    }

    set_text("search_poll_state", "polling");

    const s_url =
        "/api/search/combi/result/" + encodeURIComponent(String(g_last_search_id));
    const rr = await api.json_get(s_url);

    if (!rr || rr.b_ok !== true) {
        render_search_results([], true);
        return;
    }

    const b_partial = rr.b_partial === true;
    render_search_results(rr.v_hits || [], b_partial);

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

    const r = await api.json_post("/api/search/combi/dispatch", {
        s_query,
        i_limit,
    });

    if (!r || r.b_ok !== true) {
        toast("dispatch_failed: " + String((r && r.s_error) || "na"));
        return;
    }

    const i_search_id = Number(r.i_search_id);
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

/* -------------------------------- Document text fetch ------------------------------------- */
async function fetch_doc_text(s_peer_id, s_path) {
    const s_peer = safe_trim(s_peer_id, 256);
    const s_p = safe_trim(s_path, 1024);

    if (s_peer.length < 4 || s_p.length < 1) {
        toast("invalid_doc_request");
        return;
    }

    const r = await api.json_post("/api/doc/text_get", {
        s_peer_id: s_peer,
        s_path: s_p,
    });

    if (!r || r.b_ok !== true) {
        show_text_in_doc_area(s_p, "error: " + String((r && r.s_error) || "na"));
        return;
    }

    const s_text = String((r && r.s_text) || "");
    const s_err = String((r && r.s_error) || "");
    const s_title = s_peer + "  " + s_p;

    if (s_text.length > 0) {
        show_text_in_doc_area(s_title, s_text);
        return;
    }

    show_text_in_doc_area(s_title, s_err ? s_err : "pending");
}

/* -------------------------------- File fetch for search hits ------------------------------- */
async function api_file_fetch_get(s_peer_id, s_path) {
    const s_peer = safe_trim(s_peer_id, 256);
    const s_p = safe_trim(s_path, 1024);

    if (s_peer.length < 4 || s_p.length < 1) {
        return { b_ok: false, s_error: "invalid_file_request" };
    }

    return await api.json_post("/api/file/fetch_get", {
        s_peer_id: s_peer,
        s_path: s_p,
    });
}

async function api_file_fetch_result(i_req_id) {
    const i_id = Number(i_req_id);
    if (!Number.isFinite(i_id) || i_id <= 0) {
        return { b_ok: false, s_error: "invalid_req_id" };
    }

    return await api.json_get(
        "/api/file/fetch_result/" + encodeURIComponent(String(i_id))
    );
}

async function present_fetched_file_or_text(o_file, s_peer_id, s_path) {
    const s_mime = String((o_file && o_file.s_mime) || "").toLowerCase();
    const s_title = safe_trim(s_peer_id, 256) + "  " + safe_trim(s_path, 1024);
    const s_name_raw = String((o_file && o_file.s_name) || "");
    const s_name =
        s_name_raw.length > 0
            ? safe_file_name_from_path(s_name_raw)
            : safe_file_name_from_path(s_path);

    const o_blob = base64_to_blob(String((o_file && o_file.s_base64) || ""), s_mime);
    if (!o_blob) {
        show_text_in_doc_area(s_title, "error: invalid_file_payload");
        return;
    }

    if (can_inline_show(s_mime)) {
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
    const s_p = safe_trim(s_path, 1024);

    if (s_peer.length < 4 || s_p.length < 1) {
        toast("invalid_file_request");
        return;
    }

    const o_start = await api_file_fetch_get(s_peer, s_p);
    if (!o_start || o_start.b_ok !== true) {
        toast("file_fetch_failed: " + String((o_start && o_start.s_error) || "na"));
        return;
    }

    if (String((o_start && o_start.s_base64) || "").length > 0) {
        await present_fetched_file_or_text(o_start, s_peer, s_p);
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

        await present_fetched_file_or_text(o_poll, s_peer, s_p);
        return;
    }

    toast("file_fetch_timeout");
}

/* -------------------------------- IAM rights bitmask -------------------------------------- */
/* Central function history entry:
2026-01-11 Marcus Schlieper
- Fix robust checkbox mapping and optional preview update.
*/
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
            const el = opt_by_id(s_checkbox_id);
            if (!el) {
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

            if (el.checked === true) {
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
    } catch (e) {
        const s_msg = e && e.message ? String(e.message) : "mask_compute_failed";
        return { b_ok: false, s_rights_dec: "0", s_error: s_msg };
    }
}

function wire_rights_checkboxes(o_map_name_to_checkbox_id, s_preview_id_optional) {
    const update = () => {
        const r = compute_rights_mask_from_named_boxes(o_map_name_to_checkbox_id);
        if (s_preview_id_optional) {
            set_text(s_preview_id_optional, r.s_rights_dec);
        }
    };

    for (const s_right_name of Object.keys(o_map_name_to_checkbox_id)) {
        const s_checkbox_id = String(o_map_name_to_checkbox_id[s_right_name] || "");
        const el = opt_by_id(s_checkbox_id);
        if (!el) {
            continue;
        }
        el.addEventListener("change", update);
    }

    update();
}

/* -------------------------------- IAM groups select --------------------------------------- */
async function refresh_iam_groups_select() {
    const el_select = opt_by_id("iam_user_group_select");
    if (!el_select) {
        return;
    }

    el_select.innerHTML = "";

    const opt0 = document.createElement("option");
    opt0.value = "";
    opt0.textContent = "select_group";
    opt0.disabled = true;
    opt0.selected = true;
    el_select.appendChild(opt0);

    const v_groups = await api.json_get("/api/iam/groups");
    if (!Array.isArray(v_groups)) {
        const s_err = v_groups && v_groups.s_error ? String(v_groups.s_error) : "na";
        toast("groups_list_failed: " + s_err);
        return;
    }

    for (const g of v_groups) {
        const s_group = safe_trim((g && g.s_group) || "", 64);
        if (s_group.length < 1) {
            continue;
        }

        const opt = document.createElement("option");
        opt.value = s_group;
        opt.textContent = s_group;
        el_select.appendChild(opt);
    }

    if (el_select.options.length <= 1) {
        toast("no_groups_available");
    }
}

/* -------------------------------- IAM actions --------------------------------------------- */
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

    const r = await api.json_post("/api/iam/login", { s_user, s_password });
    if (!r || r.b_ok !== true) {
        toast("login_failed: " + String((r && r.s_error) || "na"));
        return;
    }

    set_text("iam_session", r.s_session || "-");
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

    const r = await api.json_post("/api/iam/group_add", {
        s_group,
        s_rights: o_mask.s_rights_dec,
    });

    if (!r || r.b_ok !== true) {
        toast("group_add_failed: " + String((r && r.s_error) || "na"));
        return;
    }

    toast("group_added");
    await refresh_iam_groups_select();
}

async function do_iam_user_add() {
    const s_user = safe_trim(by_id("iam_user").value, 64);
    const s_password = String(by_id("iam_user_pass").value || "");
    const el_select = opt_by_id("iam_user_group_select");

    if (!el_select) {
        toast("missing_group_select");
        return;
    }

    const s_group = safe_trim(el_select.value, 64);

    if (s_user.length < 1 || s_group.length < 1 || s_password.length < 1) {
        toast("invalid_input");
        return;
    }
    if (s_password.length > 256) {
        toast("invalid_password");
        return;
    }

    const r = await api.json_post("/api/iam/user_add", {
        s_user,
        s_password,
        s_group,
    });

    if (!r || r.b_ok !== true) {
        toast("user_add_failed: " + String((r && r.s_error) || "na"));
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

    const r = await api.json_post("/api/iam/path_add", {
        s_path,
        s_group_or_dash,
        b_public,
        s_rights: o_mask.s_rights_dec,
    });

    if (!r || r.b_ok !== true) {
        toast("path_add_failed: " + String((r && r.s_error) || "na"));
        return;
    }

    toast("path_added");
}

/* -------------------------------- Wiring -------------------------------------------------- */
function init_nav() {
    document.querySelectorAll(".nav_item").forEach((b) => {
        b.addEventListener("click", async () => {
            const s_view = b.getAttribute("data-view");
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
    by_id("btn_events_refresh_from_status").addEventListener("click", refresh_events);
    by_id("btn_refresh_peers").addEventListener("click", refresh_peers);
    by_id("btn_refresh_events").addEventListener("click", refresh_events);

    by_id("btn_clear_events_box").addEventListener("click", () => {
        by_id("events_box").textContent = "";
    });

    by_id("btn_copy_local_peer_id").addEventListener("click", async () => {
        try {
            const s = String(by_id("st_peer_id").textContent || "");
            if (s && navigator.clipboard && navigator.clipboard.writeText) {
                await navigator.clipboard.writeText(s);
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

    by_id("btn_search").addEventListener("click", async (e) => {
        if (e && typeof e.preventDefault === "function") {
            e.preventDefault();
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

    by_id("btn_iam_login").addEventListener("click", do_iam_login);
    by_id("btn_iam_group_add").addEventListener("click", do_iam_group_add);
    by_id("btn_iam_user_add").addEventListener("click", do_iam_user_add);
    by_id("btn_iam_path_add").addEventListener("click", do_iam_path_add);

    const el_doc_clear = opt_by_id("btn_doc_clear");
    if (el_doc_clear) {
        el_doc_clear.addEventListener("click", () => {
            clear_doc_view();
        });
    }

    const el_search_query = opt_by_id("search_query");
    if (el_search_query) {
        el_search_query.addEventListener("keydown", async (ev) => {
            if (!ev) {
                return;
            }
            if (ev.isComposing === true) {
                return;
            }
            if (ev.key === "Enter") {
                ev.preventDefault();
                await do_search();
            }
        });
    }

    const el_search_form = opt_by_id("search_form");
    if (el_search_form) {
        el_search_form.addEventListener("submit", async (ev) => {
            if (ev && typeof ev.preventDefault === "function") {
                ev.preventDefault();
            }
            await do_search();
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

/* -------------------------------- Main ---------------------------------------------------- */
async function main() {
    try {
        init_nav();
        init_actions();
    } catch (e) {
        toast("init_failed: " + String((e && e.message) || "na"));
        return;
    }

    try {
        init_iam_rights_wiring();
    } catch (_e) {
        /* optional checkbox area may be absent */
    }

    await refresh_iam_groups_select();
    await refresh_status();
    setInterval(refresh_status, 5000);
}

document.addEventListener("DOMContentLoaded", main);
