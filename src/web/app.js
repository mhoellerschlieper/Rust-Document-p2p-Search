/*==============================================================================================
Module name : web_ui
File        : app.js
Author      : Marcus Schlieper
----------------------------------------------------------------------------------------------
Description
- Client side SPA logic for secure_p2p_ext dashboard UI.
- Dashboard: sidebar navigation + header + content views.
- Fix: nav uses data-view (hyphen) consistently.
- IAM:
  - group add and path add: rights mask computed from checkboxes using BigInt
  - user add: group selected from a select box populated via GET /api/iam/groups
- Defensive:
  - timeouts, input validation, safe rendering
  - optional DOM elements do not break app init
History
2026-01-11  Marcus Schlieper  - Rewritten: dashboard navigation and network combi search polling
2026-01-11  Marcus Schlieper  - Fix: view navigation reads data-view attribute consistently
2026-01-11  Marcus Schlieper  - Update: rights checkboxes compute s_rights mask (BigInt, dec string)
2026-01-11  Marcus Schlieper  - Update: user add group selection via /api/iam/groups
2026-01-11  Marcus Schlieper  - Fix: robust checkbox wiring without hard dependency on preview elements
==============================================================================================*/
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
        /* Defensive: try to read response body for diagnostics, bounded length */
        let s_body = "";
        try {
          s_body = await r.text();
          if (s_body.length > 512) s_body = s_body.slice(0, 512);
        } catch (_e) {
          s_body = "";
        }

        const s_err = "http_error_" + String(r.status) + (s_body ? (": " + s_body) : "");
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

/* -------------------------------- DOM helpers ---------------------------------------------- */
function by_id(s_id) {
  const el = document.getElementById(s_id);
  if (!el) throw new Error("missing_element_" + String(s_id || ""));
  return el;
}

function opt_by_id(s_id) {
  return document.getElementById(s_id);
}

function set_text(s_id, s_text) {
  const el = opt_by_id(s_id);
  if (!el) return;
  el.textContent = s_text === null || s_text === undefined ? "" : String(s_text);
}

function toast(s_text) {
  const el = opt_by_id("toast");
  if (!el) return;
  el.textContent = String(s_text || "");
  el.classList.remove("hidden");
  setTimeout(() => el.classList.add("hidden"), 2600);
}

function safe_trim(s_value, i_max_len) {
  const s = String(s_value || "").trim();
  if (s.length > i_max_len) return s.slice(0, i_max_len);
  return s;
}

function parse_int_clamped(s_value, i_min, i_max, i_fallback) {
  const i = parseInt(String(s_value || ""), 10);
  if (!Number.isFinite(i)) return i_fallback;
  if (i < i_min) return i_min;
  if (i > i_max) return i_max;
  return i;
}

/* -------------------------------- Navigation ----------------------------------------------- */
function set_active_view(s_view_id) {
  document.querySelectorAll(".view").forEach((v) => v.classList.add("hidden"));
  by_id(s_view_id).classList.remove("hidden");

  document.querySelectorAll(".nav_item").forEach((b) => b.classList.remove("active"));
  document.querySelectorAll(".nav_item").forEach((b) => {
    if (b.getAttribute("data-view") === s_view_id) b.classList.add("active");
  });
}

/* -------------------------------- Status, peers, events ------------------------------------ */
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

/* -------------------------------- P2P ------------------------------------------------------ */
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

/* -------------------------------- Network combi search ------------------------------------- */
let g_search_poll_timer = null;
let g_last_search_id = null;

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

    /* NEW: click opens document */
    card.addEventListener("click", async () => {
      await fetch_doc_text(s_peer, s_doc);
    });

    const line1 = document.createElement("div");
    line1.className = "hit_title";
    line1.textContent = (Number.isFinite(d_score) ? d_score : 0).toFixed(4) + "  " + s_doc;

    const line2 = document.createElement("div");
    line2.className = "hit_snippet";
    line2.textContent = "peer=" + (s_peer ? s_peer : "-");

    const line3 = document.createElement("div");
    line3.className = "hit_snippet";
    line3.textContent = s_snip ? s_snip : "";

    card.appendChild(line1);
    card.appendChild(line2);
    card.appendChild(line3);
    box.appendChild(card);
  });
}

const el_doc_clear = opt_by_id("btn_doc_clear");
if (el_doc_clear) {
  el_doc_clear.addEventListener("click", () => {
    set_text("doc_title", "-");
    by_id("doc_text").textContent = "";
  });
}

async function poll_search_result_once() {
  if (!g_last_search_id || !Number.isFinite(g_last_search_id)) {
    toast("no_search_id");
    return;
  }

  set_text("search_poll_state", "polling");
  const s_url = "/api/search/combi/result/" + encodeURIComponent(String(g_last_search_id));
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

  const r = await api.json_post("/api/search/combi/dispatch", { s_query, i_limit });
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
  toast("search_dispatched");

  set_text("search_poll_state", "polling");

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

async function fetch_doc_text(s_peer_id, s_path) {
  const s_peer = safe_trim(s_peer_id, 256);
  const s_p = safe_trim(s_path, 1024);

  if (s_peer.length < 4 || s_p.length < 1) {
    toast("invalid_doc_request");
    return;
  }

  const r = await api.json_post("/api/doc/text_get", { s_peer_id: s_peer, s_path: s_p });
  if (!r || r.b_ok !== true) {
    set_text("doc_title", s_p);
    by_id("doc_text").textContent = "error: " + String((r && r.s_error) || "na");
    return;
  }

  /* If remote pending, show pending marker; caller can poll by re-click. */
  set_text("doc_title", s_peer + "  " + s_p);

  const s_text = String((r && r.s_text) || "");
  const s_err = String((r && r.s_error) || "");

  if (s_text.length > 0) {
    by_id("doc_text").textContent = s_text;
    return;
  }

  by_id("doc_text").textContent = s_err ? s_err : "pending";
}

/* -------------------------------- IAM rights bitmask --------------------------------------- */
/* Central function history entry:
   2026-01-11 Marcus Schlieper - Fix: robust checkbox mapping and optional preview update.
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
  /* Returns { b_ok, s_rights_dec, s_error } */
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
        return { b_ok: false, s_rights_dec: "0", s_error: "missing_checkbox_" + s_checkbox_id };
      }

      const bi_bit = g_right_bits[s_right_name];
      if (bi_bit === undefined) {
        return { b_ok: false, s_rights_dec: "0", s_error: "unknown_right_" + s_right_name };
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
  /* Wires change events if checkboxes exist; preview is optional. */
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
      /* No hard fail: avoids breaking page init if HTML is not fully deployed yet. */
      continue;
    }
    el.addEventListener("change", update);
  }

  update();
}

/* -------------------------------- IAM groups select ---------------------------------------- */
async function refresh_iam_groups_select() {
  const el_select = opt_by_id("iam_user_group_select");
  if (!el_select) return;

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
    if (s_group.length < 1) continue;

    const opt = document.createElement("option");
    opt.value = s_group;
    opt.textContent = s_group;
    el_select.appendChild(opt);
  }

  if (el_select.options.length <= 1) {
    toast("no_groups_available");
  }
}

/* -------------------------------- IAM actions ---------------------------------------------- */
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

  const r = await api.json_post("/api/iam/user_add", { s_user, s_password, s_group });
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

/* -------------------------------- Wiring --------------------------------------------------- */
function init_nav() {
  document.querySelectorAll(".nav_item").forEach((b) => {
    b.addEventListener("click", async () => {
      const s_view = b.getAttribute("data-view");
      if (s_view) set_active_view(s_view);

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

  /* Existing click-based search trigger */
  by_id("btn_search").addEventListener("click", async (e) => {
    /* Defensive: if button lives in a form, prevent submit navigation */
    if (e && typeof e.preventDefault === "function") e.preventDefault();
    await do_search();
  });

  by_id("btn_search_clear").addEventListener("click", () => {
    by_id("search_query").value = "";
    set_text("search_id", "-");
    render_search_results([], true);
    stop_search_polling();
  });

  by_id("btn_search_poll_once").addEventListener("click", poll_search_result_once);
  by_id("btn_search_stop_poll").addEventListener("click", stop_search_polling);

  by_id("btn_iam_login").addEventListener("click", do_iam_login);
  by_id("btn_iam_group_add").addEventListener("click", do_iam_group_add);
  by_id("btn_iam_user_add").addEventListener("click", do_iam_user_add);
  by_id("btn_iam_path_add").addEventListener("click", do_iam_path_add);

  /* New: Enter in search input triggers search, without blocking umlaut input */
  const el_search_query = opt_by_id("search_query");
  if (el_search_query) {
    el_search_query.addEventListener("keydown", async (ev) => {
      if (!ev) return;

      /* Defensive: do not interfere with IME composition (unicode input) */
      if (ev.isComposing === true) return;

      /* Only act on Enter; do not call preventDefault for any other key */
      if (ev.key === "Enter") {
        ev.preventDefault();
        await do_search();
      }
    });
  }

  /* Optional: If index.html wraps search into a form, handle submit */
  const el_search_form = opt_by_id("search_form");
  if (el_search_form) {
    el_search_form.addEventListener("submit", async (ev) => {
      if (ev && typeof ev.preventDefault === "function") ev.preventDefault();
      await do_search();
    });
  }
}

function init_iam_rights_wiring() {
  /* Wires rights checkboxes regardless of preview presence. */
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

  /* Optional preview IDs; if they do not exist, no failure occurs. */
  wire_rights_checkboxes(o_group_map, "iam_group_rights_preview");
  wire_rights_checkboxes(o_path_map, "iam_path_rights_preview");
}

/* -------------------------------- Main ----------------------------------------------------- */
async function main() {
  /* Defensive: if one optional feature fails, the base UI should still run. */
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
    /* No hard failure: checkboxes may not exist yet depending on deployed HTML. */
  }

  await refresh_iam_groups_select();
  await refresh_status();
  setInterval(refresh_status, 5000);
}

document.addEventListener("DOMContentLoaded", main);
