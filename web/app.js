/*
==============================================================================================
Modulname : web_ui
Datei     : app.js
Autor     : Marcus Schlieper
----------------------------------------------------------------------------------------------
Beschreibung
- Client Side SPA Logik: Navigation, API Calls, Rendering.
- Defensive: einfache Validierung, Fehlerausgaben, Timeout.
Historie
11.01.2026  MS  - Initiale Version: Views, Status Polling, Aktionen
==============================================================================================
*/

"use strict";

const api = {
  async json_get(s_url) {
    return await api._fetch_json(s_url, { method: "GET" });
  },

  async json_post(s_url, o_body) {
    return await api._fetch_json(s_url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(o_body),
    });
  },

  async _fetch_json(s_url, o_opts) {
    const ctrl = new AbortController();
    const i_timeout_ms = 8000;
    const t = setTimeout(() => ctrl.abort(), i_timeout_ms);

    try {
      const r = await fetch(s_url, { ...o_opts, signal: ctrl.signal });
      const s_ct = (r.headers.get("content-type") || "").toLowerCase();
      if (!r.ok) {
        const s_msg = "http_error_" + r.status;
        throw new Error(s_msg);
      }
      if (s_ct.indexOf("application/json") >= 0) {
        return await r.json();
      }
      return { b_ok: false, s_error: "unexpected_content_type" };
    } finally {
      clearTimeout(t);
    }
  },
};

function by_id(s_id) {
  const el = document.getElementById(s_id);
  if (!el) throw new Error("missing_element_" + s_id);
  return el;
}

function toast(s_text) {
  const el = by_id("toast");
  el.textContent = s_text;
  el.classList.remove("hidden");
  setTimeout(() => el.classList.add("hidden"), 2600);
}

function set_active_view(s_view_id) {
  document.querySelectorAll(".view").forEach((v) => v.classList.add("hidden"));
  by_id(s_view_id).classList.remove("hidden");

  document.querySelectorAll(".nav_item").forEach((b) => b.classList.remove("active"));
  document.querySelectorAll(".nav_item").forEach((b) => {
    if (b.getAttribute("data-view") === s_view_id) b.classList.add("active");
  });
}

async function refresh_status() {
  try {
    const st = await api.json_get("/api/status");
    by_id("st_peer_id").textContent = st.s_node_peer_id || "-";
    by_id("st_known_peers").textContent = String(st.i_known_peers || 0);
    by_id("st_chat_peer").textContent = st.s_chat_peer || "-";
    by_id("st_chat_topic").textContent = st.s_chat_topic || "-";

    const badge = by_id("status_badge");
    badge.textContent = "online";
    badge.classList.remove("badge_off");
    badge.classList.add("badge_on");
  } catch (e) {
    const badge = by_id("status_badge");
    badge.textContent = "offline";
    badge.classList.remove("badge_on");
    badge.classList.add("badge_off");
  }
}

async function refresh_peers() {
  const tb = by_id("peers_table");
  tb.innerHTML = "";
  try {
    const v = await api.json_get("/api/peers");
    v.forEach((p) => {
      const tr = document.createElement("tr");

      const td_id = document.createElement("td");
      td_id.textContent = p.s_peer_id;

      const td_on = document.createElement("td");
      td_on.textContent = p.b_online ? "true" : "false";

      const td_act = document.createElement("td");
      const btn = document.createElement("button");
      btn.className = "btn small";
      btn.textContent = "connect";
      btn.addEventListener("click", async () => {
        await do_connect(p.s_peer_id);
      });
      td_act.appendChild(btn);

      tr.appendChild(td_id);
      tr.appendChild(td_on);
      tr.appendChild(td_act);
      tb.appendChild(tr);
    });
  } catch (e) {
    toast("peers_refresh_failed");
  }
}

async function refresh_events() {
  try {
    const v = await api.json_get("/api/events");
    by_id("events_box").textContent = v.join("\n");
  } catch (e) {
    toast("events_refresh_failed");
  }
}

async function do_connect(s_peer_id) {
  const s_id = (s_peer_id || "").trim();
  if (s_id.length < 4) {
    toast("invalid_peer_id");
    return;
  }
  try {
    const r = await api.json_post("/api/p2p/connect", { s_peer_id: s_id });
    if (!r.b_ok) {
      toast("connect_failed: " + (r.s_error || "na"));
      return;
    }
    toast("connect_sent");
    await refresh_status();
  } catch (e) {
    toast("connect_error");
  }
}

async function do_send_text() {
  const s_text = by_id("send_text").value.trim();
  if (s_text.length < 1) {
    toast("empty_text");
    return;
  }
  try {
    const r = await api.json_post("/api/p2p/send_text", { s_text });
    if (!r.b_ok) {
      toast("send_failed: " + (r.s_error || "na"));
      return;
    }
    by_id("send_text").value = "";
    toast("sent");
  } catch (e) {
    toast("send_error");
  }
}

function render_search_results(v_hits) {
  const box = by_id("search_results");
  box.innerHTML = "";
  if (!v_hits || v_hits.length === 0) {
    box.textContent = "no_hits";
    return;
  }

  v_hits.forEach((h) => {
    const card = document.createElement("div");
    card.className = "hit";

    const line1 = document.createElement("div");
    line1.className = "hit_title";
    line1.textContent = (h.d_score || 0).toFixed(4) + "  " + (h.s_doc || "");

    const line2 = document.createElement("div");
    line2.className = "hit_snippet";
    line2.textContent = h.s_snippet || "";

    card.appendChild(line1);
    card.appendChild(line2);
    box.appendChild(card);
  });
}

async function do_search() {
  const s_mode = by_id("search_mode").value;
  const s_query = by_id("search_query").value.trim();
  const i_limit = parseInt(by_id("search_limit").value, 10);

  if (s_query.length < 1) {
    toast("empty_query");
    return;
  }
  if (!Number.isFinite(i_limit) || i_limit < 1 || i_limit > 50) {
    toast("invalid_limit");
    return;
  }

  let s_url = "/api/search/tantivy";
  if (s_mode === "vector") s_url = "/api/search/vector";
  if (s_mode === "combi") s_url = "/api/search/combi";

  try {
    const r = await api.json_post(s_url, { s_query, i_limit });
    if (!r.b_ok) {
      toast("search_failed: " + (r.s_error || "na"));
      render_search_results([]);
      return;
    }
    render_search_results(r.v_hits || []);
  } catch (e) {
    toast("search_error");
  }
}

async function do_iam_login() {
  const s_user = by_id("iam_login_user").value.trim();
  const s_password = by_id("iam_login_pass").value;

  if (s_user.length < 1) {
    toast("invalid_user");
    return;
  }

  try {
    const r = await api.json_post("/api/iam/login", { s_user, s_password });
    if (!r.b_ok) {
      toast("login_failed: " + (r.s_error || "na"));
      return;
    }
    by_id("iam_session").textContent = r.s_session || "-";
    by_id("iam_login_pass").value = "";
    toast("login_ok");
  } catch (e) {
    toast("login_error");
  }
}

async function do_iam_group_add() {
  const s_group = by_id("iam_group").value.trim();
  const s_rights = by_id("iam_group_rights").value.trim();
  if (s_group.length < 1 || s_rights.length < 1) {
    toast("invalid_input");
    return;
  }
  try {
    const r = await api.json_post("/api/iam/group_add", { s_group, s_rights });
    if (!r.b_ok) {
      toast("group_add_failed: " + (r.s_error || "na"));
      return;
    }
    toast("group_added");
  } catch (e) {
    toast("group_add_error");
  }
}

async function do_iam_user_add() {
  const s_user = by_id("iam_user").value.trim();
  const s_password = by_id("iam_user_pass").value;
  const s_group = by_id("iam_user_group").value.trim();

  if (s_user.length < 1 || s_group.length < 1 || s_password.length < 1) {
    toast("invalid_input");
    return;
  }
  try {
    const r = await api.json_post("/api/iam/user_add", { s_user, s_password, s_group });
    if (!r.b_ok) {
      toast("user_add_failed: " + (r.s_error || "na"));
      return;
    }
    by_id("iam_user_pass").value = "";
    toast("user_added");
  } catch (e) {
    toast("user_add_error");
  }
}

async function do_iam_path_add() {
  const s_path = by_id("iam_path").value.trim();
  const s_group_or_dash = by_id("iam_path_group").value.trim();
  const b_public = (by_id("iam_path_public").value === "true");
  const s_rights = by_id("iam_path_rights").value.trim();

  if (s_path.length < 1 || s_rights.length < 1 || s_group_or_dash.length < 1) {
    toast("invalid_input");
    return;
  }

  try {
    const r = await api.json_post("/api/iam/path_add", {
      s_path,
      s_group_or_dash,
      b_public,
      s_rights,
    });
    if (!r.b_ok) {
      toast("path_add_failed: " + (r.s_error || "na"));
      return;
    }
    toast("path_added");
  } catch (e) {
    toast("path_add_error");
  }
}

/* -------------------------------- Wiring ----------------------------------------------- */

function init_nav() {
  document.querySelectorAll(".nav_item").forEach((b) => {
    b.addEventListener("click", () => set_active_view(b.getAttribute("data-view")));
  });
}

function init_actions() {
  by_id("btn_refresh_peers").addEventListener("click", refresh_peers);
  by_id("btn_refresh_events").addEventListener("click", refresh_events);

  by_id("btn_connect").addEventListener("click", async () => {
    await do_connect(by_id("connect_peer_id").value);
  });
  by_id("btn_send_text").addEventListener("click", do_send_text);

  by_id("btn_search").addEventListener("click", do_search);

  by_id("btn_iam_login").addEventListener("click", do_iam_login);
  by_id("btn_iam_group_add").addEventListener("click", do_iam_group_add);
  by_id("btn_iam_user_add").addEventListener("click", do_iam_user_add);
  by_id("btn_iam_path_add").addEventListener("click", do_iam_path_add);
}

async function main() {
  init_nav();
  init_actions();
  await refresh_status();
  setInterval(refresh_status, 5000);
}

document.addEventListener("DOMContentLoaded", main);
