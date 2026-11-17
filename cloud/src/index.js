// Xinproof Cloud v0: the receipt hub. See docs/DESIGN-cloud.md.
// Cloudflare Worker; bindings: DB (D1). Secrets: SESSION_SECRET,
// GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET. Optional var DEV_LOGIN=1 (localhost only).

import { verifyReceipt, parsePublicKey, b64encode, b64decode, keyId, assetKey, ZERO_PREV } from "./receipt.js";
import { randomToken, sha256, cookies, setCookie, makeSession, readSession, sameOrigin, githubAuthorizeURL, githubUser } from "./auth.js";
import * as V from "./views.js";

const MAX_RECEIPT_BYTES = 256 * 1024;
const DAILY_RECEIPT_LIMIT = 1000;

const SECURITY_HEADERS = {
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; form-action 'self' https://github.com; frame-ancestors 'none'; base-uri 'none'",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer", // auditor links carry their token in the URL
};

const nowISO = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

function html(body, status = 200, extra = {}) {
  return new Response(body, { status, headers: { "Content-Type": "text/html; charset=utf-8", ...SECURITY_HEADERS, ...extra } });
}
function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json", ...SECURITY_HEADERS } });
}
function redirect(to, extra = {}) {
  return new Response(null, { status: 303, headers: { Location: to, ...extra } });
}

export default {
  async fetch(req, env, ctx) {
    try {
      return await route(req, env, ctx);
    } catch (e) {
      console.error(e && e.stack ? e.stack : e);
      return html(V.page({ title: "Error", body: V.message("Something went wrong", "The error has been logged. Please try again.") }), 500);
    }
  },
  async scheduled(_event, env, ctx) {
    ctx.waitUntil(checkStale(env));
  },
};

async function route(req, env, ctx) {
  const url = new URL(req.url);
  const p = url.pathname;
  const m = req.method;

  if (p === "/healthz") return json({ ok: true });
  if (p === "/api/v1/receipts" && m === "POST") return ingest(req, env, ctx);
  if (p === "/verify") return verifyForm(req);

  if (p === "/login" && m === "GET") return login(req, env);
  if (p === "/auth/callback" && m === "GET") return callback(req, env);
  if (p === "/dev/login" && m === "GET") return devLogin(req, env);
  if (p === "/logout" && m === "POST") return redirect("/", { "Set-Cookie": setCookie("xp_session", "", 0) });

  if (p.startsWith("/s/")) return shared(req, env, url);

  const user = await readSession(env.SESSION_SECRET, req);
  if (p === "/") return user ? redirect("/app") : html(V.page({ title: "Backups you can prove", user, body: V.landing() }));
  if (!p.startsWith("/app")) return html(V.page({ title: "Not found", user, body: V.message("Not found", "There is nothing here.") }), 404);
  if (!user) return redirect("/login");
  const ws = await workspaceFor(env, user);
  if (!ws) return redirect("/logout");

  if (m === "POST") {
    if (!sameOrigin(req)) return html(V.page({ title: "Refused", user, body: V.message("Refused", "This form was not sent from this site.") }), 403);
    return settingsAction(req, env, ctx, user, ws, p, url);
  }
  if (p === "/app") return dashboardView(env, ws, user);
  if (p === "/app/asset") return assetView(env, ws, user, url.searchParams.get("key"));
  if (p === "/app/receipt") return receiptView(env, ws, user, url.searchParams.get("id"));
  if (p === "/app/settings") return settingsView(env, ws, user, url.origin);
  return html(V.page({ title: "Not found", user, body: V.message("Not found", "There is nothing here.") }), 404);
}

// ---------- sign-in ----------

async function login(req, env) {
  if (!env.GITHUB_CLIENT_ID || !env.SESSION_SECRET) {
    return html(V.page({ title: "Sign-in not configured", body: V.message("Sign-in is not configured", "Set GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET and SESSION_SECRET.") }), 503);
  }
  const state = randomToken();
  return redirect(githubAuthorizeURL(env, new URL(req.url).origin, state), { "Set-Cookie": setCookie("xp_state", state, 600) });
}

async function callback(req, env) {
  const url = new URL(req.url);
  const state = url.searchParams.get("state");
  if (!state || state !== cookies(req).xp_state) return html(V.page({ title: "Sign-in failed", body: V.message("Sign-in failed", "The sign-in link expired. Please try again.") }), 400);
  const user = await githubUser(env, url.searchParams.get("code") || "", url.origin);
  return signedIn(env, user);
}

// Local development only: never works on a real hostname.
async function devLogin(req, env) {
  const url = new URL(req.url);
  if (env.DEV_LOGIN !== "1" || !["localhost", "127.0.0.1"].includes(url.hostname)) return new Response("not found", { status: 404 });
  const login = url.searchParams.get("login") || "dev";
  return signedIn(env, { id: Number(url.searchParams.get("id") || 1), login });
}

async function signedIn(env, user) {
  await ensureWorkspace(env, user);
  const headers = new Headers({ Location: "/app" });
  headers.append("Set-Cookie", await makeSession(env.SESSION_SECRET, user));
  headers.append("Set-Cookie", setCookie("xp_state", "", 0));
  return new Response(null, { status: 303, headers });
}

async function ensureWorkspace(env, user) {
  const existing = await env.DB.prepare("SELECT workspace_id FROM members WHERE github_id = ?").bind(user.id).first();
  if (existing) {
    await env.DB.prepare("UPDATE members SET login = ? WHERE github_id = ?").bind(user.login, user.id).run();
    return existing.workspace_id;
  }
  const id = "ws_" + randomToken().slice(0, 16);
  await env.DB.batch([
    env.DB.prepare("INSERT INTO workspaces (id, name, created_at) VALUES (?, ?, ?)").bind(id, user.login, nowISO()),
    env.DB.prepare("INSERT INTO members (workspace_id, github_id, login, role) VALUES (?, ?, ?, 'owner')").bind(id, user.id, user.login),
  ]);
  return id;
}

async function workspaceFor(env, user) {
  return env.DB.prepare("SELECT w.* FROM workspaces w JOIN members m ON m.workspace_id = w.id WHERE m.github_id = ? ORDER BY w.created_at LIMIT 1").bind(user.id).first();
}

// ---------- ingest ----------

async function ingest(req, env, ctx) {
  const auth = req.headers.get("Authorization") || "";
  const tok = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  if (!tok) return json({ error: "missing bearer token" }, 401);
  const t = await env.DB.prepare("SELECT id, workspace_id FROM tokens WHERE hash = ? AND revoked_at IS NULL").bind(await sha256(tok)).first();
  if (!t) return json({ error: "invalid or revoked token" }, 401);
  const ws = await env.DB.prepare("SELECT * FROM workspaces WHERE id = ?").bind(t.workspace_id).first();

  const len = Number(req.headers.get("Content-Length") || 0);
  if (len > MAX_RECEIPT_BYTES) return json({ error: "receipt too large" }, 413);
  const text = await req.text();
  if (text.length > MAX_RECEIPT_BYTES) return json({ error: "receipt too large" }, 413);

  const now = nowISO();
  const today = await env.DB.prepare("SELECT COUNT(*) AS n FROM receipts WHERE workspace_id = ? AND received_at >= ?").bind(ws.id, now.slice(0, 10)).first();
  if (today.n >= DAILY_RECEIPT_LIMIT) return json({ error: `daily limit of ${DAILY_RECEIPT_LIMIT} receipts reached` }, 429);

  // Signature: against the workspace's pinned keys, or, for a workspace that has
  // never had a key, the embedded key, which is then pinned on first use.
  const keyRows = (await env.DB.prepare("SELECT key_id, public_key, revoked_at FROM keys WHERE workspace_id = ?").bind(ws.id).all()).results;
  const trusted = keyRows.filter((k) => !k.revoked_at).map((k) => b64decode(k.public_key));
  const tofu = keyRows.length === 0;
  if (!tofu && trusted.length === 0) return json({ error: "this workspace has no active signing keys; add one in Settings" }, 403);
  let v;
  try {
    v = await verifyReceipt(text, trusted);
  } catch (e) {
    const status = /pinned/.test(e.message) ? 403 : 422;
    return json({ error: e.message }, status);
  }
  const r = v.receipt;
  const bad = validate(r);
  if (bad) return json({ error: bad }, 422);

  const dup = await env.DB.prepare("SELECT hash, asset_key, result, linked FROM receipts WHERE workspace_id = ? AND id = ?").bind(ws.id, r.id).first();
  if (dup) {
    if (dup.hash !== v.hash) return json({ error: "a different receipt with this id was already received" }, 409);
    return json({ id: r.id, asset: dup.asset_key, result: dup.result, linked: !!dup.linked, hash: v.hash, duplicate: true }, 200);
  }

  const seq = Number.isInteger(r.chain?.seq) ? r.chain.seq : null;
  const prev = typeof r.chain?.prev === "string" ? r.chain.prev : null;
  let linked = seq === 1 && prev === ZERO_PREV;
  if (!linked && prev) linked = !!(await env.DB.prepare("SELECT 1 AS x FROM receipts WHERE workspace_id = ? AND hash = ?").bind(ws.id, prev).first());

  const key = assetKey(r.subject.source);
  const stmts = [];
  if (tofu) {
    stmts.push(
      env.DB.prepare("INSERT OR IGNORE INTO keys (workspace_id, key_id, public_key, note, tofu, added_at) VALUES (?, ?, ?, 'pinned on first use', 1, ?)").bind(ws.id, v.keyId, b64encode(v.rawKey), now),
    );
  }
  stmts.push(
    env.DB.prepare(
      `INSERT INTO receipts (workspace_id, id, asset_key, issued_at, received_at, result, reason, source, size, restore_seconds, key_id, seq, prev, hash, linked, json)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(ws.id, r.id, key, r.issued_at, now, r.result, r.reason || null, r.subject.source, num(r.subject.size), num(r.measured?.restore_seconds), v.keyId, seq, prev, v.hash, linked ? 1 : 0, text),
    // A receipt that arrived before this one and points at it is now linked.
    env.DB.prepare("UPDATE receipts SET linked = 1 WHERE workspace_id = ? AND prev = ?").bind(ws.id, v.hash),
    env.DB.prepare("INSERT OR IGNORE INTO assets (workspace_id, key, created_at) VALUES (?, ?, ?)").bind(ws.id, key, now),
    env.DB.prepare(
      `UPDATE assets SET
         engine = COALESCE(?, engine),
         last_pass_at = CASE WHEN ? = 'PASS' AND (last_pass_at IS NULL OR ? > last_pass_at) THEN ? ELSE last_pass_at END,
         last_receipt_id = CASE WHEN last_issued_at IS NULL OR ? >= last_issued_at THEN ? ELSE last_receipt_id END,
         last_result     = CASE WHEN last_issued_at IS NULL OR ? >= last_issued_at THEN ? ELSE last_result END,
         last_restore_s  = CASE WHEN last_issued_at IS NULL OR ? >= last_issued_at THEN ? ELSE last_restore_s END,
         last_issued_at  = CASE WHEN last_issued_at IS NULL OR ? >= last_issued_at THEN ? ELSE last_issued_at END
       WHERE workspace_id = ? AND key = ?`,
    ).bind(r.engine?.kind || null, r.result, r.issued_at, r.issued_at, r.issued_at, r.id, r.issued_at, r.result, r.issued_at, num(r.measured?.restore_seconds), r.issued_at, r.issued_at, ws.id, key),
    env.DB.prepare("UPDATE tokens SET last_used_at = ? WHERE id = ?").bind(now, t.id),
  );
  await env.DB.batch(stmts);

  // Alert on a change of state: ok -> failing, failing/stale -> ok.
  const asset = await env.DB.prepare("SELECT * FROM assets WHERE workspace_id = ? AND key = ?").bind(ws.id, key).first();
  const state = asset.last_result === "PASS" ? "ok" : "failing";
  if (state !== asset.alert_state) {
    await env.DB.prepare("UPDATE assets SET alert_state = ? WHERE workspace_id = ? AND key = ?").bind(state, ws.id, key).run();
    const msg =
      state === "failing"
        ? `:red_circle: Backup ${asset.last_result === "FAIL" ? "broken" : "could not be tested"}: ${r.subject.source}\n${r.reason || ""}`
        : `:large_green_circle: Backup proven again: ${key} (restore ${V.dur(asset.last_restore_s)})`;
    ctx.waitUntil(notify(ws, msg, new URL(req.url).origin));
  }

  return json({ id: r.id, asset: key, result: r.result, key_id: v.keyId, pinned: v.pinned, pinned_on_first_use: tofu, linked, hash: v.hash }, 201);
}

function num(x) {
  return typeof x === "number" && Number.isFinite(x) ? x : null;
}

function validate(r) {
  if (typeof r.id !== "string" || !/^rcpt_[0-9A-Za-z]{10,40}$/.test(r.id)) return "bad or missing id";
  if (typeof r.issued_at !== "string" || Number.isNaN(Date.parse(r.issued_at))) return "bad or missing issued_at";
  if (!["PASS", "FAIL", "ERROR"].includes(r.result)) return "bad or missing result";
  if (!r.subject || typeof r.subject.source !== "string" || !r.subject.source || r.subject.source.length > 2048) return "bad or missing subject.source";
  return null;
}

async function notify(ws, text, origin) {
  if (!ws.webhook_url) return;
  try {
    const res = await fetch(ws.webhook_url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: `${text}\n${origin}/app` }),
    });
    if (!res.ok) console.warn("webhook", ws.id, res.status);
  } catch (e) {
    console.warn("webhook", ws.id, e.message);
  }
}

// Cron: flag assets with no receipt inside the workspace's window, once.
export async function checkStale(env, now = Date.now(), origin = env.PUBLIC_URL || "") {
  const rows = (
    await env.DB.prepare(
      `SELECT a.workspace_id, a.key, a.last_issued_at, w.stale_hours, w.webhook_url, w.id
         FROM assets a JOIN workspaces w ON w.id = a.workspace_id
        WHERE a.alert_state != 'stale' AND a.last_issued_at IS NOT NULL`,
    ).all()
  ).results;
  let n = 0;
  for (const a of rows) {
    if (now - Date.parse(a.last_issued_at) <= a.stale_hours * 3600e3) continue;
    await env.DB.prepare("UPDATE assets SET alert_state = 'stale' WHERE workspace_id = ? AND key = ?").bind(a.workspace_id, a.key).run();
    await notify(a, `:white_circle: No receipt for ${a.key} in ${a.stale_hours}h (last ${a.last_issued_at}). Is the nightly job still running?`, origin);
    n++;
  }
  return n;
}

// ---------- views ----------

async function dashboardView(env, ws, user) {
  const assets = (await env.DB.prepare("SELECT * FROM assets WHERE workspace_id = ? ORDER BY CASE last_result WHEN 'PASS' THEN 1 ELSE 0 END, key").bind(ws.id).all()).results;
  const keys = (await env.DB.prepare("SELECT * FROM keys WHERE workspace_id = ?").bind(ws.id).all()).results;
  return html(V.page({ title: "Dashboard", user, body: V.dashboard({ ws, assets, keys, now: Date.now() }) }));
}

async function assetView(env, ws, user, key, share) {
  const asset = await env.DB.prepare("SELECT * FROM assets WHERE workspace_id = ? AND key = ?").bind(ws.id, key || "").first();
  if (!asset) return html(V.page({ title: "Not found", user, body: V.message("Not found", "No such backup.") }), 404);
  const receipts = (
    await env.DB.prepare("SELECT id, issued_at, result, reason, source, size, restore_seconds, linked FROM receipts WHERE workspace_id = ? AND asset_key = ? ORDER BY issued_at DESC LIMIT 200").bind(ws.id, asset.key).all()
  ).results;
  return html(V.page({ title: asset.key, user, body: V.assetPage({ ws, asset, receipts, now: Date.now(), share }) }));
}

async function receiptView(env, ws, user, id, share) {
  const r = await env.DB.prepare("SELECT * FROM receipts WHERE workspace_id = ? AND id = ?").bind(ws.id, id || "").first();
  if (!r) return html(V.page({ title: "Not found", user, body: V.message("Not found", "No such receipt.") }), 404);
  const k = await env.DB.prepare("SELECT revoked_at FROM keys WHERE workspace_id = ? AND key_id = ?").bind(ws.id, r.key_id).first();
  return html(V.page({ title: r.id, user, body: V.receiptPage({ r, doc: JSON.parse(r.json), pinnedKey: !!k && !k.revoked_at, share }) }));
}

async function shared(req, env, url) {
  const [, , token, sub] = url.pathname.split("/");
  const link = await env.DB.prepare("SELECT workspace_id FROM share_links WHERE token_hash = ? AND revoked_at IS NULL").bind(await sha256(token || "")).first();
  if (!link) return html(V.page({ title: "Not found", body: V.message("Link not valid", "This link was revoked or never existed.") }), 404);
  const ws = await env.DB.prepare("SELECT * FROM workspaces WHERE id = ?").bind(link.workspace_id).first();
  if (!sub) {
    const assets = (await env.DB.prepare("SELECT * FROM assets WHERE workspace_id = ? ORDER BY key").bind(ws.id).all()).results;
    return html(V.page({ title: ws.name, body: V.dashboard({ ws, assets, keys: [], now: Date.now(), share: token }) }));
  }
  if (sub === "asset") return assetView(env, ws, null, url.searchParams.get("key"), token);
  if (sub === "receipt") return receiptView(env, ws, null, url.searchParams.get("id"), token);
  return html(V.page({ title: "Not found", body: V.message("Not found", "There is nothing here.") }), 404);
}

async function settingsView(env, ws, user, origin, flash = "") {
  const [tokens, keys, links] = await Promise.all([
    env.DB.prepare("SELECT * FROM tokens WHERE workspace_id = ? ORDER BY created_at DESC").bind(ws.id).all(),
    env.DB.prepare("SELECT * FROM keys WHERE workspace_id = ? ORDER BY added_at DESC").bind(ws.id).all(),
    env.DB.prepare("SELECT * FROM share_links WHERE workspace_id = ? ORDER BY created_at DESC").bind(ws.id).all(),
  ]);
  return html(V.page({ title: "Settings", user, body: V.settingsPage({ ws, tokens: tokens.results, keys: keys.results, links: links.results, flash, origin }) }));
}

async function settingsAction(req, env, ctx, user, ws, p, url) {
  const f = await req.formData();
  const s = (k) => String(f.get(k) || "").trim();
  const now = nowISO();
  const back = () => redirect("/app/settings");
  const fail = (text) => settingsView(env, ws, user, url.origin, `<div class="banner bad">${V.esc(text)}</div>`);

  switch (p) {
    case "/app/tokens": {
      const token = randomToken("xpt_");
      await env.DB.prepare("INSERT INTO tokens (id, workspace_id, name, hash, created_at) VALUES (?, ?, ?, ?, ?)")
        .bind("tok_" + randomToken().slice(0, 12), ws.id, s("name").slice(0, 60) || "token", await sha256(token), now)
        .run();
      return settingsView(env, ws, user, url.origin, V.secretOnce("New ingest token.", token));
    }
    case "/app/tokens/revoke":
      await env.DB.prepare("UPDATE tokens SET revoked_at = ? WHERE id = ? AND workspace_id = ? AND revoked_at IS NULL").bind(now, s("id"), ws.id).run();
      return back();
    case "/app/keys": {
      let raw;
      try {
        raw = parsePublicKey(s("key"));
      } catch (e) {
        return fail(e.message);
      }
      const kid = await keyId(raw);
      await env.DB.prepare(
        `INSERT INTO keys (workspace_id, key_id, public_key, note, tofu, added_at) VALUES (?, ?, ?, ?, 0, ?)
         ON CONFLICT (workspace_id, key_id) DO UPDATE SET revoked_at = NULL, tofu = 0, note = excluded.note`,
      )
        .bind(ws.id, kid, b64encode(raw), s("note").slice(0, 60) || null, now)
        .run();
      return back();
    }
    case "/app/keys/confirm":
      await env.DB.prepare("UPDATE keys SET tofu = 0, note = 'confirmed' WHERE workspace_id = ? AND key_id = ?").bind(ws.id, s("key_id")).run();
      return back();
    case "/app/keys/revoke":
      await env.DB.prepare("UPDATE keys SET revoked_at = ? WHERE workspace_id = ? AND key_id = ? AND revoked_at IS NULL").bind(now, ws.id, s("key_id")).run();
      return back();
    case "/app/alerts": {
      const hook = s("webhook_url");
      const hours = Number(s("stale_hours"));
      if (hook && !/^https:\/\/[^\s]+$/.test(hook)) return fail("The webhook URL must start with https://");
      if (!Number.isInteger(hours) || hours < 1 || hours > 720) return fail("Stale after must be between 1 and 720 hours.");
      await env.DB.prepare("UPDATE workspaces SET webhook_url = COALESCE(NULLIF(?, ''), webhook_url), stale_hours = ? WHERE id = ?").bind(hook, hours, ws.id).run();
      return back();
    }
    case "/app/alerts/test":
      ctx.waitUntil(notify(ws, ":wave: Test message from Xinproof Cloud. Alerts for this workspace will arrive here.", url.origin));
      return back();
    case "/app/links": {
      const token = randomToken();
      await env.DB.prepare("INSERT INTO share_links (token_hash, workspace_id, label, created_at) VALUES (?, ?, ?, ?)").bind(await sha256(token), ws.id, s("label").slice(0, 60) || "auditor", now).run();
      return settingsView(env, ws, user, url.origin, V.secretOnce("New auditor link.", `${url.origin}/s/${token}`));
    }
    case "/app/links/revoke":
      await env.DB.prepare("UPDATE share_links SET revoked_at = ? WHERE token_hash = ? AND workspace_id = ?").bind(now, s("h"), ws.id).run();
      return back();
  }
  return html(V.page({ title: "Not found", user, body: V.message("Not found", "There is nothing here.") }), 404);
}

async function verifyForm(req) {
  if (req.method !== "POST") return html(V.page({ title: "Verify a receipt", body: V.verifyPage({}) }));
  const f = await req.formData();
  const input = String(f.get("receipt") || "").slice(0, MAX_RECEIPT_BYTES);
  const keyText = String(f.get("key") || "").trim();
  let result;
  try {
    const trusted = keyText ? [parsePublicKey(keyText)] : [];
    result = { ok: true, ...(await verifyReceipt(input, trusted)) };
  } catch (e) {
    result = { ok: false, error: e.message };
  }
  return html(V.page({ title: "Verify a receipt", body: V.verifyPage({ result, input, key: keyText }) }));
}
