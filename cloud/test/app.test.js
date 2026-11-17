import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import worker, { checkStale } from "../src/index.js";
import { canonicalize, verifyReceipt, parsePublicKey, assetKey, b64encode, sha256hex, ZERO_PREV } from "../src/receipt.js";
import { d1 } from "./d1.js";

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
const ORIGIN = "http://localhost:8787";

// ---------- helpers ----------

async function newKey() {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const kid = "ed25519:" + (await sha256hex(raw)).slice(0, 16);
  return { kp, raw, kid };
}

let counter = 0;
async function sign(key, { source, result = "PASS", issued_at, seq = 1, prev = ZERO_PREV, reason } = {}) {
  counter++;
  const doc = {
    schema: "xinproof.receipt/v1",
    id: "rcpt_01JD8Q4M7XK3V9Q2ZB6T5W" + String(counter).padStart(4, "0"),
    issued_at,
    subject: { source, size: 1234, format: "postgres-custom" },
    engine: { kind: "postgres", dump_version: "16.4" },
    result,
    ...(reason ? { reason } : {}),
    measured: { restore_seconds: 12.5, total_seconds: 20 },
    checks: [{ id: "l2.restore", status: result === "PASS" ? "pass" : "fail", detail: "x" }],
    tool: { name: "xinproof", version: "test" },
    chain: { seq, prev },
  };
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key.kp.privateKey, new TextEncoder().encode(canonicalize(doc))));
  doc.signature = { alg: "ed25519", key_id: key.kid, public_key: b64encode(key.raw), sig: b64encode(sig) };
  const text = JSON.stringify(doc, null, 2);
  const hash = "sha256:" + (await sha256hex(canonicalize(doc)));
  return { doc, text, hash };
}

function setup() {
  const sent = [];
  const env = { DB: d1(here("../schema.sql")), SESSION_SECRET: "test-secret", DEV_LOGIN: "1", PUBLIC_URL: ORIGIN };
  const waits = [];
  const ctx = { waitUntil: (p) => waits.push(p) };
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    sent.push({ url: String(url), body: JSON.parse(init.body) });
    return new Response("ok");
  };
  let cookie = "";
  const call = async (path, init = {}) => {
    const headers = new Headers(init.headers || {});
    if (cookie) headers.set("Cookie", cookie);
    const res = await worker.fetch(new Request(ORIGIN + path, { ...init, headers, redirect: "manual" }), env, ctx);
    await Promise.all(waits.splice(0));
    return res;
  };
  const signIn = async (login = "alice", id = 7) => {
    const res = await call(`/dev/login?login=${login}&id=${id}`);
    assert.equal(res.status, 303);
    cookie = res.headers.getSetCookie().map((c) => c.split(";")[0]).filter((c) => c.startsWith("xp_session=")).join("; ");
  };
  const form = (path, fields) =>
    call(path, { method: "POST", headers: { Origin: ORIGIN, "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(fields).toString() });
  const newToken = async () => {
    const res = await form("/app/tokens", { name: "ci" });
    const m = (await res.text()).match(/xpt_[A-Za-z0-9_-]{43}/);
    assert.ok(m, "token shown once");
    return m[0];
  };
  const post = (token, text) => call("/api/v1/receipts", { method: "POST", headers: { Authorization: `Bearer ${token}` }, body: text });
  const restore = () => (globalThis.fetch = realFetch);
  return { env, call, signIn, form, newToken, post, sent, restore, ctx };
}

// ---------- receipt module ----------

test("verifies the Go golden receipt and rejects tampering", async () => {
  const text = fs.readFileSync(here("../../internal/receipt/testdata/receipt-v1.json"), "utf8");
  const pub = parsePublicKey(fs.readFileSync(here("../../internal/receipt/testdata/receipt-v1.pub"), "utf8"));
  const v = await verifyReceipt(text, [pub]);
  assert.equal(v.pinned, true);
  assert.equal(v.keyId, "ed25519:56475aa75463474c");
  const doc = JSON.parse(text);
  doc.subject.size += 1;
  await assert.rejects(verifyReceipt(JSON.stringify(doc), [pub]), /does not verify/);
  const other = await newKey();
  await assert.rejects(verifyReceipt(text, [other.raw]), /pinned/);
});

test("asset keys strip dates and timestamps from file names", () => {
  assert.equal(assetKey("s3://b/pg/app-2026-11-17.dump"), "s3://b/pg/app-*.dump");
  assert.equal(assetKey("s3://b/pg/app-2026-11-17T02:00:11Z.dump.gz"), "s3://b/pg/app-*.dump.gz");
  assert.equal(assetKey("gs://x/shop_20261117_0200.sql.gz"), "gs://x/shop_*.sql.gz");
  assert.equal(assetKey("r2://b/db-1731801600.dump"), "r2://b/db-*.dump");
  assert.equal(assetKey("s3://b/v2/app-12.dump"), "s3://b/v2/app-12.dump");
});

// ---------- the Worker ----------

test("ingest: token auth, pin on first use, chain linking, idempotency, dashboard", async (t) => {
  const s = setup();
  t.after(s.restore);
  await s.signIn();
  const token = await s.newToken();
  const key = await newKey();

  assert.equal((await s.post("xpt_wrong", "{}")).status, 401);

  const r1 = await sign(key, { source: "s3://b/pg/app-2026-11-16.dump", issued_at: "2026-11-16T02:00:00Z" });
  let res = await s.post(token, r1.text);
  let body = await res.json();
  assert.equal(res.status, 201, JSON.stringify(body));
  assert.equal(body.asset, "s3://b/pg/app-*.dump");
  assert.equal(body.pinned_on_first_use, true);
  assert.equal(body.linked, true);
  assert.equal(body.hash, r1.hash);

  // Same receipt again: 200, not stored twice.
  res = await s.post(token, r1.text);
  assert.equal(res.status, 200);
  assert.equal((await res.json()).duplicate, true);

  // Next in the chain links; a receipt from another key is now refused.
  const r2 = await sign(key, { source: "s3://b/pg/app-2026-11-17.dump", issued_at: "2026-11-17T02:00:00Z", seq: 2, prev: r1.hash });
  body = await (await s.post(token, r2.text)).json();
  assert.equal(body.linked, true);
  assert.equal(body.pinned, true);
  const intruder = await newKey();
  const bad = await sign(intruder, { source: "s3://b/pg/app-2026-11-18.dump", issued_at: "2026-11-18T02:00:00Z" });
  res = await s.post(token, bad.text);
  assert.equal(res.status, 403);

  // Tampered receipt: refused (it no longer verifies against the pinned key).
  const tampered = JSON.parse(r2.text);
  tampered.result = "FAIL";
  tampered.id = "rcpt_01JD8Q4M7XK3V9Q2ZB6T5W9999";
  res = await s.post(token, JSON.stringify(tampered));
  assert.equal(res.status, 403);
  assert.match((await res.json()).error, /does not verify/);
  assert.equal((await s.post(token, "not json")).status, 422);

  // Gap: prev points at a receipt we never got.
  const r4 = await sign(key, { source: "s3://b/pg/app-2026-11-19.dump", issued_at: "2026-11-19T02:00:00Z", seq: 4, prev: "sha256:" + "a".repeat(64) });
  assert.equal((await (await s.post(token, r4.text)).json()).linked, false);

  const dash = await (await s.call("/app")).text();
  assert.match(dash, /s3:\/\/b\/pg\/app-\*\.dump/);
  assert.match(dash, /pinned on first use/);
  const asset = await (await s.call("/app/asset?key=" + encodeURIComponent("s3://b/pg/app-*.dump"))).text();
  assert.equal((asset.match(/<tr><td><a/g) || []).length, 3);
  assert.match(asset, /gap/);
  const rec = await s.call("/app/receipt?id=" + encodeURIComponent(r2.doc.id));
  assert.equal(rec.status, 200);
  assert.match(await rec.text(), /pinned key/);
});

test("revoked keys and tokens are refused; no TOFU after keys exist", async (t) => {
  const s = setup();
  t.after(s.restore);
  await s.signIn();
  const token = await s.newToken();
  const key = await newKey();
  const pem = "-----BEGIN PUBLIC KEY-----\n" + b64encode(new Uint8Array([...Buffer.from("302a300506032b6570032100", "hex"), ...key.raw])) + "\n-----END PUBLIC KEY-----\n";
  assert.equal((await s.form("/app/keys", { key: pem, note: "runner" })).status, 303);
  const r = await sign(key, { source: "gs://b/x-2026-11-17.dump", issued_at: "2026-11-17T01:00:00Z" });
  const body = await (await s.post(token, r.text)).json();
  assert.equal(body.pinned, true);
  assert.equal(body.pinned_on_first_use, false);

  await s.form("/app/keys/revoke", { key_id: key.kid });
  const r2 = await sign(key, { source: "gs://b/x-2026-11-18.dump", issued_at: "2026-11-18T01:00:00Z" });
  assert.equal((await s.post(token, r2.text)).status, 403);

  const row = await s.env.DB.prepare("SELECT id FROM tokens").first();
  await s.form("/app/tokens/revoke", { id: row.id });
  assert.equal((await s.post(token, r2.text)).status, 401);
});

test("alerts fire on state changes only, and the cron flags stale backups once", async (t) => {
  const s = setup();
  t.after(s.restore);
  await s.signIn();
  await s.form("/app/alerts", { webhook_url: "https://hooks.example.test/T1", stale_hours: "26" });
  const token = await s.newToken();
  const key = await newKey();
  const src = (d) => `azblob://acct/c/app-${d}.dump`;

  await s.post(token, (await sign(key, { source: src("2026-11-15"), issued_at: "2026-11-15T02:00:00Z" })).text);
  assert.equal(s.sent.length, 0, "first PASS: no alert");
  await s.post(token, (await sign(key, { source: src("2026-11-16"), issued_at: "2026-11-16T02:00:00Z", result: "FAIL", reason: "pg_restore exit 1" })).text);
  assert.equal(s.sent.length, 1);
  assert.match(s.sent[0].body.text, /broken.*pg_restore exit 1/s);
  await s.post(token, (await sign(key, { source: src("2026-11-17"), issued_at: "2026-11-17T02:00:00Z", result: "FAIL" })).text);
  assert.equal(s.sent.length, 1, "still failing: no repeat");
  await s.post(token, (await sign(key, { source: src("2026-11-18"), issued_at: "2026-11-18T02:00:00Z" })).text);
  assert.equal(s.sent.length, 2);
  assert.match(s.sent[1].body.text, /proven again/);

  // An older receipt arriving late does not change the latest state.
  await s.post(token, (await sign(key, { source: src("2026-11-10"), issued_at: "2026-11-10T02:00:00Z", result: "FAIL" })).text);
  assert.equal(s.sent.length, 2);

  const later = Date.parse("2026-11-19T06:00:00Z");
  assert.equal(await checkStale(s.env, later), 1);
  assert.match(s.sent[2].body.text, /No receipt for azblob:\/\/acct\/c\/app-\*\.dump in 26h/);
  assert.equal(await checkStale(s.env, later + 3600e3), 0, "stale alert sent once");
});

test("auditor links are read-only and revocable", async (t) => {
  const s = setup();
  t.after(s.restore);
  await s.signIn();
  const token = await s.newToken();
  const key = await newKey();
  const r = await sign(key, { source: "s3://b/app-2026-11-17.dump", issued_at: "2026-11-17T02:00:00Z" });
  await s.post(token, r.text);
  const page = await (await s.form("/app/links", { label: "SOC 2" })).text();
  const link = page.match(/http:\/\/localhost:8787(\/s\/[A-Za-z0-9_-]{43})/)[1];

  const anon = (p) => worker.fetch(new Request(ORIGIN + p), s.env, s.ctx);
  let res = await anon(link);
  assert.equal(res.status, 200);
  const text = await res.text();
  assert.match(text, /Read-only auditor view/);
  assert.doesNotMatch(text, /Settings/);
  assert.equal((await anon(`${link}/receipt?id=${r.doc.id}`)).status, 200);
  assert.equal(res.headers.get("Referrer-Policy"), "no-referrer");

  const h = await s.env.DB.prepare("SELECT token_hash FROM share_links").first();
  await s.form("/app/links/revoke", { h: h.token_hash });
  assert.equal((await anon(link)).status, 404);
});

test("forms need same-origin; pages need sign-in; workspaces are isolated", async (t) => {
  const s = setup();
  t.after(s.restore);
  assert.equal((await s.call("/app")).status, 303);
  await s.signIn("alice", 1);
  const res = await s.call("/app/tokens", { method: "POST", headers: { Origin: "https://evil.example", "Content-Type": "application/x-www-form-urlencoded" }, body: "name=x" });
  assert.equal(res.status, 403);
  const token = await s.newToken();
  const key = await newKey();
  const r = await sign(key, { source: "s3://alice/db-2026-11-17.dump", issued_at: "2026-11-17T02:00:00Z" });
  await s.post(token, r.text);

  await s.signIn("bob", 2);
  assert.equal((await s.call("/app/receipt?id=" + r.doc.id)).status, 404);
  assert.doesNotMatch(await (await s.call("/app")).text(), /s3:\/\/alice/);
});

test("public verifier and dev login guard", async (t) => {
  const s = setup();
  t.after(s.restore);
  const text = fs.readFileSync(here("../../internal/receipt/testdata/receipt-v1.json"), "utf8");
  const pub = fs.readFileSync(here("../../internal/receipt/testdata/receipt-v1.pub"), "utf8");
  let res = await s.call("/verify", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ receipt: text, key: pub }).toString() });
  assert.match(await res.text(), /Valid\.<\/b> Signed by the key you gave \(ed25519:56475aa75463474c\)/);
  res = await s.call("/verify", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ receipt: text.replace('"PASS"', '"FAIL"') }).toString() });
  assert.match(await res.text(), /Not valid/);

  const prod = await worker.fetch(new Request("https://xinproof.example/dev/login"), s.env, s.ctx);
  assert.equal(prod.status, 404);
});
