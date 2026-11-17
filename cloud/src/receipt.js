// Receipt verification, matching docs/RECEIPT-v1.md and internal/receipt.
// Runs on WebCrypto (Cloudflare Workers, Node 20+, browsers).

export const SCHEMA = "xinproof.receipt/v1";
export const ZERO_PREV = "sha256:" + "0".repeat(64);
const SPKI_ED25519_PREFIX = "302a300506032b6570032100"; // DER header of an Ed25519 SubjectPublicKeyInfo

// canonicalize implements RFC 8785 (JCS) for values produced by JSON.parse:
// members sorted by UTF-16 code units (JavaScript's default string order),
// ECMAScript number formatting and JSON.stringify string escaping.
export function canonicalize(v) {
  if (v === null || typeof v === "boolean" || typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error("non-finite number");
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return "[" + v.map(canonicalize).join(",") + "]";
  if (typeof v === "object") {
    return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonicalize(v[k])).join(",") + "}";
  }
  throw new Error("unsupported JSON value");
}

const enc = new TextEncoder();

export function hex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function b64decode(s) {
  if (typeof s !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) throw new Error("bad base64");
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function b64encode(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export async function sha256hex(data) {
  return hex(await crypto.subtle.digest("SHA-256", typeof data === "string" ? enc.encode(data) : data));
}

// keyId is "ed25519:" + the first 8 bytes of SHA-256(raw public key), in hex.
export async function keyId(raw) {
  return "ed25519:" + (await sha256hex(raw)).slice(0, 16);
}

// parsePublicKey accepts a PKIX PEM block (what `xinproof key` writes) or the
// bare base64 raw 32-byte key, and returns the raw key bytes.
export function parsePublicKey(text) {
  const t = String(text || "").trim();
  let der;
  const m = t.match(/-----BEGIN PUBLIC KEY-----([\s\S]+?)-----END PUBLIC KEY-----/);
  if (m) der = b64decode(m[1].replace(/\s+/g, ""));
  else der = b64decode(t.replace(/\s+/g, ""));
  if (der.length === 32) return der;
  if (der.length === 44 && hex(der.slice(0, 12)) === SPKI_ED25519_PREFIX) return der.slice(12);
  throw new Error("not an Ed25519 public key (expected a PEM block or 32-byte base64 key)");
}

async function ed25519Verify(raw, sig, msg) {
  const key = await crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "Ed25519" }, key, sig, msg);
}

// verifyReceipt checks one receipt document (a JSON string). trusted is a list
// of raw public keys; when given, the signature must verify against one of them
// (pinned). Otherwise the embedded key is used and pinned is false.
// Returns { receipt, hash, keyId, pinned, rawKey } or throws with a reason.
export async function verifyReceipt(text, trusted = []) {
  let doc;
  try {
    doc = JSON.parse(text);
  } catch {
    throw new Error("not JSON");
  }
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) throw new Error("not a receipt object");
  if (doc.schema !== SCHEMA) throw new Error(`unknown receipt schema ${JSON.stringify(doc.schema)}`);
  const s = doc.signature;
  if (!s || typeof s !== "object") throw new Error("receipt is not signed");
  if (s.alg !== "ed25519") throw new Error(`unsupported signature algorithm ${JSON.stringify(s.alg)}`);
  let sig;
  try {
    sig = b64decode(s.sig);
  } catch {
    throw new Error("malformed signature");
  }
  if (sig.length !== 64) throw new Error("malformed signature");

  const full = canonicalize(doc);
  const { signature, ...unsigned } = doc;
  const msg = enc.encode(canonicalize(unsigned));
  const hash = "sha256:" + (await sha256hex(full));

  if (trusted.length > 0) {
    for (const k of trusted) {
      if (await ed25519Verify(k, sig, msg)) return { receipt: doc, hash, keyId: await keyId(k), pinned: true, rawKey: k };
    }
    throw new Error("signature does not verify against the pinned key(s)");
  }
  let raw;
  try {
    raw = b64decode(s.public_key);
  } catch {
    raw = new Uint8Array();
  }
  if (raw.length !== 32) throw new Error("receipt has no usable embedded public key");
  if (!(await ed25519Verify(raw, sig, msg))) throw new Error("signature does not verify");
  const kid = await keyId(raw);
  if (kid !== s.key_id) throw new Error(`key_id ${s.key_id} does not match embedded key ${kid}`);
  return { receipt: doc, hash, keyId: kid, pinned: false, rawKey: raw };
}

// assetKey groups receipts of the same backup series: the location with
// dates and times in the file name replaced by "*", e.g.
// s3://b/pg/app-2026-11-17T0200.dump.gz -> s3://b/pg/app-*.dump.gz
export function assetKey(source) {
  const src = String(source || "");
  const i = src.lastIndexOf("/");
  const dir = src.slice(0, i + 1);
  let name = src.slice(i + 1);
  name = name
    .replace(
      /(?:19|20)\d{2}[-_.]?(?:0[1-9]|1[0-2])[-_.]?(?:0[1-9]|[12]\d|3[01])(?:[T_\-. ]?[0-2]\d[-_:.]?[0-5]\d(?:[-_:.]?[0-5]\d)?(?:\.\d+)?Z?)?/g,
      "*",
    )
    .replace(/(?<!\d)1\d{9}(?:\d{3})?(?!\d)/g, "*") // unix timestamps in seconds or milliseconds
    .replace(/\*(?:[-_.]?\*)+/g, "*");
  return dir + name;
}
