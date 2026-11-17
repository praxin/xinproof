// Sessions, random tokens and GitHub sign-in.

const enc = new TextEncoder();

export function b64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function randomToken(prefix = "") {
  return prefix + b64url(crypto.getRandomValues(new Uint8Array(32)));
}

export async function sha256(s) {
  const d = await crypto.subtle.digest("SHA-256", enc.encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function hmac(secret, data) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(data))));
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

export function cookies(req) {
  const out = {};
  for (const part of (req.headers.get("Cookie") || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

export function setCookie(name, value, maxAge) {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

const SESSION_DAYS = 7;

// A session cookie is "<github_id>.<login>.<expiry unix>.<hmac>".
export async function makeSession(secret, user, now = Date.now()) {
  const exp = Math.floor(now / 1000) + SESSION_DAYS * 86400;
  const body = `${user.id}.${b64url(enc.encode(user.login))}.${exp}`;
  return setCookie("xp_session", `${body}.${await hmac(secret, body)}`, SESSION_DAYS * 86400);
}

export async function readSession(secret, req, now = Date.now()) {
  const v = cookies(req).xp_session;
  if (!v || !secret) return null;
  const parts = v.split(".");
  if (parts.length !== 4) return null;
  const body = parts.slice(0, 3).join(".");
  if (!timingSafeEqual(parts[3], await hmac(secret, body))) return null;
  if (Number(parts[2]) * 1000 < now) return null;
  const login = new TextDecoder().decode(Uint8Array.from(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)));
  return { id: Number(parts[0]), login };
}

// sameOrigin guards state-changing form posts (CSRF): browsers send Origin on POST.
export function sameOrigin(req) {
  const o = req.headers.get("Origin");
  return o !== null && o === new URL(req.url).origin;
}

// GitHub OAuth (web flow). Needs GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET.
export function githubAuthorizeURL(env, origin, state) {
  const u = new URL("https://github.com/login/oauth/authorize");
  u.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
  u.searchParams.set("redirect_uri", origin + "/auth/callback");
  u.searchParams.set("scope", "read:user");
  u.searchParams.set("state", state);
  u.searchParams.set("allow_signup", "true");
  return u.toString();
}

export async function githubUser(env, code, origin) {
  const t = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: env.GITHUB_CLIENT_ID,
      client_secret: env.GITHUB_CLIENT_SECRET,
      code,
      redirect_uri: origin + "/auth/callback",
    }),
  }).then((r) => r.json());
  if (!t.access_token) throw new Error("GitHub did not return a token: " + (t.error_description || t.error || "unknown"));
  const u = await fetch("https://api.github.com/user", {
    headers: { Authorization: `Bearer ${t.access_token}`, "User-Agent": "xinproof-cloud", Accept: "application/vnd.github+json" },
  }).then((r) => r.json());
  if (!u.id || !u.login) throw new Error("GitHub did not return a user");
  return { id: u.id, login: u.login };
}
