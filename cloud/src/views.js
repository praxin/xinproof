// Server-rendered HTML. Every value from a receipt or a user is untrusted: esc() it.

export function esc(v) {
  return String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

const CSS = `
:root{--bg:#fafaf9;--card:#fff;--fg:#1c1917;--muted:#78716c;--line:#e7e5e4;--green:#16a34a;--green-bg:#dcfce7;--red:#dc2626;--red-bg:#fee2e2;--grey:#78716c;--grey-bg:#f5f5f4;--amber:#b45309;--amber-bg:#fef3c7;--mono:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#0c0a09;--card:#1c1917;--fg:#f5f5f4;--muted:#a8a29e;--line:#292524;--green:#4ade80;--green-bg:#14532d;--red:#f87171;--red-bg:#450a0a;--grey:#a8a29e;--grey-bg:#292524;--amber:#fbbf24;--amber-bg:#451a03}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 Inter,system-ui,-apple-system,"Segoe UI",sans-serif}
a{color:inherit}header{display:flex;gap:16px;align-items:center;padding:14px 24px;border-bottom:1px solid var(--line)}
header .brand{font-weight:700;text-decoration:none}header nav{display:flex;gap:14px;margin-left:auto;font-size:14px}
main{max-width:1040px;margin:0 auto;padding:24px 16px 64px}h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 10px}
.muted{color:var(--muted)}.mono{font-family:var(--mono);font-size:13px;overflow-wrap:anywhere}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
a.card{display:block;text-decoration:none}a.card:hover{border-color:var(--muted)}
.pill{display:inline-block;font-size:12px;font-weight:600;padding:2px 8px;border-radius:999px}
.ok{background:var(--green-bg);color:var(--green)}.bad{background:var(--red-bg);color:var(--red)}.stale{background:var(--grey-bg);color:var(--grey)}.warn{background:var(--amber-bg);color:var(--amber)}
.banner{border-radius:10px;padding:12px 16px;margin:12px 0}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:500}
.scroll{overflow-x:auto}
input,textarea,select{font:inherit;color:inherit;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 10px;width:100%}
textarea{font-family:var(--mono);font-size:12px;min-height:160px}
button,.btn{font:inherit;font-weight:600;border:0;border-radius:8px;padding:8px 14px;background:var(--fg);color:var(--bg);cursor:pointer;text-decoration:none;display:inline-block}
button.link{background:none;color:var(--red);padding:0;font-weight:500}
form.row{display:flex;gap:8px;align-items:end;flex-wrap:wrap}form.row>*{flex:1 1 180px}form.row>button{flex:0 0 auto}
.receipt{font-family:var(--mono);font-size:13px;max-width:560px;border:1px dashed var(--muted);border-radius:6px;padding:18px;background:var(--card)}
.receipt .line{display:flex;justify-content:space-between;gap:12px}.receipt hr{border:0;border-top:1px dashed var(--line);margin:10px 0}
.stat{font-size:28px;font-weight:700}pre{white-space:pre-wrap;overflow-wrap:anywhere}
`;

export function page({ title, user, body, nav = true }) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} · Xinproof</title><style>${CSS}</style></head><body>
<header><a class="brand" href="/">Xinproof</a>${
    nav
      ? `<nav>${user ? `<a href="/app">Dashboard</a><a href="/app/settings">Settings</a>` : ""}<a href="/verify">Verify a receipt</a>${
          user ? `<form method="post" action="/logout" style="display:inline"><button class="link" style="color:var(--muted)">Sign out ${esc(user.login)}</button></form>` : `<a href="/login">Sign in</a>`
        }</nav>`
      : ""
  }</header><main>${body}</main></body></html>`;
}

export function statusOf(asset, staleHours, now = Date.now()) {
  if (asset.last_result === "FAIL" || asset.last_result === "ERROR") return { cls: "bad", label: asset.last_result === "FAIL" ? "Broken" : "Could not test" };
  const age = now - Date.parse(asset.last_issued_at || 0);
  if (age > staleHours * 3600e3) return { cls: "stale", label: "Stale" };
  return { cls: "ok", label: "Proven" };
}

export function ago(iso, now = Date.now()) {
  if (!iso) return "never";
  const s = Math.max(0, Math.round((now - Date.parse(iso)) / 1000));
  if (s < 90) return `${s}s ago`;
  if (s < 5400) return `${Math.round(s / 60)}m ago`;
  if (s < 129600) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

export function dur(sec) {
  if (sec == null) return "–";
  const s = Math.round(sec);
  return s < 60 ? `${s}s` : s < 3600 ? `${Math.floor(s / 60)}m${String(s % 60).padStart(2, "0")}s` : `${Math.floor(s / 3600)}h${String(Math.floor((s % 3600) / 60)).padStart(2, "0")}m`;
}

export function bytes(n) {
  if (n == null) return "–";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) (n /= 1024), i++;
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}

function resultPill(r) {
  const cls = r === "PASS" ? "ok" : r === "FAIL" || r === "ERROR" ? "bad" : "stale";
  return `<span class="pill ${cls}">${esc(r)}</span>`;
}

export function landing() {
  return `<h1>Backups you can prove.</h1>
<p class="muted" style="max-width:640px">Xinproof restores every backup into a throwaway database, checks it, and signs a receipt.
Xinproof Cloud collects those receipts: one dashboard for every database, an alert when a backup breaks or the nightly
job stops running, and a link you can hand your auditor.</p>
<p><a class="btn" href="/login">Sign in with GitHub</a> &nbsp; <a href="/verify">Verify a receipt without signing in</a></p>
<h2>How it works</h2>
<div class="grid">
<div class="card"><b>1. Run the verifier</b><p class="muted">The open-source <span class="mono">xinproof</span> CLI runs in your GitHub Actions or on your own machine. Your backups never reach us.</p></div>
<div class="card"><b>2. Send the receipts</b><p class="muted">Each receipt holds sizes, hashes, row counts and check results, signed with your key. Never row data.</p></div>
<div class="card"><b>3. Know, and show</b><p class="muted">Green only means a restore that passed. Stale and broken backups stand out, and you get a message when it changes.</p></div>
</div>`;
}

export function dashboard({ ws, assets, keys, now, share }) {
  const counts = { ok: 0, bad: 0, stale: 0 };
  const cards = assets.map((a) => {
    const st = statusOf(a, ws.stale_hours, now);
    counts[st.cls]++;
    const href = share ? `/s/${share}/asset?key=${encodeURIComponent(a.key)}` : `/app/asset?key=${encodeURIComponent(a.key)}`;
    return `<a class="card" href="${esc(href)}"><div style="display:flex;justify-content:space-between;gap:8px"><span class="pill ${st.cls}">${st.label}</span><span class="muted" style="font-size:13px">${esc(a.engine || "")}</span></div>
<div class="mono" style="margin:8px 0">${esc(a.key)}</div>
<div class="muted" style="font-size:13px">Last proven restore: <b style="color:var(--fg)">${esc(ago(a.last_pass_at, now))}</b> · restore ${esc(dur(a.last_restore_s))}<br>Last receipt ${esc(ago(a.last_issued_at, now))} · ${esc(a.last_result)}</div></a>`;
  });
  const tofu = !share && keys.some((k) => k.tofu && !k.revoked_at);
  const empty = `<div class="card"><b>No receipts yet.</b><p class="muted">Create an ingest token in <a href="/app/settings">Settings</a>, then add it to your runner as <span class="mono">XINPROOF_CLOUD_TOKEN</span>
with <span class="mono">XINPROOF_CLOUD_URL</span> set to this site. The nightly GitHub Actions template sends receipts automatically.</p></div>`;
  return `<h1>${esc(ws.name)}</h1><p class="muted">${share ? "Read-only auditor view. " : ""}Green means a restore that passed within ${esc(ws.stale_hours)} hours.</p>
${tofu ? `<div class="banner warn">A signing key was pinned on first use. Confirm it in <a href="/app/settings">Settings</a> so only receipts signed by your keys are accepted.</div>` : ""}
<div class="grid" style="grid-template-columns:repeat(3,minmax(0,1fr));margin:16px 0">
<div class="card"><div class="stat" style="color:var(--green)">${counts.ok}</div><div class="muted">Proven</div></div>
<div class="card"><div class="stat" style="color:var(--red)">${counts.bad}</div><div class="muted">Broken or untestable</div></div>
<div class="card"><div class="stat" style="color:var(--grey)">${counts.stale}</div><div class="muted">Stale</div></div></div>
<h2>Backups</h2><div class="grid">${cards.join("") || empty}</div>`;
}

export function assetPage({ ws, asset, receipts, now, share }) {
  const st = statusOf(asset, ws.stale_hours, now);
  const rows = receipts
    .map((r) => {
      const href = share ? `/s/${share}/receipt?id=${encodeURIComponent(r.id)}` : `/app/receipt?id=${encodeURIComponent(r.id)}`;
      return `<tr><td><a href="${esc(href)}">${esc(r.issued_at.replace("T", " ").replace("Z", ""))}</a></td><td>${resultPill(r.result)}</td><td class="mono">${esc(r.source.slice(r.source.lastIndexOf("/") + 1))}</td><td>${esc(bytes(r.size))}</td><td>${esc(dur(r.restore_seconds))}</td><td>${r.linked ? "linked" : '<span class="pill warn">gap</span>'}</td><td class="muted">${esc(r.reason || "")}</td></tr>`;
    })
    .join("");
  return `<p><a href="${share ? `/s/${esc(share)}` : "/app"}">← All backups</a></p><h1 class="mono" style="font-size:18px">${esc(asset.key)}</h1>
<p><span class="pill ${st.cls}">${st.label}</span> <span class="muted">last proven restore ${esc(ago(asset.last_pass_at, now))}</span></p>
<h2>History</h2><div class="scroll"><table><tr><th>Issued (UTC)</th><th>Result</th><th>File</th><th>Size</th><th>Restore</th><th>Chain</th><th>Reason</th></tr>${rows}</table></div>`;
}

export function receiptPage({ r, doc, pinnedKey, share }) {
  const checks = (doc.checks || [])
    .map((c) => `<div class="line"><span>${c.status === "pass" ? "✓" : c.status === "fail" || c.status === "error" ? "✗" : "·"} ${esc(c.id)}</span><span class="muted" style="text-align:right">${esc(c.detail || c.status)}</span></div>`)
    .join("");
  const back = share ? `/s/${esc(share)}/asset?key=${encodeURIComponent(r.asset_key)}` : `/app/asset?key=${encodeURIComponent(r.asset_key)}`;
  return `<p><a href="${back}">← ${esc(r.asset_key)}</a></p>
<div class="receipt"><div style="text-align:center;font-weight:700">XINPROOF PROOF RECEIPT</div><div style="text-align:center" class="muted">${esc(r.id)}</div><hr>
<div class="line"><span>Backup</span><span style="overflow-wrap:anywhere;text-align:right">${esc(r.source)}</span></div>
<div class="line"><span>Size</span><span>${esc(bytes(r.size))}</span></div>
<div class="line"><span>Engine</span><span>${esc(doc.engine?.kind || "")} ${esc(doc.engine?.dump_version || "")}</span></div>
<div class="line"><span>Restore time</span><span>${esc(dur(r.restore_seconds))}</span></div>
<div class="line"><span>Issued</span><span>${esc(r.issued_at)}</span></div><hr>${checks}<hr>
<div class="line"><span>RESULT</span><span>${resultPill(r.result)}</span></div>${r.reason ? `<div class="muted">${esc(r.reason)}</div>` : ""}<hr>
<div class="line"><span>Signed by</span><span>${esc(r.key_id)} ${pinnedKey ? '<span class="pill ok">pinned key</span>' : '<span class="pill warn">not pinned</span>'}</span></div>
<div class="line"><span>Chain</span><span>#${esc(r.seq)} ${r.linked ? '<span class="pill ok">linked</span>' : '<span class="pill warn">previous receipt not received</span>'}</span></div>
<div class="muted" style="overflow-wrap:anywhere">${esc(r.hash)}</div></div>
<p class="muted">Check it yourself: save the JSON below as <span class="mono">receipt.json</span> and run <span class="mono">xinproof receipt verify --pubkey ed25519.pub receipt.json</span>, or paste it into <a href="/verify">/verify</a>.</p>
<h2>Receipt JSON</h2><pre class="card mono">${esc(JSON.stringify(doc, null, 2))}</pre>`;
}

export function settingsPage({ ws, tokens, keys, links, flash, origin }) {
  const tokRows = tokens
    .map((t) => `<tr><td>${esc(t.name)}</td><td>${esc(t.created_at.slice(0, 10))}</td><td>${esc(t.last_used_at ? ago(t.last_used_at) : "never")}</td><td>${t.revoked_at ? "revoked" : `<form method="post" action="/app/tokens/revoke"><input type="hidden" name="id" value="${esc(t.id)}"><button class="link">Revoke</button></form>`}</td></tr>`)
    .join("");
  const keyRows = keys
    .map((k) => `<tr><td class="mono">${esc(k.key_id)}</td><td>${esc(k.note || "")}${k.tofu && !k.revoked_at ? ' <span class="pill warn">pinned on first use</span>' : ""}</td><td>${esc(k.added_at.slice(0, 10))}</td><td>${
      k.revoked_at
        ? "revoked"
        : `${k.tofu ? `<form method="post" action="/app/keys/confirm" style="display:inline"><input type="hidden" name="key_id" value="${esc(k.key_id)}"><button class="link" style="color:var(--green)">Confirm</button></form> · ` : ""}<form method="post" action="/app/keys/revoke" style="display:inline"><input type="hidden" name="key_id" value="${esc(k.key_id)}"><button class="link">Revoke</button></form>`
    }</td></tr>`)
    .join("");
  const linkRows = links
    .map((l) => `<tr><td>${esc(l.label)}</td><td>${esc(l.created_at.slice(0, 10))}</td><td>${l.revoked_at ? "revoked" : `<form method="post" action="/app/links/revoke"><input type="hidden" name="h" value="${esc(l.token_hash)}"><button class="link">Revoke</button></form>`}</td></tr>`)
    .join("");
  const hook = ws.webhook_url ? ws.webhook_url.replace(/^(https:\/\/[^/]+\/).*$/, "$1…") : "";
  return `<h1>Settings</h1>${flash || ""}
<h2>Ingest tokens</h2><p class="muted">Runners send receipts with <span class="mono">Authorization: Bearer &lt;token&gt;</span> to <span class="mono">${esc(origin)}/api/v1/receipts</span>.</p>
<div class="scroll"><table><tr><th>Name</th><th>Created</th><th>Last used</th><th></th></tr>${tokRows}</table></div>
<form class="row" method="post" action="/app/tokens"><label>Name<input name="name" required maxlength="60" placeholder="github-actions"></label><button>Create token</button></form>
<h2>Signing keys</h2><p class="muted">Only receipts signed by these keys are accepted. Paste <span class="mono">~/.xinproof/keys/ed25519.pub</span> or the base64 key that <span class="mono">xinproof key</span> prints.</p>
<div class="scroll"><table><tr><th>Key ID</th><th>Note</th><th>Added</th><th></th></tr>${keyRows}</table></div>
<form method="post" action="/app/keys"><label>Public key<textarea name="key" required placeholder="-----BEGIN PUBLIC KEY-----"></textarea></label><div style="display:flex;gap:8px;margin-top:8px"><input name="note" maxlength="60" placeholder="Note, e.g. nightly runner"><button>Add key</button></div></form>
<h2>Alerts</h2><p class="muted">A message is posted when a backup breaks, recovers, or goes stale. Slack incoming webhooks work as is; Discord (append <span class="mono">/slack</span>) and Teams take the same payload.</p>
<form class="row" method="post" action="/app/alerts"><label>Webhook URL (https)<input name="webhook_url" type="url" placeholder="${esc(hook || "https://hooks.slack.com/services/…")}"></label><label>Stale after (hours)<input name="stale_hours" type="number" min="1" max="720" value="${esc(ws.stale_hours)}"></label><button>Save</button></form>
${ws.webhook_url ? `<form method="post" action="/app/alerts/test" style="margin-top:8px"><button class="link" style="color:var(--fg)">Send a test message to ${esc(hook)}</button></form>` : ""}
<h2>Auditor links</h2><p class="muted">Read-only view of this workspace's backups and receipts. No sign-in needed; revoke any time.</p>
<div class="scroll"><table><tr><th>Label</th><th>Created</th><th></th></tr>${linkRows}</table></div>
<form class="row" method="post" action="/app/links"><label>Label<input name="label" required maxlength="60" placeholder="SOC 2 audit 2026"></label><button>Create link</button></form>`;
}

export function secretOnce(what, value) {
  return `<div class="banner ok"><b>${esc(what)}</b> Copy it now; it will not be shown again.<div class="mono card" style="margin-top:8px">${esc(value)}</div></div>`;
}

export function verifyPage({ result, input = "", key = "" }) {
  let out = "";
  if (result) {
    out = result.ok
      ? `<div class="banner ok"><b>Valid.</b> ${result.pinned ? `Signed by the key you gave (${esc(result.keyId)}).` : `Signed by the key embedded in the receipt (${esc(result.keyId)}). That only proves it has not changed since someone signed it; give the signer's public key to check who.`}<br>Result: <b>${esc(result.receipt.result)}</b> · ${esc(result.receipt.subject?.source)} · ${esc(result.receipt.issued_at)}<br><span class="mono">${esc(result.hash)}</span></div>`
      : `<div class="banner bad"><b>Not valid:</b> ${esc(result.error)}</div>`;
  }
  return `<h1>Verify a receipt</h1><p class="muted">Paste a Xinproof receipt. Nothing is stored. This is the same check as <span class="mono">xinproof receipt verify</span>.</p>${out}
<form method="post" action="/verify"><label>Receipt JSON<textarea name="receipt" required>${esc(input)}</textarea></label>
<label style="display:block;margin-top:8px">Signer's public key (optional)<textarea name="key" style="min-height:70px">${esc(key)}</textarea></label><p><button>Verify</button></p></form>`;
}

export function message(title, text) {
  return `<h1>${esc(title)}</h1><p class="muted">${esc(text)}</p>`;
}
