# Xinproof Cloud: design (v0, the receipt hub)

Status: MVP in `cloud/` · Owner: praxin · 2026-11-17

## 1. What it is

The CLI already tests backups and signs a receipt for each one. What a team
cannot do with the CLI alone:

- see every database's state in one place, and how it changed over time;
- notice when the nightly job **stopped running** (no receipt is the worst
  failure, because nothing goes red);
- hand an auditor a link instead of a folder of JSON files;
- get a Slack message when a backup fails.

Xinproof Cloud v0 is the place receipts go. Runners (the GitHub Actions template,
the Docker cron job, or a laptop) POST each receipt to it. It checks the
signature against keys the team has pinned, files the receipt under an asset,
and shows a dashboard. It never sees backups, credentials, or row data: only
receipts, which already carry nothing sensitive beyond the backup's location
and table/row counts.

This is the "Prove" and "Alert and monitor" parts of the product spec
(`Product-Spec-Verified-Backups.md` §3.4, §3.5) built first, because they are
what turns the free CLI into something a team pays for, and they need no
access to customer data. Backup, restore and XinVault come later.

## 2. Scope

**In v0**

1. Sign in with GitHub. First sign-in creates a personal workspace.
2. Ingest tokens (`xpt_…`, shown once, stored as SHA-256) for runners.
3. `POST /api/v1/receipts`: schema check, Ed25519 signature check (RFC 8785
   canonical JSON, same as `xinproof receipt verify`), key pinning, chain
   linking, idempotent on receipt ID.
4. Pinned keys: add the runner's public key (PEM or base64). If a workspace has
   no keys yet, the first key that signs a valid receipt is pinned and marked
   "pinned on first use" so the owner can confirm it. After that, receipts
   signed by other keys are rejected.
5. Assets: receipts are grouped by backup location, with the date and time
   stripped from the file name (`s3://b/pg/app-2026-11-17.dump` →
   `s3://b/pg/app-*.dump`). Each asset shows its latest result, last proven
   restore, measured restore time, and history.
6. Status rule from the spec: **green only for a recent PASS**. Grey means
   stale (no receipt within the workspace's window, 26 hours by default), red
   means the latest receipt is FAIL or ERROR.
7. Alerts to a webhook (Slack-compatible JSON; Discord and Teams accept it
   through their Slack-compatible endpoints): a receipt that FAILs or ERRORs,
   and an asset going stale. One alert per state change, not per run.
8. Receipt page: the receipt card, every check, the raw JSON, and whether it is
   signed by a pinned key and linked into a chain.
9. Auditor links: read-only, revocable, no sign-in. Show the assets and receipts
   of one workspace.
10. Public verifier at `/verify`: paste a receipt and, optionally, a public key;
    get the same answer `xinproof receipt verify` gives. No sign-in, nothing
    stored.

**Not in v0** (in order of what is likely next): teams and invites, email
alerts, auditor PDF and SOC 2 / ISO mapping, billing (Stripe), Vanta/Drata
push, hosted runners, receipts signed by Xinproof's own KMS key, SSO.

## 3. Architecture

```
 runner (GitHub Actions / Docker / laptop)
   xinproof verify … → receipts/*.json
        │  POST /api/v1/receipts   Authorization: Bearer xpt_…
        ▼
 ┌────────────── Cloudflare Worker: xinproof-cloud ──────────────┐
 │ router · GitHub OAuth · session cookies (HMAC) · HTML views   │
 │ receipt verify (WebCrypto Ed25519 + JCS) · cron (stale check) │
 └───────────────┬───────────────────────────────┬───────────────┘
                 ▼                               ▼
          D1 (SQLite): workspaces,          webhook (Slack, Discord,
          members, tokens, keys, assets,    Teams, anything that takes JSON)
          receipts, share links, alerts
```

**Why Cloudflare Workers + D1 for v0, when the spec says Go + Postgres:**
it costs $0 at this size (Workers free plan: 100k requests a day; D1 free: 5 GB,
5M reads a day), deploys in seconds, needs no servers, and the account already
has hard spending guardrails. A receipt is about 2 KB, so 5 GB holds over two
million. The schema is plain SQL that moves to Postgres unchanged when the
control plane in spec §4 is built. No framework and no npm dependencies:
WebCrypto, `fetch` and SQL are enough, so there is nothing to patch.

## 4. Data model (D1)

| Table | Columns (main) |
| --- | --- |
| `workspaces` | `id`, `name`, `webhook_url`, `stale_hours` (26), `created_at` |
| `members` | `workspace_id`, `github_id`, `login`, `role` (`owner`) |
| `tokens` | `id`, `workspace_id`, `name`, `hash` (sha256 of token), `created_at`, `last_used_at`, `revoked_at` |
| `keys` | `workspace_id`, `key_id` (`ed25519:` + 16 hex), `public_key` (base64), `note`, `tofu`, `added_at`, `revoked_at` |
| `assets` | `workspace_id`, `key` (normalized location), `engine`, `last_receipt_id`, `last_result`, `last_issued_at`, `last_pass_at`, `alert_state` |
| `receipts` | `workspace_id`, `id` (receipt ID), `asset_key`, `issued_at`, `received_at`, `result`, `reason`, `source`, `size`, `restore_seconds`, `key_id`, `seq`, `prev`, `hash`, `linked` (prev found), `json` |
| `share_links` | `token_hash`, `workspace_id`, `label`, `created_at`, `revoked_at` |

`receipts` is unique on (`workspace_id`, `id`); posting the same receipt again
returns the stored result (runners retry safely). A receipt with the same ID but
different content is rejected (409).

## 5. Security

- **Tokens and share links** are 32 random bytes, base64url, and stored only as
  SHA-256 hashes. Revocation is immediate.
- **Sessions**: an HMAC-SHA256-signed cookie (`HttpOnly`, `Secure`,
  `SameSite=Lax`, 7 days) holding the user ID and expiry. Every state-changing
  form also checks the `Origin` header.
- **GitHub OAuth** with `state` (random, in a short-lived cookie) and only the
  `read:user` scope.
- **Signatures** are verified server-side before anything is stored. A receipt
  signed by a revoked or unknown key (once keys are pinned) is rejected with
  403 and a clear reason.
- **Webhooks**: `https://` only. The URL is a secret; it is shown masked.
- **Output**: all HTML is escaped; receipt fields are untrusted input.
- **Limits**: receipt body ≤ 256 KB; 1,000 receipts per workspace per day on the
  free tier.
- **No customer data**: receipts carry counts, hashes and locations. That is
  the privacy line in the receipt spec and the reason this can be multi-tenant
  on day one.

## 6. Pricing hook

The spec's tiers map onto v0 as: Free = 1 asset, receipts kept 7 days;
Starter $29 = 5 assets, 30 days, webhook alerts; Pro $99 = 20 assets, 90 days,
auditor links. v0 enforces nothing; it records asset counts so limits can be
switched on with billing.

## 7. Rollout

1. Deploy to `xinproof-cloud.<account>.workers.dev` with D1, on the free plan.
2. Design partners point the template's `XINPROOF_CLOUD_URL` at it.
3. Custom domain (praxin.dev or similar) once bought.
4. Next: teams/invites, email alerts, the auditor PDF.

## 8. Open questions

- Should the hosted service counter-sign receipts with its own key (spec §5),
  so an auditor can trust "received at" times? Likely yes, after v0.
- Is "pinned on first use" acceptable to security-minded buyers, or should the
  key be required up front? v0 does TOFU with a visible banner until confirmed.
