# Xinproof Cloud (v0)

The receipt hub: runners POST signed receipts, the Worker checks them against
pinned keys and shows a dashboard, alerts and auditor links. Design:
[docs/DESIGN-cloud.md](../docs/DESIGN-cloud.md).

A Cloudflare Worker plus a D1 database. No runtime dependencies; it runs on the
Workers free plan.

## Test

```bash
cd cloud
npm test
```

Node 22.5+ runs the Worker's real request handler against an in-memory SQLite
database (`test/d1.js` stands in for D1). The tests cover the Go golden receipt,
ingest, key pinning, chains, alerts, the stale-backup cron, auditor links,
same-origin checks and workspace isolation.

## Deploy (about 10 minutes, free)

1. **GitHub OAuth app** (github.com → Settings → Developer settings → OAuth Apps
   → New): homepage `https://xinproof-cloud.<your-subdomain>.workers.dev`,
   callback `https://xinproof-cloud.<your-subdomain>.workers.dev/auth/callback`.
   Keep the client ID and generate a client secret.
2. **Database:**
   ```bash
   npx wrangler@4 login
   npx wrangler@4 d1 create xinproof-cloud     # put the printed database_id in wrangler.toml
   npm run db:init
   ```
3. **Secrets** (each command prompts for the value; nothing goes on the command line):
   ```bash
   npx wrangler@4 secret put GITHUB_CLIENT_ID
   npx wrangler@4 secret put GITHUB_CLIENT_SECRET
   npx wrangler@4 secret put SESSION_SECRET      # any long random string
   ```
4. Set `PUBLIC_URL` in `wrangler.toml`, then `npm run deploy`.
5. Sign in, create an ingest token in Settings, and add it to a runner:
   `XINPROOF_CLOUD_URL` (variable) and `XINPROOF_CLOUD_TOKEN` (secret) in the
   [nightly workflow](../deploy/github-actions/xinproof-nightly.yml).

Schema changes: edit `schema.sql` (only `CREATE … IF NOT EXISTS` or additive
`ALTER TABLE`), then `npm run db:init` again.

## Local run

`.dev.vars` (gitignored):

```
SESSION_SECRET=dev
DEV_LOGIN=1
```

```bash
npx wrangler@4 d1 execute xinproof-cloud --local --file schema.sql
npm run dev        # http://localhost:8787/dev/login?login=you
```

`/dev/login` works only with `DEV_LOGIN=1` on `localhost`, never on a real host.

## Sending a receipt by hand

```bash
curl -fsS -X POST "$XINPROOF_CLOUD_URL/api/v1/receipts" \
  -H "Authorization: Bearer $XINPROOF_CLOUD_TOKEN" \
  -H "Content-Type: application/json" --data-binary @receipts/receipt-000001.json
```

| Status | Meaning |
| --- | --- |
| 201 | Stored. Body: `id`, `asset`, `result`, `key_id`, `pinned`, `pinned_on_first_use`, `linked`, `hash`. |
| 200 | Already received (same receipt sent again); safe to retry. |
| 401 | Missing, wrong or revoked token. |
| 403 | Not signed by a pinned key of this workspace. |
| 409 | A different receipt with the same ID was already received. |
| 413 / 422 / 429 | Too large / not a valid receipt / daily limit (1,000) reached. |
