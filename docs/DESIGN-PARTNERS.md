# Xinproof design partners

A design partner runs Xinproof against their real backups for 8 weeks, free,
and tells us what is missing. This page is what we send them.

## What you get

- Every night, your newest backups are restored into throwaway databases and
  checked: is the file complete, does it match its checksum, does it restore,
  and are all the tables and rows from the dump there. If a backup is broken, you hear about
  it the next morning, not on the day you need it.
- A signed receipt for every backup tested. Give your auditor the public key and
  they can check every receipt themselves (useful for SOC 2 CC9.1, ISO 27001
  A.8.13, and the restore-test requirement in most cyber-insurance forms).
- Direct access to the people building it, and features you ask for go first.
- Early access to Xinproof Cloud (dashboard, history, alerts) when it opens.

## What we ask

- A 30-minute setup call, and a 20-minute check-in in weeks 2, 4 and 8.
- Run it against at least one real production backup location.
- Tell us honestly what broke, what was confusing, and what you would pay for.
- Optional: a short quote or case study if it helped.

## What stays with you

Xinproof runs in your account: your GitHub Actions, or a machine in your cloud.
It gets read-only access to one bucket. Your backups are never sent to us
and we never see them. Receipts hold sizes, hashes, table and row
counts and check results, never row data. You can delete the identity and the workflow at
any time and nothing is left behind.

## Who fits

- You back up **PostgreSQL or MySQL/MariaDB** with `pg_dump` or `mysqldump` (or
  a tool that produces those formats) to **S3, Azure Blob, Google Cloud Storage,
  Cloudflare R2** or any S3-compatible store.
- Backups up to roughly 10 GB each on GitHub-hosted runners; larger on your own
  runner or VM.
- Not yet supported: physical backups (pgBackRest, WAL-G, Percona XtraBackup),
  managed-database snapshots (RDS, Cloud SQL), MongoDB, SQL Server. Tell us if
  you need these; it decides what we build next.

## Onboarding checklist (for the setup call)

1. Pick the backup location and the GitHub repo (or VM) that will run it.
2. Create the read-only identity: [deploy/README.md](../deploy/README.md).
3. `xinproof key`; store the private key as the `XINPROOF_KEY` secret; save `ed25519.pub`.
4. Add [the workflow](../deploy/github-actions/xinproof-nightly.yml), set the variables, run it once by hand.
5. Read the first results together. Any FAIL: work out whether it is a real
   broken backup or a gap in Xinproof, and log it.
6. Turn on GitHub notifications for failed workflow runs.

## Check-in questions

- Did it find anything you did not know about?
- Any false alarm? What did it say, and what was actually true?
- How long did the nightly run take, and was that acceptable?
- Who looked at the results? Did anyone outside engineering (security,
  compliance, an auditor) use a receipt?
- What would stop you from paying for this? What would make it a must-have?
- If it cost $X per month per database, would you buy it? At what price would you not?

## What success looks like after 8 weeks

- Nightly runs green for at least 4 weeks, or every failure explained.
- At least one receipt handed to someone outside engineering.
- A clear yes or no on paying, and the reason.
