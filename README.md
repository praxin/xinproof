# xinproof

[![ci](https://github.com/praxin/xinproof/actions/workflows/ci.yml/badge.svg)](https://github.com/praxin/xinproof/actions/workflows/ci.yml)

**Backups that keep their word.** `xinproof` proves whether your database backups actually restore, and gives you a signed receipt anyone can verify.

> Name: 信 (xìn) means trust, or a promise kept. Pronounced "shin-proof".

```
$ xinproof verify ./dumps/
  found 2 dumps · restoring 2 in sandboxes…
  ✗ pg_2026-11-15.dump  pg_restore failed (exit 1): pg_restore: error: could not read from input file: end of file
  ✓ pg_2026-11-14.dump  3 tables  65.0K rows  0m00s
  signed receipts → receipts/receipt-000001.json … receipt-000002.json
  check one: xinproof receipt verify receipts/receipt-000002.json
  → Let Xinproof take over this backup: https://xinproof.dev

$ xinproof receipt verify receipts/*.json
✓ receipt-000001.json  signature valid (pinned: this machine's key) · chain intact (first receipt)
✓ receipt-000002.json  signature valid (pinned: this machine's key) · chain intact
```

Status: pre-release (0.1.0). Postgres works today, from local folders, S3, S3-compatible stores and Cloudflare R2. MySQL, Azure Blob/ADLS Gen2 and GCS are next. See [docs/DESIGN-verifier.md](docs/DESIGN-verifier.md).

## What it does
1. **Finds** the backups at a location (read-only: list and read, never write) and identifies each one by content: `pg_dump` custom format (`PGDMP`), plain SQL from `pg_dump`/`pg_dumpall`, optionally gzip/zstd/lz4 compressed. MySQL dumps are recognized and reported as not yet testable.
2. **Checks integrity** (L1): SHA-256 of the whole object, compared with a `<file>.sha256` sidecar or the S3 `ChecksumSHA256` when present; full decompression; plain dumps must end with pg_dump's "dump complete" trailer and must not stop inside table data.
3. **Restores** (L2) each backup into a fresh `postgres:<major>` container matching the `pg_dump` version: **no network**, memory/CPU/PID limits, all capabilities dropped except the few the image needs, `no-new-privileges`. `pg_restore --exit-on-error` or `psql -v ON_ERROR_STOP=1`.
4. **Checks the result**: tables restored vs. the dump's table of contents, exact row counts, restore duration.
5. **Signs a receipt** for every backup: Ed25519 over the RFC 8785 canonical JSON, hash-chained to the previous receipt.

Every backup ends in exactly one of **PASS**, **FAIL** (it won't restore, with the reason) or **ERROR** (it couldn't be tested, with the reason). Nothing is silently skipped. Sandboxes are always removed: on success, on failure, on Ctrl-C, and, if the CLI is killed, by a reaper at the start of the next run (containers carry `xinproof.*` labels and an expiry).

## Requirements
- Docker: Docker Engine on Linux; Docker Desktop (or colima, etc.) on macOS; Docker Desktop with WSL2 on Windows.
- Read-only access to wherever the backups live.
- Building from source: Go (version in `go.mod`).

```bash
go build -o bin/xinproof ./cmd/xinproof
```

## Usage

```
xinproof verify [flags] <location>
xinproof receipt verify [--pubkey K] <receipt.json>...
xinproof key
xinproof version
```

### Locations
| Location | Example | Credentials |
| --- | --- | --- |
| Local folder (recursive) or one file | `./dumps/`, `/mnt/nfs/pg.dump` | — |
| AWS S3 | `s3://acme-backups/postgres/` | standard AWS chain: env vars, `--profile`, SSO, instance/task role, IRSA |
| S3-compatible (MinIO, B2, Wasabi, Ceph, …) | `s3://bucket/prefix/ --endpoint https://minio:9000 --path-style` | `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` |
| Cloudflare R2 | `r2://bucket/prefix/ --r2-account-id <id>` (or `R2_ACCOUNT_ID`) | R2 API token as `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` |

Least privilege for S3: `s3:ListBucket` on the bucket (prefix) and `s3:GetObject` on the objects. Nothing else is called.

### `verify` flags
| Flag | Default | Meaning |
| --- | --- | --- |
| `--newest N` | all | test only the newest N backups |
| `--since 7d` | all | only backups modified within this window (`7d`, `36h`) |
| `--receipts DIR` | `receipts` | where signed receipts and the chain `HEAD` are written |
| `--timeout` | `2h` | per-backup budget; exceeding it is an ERROR |
| `--memory`, `--cpus` | `2g`, `2` | sandbox limits |
| `--tmpfs SIZE` | off | keep the dump and restored data in RAM instead of the container's disk |
| `--pg-image` | `postgres:<major>` | override the sandbox image |
| `--endpoint`, `--region`, `--profile`, `--path-style`, `--r2-account-id` | | storage options |
| `--no-color` | | also honors `NO_COLOR` |

### Exit codes
`0` all PASS · `1` any FAIL · `2` any ERROR and no FAIL (including "no backups found") · `3` usage error. A FAIL outranks an ERROR, so CI fails on a broken backup even if another couldn't be tested.

### Receipts and keys
- On first run `xinproof` creates an Ed25519 key pair in `~/.xinproof/keys` (override with `XINPROOF_HOME`). `xinproof key` prints the key ID and public key.
- Receipts are `receipts/receipt-NNNNNN.json`. Each one records the source, size, SHA-256, format, dump version, sandbox image (pinned by digest), result, reason, every check, timings, and the chain link (`chain.prev` = SHA-256 of the previous receipt's canonical bytes, signature included). Receipts contain no row data.
- `xinproof receipt verify` works offline. It checks the signature and the link to the previous receipt (given on the command line, or `receipt-<seq-1>.json` next to it). Pass `--pubkey ed25519.pub` (or a base64 key) to pin the signer. Without it, receipts signed by this machine's key are pinned automatically, and others are checked against their embedded key and reported as **not pinned**.

## Development
```bash
go test -short ./...                       # unit tests, no Docker needed
go test ./...                              # plus real restores in Docker (corrupted dumps must FAIL)
bash scripts/demo.sh                       # one good + one truncated dump, end to end
```
CI (`.github/workflows/ci.yml`) runs `go mod tidy` drift check, build, vet, gofmt, race-enabled unit tests, the Docker integration test, the demo, and govulncheck on every push.

## License
Apache-2.0 (planned)
