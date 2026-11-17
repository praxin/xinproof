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

Status: pre-release (0.1.0). PostgreSQL (13–18) and MySQL / MariaDB (MySQL 8.0, 8.4; MariaDB 10.11, 11.4), from local folders, AWS S3, S3-compatible stores, Cloudflare R2, Azure Blob Storage / ADLS Gen2 and Google Cloud Storage. See [docs/DESIGN-verifier.md](docs/DESIGN-verifier.md).

## What it does
1. **Finds** the backups at a location (read-only: list and read, never write) and identifies each one by content: every `pg_dump` format — custom (`-Fc`, including gzip/lz4/zstd compression inside), tar (`-Ft`), directory (`-Fd`, a folder holding `toc.dat`, treated as one backup) — and plain SQL from `pg_dump`/`pg_dumpall`; `mysqldump` and `mariadb-dump` output (with or without comments, extended or one-row inserts, single or `--databases`); whole files may also be gzip/zstd/lz4 compressed. Tarballs that aren't pg_dump archives are skipped.
2. **Checks integrity** (L1): SHA-256 of the whole object (for a directory dump, of the per-file manifest), compared with a `<file>.sha256` sidecar or the S3 `ChecksumSHA256` when present; full decompression of the object and of every compressed data file; plain dumps must end with pg_dump's "dump complete" trailer and must not stop inside table data; tar archives must be complete, with their end-of-archive marker (`pg_restore` restores a truncated tar archive without complaint, so this matters); MySQL dumps must not stop inside an `INSERT` and must end with mysqldump's `-- Dump completed` line.
3. **Restores** (L2) each backup into a fresh container matching the version that made it — `postgres:<major>`, `mysql:<major.minor>` or `mariadb:<major.minor>`: **no network**, memory/CPU/PID limits, all capabilities dropped except the few the image needs, `no-new-privileges`, durability off (the sandbox is thrown away). `pg_restore --exit-on-error`, `psql -v ON_ERROR_STOP=1`, or the `mysql`/`mariadb` client, which stops at the first error.
4. **Checks the result**:
   - tables restored vs. the dump's table of contents;
   - **row audit**: the exact row count of every table is compared with the rows the dump holds for it — any table that lost rows is a FAIL;
   - **index integrity**: Postgres `amcheck` (`bt_index_check` with `heapallindexed`) on every B-tree index, largest first; MySQL `CHECK TABLE` on every table; both within `--amcheck-budget`;
   - **schema hash**: a SHA-256 fingerprint of columns, types, constraints and indexes, identical for the same database whatever the dump format;
   - restore duration (the measured RTO).
5. **Signs a receipt** for every backup: Ed25519 over the RFC 8785 canonical JSON, hash-chained to the previous receipt.

Every backup ends in exactly one of **PASS**, **FAIL** (it won't restore, with the reason) or **ERROR** (it couldn't be tested, with the reason). Nothing is silently skipped.

### When things go wrong
xinproof blames the backup only when the backup is at fault. Everything else is an ERROR that says what broke, and each scenario below is a test that runs in CI (`internal/chaos`, `internal/verify`):

| What happens | Result |
| --- | --- |
| Network drops mid-download (even for a gzip that then looks truncated) | ERROR `reading object: unexpected EOF` |
| Sandbox container killed or OOM-killed mid-restore | ERROR naming the sandbox (`raise --memory` for OOM) |
| Sandbox database crashes (connection lost mid-restore) | ERROR, not FAIL |
| Sandbox runs out of disk | ERROR `No space left on device` |
| Restore exceeds `--timeout` | ERROR `… exceeded the time budget` |
| Dump needs an extension the sandbox image lacks (PostGIS, TimescaleDB, pgvector, …) | ERROR naming the extension and an image to rerun with (`--pg-image`), never a FAIL |
| Ctrl-C / SIGTERM | current restore stopped, its sandbox removed, every untested backup reported as ERROR with a receipt; exit 2 |
| CLI killed with SIGKILL | the next run removes the orphaned sandbox at once (its owner process is gone; containers carry `xinproof.pid` / `xinproof.host` labels, plus an expiry for sandboxes started from other hosts) |
| Killed between writing a receipt and updating `HEAD` | the next run notices, rebuilds `HEAD` from the receipts, and continues the chain |

## Scale
Measured on a laptop (WSL2, Docker Engine): an 8.8 GB PostgreSQL 16 database (57 M rows; a 690 MB custom-format dump) verifies with every check — restore, exact per-table row audit against the dump, schema hash, amcheck on all indexes — in **2m24s** with `--memory 4g --cpus 4` and **3m09s** with the defaults (2 GB, 2 CPUs). The CLI itself uses about 45 MB of memory; dumps are streamed, never held in memory. Custom and directory dumps restore in parallel (`pg_restore -j`, one job per sandbox CPU, up to 8).

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
| Azure Blob Storage / ADLS Gen2 | `azblob://account/container/prefix/` (`--endpoint` for Azurite, sovereign clouds, private endpoints) | `AZURE_STORAGE_CONNECTION_STRING`, `AZURE_STORAGE_SAS_TOKEN`, `AZURE_STORAGE_KEY`, else the default Azure chain (env, workload identity, managed identity, `az login`) |
| Google Cloud Storage | `gs://bucket/prefix/` (`--endpoint` or `STORAGE_EMULATOR_HOST` for emulators) | Application Default Credentials (`GOOGLE_APPLICATION_CREDENTIALS`, `gcloud auth application-default login`, workload identity) |

Least privilege — nothing beyond list and read is ever called:
- **S3 / R2 / compatible:** `s3:ListBucket` on the bucket (prefix) and `s3:GetObject` on the objects.
- **Azure:** the `Storage Blob Data Reader` role on the container, or a SAS with only **read + list** (tested).
- **GCS:** `storage.objects.list` and `storage.objects.get` (e.g. `roles/storage.objectViewer`); the client requests the read-only OAuth scope.

Provider checksums are checked during L1 when the store has them: S3 `ChecksumSHA256` (single-part uploads), Azure `Content-MD5`, GCS MD5 (non-composite objects) and CRC32C. A mismatch is a FAIL.

### `verify` flags
| Flag | Default | Meaning |
| --- | --- | --- |
| `--newest N` | all | test only the newest N backups |
| `--since 7d` | all | only backups modified within this window (`7d`, `36h`) |
| `--receipts DIR` | `receipts` | where signed receipts and the chain `HEAD` are written |
| `--timeout` | `2h` | per-backup budget; exceeding it is an ERROR |
| `--memory`, `--cpus` | `2g`, `2` | sandbox limits |
| `--tmpfs SIZE` | off | keep the dump and restored data in RAM instead of the container's disk |
| `--engine` | `auto` | `postgres` or `mysql` to restrict which dumps are tested |
| `--pg-image`, `--mysql-image` | matched to the dump | override the sandbox image |
| `--amcheck-budget` | `10m` | time budget for index verification (amcheck / CHECK TABLE); `0` disables it |
| `--endpoint`, `--region`, `--profile`, `--path-style`, `--r2-account-id` | | storage options |
| `--format` | `human` | `json` (schema `xinproof.report/v1`) or `junit` for CI; the report goes to stdout and human progress to stderr |
| `--output FILE` | | write the json/junit report to a file and keep human output on stdout |
| `--log-level`, `--log-format` | `warn`, `text` | structured logs on stderr (`debug`/`info`/`warn`/`error`/`off`; `text` or `json`) |
| `--no-color` | | also honors `NO_COLOR` |

Interrupting a run (Ctrl-C, SIGTERM) stops the current restore, removes its sandbox, and reports every backup not yet tested as ERROR, each with a receipt.

### Exit codes
`0` all PASS · `1` any FAIL · `2` any ERROR and no FAIL (including "no backups found") · `3` usage error. A FAIL outranks an ERROR, so CI fails on a broken backup even if another couldn't be tested.

### Receipts and keys
The format is specified in [docs/RECEIPT-v1.md](docs/RECEIPT-v1.md).
- On first run `xinproof` creates an Ed25519 key pair in `~/.xinproof/keys` (override with `XINPROOF_HOME`). `xinproof key` prints the key ID and public key.
- Receipts are `receipts/receipt-NNNNNN.json`. Each one records the source, size, SHA-256, format, dump version, sandbox image (pinned by digest), result, reason, every check, timings, and the chain link (`chain.prev` = SHA-256 of the previous receipt's canonical bytes, signature included). Receipts contain no row data.
- `xinproof receipt verify` works offline. It checks the signature and the link to the previous receipt (given on the command line, or `receipt-<seq-1>.json` next to it). Pass `--pubkey ed25519.pub` (or a base64 key) to pin the signer. Without it, receipts signed by this machine's key are pinned automatically, and others are checked against their embedded key and reported as **not pinned**.

## Development
```bash
go test -short ./...                       # unit tests, no Docker needed
go test ./...                              # plus real restores in Docker (corrupted dumps must FAIL)
bash scripts/demo.sh                       # one good + one truncated dump, end to end
```
CI (`.github/workflows/ci.yml`) runs a `go mod tidy` drift check, cross-builds, vet, gofmt, race-enabled unit tests, the storage conformance suite against emulators (SeaweedFS for S3, Azurite, fake-gcs-server), restores against every supported PostgreSQL (13–18), MySQL (8.0, 8.4) and MariaDB (10.11, 11.4), the chaos tests, the demo, the JSON/JUnit report checks and govulncheck on every push.

## License
Apache-2.0 (planned)
