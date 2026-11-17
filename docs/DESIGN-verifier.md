# Xinproof Verifier: engineering design (v0.1)

Status: draft · Owner: founder · Scope: the free "Verify your existing backups" tool, which is also the core engine of the paid product.

## 1. Goal

Given a location holding existing database backups, prove whether each backup actually restores. Then emit a **signed, hash-chained proof receipt** for each one.

```
xinproof verify s3://acme-backups/postgres/
xinproof verify azblob://acct/container/pg/ --since 7d
xinproof verify gs://bucket/mysql/ --engine mysql
xinproof verify ./local-dumps/
xinproof receipt verify receipt.json        # anyone can check a receipt
```

**Non-goals for v1:** taking backups, bucket point-in-time recovery, the web UI, scheduling. Those belong to the full product and reuse this engine.

## 2. Guarantees (the contract)

1. **Never silently partial.** Every discovered backup ends in exactly one of `PASS`, `FAIL`, or `ERROR` (meaning we couldn't test it, with the reason). The tool never says "done" for a backup it didn't test.
2. **Read-only on the source.** It needs list and read permission only. It never writes, deletes or modifies source objects.
3. **Isolated restores.** Each restore runs in a fresh container with **no network** and resource limits. The container is destroyed afterwards, even on crash (cleanup on start, labels, TTL reaper).
4. **Data never leaves the machine running the CLI.** The free tool runs locally or in the customer's CI. The hosted version runs the same engine in our sandboxes.
5. **Anyone can check a receipt** with the public key alone, offline.

## 3. Architecture

```
cmd/xinproof            CLI (cobra): verify, receipt verify, version
internal/source         Storage abstraction: List(prefix) / Open(key) / Stat
  ├─ s3                 AWS S3 + S3-compatible (R2, MinIO, Wasabi, B2): aws-sdk-go-v2
  ├─ azblob             Azure Blob / ADLS Gen2: azure-sdk-for-go
  ├─ gcs                Google Cloud Storage: cloud.google.com/go/storage
  └─ local              Local filesystem (tests, offline use)
internal/discover       Backup detection: magic bytes + extension + compression sniffing
internal/sandbox        Container runtime: Docker Engine API (moby client); later Firecracker
internal/engine
  ├─ postgres           pg_restore / psql restore + checks
  └─ mysql              mysql client restore + checks
internal/checks         Check framework: L1 integrity, L2 restorability, L3 custom SQL
internal/receipt        Canonical JSON (RFC 8785 JCS), Ed25519 sign/verify, hash chain
internal/report         Human table, JSON, JUnit XML (for CI)
```

### Data flow for one backup
1. **Discover:** list the prefix. For each candidate object, read the first 64 KB to detect format:
   - Postgres custom format: magic `PGDMP`.
   - Plain SQL: a `-- PostgreSQL database dump` or `-- MySQL dump` header.
   - Compression: gzip, zstd or lz4, by magic number.
2. **L1 integrity:** stream the whole object and compute SHA-256 and size.
   - If a checksum sidecar exists (`.sha256`, the S3 `ChecksumSHA256` attribute, or an Azure `Content-MD5`), compare against it.
   - Decompress fully to catch truncated or corrupt archives (gzip CRC, zstd frame errors).
   - For `PGDMP`, also parse the TOC with `pg_restore -l` inside the sandbox.
3. **Sandbox:** start `postgres:<major>` or `mysql:<major>`, with the version taken from the dump header (`pg_dump` version / server version). Settings:
   - `--network none`, a tmpfs data directory if size allows, memory and CPU limits, a random superuser password, and labels `xinproof.run=<id>`.
4. **L2 restore:** stream the object into the container over its stdin (no temporary file on the host by default).
   - Postgres custom format: `pg_restore --exit-on-error --no-owner --no-acl -d restore`.
   - Plain SQL: `psql -v ON_ERROR_STOP=1`.
   - Record the exit code, stderr and wall-clock **restore duration** (the measured RTO).
5. **L2 checks:**
   - Restored object counts vs the TOC: tables, sequences, indexes, functions.
   - Row counts per table (exact `count(*)` up to a size budget, otherwise `pg_class.reltuples` estimates, flagged as such).
   - Schema fingerprint: a SHA-256 of the normalized catalog query.
   - Postgres: `amcheck` (`bt_index_check`) on B-tree indexes, within a time budget.
   - Postgres: largest tables are non-empty if the TOC says they had data (`COPY` entries present).
   - Truncation heuristic: a TOC entry with data but zero restored rows causes a FAIL with an explicit reason.
6. **L3 custom checks (optional):** user SQL assertions from `xinproof.yaml`, for example `SELECT count(*) > 0 FROM orders WHERE created_at > now() - interval '1 day'`.
7. **Receipt:** build the receipt, sign it, append it to the chain, write it out, then tear down the sandbox.

## 4. Receipt format (v1)

```json
{
  "schema": "xinproof.receipt/v1",
  "id": "rcpt_01JD8Q4M7X…",            // ULID
  "issued_at": "2026-11-16T14:21:07Z",
  "subject": {
    "source": "s3://acme-backups/postgres/pg_2026-11-16.dump",
    "size": 13314398208,
    "sha256": "…",
    "etag": "…", "last_modified": "…"
  },
  "engine": { "kind": "postgres", "dump_version": "16.4", "sandbox_image": "postgres:16.4@sha256:…" },
  "result": "PASS",                    // PASS | FAIL | ERROR
  "measured": { "restore_seconds": 238.4, "total_seconds": 291.0 },
  "checks": [
    { "id": "l1.sha256", "status": "pass", "detail": "…" },
    { "id": "l2.restore", "status": "pass", "detail": "exit 0" },
    { "id": "l2.objects", "status": "pass", "detail": "214/214 tables" },
    { "id": "l2.rows", "status": "pass", "detail": "38,212,904 rows" },
    { "id": "l2.schema_hash", "status": "pass", "detail": "sha256:e1c9…" },
    { "id": "l2.amcheck", "status": "pass", "detail": "412 indexes" }
  ],
  "tool": { "name": "xinproof", "version": "0.1.0", "commit": "…" },
  "chain": { "prev": "sha256:7b01…44d0", "seq": 1284 },
  "signature": { "alg": "ed25519", "key_id": "…", "sig": "base64…" }
}
```

- **Signing:** `sig = Ed25519(private_key, JCS(receipt without "signature"))`.
- **Chain:** `prev` is the SHA-256 of the previous receipt's canonical bytes, including its signature. A local `receipts/` store keeps the chain head. The hosted product keeps chains per tenant.
- **Keys:**
  - The free CLI generates a local key pair on first run (`~/.xinproof/keys`) and prints its fingerprint.
  - The hosted service signs with keys held in KMS and published at `/.well-known/xinproof-keys.json`, with rotation and key IDs.
- **Privacy:** receipts never contain row data, only counts, hashes and metadata. Table names can be hashed with `--redact-names`.

## 5. Credentials and security

- **Credentials:** the standard credential chain for each cloud (AWS profile/role, Azure DefaultAzureCredential, GCP ADC). They're never written to disk or into receipts.
- **Least-privilege examples ship in the docs:**
  - S3: `s3:ListBucket` + `s3:GetObject` on the prefix.
  - Azure: `Storage Blob Data Reader`.
  - GCS: `storage.objects.list` / `get`.
- **Untrusted input:** backups are untrusted. Restores happen only inside containers with no network, limits, and no host mounts other than a scratch tmpfs. The host never runs dump content.
- **Supply chain:**
  - Sandbox images are pinned by digest.
  - Releases are built reproducibly, signed with cosign, and ship an SBOM.

## 6. Failure model (explicit, tested)

| Failure | Result | Reported reason |
| --- | --- | --- |
| Object truncated or corrupt compression | FAIL | "gzip stream ends early at byte N" |
| `pg_restore` error | FAIL | first error lines from stderr |
| TOC says data, table restored empty | FAIL | "table X expected data, restored 0 rows" |
| Container can't start / Docker missing | ERROR | actionable message, never PASS |
| Credential / permission denied | ERROR | which permission is missing |
| Timeout (default 2 h, configurable) | ERROR | "restore exceeded 2h budget" |
| CLI killed mid-run | no receipt; the sandbox is reaped on the next run | — |

**Exit codes:** `0` all PASS · `1` any FAIL · `2` any ERROR · `3` usage error. This makes it usable directly in CI.

## 7. Testing strategy (production-grade bar)

- **Unit:** format detection (golden files), canonical JSON, sign/verify, chain verification, report rendering.
- **Integration (testcontainers-go):** MinIO plus real Postgres 13–17 and MySQL 8.0/8.4. Generate fixture databases, dump them, then corrupt them deliberately:
  - truncate at 10% / 61% / 99%
  - flip bytes
  - drop a table's data section
  - wrong-version dump
  - empty file

  Every corruption **must** produce FAIL with the right reason. Every clean dump **must** PASS.
- **Chaos:** kill the CLI mid-restore, then make sure the next run reaps the container and leaves no partial receipt.
- **Cross-platform:** CI on Linux, macOS and Windows (with Docker Desktop).
- **Golden receipts:** the receipt schema is versioned and tested for backward compatibility.

## 8. Milestones

1. **M1:** CLI skeleton, local and S3 sources, Postgres custom and plain-SQL formats, the L1 and L2 restore/objects/rows checks, signed receipts plus `receipt verify`, and the integration tests above.
2. **M2:** schema hash, `amcheck`, L3 custom SQL, JSON/JUnit output, the GitHub Action.
3. **M3:** Azure Blob, GCS, R2/B2/Wasabi; MySQL engine.
4. **M4:** open-source release (Apache-2.0), docs site, Show HN. A hosted "verify" web flow uses the same engine.

## 9. Open decisions

- **License:** Apache-2.0 for the verifier is recommended (trust and adoption). The hosted product stays proprietary.
- **Large dumps (>100 GB):** sample-restore mode (schema plus the largest N tables) vs full restore. Default to full, and add sampling as an explicit flag.
- **Windows-native without Docker:** out of scope. Document WSL2 or Docker Desktop as the requirement.
