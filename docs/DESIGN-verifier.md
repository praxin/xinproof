# How xinproof works

This is the design of `xinproof verify`: what it promises, how a backup moves through it, and how failures are handled. For usage and flags, see the [README](../README.md); for the receipt format, see [RECEIPT-v1.md](RECEIPT-v1.md).

## 1. Goal

Given a location holding existing database backups, prove whether each backup actually restores, and emit a **signed, hash-chained receipt** for each one.

```
xinproof verify s3://acme-backups/postgres/
xinproof verify azblob://acct/container/pg/ --since 7d
xinproof verify gs://bucket/mysql/ --engine mysql
xinproof verify ./local-dumps/
xinproof receipt verify receipt.json        # anyone can check a receipt
```

Out of scope for `verify`: taking backups, and changing anything at the backup location. Scheduling is either your own (cron, CI, the [GitHub Actions template](../deploy/github-actions/xinproof-nightly.yml)) or `xinproof agent`, which runs `verify` on work it receives from Xinproof Cloud.

## 2. Guarantees

1. **Never silently partial.** Every backup found ends in exactly one of `PASS`, `FAIL` (it won't restore, with the reason) or `ERROR` (it couldn't be tested, with the reason). Each gets a receipt, including on Ctrl-C.
2. **Read-only on the source.** Only list and read are ever called. Nothing is written, deleted or modified at the backup location.
3. **Isolated restores.** Each restore runs in a fresh container with no network and resource limits, and is removed afterwards, including after a crash (cleanup on the next start, using container labels).
4. **Data stays where the CLI runs.** Restores happen on the machine running `xinproof`. Receipts contain counts, hashes, versions, table names and results, never row data.
5. **Anyone can check a receipt** offline, with only the public key.
6. **Blame the backup only when it is at fault.** Problems with the environment (out of memory, a network drop, a missing extension, a timeout) are `ERROR`, not `FAIL`.

## 3. Layout

```
cmd/xinproof            CLI: verify, receipt verify, key, agent, version
internal/source         Read-only storage: List / Open / Stat
  ├─ s3                 AWS S3 and S3-compatible stores (R2, MinIO, B2, Wasabi, Ceph, …)
  ├─ azblob             Azure Blob Storage / ADLS Gen2
  ├─ gcs                Google Cloud Storage
  ├─ local              Local folders and files
  └─ conformance        One test suite every backend must pass (run against emulators in CI)
internal/discover       Backup detection by content: magic bytes, headers, compression
internal/sandbox        Throwaway Docker containers with no network and limits
internal/engine         Per-engine restore and checks
  ├─ postgres           pg_restore / psql, amcheck, schema hash, extension detection
  ├─ mysql              mysql / mariadb client, CHECK TABLE, schema hash
  └─ mongodb            mongorestore, archive CRC checks, document counts
internal/verify         Runs the pipeline for each backup, including custom checks
internal/receipt        RFC 8785 canonical JSON, Ed25519 signing, hash chain
internal/report         Human, JSON and JUnit output
internal/chaos          Tests for crashes, kills, OOM, disk full and network drops
```

## 4. One backup, start to finish

1. **Discover.** List the location and identify each object by its content, not its name: every `pg_dump` format (custom, tar, directory, plain SQL, `pg_dumpall`), `mysqldump` / `mariadb-dump`, and `mongodump --archive`, optionally wrapped in gzip, zstd or lz4. Other files are skipped.
2. **L1 integrity.** Stream the object once: SHA-256 and size; compare with a `.sha256` sidecar or the provider's checksum when there is one (S3 `ChecksumSHA256`, Azure `Content-MD5`, GCS MD5/CRC32C); decompress everything; check the dump's own end markers (pg_dump's "dump complete" trailer, the tar end-of-archive marker, mysqldump's `-- Dump completed`, every MongoDB namespace closed and matching its CRC-64).
3. **Sandbox.** Start the image that matches the version that made the dump (`postgres:<major>`, `mysql:<major.minor>`, `mariadb:<major.minor>`, `mongo:7`), pinned by digest, with no network, memory/CPU/PID limits, capabilities dropped and `no-new-privileges`. Durability is turned off because the data is thrown away.
4. **L2 restore.** Stream the dump into the container and restore it, stopping at the first error (`pg_restore --exit-on-error`, `psql -v ON_ERROR_STOP=1`, the MySQL client, `mongorestore --stopOnError`). The wall-clock restore time is recorded as the measured RTO.
5. **L2 checks.**
   - Tables restored vs. the dump's table of contents.
   - Row audit: the exact row count of every table (MongoDB: documents per collection) compared with what the dump contains. Any table that lost rows is a `FAIL`.
   - Index integrity: Postgres `amcheck` on every B-tree index; MySQL `CHECK TABLE`. Both run within `--amcheck-budget`.
   - Schema hash: a fingerprint of columns, types, constraints and indexes that is the same whatever the dump format.
6. **L3 custom checks (optional).** Each `--check 'name=SQL'` runs in the restored database and must return one truthy value.
7. **Receipt.** Build the receipt, sign it, chain it to the previous one, write it, then remove the sandbox.

## 5. Receipts

Specified in [RECEIPT-v1.md](RECEIPT-v1.md). In short: the signature is Ed25519 over the RFC 8785 canonical JSON of the receipt without its `signature` field. `chain.prev` is the SHA-256 of the previous receipt's canonical bytes, including its signature. The CLI creates a key pair in `~/.xinproof/keys` on first run; `xinproof key` prints it.

## 6. Credentials and security

- **Credentials** come from each cloud's standard chain (AWS profiles and roles, Azure `DefaultAzureCredential`, Google Application Default Credentials). They are never written to disk or into receipts.
- **Least privilege:** S3 `s3:ListBucket` + `s3:GetObject`; Azure `Storage Blob Data Reader` (or a read + list SAS); GCS `storage.objects.list` + `get`. The [deploy guide](../deploy/README.md) has keyless (OIDC) setups for each cloud.
- **Backups are untrusted input.** Their contents only ever run inside the sandbox, never on the host.

## 7. Failure model

Each case below is covered by a test (`internal/chaos`, `internal/verify`).

| What happens | Result |
| --- | --- |
| Truncated or corrupt file, or broken compression | FAIL, with where it breaks |
| Restore error | FAIL, with the first error lines |
| A table restored with fewer rows than the dump holds | FAIL, naming the table |
| Network drop while downloading | ERROR |
| Sandbox killed, out of memory, or out of disk | ERROR, naming the cause |
| Dump needs an extension the image lacks | ERROR, naming the extension and an image to use |
| Restore exceeds `--timeout` (default 2h) | ERROR |
| Ctrl-C or SIGTERM | current sandbox removed; every untested backup gets an ERROR receipt |
| CLI killed with SIGKILL | the next run removes the leftover sandbox and repairs the chain head |

**Exit codes:** `0` all PASS · `1` any FAIL · `2` any ERROR and no FAIL · `3` usage error.

## 8. Testing

- **Unit:** format detection, canonical JSON, signing and chains, reports. `go test -short ./...` needs no Docker.
- **Restores:** real restores against every supported version (PostgreSQL 13–18, MySQL 8.0/8.4, MariaDB 10.11/11.4, MongoDB 6.0–8.0), with dumps corrupted on purpose (truncated, byte-flipped, missing data). Every corrupted dump must FAIL with the right reason, and every clean one must PASS.
- **Storage:** one conformance suite against emulators (SeaweedFS for S3, Azurite, fake-gcs-server), plus a nightly run against real cloud buckets (AWS S3, Azure Blob, Google Cloud Storage, Cloudflare R2).
- **Chaos:** the failure cases in §7.

## 9. Known limits

- Logical dumps only. Physical backups (pgBackRest, WAL-G, XtraBackup) and managed-database snapshots are not supported.
- Large dumps are always fully restored, so they need enough sandbox memory and disk (`--memory`, `--tmpfs`).
- Windows runs through Docker Desktop with WSL2; there is no native Windows sandbox.
