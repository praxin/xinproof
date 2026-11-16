# xinproof

**Backups that keep their word.** `xinproof` proves whether your database backups actually restore, and gives you a signed receipt anyone can verify.

> Name: 信 (xìn) means trust, or a promise kept. Pronounced "shin-proof".

```
xinproof verify s3://acme-backups/postgres/
xinproof receipt verify receipt.json
```

Status: pre-alpha, design stage. See [docs/DESIGN-verifier.md](docs/DESIGN-verifier.md).

## What it does
1. Finds the backups in S3, Azure Blob, GCS, R2 or a local folder (read-only).
2. Restores each one into an isolated, network-less sandbox container.
3. Checks the result: integrity, restore success, object and row counts, schema hash, index health, and your own SQL assertions.
4. Issues an Ed25519-signed, hash-chained proof receipt for each backup. Each result is PASS, FAIL or ERROR, never silently partial.

## Requirements
- Docker (Docker Desktop on Windows/macOS, Docker Engine on Linux)
- Read-only credentials for wherever your backups live

## License
Apache-2.0 (planned)
