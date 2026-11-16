# Xinproof proof receipt, format v1

Status: stable · Schema ID: `xinproof.receipt/v1` · Reference implementation: [`internal/receipt`](../internal/receipt) · Golden example: [`internal/receipt/testdata/receipt-v1.json`](../internal/receipt/testdata/receipt-v1.json) (signed with the public test key [`receipt-v1.pub`](../internal/receipt/testdata/receipt-v1.pub))

A receipt is a JSON document that records what xinproof did to one backup and what happened. Receipts are signed with Ed25519 and chained by hash, so anyone with the public key can check them offline, and history can't be rewritten without breaking the chain.

## 1. Fields

| Field | Type | Meaning |
| --- | --- | --- |
| `schema` | string | Always `xinproof.receipt/v1`. |
| `id` | string | `rcpt_` + a ULID (time-ordered, 26 Crockford base32 chars). |
| `issued_at` | string | RFC 3339 UTC time the receipt was issued. |
| `subject.source` | string | Where the backup lives: `s3://bucket/key`, `r2://…`, or an absolute local path. |
| `subject.size` | integer | Size in bytes, from the storage provider. |
| `subject.sha256` | string | Hex SHA-256 of the object's bytes as stored (compressed), computed by reading all of it. Absent if the object wasn't read in full (rejected from its header, or a read error). |
| `subject.etag`, `subject.last_modified` | string | Provider metadata, when available. |
| `subject.format` | string | `postgres-custom`, `postgres-plain`, `mysql-plain`, `empty` or `unknown`. |
| `subject.compression` | string | `gzip`, `zstd`, `lz4`, or absent. |
| `engine.kind` | string | `postgres` or `mysql`. |
| `engine.dump_version`, `engine.server_version` | string | Versions read from the dump header. |
| `engine.sandbox_image` | string | The restore image, as `name:tag@sha256:digest` when the digest is known. |
| `result` | string | `PASS`, `FAIL` (the backup does not restore) or `ERROR` (it couldn't be tested). |
| `reason` | string | Why, for `FAIL` and `ERROR`. Absent for `PASS`. |
| `measured.restore_seconds` | number | Wall-clock restore time (the measured RTO). Milliseconds precision. |
| `measured.total_seconds` | number | Wall-clock time for the whole verification of this backup. |
| `checks[]` | array | Each `{id, status, detail}`. `status` is `pass`, `fail`, `error`, `skip` or `info`. |
| `tool` | object | `name`, `version`, `commit` of the xinproof build that issued it. |
| `chain.seq` | integer | Position in the chain, starting at 1. |
| `chain.prev` | string | `sha256:<hex>` of the previous receipt (see §3). For seq 1 it is `sha256:` followed by 64 zeros. |
| `signature` | object | See §2. |

Check IDs used by v1: `l1.format`, `l1.sha256`, `l1.checksum` (sidecar or provider checksum), `l1.decompress`, `l1.structure` (plain-dump completeness), `l2.toc`, `l2.roles`, `l2.restore`, `l2.objects`, `l2.rows`.

**Privacy:** receipts never contain row data. They contain counts, hashes, versions and the backup's location.

## 2. Signature

```
signature = {
  "alg": "ed25519",
  "key_id": "ed25519:" + hex(SHA-256(raw public key))[0:16],
  "public_key": base64(raw 32-byte public key),
  "sig": base64(Ed25519(private_key, JCS(receipt without the "signature" member)))
}
```

- **JCS** is the JSON Canonicalization Scheme, [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785): object members sorted by UTF-16 code units, no insignificant whitespace, ECMAScript number formatting, minimal string escaping.
- The signature covers **every member except `signature`**, including members a verifier doesn't know about. Adding, removing or changing any field invalidates it. Reformatting the file (indentation, key order) does not.
- `public_key` and `key_id` are hints, not trust. A verifier must decide which key it trusts (see §4).

## 3. Chain

`chain.prev` of receipt *n* is `"sha256:" + hex(SHA-256(JCS(receipt n−1)))`, computed over receipt *n−1* **including its signature**. A local store keeps receipts as `receipt-NNNNNN.json` plus a `HEAD` file holding the latest `seq` and hash. Appends are serialized with a lock on the directory, so concurrent runs can't fork the chain. If `HEAD` is lost, it is rebuilt from the highest-numbered receipt after that receipt's signature is verified.

Rewriting any receipt (even re-signing it with the right key) changes its hash and breaks the link from the next receipt. Deleting the newest receipts can't be detected from the chain alone; publish the chain head (or the hosted product's per-tenant head) if that matters.

## 4. Verifying a receipt

1. Parse the JSON. Reject it if `schema` isn't `xinproof.receipt/v1`, there's trailing data, or a number isn't finite.
2. Remove `signature`, canonicalize the rest with JCS, and verify `sig` with Ed25519 against a **trusted** public key: one given out of band (`--pubkey`), or this machine's own key. Without one, verification against the embedded `public_key` only proves the receipt hasn't changed since *someone* signed it; tools must report that as "not pinned".
3. For the chain, compute the receipt's hash (JCS including `signature`) and check that the next receipt's `chain.prev` equals it and its `chain.seq` is one higher. The first receipt must have `seq` 1 and the all-zero `prev`.

`xinproof receipt verify [--pubkey K] receipt-*.json` does all three.

## 5. Keys

- The CLI generates an Ed25519 key pair on first use in `$XINPROOF_HOME/keys` (default `~/.xinproof/keys`): `ed25519.key` (PKCS#8 PEM, mode 0600) and `ed25519.pub` (PKIX PEM). `xinproof key` prints the key ID and public key to share.
- `--pubkey` accepts that PEM file or the bare base64 key.
- The hosted service will sign with keys held in a KMS and publish them, with key IDs and rotation, at `/.well-known/xinproof-keys.json`.

## 6. Compatibility policy

- A v1 receipt that verifies today must verify with every future xinproof release. The golden receipt in `testdata` is checked byte for byte in CI to enforce this.
- New **optional** fields may be added in v1; older verifiers still verify such receipts, because the signature covers whatever is present.
- Removing a field, renaming one, or changing a field's meaning requires `xinproof.receipt/v2`.
