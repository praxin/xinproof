#!/usr/bin/env bash
# Verify the real-cloud test dumps at a location and check the outcome:
# every dump PASSes except the deliberately truncated one, which must FAIL.
#
#   scripts/real-cloud.sh <location> [xinproof verify flags...]
#
# The test set (scripts/make-test-dumps.sh, uploaded once per cloud):
#   app-2026-11-17.dump (+ .sha256)  Postgres custom format   -> PASS
#   shop-2026-11-17.sql.gz           MySQL plain, gzipped      -> PASS
#   app-truncated.dump               first 2/3 of the above    -> FAIL
set -euo pipefail
loc=$1; shift
bin=${XINPROOF_BIN:-./xinproof}
out=$(mktemp)
code=0
"$bin" verify "$loc" --format json --output "$out" --receipts "$(mktemp -d)" "$@" || code=$?
python3 - "$out" "$code" "$loc" <<'PY'
import json, sys
path, code, loc = sys.argv[1], int(sys.argv[2]), sys.argv[3]
rep = json.load(open(path))
res = rep.get("results", [])
for r in res:
    print(f"{r['status']}\t{r['name']}\t{r.get('reason', '')}")
wrong = [r["name"] for r in res
         if r["status"] != ("FAIL" if "truncated" in r["name"] else "PASS")]
truncated = sum("truncated" in r["name"] for r in res)
if code != 1 or len(res) != 3 or truncated != 1 or wrong:
    print(f"unexpected result at {loc}: exit {code}, {len(res)} dumps, wrong: {wrong or 'none'}", file=sys.stderr)
    print(json.dumps(rep, indent=2), file=sys.stderr)
    sys.exit(1)
print(f"ok: {loc} -> 2 PASS, 1 FAIL (exit 1), as expected")
PY
