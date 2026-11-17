#!/usr/bin/env bash
# Demo: one good and one truncated pg_dump in a local folder.
# Expected: the good dump PASSes, the truncated one FAILs, both get signed receipts.
# Needs Go and Docker (Linux, macOS, or WSL2 on Windows).
set -euo pipefail
cd "$(dirname "$0")/.."

PG_IMAGE=${PG_IMAGE:-postgres:16}
WORK=${WORK:-$(mktemp -d)}
mkdir -p "$WORK/dumps" bin

echo "building xinproof…"
go build -o bin/xinproof ./cmd/xinproof

echo "making a sample database in $PG_IMAGE…"
name="xinproof-demo-$RANDOM"
docker run -d --name "$name" --network none -e POSTGRES_PASSWORD=demo \
  --label xinproof.managed=true --label "xinproof.expires=$(( $(date +%s) + 1800 ))" "$PG_IMAGE" >/dev/null
trap 'docker rm -f -v "$name" >/dev/null 2>&1 || true' EXIT
until docker exec -e PGPASSWORD=demo "$name" pg_isready -q -h 127.0.0.1 -U postgres; do sleep 0.5; done
docker exec -i "$name" psql -X -q -v ON_ERROR_STOP=1 -U postgres <<'SQL'
CREATE TABLE customers (id serial PRIMARY KEY, name text NOT NULL);
INSERT INTO customers (name) SELECT 'customer ' || g FROM generate_series(1, 5000) g;
CREATE TABLE orders (id bigserial PRIMARY KEY, customer_id int REFERENCES customers(id), total numeric(10,2));
INSERT INTO orders (customer_id, total) SELECT 1 + (g % 5000), (g % 997) * 1.25 FROM generate_series(1, 40000) g;
CREATE TABLE audit_log (id bigserial, payload text);
INSERT INTO audit_log (payload) SELECT md5(g::text) FROM generate_series(1, 20000) g;
SQL
docker exec "$name" pg_dump -U postgres -Fc > "$WORK/dumps/pg_2026-11-14.dump"
# Simulate a backup job that died part-way: keep the first 61% of the file.
size=$(stat -c %s "$WORK/dumps/pg_2026-11-14.dump")
head -c $(( size * 61 / 100 )) "$WORK/dumps/pg_2026-11-14.dump" > "$WORK/dumps/pg_2026-11-15.dump"

echo
echo "\$ xinproof verify $WORK/dumps/"
set +e
XINPROOF_HOME="$WORK/home" ./bin/xinproof verify --receipts "$WORK/receipts" "$WORK/dumps/"
code=$?
set -e
echo "(exit code $code: 0 all PASS · 1 any FAIL · 2 any ERROR)"
if [ "$code" != 1 ]; then echo "demo: expected exit code 1 (one PASS, one FAIL)" >&2; exit 1; fi

echo
echo "\$ xinproof receipt verify $WORK/receipts/receipt-*.json"
XINPROOF_HOME="$WORK/home" ./bin/xinproof receipt verify "$WORK"/receipts/receipt-*.json
echo
echo "receipts and dumps are in $WORK"
