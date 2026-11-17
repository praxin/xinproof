#!/usr/bin/env bash
# Make the small real-cloud test set (needs Docker):
#   good/app-2026-11-17.dump (+ .sha256)  Postgres 16 custom format, 2 tables, 2,000 rows
#   good/shop-2026-11-17.sql.gz           MySQL 8.0 plain dump, gzipped
#   broken/app-truncated.dump             the first 2/3 of the Postgres dump
# Upload the result to each cloud's test bucket; scripts/real-cloud.sh checks it.
#
#   scripts/make-test-dumps.sh [out-dir]   (default ./test-dumps)
set -euo pipefail
out=${1:-test-dumps}
rm -rf "$out"; mkdir -p "$out/good" "$out/broken"
pg=xp-fix-pg-$$; my=xp-fix-my-$$
trap 'docker rm -f -v $pg $my >/dev/null 2>&1 || true' EXIT

docker run -d --name $pg --network none -e POSTGRES_PASSWORD=x postgres:16 >/dev/null
docker run -d --name $my --network none -e MYSQL_ROOT_PASSWORD=x mysql:8.0 >/dev/null
until docker exec $pg pg_isready -q -U postgres 2>/dev/null; do sleep 0.5; done
docker exec -i $pg psql -q -v ON_ERROR_STOP=1 -U postgres <<'SQL'
CREATE TABLE customers (id int PRIMARY KEY, name text NOT NULL, created timestamptz DEFAULT now());
INSERT INTO customers (id, name) SELECT g, 'customer ' || g FROM generate_series(1, 500) g;
CREATE TABLE orders (id int PRIMARY KEY, customer_id int REFERENCES customers(id), total numeric(10,2));
INSERT INTO orders SELECT g, 1 + g % 500, (g * 7 % 1000) / 10.0 FROM generate_series(1, 1500) g;
CREATE INDEX ON orders (customer_id);
SQL
docker exec $pg pg_dump -U postgres -Fc -Z 6 > "$out/good/app-2026-11-17.dump"
(cd "$out/good" && sha256sum app-2026-11-17.dump > app-2026-11-17.dump.sha256)
size=$(stat -c %s "$out/good/app-2026-11-17.dump")
head -c $((size * 2 / 3)) "$out/good/app-2026-11-17.dump" > "$out/broken/app-truncated.dump"

until docker exec $my mysqladmin -uroot -px ping >/dev/null 2>&1; do sleep 1; done
sleep 3
docker exec -i $my mysql -uroot -px 2>/dev/null <<'SQL'
CREATE DATABASE shop;
USE shop;
CREATE TABLE products (id INT PRIMARY KEY, name VARCHAR(64), price DECIMAL(8,2));
INSERT INTO products VALUES (1,'pen',1.50),(2,'book',12.00),(3,'lamp',30.25),(4,'mug',8.00),(5,'desk',150.00);
SQL
docker exec $my mysqldump -uroot -px --single-transaction --databases shop 2>/dev/null | gzip -9 > "$out/good/shop-2026-11-17.sql.gz"
ls -l "$out"/good "$out"/broken
