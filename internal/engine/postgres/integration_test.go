package postgres_test

// Integration test: real pg_dump output, real pg_restore/psql in real sandbox
// containers. Every clean dump must PASS and every corrupted one must FAIL.
// Needs Docker; skipped with -short or when no Docker daemon is reachable.
//
//   XINPROOF_TEST_PG_IMAGE=postgres:17 go test ./internal/engine/postgres -run Real -v

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/praxin/xinproof/internal/engine/postgres"
	"github.com/praxin/xinproof/internal/receipt"
	"github.com/praxin/xinproof/internal/sandbox"
	"github.com/praxin/xinproof/internal/source/local"
	"github.com/praxin/xinproof/internal/verify"
)

const fixtureSQL = `
CREATE ROLE app_owner;
CREATE ROLE app_reader;
CREATE TABLE customers (id serial PRIMARY KEY, name text NOT NULL, email text);
INSERT INTO customers (name, email) SELECT 'customer ' || g, 'c' || g || '@example.com' FROM generate_series(1, 5000) g;
CREATE TABLE orders (id bigserial PRIMARY KEY, customer_id int REFERENCES customers(id), total numeric(10,2), created_at timestamptz DEFAULT now());
INSERT INTO orders (customer_id, total) SELECT 1 + (g % 5000), (g % 997) * 1.25 FROM generate_series(1, 40000) g;
CREATE INDEX orders_customer_idx ON orders (customer_id);
CREATE TABLE audit_log (id bigserial, payload text);
INSERT INTO audit_log (payload) SELECT md5(g::text) FROM generate_series(1, 20000) g;
ALTER TABLE audit_log OWNER TO app_owner;
GRANT SELECT ON orders TO app_reader;
`

const fixtureTables, fixtureRows = 3, 65000

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func docker(t *testing.T, stdin []byte, args ...string) []byte {
	t.Helper()
	cmd := exec.Command("docker", args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args[:min(3, len(args))], " "), err, errb.String())
	}
	return out.Bytes()
}

// makeFixtures builds a small database in a throwaway container and dumps it
// in custom and plain formats.
func makeFixtures(t *testing.T, image string) (custom, plain []byte) {
	t.Helper()
	name := "xinproof-fixture-" + randHex(4)
	docker(t, nil, "run", "-d", "--name", name, "--network", "none",
		"--label", "xinproof.managed=true", "--label", fmt.Sprintf("xinproof.expires=%d", time.Now().Add(30*time.Minute).Unix()),
		"-e", "POSTGRES_PASSWORD=fixture", image)
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", "-v", name).Run() })
	deadline := time.Now().Add(2 * time.Minute)
	for {
		if exec.Command("docker", "exec", "-e", "PGPASSWORD=fixture", name, "pg_isready", "-q", "-h", "127.0.0.1", "-U", "postgres").Run() == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fixture postgres did not become ready")
		}
		time.Sleep(500 * time.Millisecond)
	}
	docker(t, []byte(fixtureSQL), "exec", "-i", name, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres")
	custom = docker(t, nil, "exec", name, "pg_dump", "-U", "postgres", "-Fc", "-d", "postgres")
	plain = docker(t, nil, "exec", name, "pg_dump", "-U", "postgres", "-d", "postgres")
	return custom, plain
}

func flip(b []byte, at float64, n int) []byte {
	c := append([]byte(nil), b...)
	i := int(float64(len(c)) * at)
	for j := i; j < i+n && j < len(c); j++ {
		c[j] ^= 0xff
	}
	return c
}

func cut(b []byte, frac float64) []byte { return b[:int(float64(len(b))*frac)] }

func TestRealRestores(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (needs Docker); skipped with -short")
	}
	ctx := context.Background()
	d := &sandbox.Docker{}
	if err := d.Available(ctx); err != nil {
		t.Skipf("skipping: %v", err)
	}
	image := os.Getenv("XINPROOF_TEST_PG_IMAGE")
	if image == "" {
		image = "postgres:16"
	}
	if _, err := d.EnsureImage(ctx, image); err != nil {
		t.Skipf("skipping: %v", err)
	}
	custom, plain := makeFixtures(t, image)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(plain)
	zw.Close()

	cases := map[string]struct {
		content []byte
		want    receipt.Result
	}{
		"good.dump":         {custom, receipt.Pass},
		"good.sql":          {plain, receipt.Pass},
		"good.sql.gz":       {gz.Bytes(), receipt.Pass},
		"truncated-10.dump": {cut(custom, 0.10), receipt.Fail},
		"truncated-61.dump": {cut(custom, 0.61), receipt.Fail},
		"truncated-99.dump": {cut(custom, 0.99), receipt.Fail},
		"flipped.dump":      {flip(custom, 0.5, 64), receipt.Fail},
		"empty.dump":        {nil, receipt.Fail},
		"truncated-61.sql":  {cut(plain, 0.61), receipt.Fail},
		"truncated.sql.gz":  {cut(gz.Bytes(), 0.5), receipt.Fail},
	}
	dir := t.TempDir()
	data := filepath.Join(dir, "dumps")
	os.MkdirAll(data, 0o755)
	for name, c := range cases {
		if err := os.WriteFile(filepath.Join(data, name), c.content, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	runID := "it" + randHex(3)
	eng := &postgres.Engine{Docker: d, RunID: runID, Image: image, Memory: "1g", CPUs: "2", TTL: 30 * time.Minute}
	src, _ := local.New(data)
	v := &verify.Verifier{Src: src, Engine: eng, Opts: verify.Options{
		Timeout: 10 * time.Minute, Store: &receipt.Store{Dir: filepath.Join(dir, "receipts")}, Key: priv, ToolVersion: "test",
	}}
	results, err := v.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != len(cases) {
		t.Fatalf("got %d results for %d dumps", len(results), len(cases))
	}
	for _, r := range results {
		c := cases[r.Object.Name]
		t.Logf("%-18s %-5s tables=%d rows=%d restore=%.1fs %s", r.Object.Name, r.Status, r.Tables, r.Rows, r.Restore.Seconds(), r.Reason)
		if r.Status != c.want {
			t.Errorf("%s: %s (%s), want %s", r.Object.Name, r.Status, r.Reason, c.want)
		}
		if c.want == receipt.Pass && (r.Tables != fixtureTables || r.Rows != fixtureRows) {
			t.Errorf("%s: restored %d tables / %d rows, want %d / %d", r.Object.Name, r.Tables, r.Rows, fixtureTables, fixtureRows)
		}
		if c.want == receipt.Fail && r.Reason == "" {
			t.Errorf("%s: FAIL without a reason", r.Object.Name)
		}
		doc, err := os.ReadFile(r.ReceiptPath)
		if err != nil {
			t.Fatalf("%s: no receipt", r.Object.Name)
		}
		if _, err := receipt.Verify(doc, []ed25519.PublicKey{priv.Public().(ed25519.PublicKey)}); err != nil {
			t.Errorf("%s: receipt: %v", r.Object.Name, err)
		}
	}

	// Guaranteed cleanup: no sandbox from this run may survive.
	left := docker(t, nil, "ps", "-a", "-q", "--filter", "label="+sandbox.LabelRun+"="+runID)
	if len(bytes.TrimSpace(left)) > 0 {
		t.Errorf("sandbox containers left behind: %s", left)
	}
}
