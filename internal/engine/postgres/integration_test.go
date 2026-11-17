package postgres_test

// Integration test: real pg_dump output, real pg_restore/psql in real sandbox
// containers. Every clean dump must PASS and every corrupted one must FAIL.
// Needs Docker; skipped with -short or when no Docker daemon is reachable.
//
//   XINPROOF_TEST_PG_IMAGE=postgres:17 go test ./internal/engine/postgres -run Real -v

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
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

// fixtureTableCounts is the receipt's "tables" for the fixture, as fmt prints it.
const fixtureTableCounts = "[{public.audit_log 20000} {public.customers 5000} {public.orders 40000}]"

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

// fixtures are the same small database dumped in every format pg_dump offers.
type fixtures struct {
	custom, plain, tar []byte
	dir                map[string][]byte // pg_dump -Fd, gzip-compressed data files
	extra              map[string][]byte // custom format with lz4/zstd compression (PostgreSQL 16+)
}

func tryDocker(stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.Command("docker", args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%v: %s", err, errb.String())
	}
	return out.Bytes(), nil
}

// makeFixtures builds a small database in a throwaway container and dumps it
// in every format.
func makeFixtures(t *testing.T, image string) fixtures {
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
	f := fixtures{dir: map[string][]byte{}, extra: map[string][]byte{}}
	f.custom = docker(t, nil, "exec", name, "pg_dump", "-U", "postgres", "-Fc", "-d", "postgres")
	f.plain = docker(t, nil, "exec", name, "pg_dump", "-U", "postgres", "-d", "postgres")
	f.tar = docker(t, nil, "exec", name, "pg_dump", "-U", "postgres", "-Ft", "-d", "postgres")
	docker(t, nil, "exec", name, "pg_dump", "-U", "postgres", "-Fd", "-Z", "6", "-f", "/tmp/dirdump", "-d", "postgres")
	tarred := docker(t, nil, "exec", name, "tar", "-C", "/tmp/dirdump", "-cf", "-", ".")
	tr := tar.NewReader(bytes.NewReader(tarred))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		body, _ := io.ReadAll(tr)
		f.dir[strings.TrimPrefix(h.Name, "./")] = body
	}
	for _, method := range []string{"lz4", "zstd"} { // only PostgreSQL 16+ pg_dump has these
		if b, err := tryDocker(nil, "exec", name, "pg_dump", "-U", "postgres", "-Fc", "-Z", method, "-d", "postgres"); err == nil {
			f.extra["good-"+method+".dump"] = b
		} else {
			t.Logf("no %s fixture: %v", method, err)
		}
	}
	return f
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

// largestData returns the biggest data file in a directory dump.
func largestData(dir map[string][]byte) string {
	best := ""
	for n, b := range dir {
		if n != "toc.dat" && (best == "" || len(b) > len(dir[best])) {
			best = n
		}
	}
	return best
}

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
	f := makeFixtures(t, image)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(f.plain)
	zw.Close()

	files := map[string][]byte{} // path under the dumps folder → content
	want := map[string]receipt.Result{}
	add := func(name string, content []byte, w receipt.Result) {
		files[name] = content
		want[name] = w
	}
	addDir := func(name string, dir map[string][]byte, w receipt.Result) {
		for n, b := range dir {
			files[name+"/"+n] = b
		}
		want[name+"/"] = w
	}
	add("good.dump", f.custom, receipt.Pass)
	add("good.sql", f.plain, receipt.Pass)
	add("good.sql.gz", gz.Bytes(), receipt.Pass)
	add("good.tar", f.tar, receipt.Pass)
	addDir("good.dir", f.dir, receipt.Pass)
	for n, b := range f.extra {
		add(n, b, receipt.Pass)
	}
	add("truncated-10.dump", cut(f.custom, 0.10), receipt.Fail)
	add("truncated-61.dump", cut(f.custom, 0.61), receipt.Fail)
	add("truncated-99.dump", cut(f.custom, 0.99), receipt.Fail)
	add("flipped.dump", flip(f.custom, 0.5, 64), receipt.Fail)
	add("empty.dump", nil, receipt.Fail)
	add("truncated-61.sql", cut(f.plain, 0.61), receipt.Fail)
	add("truncated.sql.gz", cut(gz.Bytes(), 0.5), receipt.Fail)
	add("truncated-61.tar", cut(f.tar, 0.61), receipt.Fail)
	big := largestData(f.dir)
	trunc := map[string][]byte{}
	missing := map[string][]byte{}
	for n, b := range f.dir {
		trunc[n] = b
		if n != big {
			missing[n] = b
		}
	}
	trunc[big] = cut(f.dir[big], 0.5)
	addDir("truncated-member.dir", trunc, receipt.Fail)
	addDir("missing-member.dir", missing, receipt.Fail)

	dir := t.TempDir()
	data := filepath.Join(dir, "dumps")
	for name, content := range files {
		p := filepath.Join(data, filepath.FromSlash(name))
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	runID := "it" + randHex(3)
	eng := &postgres.Engine{Docker: d, RunID: runID, Image: image, Memory: "1g", CPUs: "2", TTL: 30 * time.Minute, AmcheckBudget: 2 * time.Minute}
	src, _ := local.New(data)
	v := &verify.Verifier{Src: src, Engine: eng, Opts: verify.Options{
		Timeout: 10 * time.Minute, Store: &receipt.Store{Dir: filepath.Join(dir, "receipts")}, Key: priv, ToolVersion: "test",
	}}
	results, err := v.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != len(want) {
		var got []string
		for _, r := range results {
			got = append(got, r.Object.Name)
		}
		t.Fatalf("got %d results for %d dumps: %v", len(results), len(want), got)
	}
	schemaHashes := map[string]string{}
	for _, r := range results {
		w, ok := want[r.Object.Name]
		t.Logf("%-22s %-5s tables=%d rows=%d restore=%.1fs %s", r.Object.Name, r.Status, r.Tables, r.Rows, r.Restore.Seconds(), r.Reason)
		if !ok {
			t.Errorf("unexpected backup %q", r.Object.Name)
			continue
		}
		if r.Status != w {
			t.Errorf("%s: %s (%s), want %s", r.Object.Name, r.Status, r.Reason, w)
		}
		if w == receipt.Fail && r.Reason == "" {
			t.Errorf("%s: FAIL without a reason", r.Object.Name)
		}
		if w == receipt.Pass {
			if r.Tables != fixtureTables || r.Rows != fixtureRows {
				t.Errorf("%s: restored %d tables / %d rows, want %d / %d", r.Object.Name, r.Tables, r.Rows, fixtureTables, fixtureRows)
			}
			status := map[string]string{}
			for _, c := range r.Receipt.Checks {
				status[c.ID] = c.Status
				if c.ID == "l2.schema_hash" {
					schemaHashes[r.Object.Name] = c.Detail
				}
				if c.ID == "l2.amcheck" || c.ID == "l2.rows" {
					t.Logf("    %s: %s", c.ID, c.Detail)
				}
			}
			for _, id := range []string{"l2.restore", "l2.objects", "l2.rows", "l2.schema_hash", "l2.amcheck"} {
				if status[id] != receipt.CheckPass {
					t.Errorf("%s: check %s = %q, want pass", r.Object.Name, id, status[id])
				}
			}
			if got := fmt.Sprint(r.Receipt.Tables); got != fixtureTableCounts {
				t.Errorf("%s: receipt tables %s, want %s", r.Object.Name, got, fixtureTableCounts)
			}
		}
		doc, err := os.ReadFile(r.ReceiptPath)
		if err != nil {
			t.Fatalf("%s: no receipt", r.Object.Name)
		}
		if _, err := receipt.Verify(doc, []ed25519.PublicKey{priv.Public().(ed25519.PublicKey)}); err != nil {
			t.Errorf("%s: receipt: %v", r.Object.Name, err)
		}
	}

	// Every format of the same database must restore to the same schema.
	var first string
	for name, h := range schemaHashes {
		if first == "" {
			first = h
		}
		if h != first {
			t.Errorf("schema hash differs across formats: %s has %s, others %s", name, h, first)
		}
	}

	// Guaranteed cleanup: no sandbox from this run may survive.
	left := docker(t, nil, "ps", "-a", "-q", "--filter", "label="+sandbox.LabelRun+"="+runID)
	if len(bytes.TrimSpace(left)) > 0 {
		t.Errorf("sandbox containers left behind: %s", left)
	}
}
