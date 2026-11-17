package mysql_test

// Integration test: real mysqldump / mariadb-dump output restored in real
// sandbox containers. Clean dumps must PASS, corrupted ones must FAIL.
// Needs Docker; skipped with -short or when no Docker daemon is reachable.
//
//   XINPROOF_TEST_MYSQL_IMAGE=mariadb:11.4 go test ./internal/engine/mysql -run Real -v

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

	"github.com/praxin/xinproof/internal/engine"
	mysqlengine "github.com/praxin/xinproof/internal/engine/mysql"
	"github.com/praxin/xinproof/internal/receipt"
	"github.com/praxin/xinproof/internal/sandbox"
	"github.com/praxin/xinproof/internal/source/local"
	"github.com/praxin/xinproof/internal/verify"
)

const fixtureSQL = `
CREATE TABLE digits (d INT NOT NULL PRIMARY KEY);
INSERT INTO digits VALUES (0),(1),(2),(3),(4),(5),(6),(7),(8),(9);
CREATE TABLE customers (id INT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(100) NOT NULL, note TEXT, KEY idx_name (name));
INSERT INTO customers (name, note)
  SELECT CONCAT('customer ', a.d*1000 + b.d*100 + c.d*10 + e.d),
         CASE WHEN e.d = 3 THEN 'has ''quotes'', (parens), commas; semicolons; and \\backslash),(' ELSE NULL END
  FROM digits a, digits b, digits c, digits e;
CREATE TABLE orders (id BIGINT PRIMARY KEY AUTO_INCREMENT, customer_id INT NOT NULL, total DECIMAL(10,2),
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP, KEY (customer_id), FOREIGN KEY (customer_id) REFERENCES customers (id));
INSERT INTO orders (customer_id, total)
  SELECT 1 + (n % 10000), (n % 997) * 1.25
  FROM (SELECT a.d*10000 + b.d*1000 + c.d*100 + e.d*10 + f.d AS n FROM digits a, digits b, digits c, digits e, digits f) x
  WHERE n < 40000;
CREATE TABLE audit_log (id BIGINT PRIMARY KEY AUTO_INCREMENT, payload TEXT);
INSERT INTO audit_log (payload)
  SELECT MD5(n) FROM (SELECT a.d*10000 + b.d*1000 + c.d*100 + e.d*10 + f.d AS n FROM digits a, digits b, digits c, digits e, digits f) x
  WHERE n < 20000;
CREATE VIEW big_orders AS SELECT * FROM orders WHERE total > 1000;
CREATE TRIGGER audit_orders AFTER INSERT ON orders FOR EACH ROW INSERT INTO audit_log (payload) VALUES (NEW.id);
CREATE FUNCTION fmt_total(t DECIMAL(10,2)) RETURNS VARCHAR(20) DETERMINISTIC RETURN CONCAT('$', t);
`

const fixtureTables, fixtureRows = 4, 10 + 10000 + 40000 + 20000

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
		t.Fatalf("docker %s: %v\n%s", strings.Join(args[:min(4, len(args))], " "), err, errb.String())
	}
	return out.Bytes()
}

type tools struct{ client, dump string }

func toolsFor(image string) tools {
	if strings.Contains(image, "mariadb") {
		return tools{"mariadb", "mariadb-dump"}
	}
	return tools{"mysql", "mysqldump"}
}

// makeFixtures builds the test database in a throwaway container and dumps it
// the ways people commonly do.
func makeFixtures(t *testing.T, image string) map[string][]byte {
	t.Helper()
	tl := toolsFor(image)
	name := "xinproof-fixture-" + randHex(4)
	args := []string{"run", "-d", "--name", name, "--network", "none",
		"--label", "xinproof.managed=true", "--label", fmt.Sprintf("xinproof.expires=%d", time.Now().Add(30*time.Minute).Unix()),
		"-e", "MYSQL_ROOT_PASSWORD=fixture", "-e", "MARIADB_ROOT_PASSWORD=fixture",
		"-e", "MYSQL_DATABASE=shop", "-e", "MARIADB_DATABASE=shop", image, "--log-bin-trust-function-creators=1"}
	if tl.client == "mysql" {
		args = append(args, "--gtid-mode=ON", "--enforce-gtid-consistency=ON") // dumps then carry GTID_PURGED
	}
	docker(t, nil, args...)
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", "-v", name).Run() })
	conn := []string{"--protocol=tcp", "-h127.0.0.1", "-uroot"}
	deadline := time.Now().Add(4 * time.Minute)
	for {
		ready := append([]string{"exec", "-e", "MYSQL_PWD=fixture", name, tl.client}, conn...)
		if exec.Command("docker", append(ready, "-e", "SELECT 1")...).Run() == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fixture database did not become ready")
		}
		time.Sleep(time.Second)
	}
	docker(t, []byte(fixtureSQL), append(append([]string{"exec", "-i", "-e", "MYSQL_PWD=fixture", name, tl.client}, conn...), "shop")...)
	dump := func(extra ...string) []byte {
		a := append(append([]string{"exec", "-e", "MYSQL_PWD=fixture", name, tl.dump}, conn...), "--single-transaction", "--routines", "--triggers")
		return docker(t, nil, append(a, extra...)...)
	}
	return map[string][]byte{
		"single":        dump("shop"),
		"databases":     dump("--databases", "shop"),
		"skip-comments": dump("--skip-comments", "shop"),
		"one-per-row":   dump("--skip-extended-insert", "shop"),
	}
}

func cut(b []byte, frac float64) []byte { return b[:int(float64(len(b))*frac)] }

func gz(b []byte) []byte {
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	w.Write(b)
	w.Close()
	return out.Bytes()
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
	image := os.Getenv("XINPROOF_TEST_MYSQL_IMAGE")
	if image == "" {
		image = "mysql:8.4"
	}
	if _, err := d.EnsureImage(ctx, image); err != nil {
		t.Skipf("skipping: %v", err)
	}
	f := makeFixtures(t, image)
	single := f["single"]

	cases := map[string]struct {
		content []byte
		want    receipt.Result
	}{
		"good.sql":               {single, receipt.Pass},
		"good.sql.gz":            {gz(single), receipt.Pass},
		"good-databases.sql":     {f["databases"], receipt.Pass},
		"good-skip-comments.sql": {f["skip-comments"], receipt.Pass},
		"good-one-per-row.sql":   {f["one-per-row"], receipt.Pass},
		"truncated-10.sql":       {cut(single, 0.10), receipt.Fail},
		"truncated-61.sql":       {cut(single, 0.61), receipt.Fail},
		"truncated-99.sql":       {cut(single, 0.99), receipt.Fail},
		"truncated.sql.gz":       {cut(gz(single), 0.5), receipt.Fail},
		"empty.sql":              {nil, receipt.Fail},
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
	eng := &mysqlengine.Engine{Docker: d, RunID: runID, Image: image, Memory: "2g", CPUs: "2", TTL: 30 * time.Minute, CheckBudget: 2 * time.Minute}
	src, _ := local.New(data)
	v := &verify.Verifier{Src: src, Engine: engine.Multi{eng}, Opts: verify.Options{
		Timeout: 10 * time.Minute, Store: &receipt.Store{Dir: filepath.Join(dir, "receipts")}, Key: priv, ToolVersion: "test",
	}}
	results, err := v.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != len(cases) {
		t.Fatalf("got %d results for %d dumps", len(results), len(cases))
	}
	hashes := map[string]string{}
	for _, r := range results {
		c := cases[r.Object.Name]
		t.Logf("%-24s %-5s tables=%d rows=%d restore=%.1fs %s", r.Object.Name, r.Status, r.Tables, r.Rows, r.Restore.Seconds(), r.Reason)
		if r.Status != c.want {
			t.Errorf("%s: %s (%s), want %s", r.Object.Name, r.Status, r.Reason, c.want)
		}
		if c.want == receipt.Fail && r.Reason == "" {
			t.Errorf("%s: FAIL without a reason", r.Object.Name)
		}
		if c.want == receipt.Pass {
			if r.Tables != fixtureTables || r.Rows != fixtureRows {
				t.Errorf("%s: restored %d tables / %d rows, want %d / %d", r.Object.Name, r.Tables, r.Rows, fixtureTables, fixtureRows)
			}
			status := map[string]string{}
			for _, ch := range r.Receipt.Checks {
				status[ch.ID] = ch.Status
				if ch.ID == "l2.schema_hash" && r.Object.Name != "good-databases.sql" {
					hashes[r.Object.Name] = ch.Detail
				}
				if ch.ID == "l2.rows" || ch.ID == "l2.check_table" || ch.ID == "l1.structure" {
					t.Logf("    %s: %s", ch.ID, ch.Detail)
				}
			}
			for _, id := range []string{"l1.structure", "l2.restore", "l2.objects", "l2.rows", "l2.schema_hash", "l2.check_table"} {
				if status[id] != receipt.CheckPass {
					t.Errorf("%s: check %s = %q, want pass", r.Object.Name, id, status[id])
				}
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
	var first string
	for name, h := range hashes {
		if first == "" {
			first = h
		} else if h != first {
			t.Errorf("schema hash differs between dump styles: %s has %s, others %s", name, h, first)
		}
	}
	left := docker(t, nil, "ps", "-a", "-q", "--filter", "label="+sandbox.LabelRun+"="+runID)
	if len(bytes.TrimSpace(left)) > 0 {
		t.Errorf("sandbox containers left behind: %s", left)
	}
}
