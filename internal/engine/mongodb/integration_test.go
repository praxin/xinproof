package mongodb_test

// Integration test: real mongodump --archive output restored with real
// mongorestore in real sandbox containers. Clean dumps must PASS, corrupted
// ones must FAIL. Needs Docker; skipped with -short or when no Docker daemon
// is reachable.
//
//   XINPROOF_TEST_MONGO_IMAGE=mongo:8 go test ./internal/engine/mongodb -run Real -v

import (
	"bytes"
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
	mongoengine "github.com/praxin/xinproof/internal/engine/mongodb"
	"github.com/praxin/xinproof/internal/receipt"
	"github.com/praxin/xinproof/internal/sandbox"
	"github.com/praxin/xinproof/internal/source/local"
	"github.com/praxin/xinproof/internal/verify"
)

const fixtureJS = `
const shop = db.getSiblingDB("shop");
for (let b = 0; b < 5; b++) {
  shop.customers.insertMany(Array.from({length: 1000}, (_, i) => ({_id: b * 1000 + i, name: "customer " + (b * 1000 + i), email: "c" + i + "@example.com"})));
}
for (let b = 0; b < 40; b++) {
  shop.orders.insertMany(Array.from({length: 1000}, (_, i) => ({customer: (b * 1000 + i) % 5000, total: ((b * 1000 + i) % 997) * 1.25, note: "has \"quotes\" and ünïcode"})));
}
shop.orders.createIndex({customer: 1});
shop.createCollection("empty");
shop.createView("big_orders", "orders", [{$match: {total: {$gt: 1000}}}]);
const analytics = db.getSiblingDB("analytics");
analytics.events.insertMany(Array.from({length: 2000}, (_, i) => ({kind: "click", n: i, at: new Date(1700000000000 + i)})));
print("fixture-ok");
`

const (
	fixtureTables, fixtureRows = 4, 5000 + 40000 + 2000
	fixtureTableCounts         = "[{analytics.events 2000} {shop.customers 5000} {shop.empty 0} {shop.orders 40000}]"
	shopTableCounts            = "[{shop.customers 5000} {shop.empty 0} {shop.orders 40000}]"
)

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func docker(t *testing.T, args ...string) []byte {
	t.Helper()
	cmd := exec.Command("docker", args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args[:min(4, len(args))], " "), err, errb.String())
	}
	return out.Bytes()
}

// makeFixtures builds the test databases in a throwaway container and dumps them.
func makeFixtures(t *testing.T, image string) (all, allGz, shopOnly []byte) {
	t.Helper()
	name := "xinproof-fixture-" + randHex(4)
	docker(t, "run", "-d", "--name", name, "--network", "none",
		"--label", "xinproof.managed=true", "--label", fmt.Sprintf("xinproof.expires=%d", time.Now().Add(30*time.Minute).Unix()), image)
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", "-v", name).Run() })
	deadline := time.Now().Add(2 * time.Minute)
	for {
		out, _ := exec.Command("docker", "exec", name, "mongosh", "--quiet", "--norc", "--eval", "db.runCommand({ping: 1}).ok").Output()
		if strings.TrimSpace(string(out)) == "1" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fixture mongod did not become ready")
		}
		time.Sleep(time.Second)
	}
	if out := docker(t, "exec", name, "mongosh", "--quiet", "--norc", "--eval", fixtureJS); !bytes.Contains(out, []byte("fixture-ok")) {
		t.Fatalf("fixture: %s", out)
	}
	all = docker(t, "exec", name, "mongodump", "--quiet", "--archive")
	allGz = docker(t, "exec", name, "mongodump", "--quiet", "--gzip", "--archive")
	shopOnly = docker(t, "exec", name, "mongodump", "--quiet", "--db", "shop", "--archive")
	return all, allGz, shopOnly
}

func cut(b []byte, frac float64) []byte { return b[:int(float64(len(b))*frac)] }

func flip(b []byte, at float64, n int) []byte {
	c := append([]byte(nil), b...)
	i := int(float64(len(c)) * at)
	for j := i; j < i+n && j < len(c); j++ {
		c[j] ^= 0xff
	}
	return c
}

// flipValue changes one byte inside a string value, keeping the BSON valid:
// only the archive's CRC can catch it (mongorestore reports it but exits 0).
func flipValue(t *testing.T, b []byte) []byte {
	i := bytes.Index(b, []byte("customer 2500"))
	if i < 0 {
		t.Fatal("value to corrupt not found in the dump")
	}
	c := append([]byte(nil), b...)
	c[i] = 'C'
	return c
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
	image := os.Getenv("XINPROOF_TEST_MONGO_IMAGE")
	if image == "" {
		image = mongoengine.DefaultImage
	}
	if _, err := d.EnsureImage(ctx, image); err != nil {
		t.Skipf("skipping: %v", err)
	}
	all, allGz, shopOnly := makeFixtures(t, image)

	cases := map[string]struct {
		content []byte
		want    receipt.Result
		tables  string
	}{
		"good.archive":         {all, receipt.Pass, fixtureTableCounts},
		"good.archive.gz":      {allGz, receipt.Pass, fixtureTableCounts},
		"good-shop.archive":    {shopOnly, receipt.Pass, shopTableCounts},
		"truncated-10.archive": {cut(all, 0.10), receipt.Fail, ""},
		"truncated-61.archive": {cut(all, 0.61), receipt.Fail, ""},
		"truncated-99.archive": {cut(all, 0.99), receipt.Fail, ""},
		"truncated.archive.gz": {cut(allGz, 0.5), receipt.Fail, ""},
		"flipped.archive":      {flip(all, 0.5, 64), receipt.Fail, ""},
		"bad-value.archive":    {flipValue(t, all), receipt.Fail, ""},
		"empty.archive":        {nil, receipt.Fail, ""},
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
	eng := &mongoengine.Engine{Docker: d, RunID: runID, Image: image, Memory: "1g", CPUs: "2", TTL: 30 * time.Minute}
	src, _ := local.New(data)
	v := &verify.Verifier{Src: src, Engine: engine.Multi{eng}, Opts: verify.Options{
		Timeout: 10 * time.Minute, Store: &receipt.Store{Dir: filepath.Join(dir, "receipts")}, Key: priv, ToolVersion: "test",
		Checks: []verify.CustomCheck{{Name: "sql", SQL: "SELECT 1"}},
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
		t.Logf("%-22s %-5s tables=%d rows=%d restore=%.1fs %s", r.Object.Name, r.Status, r.Tables, r.Rows, r.Restore.Seconds(), r.Reason)
		if r.Status != c.want {
			t.Errorf("%s: %s (%s), want %s", r.Object.Name, r.Status, r.Reason, c.want)
		}
		if c.want == receipt.Fail && r.Reason == "" {
			t.Errorf("%s: FAIL without a reason", r.Object.Name)
		}
		if c.want == receipt.Pass {
			if r.Receipt.Engine.Kind != "mongodb" || r.Receipt.Subject.Format != "mongodb-archive" {
				t.Errorf("%s: engine %q format %q", r.Object.Name, r.Receipt.Engine.Kind, r.Receipt.Subject.Format)
			}
			status := map[string]string{}
			for _, ch := range r.Receipt.Checks {
				status[ch.ID] = ch.Status
				if ch.ID != "l1.sha256" {
					t.Logf("    %s %s: %s", ch.ID, ch.Status, ch.Detail)
				}
			}
			for _, id := range []string{"l1.format", "l1.structure", "l2.restore", "l2.objects", "l2.rows"} {
				if status[id] != receipt.CheckPass {
					t.Errorf("%s: check %s = %q, want pass", r.Object.Name, id, status[id])
				}
			}
			if status[verify.CustomCheckID] != receipt.CheckSkip {
				t.Errorf("%s: SQL check on a MongoDB backup = %q, want skip", r.Object.Name, status[verify.CustomCheckID])
			}
			if got := fmt.Sprint(r.Receipt.Tables); got != c.tables {
				t.Errorf("%s: receipt tables %s, want %s", r.Object.Name, got, c.tables)
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
	if r := find(results, "good.archive"); r != nil && (r.Tables != fixtureTables || r.Rows != fixtureRows) {
		t.Errorf("good.archive: %d tables / %d rows, want %d / %d", r.Tables, r.Rows, fixtureTables, fixtureRows)
	}

	// Data files on a tmpfs (--tmpfs) restore the same way.
	tdata := filepath.Join(dir, "tmpfs-dumps")
	os.MkdirAll(tdata, 0o755)
	os.WriteFile(filepath.Join(tdata, "good.archive.gz"), allGz, 0o644)
	teng := &mongoengine.Engine{Docker: d, RunID: runID, Image: image, Memory: "1g", CPUs: "2", TmpfsSize: "1g", TTL: 30 * time.Minute}
	tsrc, _ := local.New(tdata)
	tv := &verify.Verifier{Src: tsrc, Engine: engine.Multi{teng}, Opts: verify.Options{Timeout: 10 * time.Minute}}
	tres, err := tv.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(tres) != 1 || tres[0].Status != receipt.Pass || tres[0].Rows != fixtureRows {
		t.Errorf("tmpfs: %+v", tres)
	}

	left := docker(t, "ps", "-a", "-q", "--filter", "label="+sandbox.LabelRun+"="+runID)
	if len(bytes.TrimSpace(left)) > 0 {
		t.Errorf("sandbox containers left behind: %s", left)
	}
}

func find(rs []verify.Result, name string) *verify.Result {
	for i := range rs {
		if rs[i].Object.Name == name {
			return &rs[i]
		}
	}
	return nil
}
