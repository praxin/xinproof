package postgres_test

// Integration test for --check custom checks against a real restore.
// Needs Docker; skipped with -short or when no Docker daemon is reachable.
//
//   XINPROOF_TEST_PG_IMAGE=postgres:17 go test ./internal/engine/postgres -run RealCustom -v

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
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

func TestRealCustomChecks(t *testing.T) {
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
	dir := t.TempDir()
	data := filepath.Join(dir, "dumps")
	os.MkdirAll(data, 0o755)
	if err := os.WriteFile(filepath.Join(data, "good.dump"), f.custom, 0o644); err != nil {
		t.Fatal(err)
	}

	type want struct{ status, detail string }
	cases := []struct {
		check string
		want  want
	}{
		{"customers=SELECT count(*) = 5000 FROM customers", want{"pass", "customers: t"}},
		{"order_rows=SELECT count(*) FROM public.orders", want{"pass", "order_rows: 40000"}},
		{"multiline=SELECT E'line 1\\nline 2'", want{"pass", "multiline: line 1\nline 2"}},
		{"with_semicolon=SELECT 'a;b';", want{"pass", "with_semicolon: a;b"}},
		{"negative_totals=SELECT count(*) FROM orders WHERE total < 0", want{"fail", "negative_totals: 0"}},
		{"is_false=SELECT false", want{"fail", "is_false: f"}},
		{"null_value=SELECT NULL", want{"fail", "null_value: NULL"}},
		{"empty_string=SELECT ''", want{"fail", `empty_string: ""`}},
		{"two_rows=SELECT 1 UNION ALL SELECT 2", want{"fail", "two_rows: query returned 2 rows (want one row with one column)"}},
		{"two_cols=SELECT 1, 2", want{"fail", "two_cols: query returned 2 columns (want one row with one column)"}},
		{"no_rows=SELECT 1 WHERE false", want{"fail", "no_rows: query returned no rows (want one row with one column)"}},
		{"bad_sql=SELECT * FROM no_such_table", want{"fail", `bad_sql: ERROR:  relation "no_such_table" does not exist`}},
	}

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	runID := "it" + randHex(3)
	run := func(checks []verify.CustomCheck) verify.Result {
		t.Helper()
		eng := &postgres.Engine{Docker: d, RunID: runID, Image: image, Memory: "1g", CPUs: "2", TTL: 30 * time.Minute}
		src, _ := local.New(data)
		v := &verify.Verifier{Src: src, Engine: eng, Opts: verify.Options{
			Timeout: 10 * time.Minute, Store: &receipt.Store{Dir: filepath.Join(dir, "receipts")}, Key: priv, ToolVersion: "test",
			Checks: checks,
		}}
		results, err := v.Run(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(results) != 1 {
			t.Fatalf("got %d results", len(results))
		}
		doc, err := os.ReadFile(results[0].ReceiptPath)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := receipt.Verify(doc, []ed25519.PublicKey{priv.Public().(ed25519.PublicKey)}); err != nil {
			t.Fatalf("receipt: %v", err)
		}
		return results[0]
	}

	// Every check in one run: each is recorded, and the first failing one fails the backup.
	var all []verify.CustomCheck
	for _, c := range cases {
		ck, err := verify.ParseCustomCheck(c.check)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, ck)
	}
	r := run(all)
	t.Logf("result %s: %s", r.Status, r.Reason)
	if r.Status != receipt.Fail || r.Reason != `custom check "negative_totals" failed: returned 0` {
		t.Errorf("got %s %q", r.Status, r.Reason)
	}
	var got []receipt.Check
	for _, c := range r.Receipt.Checks {
		if c.ID == verify.CustomCheckID {
			got = append(got, c)
		}
	}
	if len(got) != len(cases) {
		t.Fatalf("got %d l3.custom checks, want %d: %+v", len(got), len(cases), got)
	}
	for i, c := range cases {
		t.Logf("    %s %q", got[i].Status, got[i].Detail)
		if got[i].Status != c.want.status || !strings.HasPrefix(got[i].Detail, c.want.detail) {
			t.Errorf("%s: got %s %q, want %s %q", c.check, got[i].Status, got[i].Detail, c.want.status, c.want.detail)
		}
	}
	if len(r.Receipt.Tables) != fixtureTables {
		t.Errorf("tables %v", r.Receipt.Tables)
	}

	// Only passing checks: the backup passes.
	r = run(all[:4])
	if r.Status != receipt.Pass {
		t.Errorf("passing checks: got %s %q", r.Status, r.Reason)
	}

	left := docker(t, nil, "ps", "-a", "-q", "--filter", "label="+sandbox.LabelRun+"="+runID)
	if len(bytes.TrimSpace(left)) > 0 {
		t.Errorf("sandbox containers left behind: %s", left)
	}
}
