package verify

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/praxin/xinproof/internal/engine"
	"github.com/praxin/xinproof/internal/receipt"
	"github.com/praxin/xinproof/internal/source/local"
)

// runOne verifies a single custom-format dump with eng and returns the
// result and its receipt as read back from disk and verified.
func runOne(t *testing.T, eng engine.Engine, opts Options) (Result, *receipt.Receipt) {
	t.Helper()
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	os.MkdirAll(data, 0o755)
	os.WriteFile(filepath.Join(data, "pg.dump"), pgCustom(), 0o644)
	src, err := local.New(data)
	if err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	opts.Store, opts.Key, opts.ToolVersion = &receipt.Store{Dir: filepath.Join(dir, "receipts")}, priv, "test"
	v := &Verifier{Src: src, Engine: eng, Opts: opts}
	results, err := v.Run(context.Background())
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
	rv, err := receipt.Verify(doc, []ed25519.PublicKey{priv.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatalf("receipt does not verify: %v", err)
	}
	return results[0], rv.Receipt
}

func TestReceiptTables(t *testing.T) {
	out := passOutcome
	out.TableCounts = []engine.TableCount{
		{Qualified: "public.orders", Kind: 'r', Rows: 40000},
		{Qualified: "public.customers", Kind: 'r', Rows: 5000},
		{DB: "other", Qualified: "public.t", Kind: 'r', Rows: 2},
	}
	_, r := runOne(t, &fakeEngine{outcome: out}, Options{})
	want := []receipt.Table{{Name: "other:public.t", Rows: 2}, {Name: "public.customers", Rows: 5000}, {Name: "public.orders", Rows: 40000}}
	if fmt.Sprint(r.Tables) != fmt.Sprint(want) {
		t.Errorf("tables = %v, want %v", r.Tables, want)
	}
	for _, c := range r.Checks {
		if c.ID == "l2.tables" {
			t.Errorf("unexpected cap note: %s", c.Detail)
		}
	}

	// No counts (e.g. the restore failed before inspection): no tables member.
	_, r = runOne(t, &fakeEngine{outcome: engine.Outcome{Result: receipt.Fail, Reason: "pg_restore failed"}}, Options{})
	if r.Tables != nil {
		t.Errorf("tables on a failed restore: %v", r.Tables)
	}
}

func TestReceiptTablesCapped(t *testing.T) {
	out := passOutcome
	n := receipt.MaxTables + 5
	for i := 0; i < n; i++ {
		out.TableCounts = append(out.TableCounts, engine.TableCount{Qualified: fmt.Sprintf("public.t%05d", i), Rows: 1})
	}
	_, r := runOne(t, &fakeEngine{outcome: out}, Options{})
	if len(r.Tables) != receipt.MaxTables || r.Tables[0].Name != "public.t00000" {
		t.Fatalf("got %d tables starting %v", len(r.Tables), r.Tables[0])
	}
	note := ""
	for _, c := range r.Checks {
		if c.ID == "l2.tables" {
			note = c.Status + " " + c.Detail
		}
	}
	if want := fmt.Sprintf("info tables list capped: first %d of %d tables by name", receipt.MaxTables, n); note != want {
		t.Errorf("cap note %q, want %q", note, want)
	}
}
