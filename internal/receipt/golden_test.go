package receipt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// goldenKey is a fixed, public test key. Never use it for anything real.
func goldenKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func goldenReceipt(t *testing.T) []byte {
	t.Helper()
	r := &Receipt{
		Schema:   Schema,
		ID:       "rcpt_01JD8Q4M7XK3V9Q2ZB6T5W1H0E",
		IssuedAt: "2026-11-16T14:21:07Z",
		Subject: Subject{
			Source:       "s3://acme-backups/postgres/pg_2026-11-16.dump",
			Size:         13314398208,
			SHA256:       "9f2d4c1e7b0a5f3e8d6c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e",
			ETag:         "d41d8cd98f00b204e9800998ecf8427e-1588",
			LastModified: "2026-11-16T02:00:11Z",
			Format:       "postgres-custom",
			Compression:  "",
		},
		Engine: Engine{Kind: "postgres", DumpVersion: "16.4", ServerVersion: "16.4",
			SandboxImage: "postgres:16@sha256:4f1b6d3c2a1e0f9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d"},
		Result:   Pass,
		Measured: Measured{RestoreSeconds: 238.4, TotalSeconds: 291},
		Checks: []Check{
			{ID: "l1.format", Status: CheckPass, Detail: "postgres-custom, dumped by version 16.4"},
			{ID: "l1.sha256", Status: CheckPass, Detail: "sha256:9f2d… (13314398208 bytes)"},
			{ID: "l2.toc", Status: CheckPass, Detail: "1093 TOC entries, 214 tables"},
			{ID: "l2.restore", Status: CheckPass, Detail: "exit 0 in 238.4s"},
			{ID: "l2.objects", Status: CheckPass, Detail: "214/214 tables"},
			{ID: "l2.rows", Status: CheckPass, Detail: "38212904 rows (exact count)"},
			{ID: "note", Status: CheckInfo, Detail: "unicode survives canonicalization: 信 \"quoted\" <tag> & é"},
		},
		Tool:  Tool{Name: "xinproof", Version: "0.1.0", Commit: "0123456789ab"},
		Chain: Chain{Prev: GenesisPrev, Seq: 1},
	}
	if err := r.Sign(goldenKey()); err != nil {
		t.Fatal(err)
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

// TestGoldenReceipt pins the v1 receipt format byte for byte. If it fails, the
// format changed: that needs a schema bump (xinproof.receipt/v2) and old
// receipts must keep verifying. Regenerate only for a deliberate change:
//
//	XINPROOF_UPDATE_GOLDEN=1 go test ./internal/receipt -run Golden
func TestGoldenReceipt(t *testing.T) {
	path := filepath.Join("testdata", "receipt-v1.json")
	pubPath := filepath.Join("testdata", "receipt-v1.pub")
	got := goldenReceipt(t)
	if os.Getenv("XINPROOF_UPDATE_GOLDEN") == "1" {
		os.MkdirAll("testdata", 0o755)
		pub, _ := EncodePublicKey(goldenKey().Public().(ed25519.PublicKey))
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pubPath, pub, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s and %s", path, pubPath)
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing golden receipt (generate with XINPROOF_UPDATE_GOLDEN=1): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("receipt v1 encoding changed.\ngot:\n%s\nwant:\n%s", got, want)
	}
	pubPEM, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	// Old receipts must keep verifying with the published key.
	v, err := Verify(want, []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatalf("golden receipt no longer verifies: %v", err)
	}
	if !v.Pinned || v.Receipt.Subject.Size != 13314398208 {
		t.Errorf("verified receipt = %+v", v.Receipt.Subject)
	}
}

// TestTablesField checks the optional "tables" member: absent when there are
// no counts (so receipts without it, like the golden one, are unchanged),
// present with the documented shape otherwise, and covered by the signature.
func TestTablesField(t *testing.T) {
	priv := goldenKey()
	pub := priv.Public().(ed25519.PublicKey)

	plain := sample(Pass)
	b, _ := json.Marshal(plain)
	if bytes.Contains(b, []byte(`"tables"`)) {
		t.Errorf("receipt without counts has a tables member: %s", b)
	}

	r := sample(Pass)
	r.Tables = []Table{{Name: "public.customers", Rows: 5000}, {Name: "public.orders", Rows: 40000}}
	if err := r.Sign(priv); err != nil {
		t.Fatal(err)
	}
	doc, _ := json.Marshal(r)
	if !bytes.Contains(doc, []byte(`"tables":[{"name":"public.customers","rows":5000},{"name":"public.orders","rows":40000}]`)) {
		t.Errorf("unexpected tables encoding: %s", doc)
	}
	v, err := Verify(doc, []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Receipt.Tables) != 2 || v.Receipt.Tables[1].Rows != 40000 {
		t.Errorf("tables after verify: %+v", v.Receipt.Tables)
	}
	tampered := bytes.Replace(doc, []byte(`"rows":40000`), []byte(`"rows":40001`), 1)
	if _, err := Verify(tampered, []ed25519.PublicKey{pub}); err == nil {
		t.Error("a changed row count still verifies")
	}
}

func TestConcurrentAppendsKeepOneChain(t *testing.T) {
	dir := t.TempDir()
	priv := testKey(t)
	const n = 24
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := &Store{Dir: dir} // separate Store values, like separate runs
			r := sample(Pass)
			r.Reason = fmt.Sprint("writer ", i)
			if _, err := s.Append(r, priv); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	var prev *Verified
	for seq := int64(1); seq <= n; seq++ {
		doc, err := os.ReadFile(filepath.Join(dir, FileName(seq)))
		if err != nil {
			t.Fatalf("receipt %d missing: %v", seq, err)
		}
		v, err := Verify(doc, nil)
		if err != nil {
			t.Fatal(err)
		}
		if prev != nil {
			if err := CheckLink(prev, v); err != nil {
				t.Fatalf("chain forked at %d: %v", seq, err)
			}
		}
		prev = v
	}
	if _, err := os.Stat(filepath.Join(dir, FileName(n+1))); err == nil {
		t.Error("more receipts than appends")
	}
}
