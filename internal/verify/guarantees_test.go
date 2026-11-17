package verify

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/praxin/xinproof/internal/receipt"
	"github.com/praxin/xinproof/internal/source/local"
	s3src "github.com/praxin/xinproof/internal/source/s3"
	"github.com/praxin/xinproof/internal/source/s3/s3test"
)

// Interrupting a run must not leave backups silently unreported: the ones not
// reached end in ERROR, each with a signed receipt.
func TestInterruptedRunReportsEveryBackup(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	os.MkdirAll(data, 0o755)
	for _, n := range []string{"a.dump", "b.dump", "c.dump", "d.dump"} {
		os.WriteFile(filepath.Join(data, n), pgCustom(), 0o644)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	src, _ := local.New(data)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eng := &fakeEngine{outcome: passOutcome}
	v := &Verifier{Src: src, Engine: eng, Opts: Options{
		Store: &receipt.Store{Dir: filepath.Join(dir, "receipts")}, Key: priv,
		OnResult: func(r Result) { cancel() }, // Ctrl-C right after the first backup
	}}
	results, err := v.Run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if len(results) != 4 {
		t.Fatalf("%d results for 4 backups", len(results))
	}
	if results[0].Status != receipt.Pass {
		t.Errorf("first backup = %s", results[0].Status)
	}
	for _, r := range results[1:] {
		if r.Status != receipt.Error || !strings.Contains(r.Reason, "interrupted") || r.ReceiptPath == "" {
			t.Errorf("%s: %s %q receipt=%q", r.Object.Name, r.Status, r.Reason, r.ReceiptPath)
		}
	}
	if eng.sessions != 1 || eng.closed != 1 {
		t.Errorf("sandboxes started %d, closed %d", eng.sessions, eng.closed)
	}
	if ExitCode(results) != 2 {
		t.Errorf("exit code %d, want 2", ExitCode(results))
	}
}

// snapshot records every file's content hash and mtime.
func snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := os.ReadFile(p)
		fi, _ := d.Info()
		sum := sha256.Sum256(b)
		out[p] = hex.EncodeToString(sum[:]) + " " + fi.ModTime().String() + " " + fi.Mode().String()
		return nil
	})
	return out
}

func TestLocalSourceIsNeverModified(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	os.MkdirAll(filepath.Join(data, "sub"), 0o755)
	os.WriteFile(filepath.Join(data, "good.dump"), pgCustom(), 0o644)
	os.WriteFile(filepath.Join(data, "sub", "bad.sql.gz"), gzipped([]byte(completePlain))[:40], 0o644)
	os.WriteFile(filepath.Join(data, "notes.txt"), []byte("hi"), 0o644)
	before := snapshot(t, data)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	src, _ := local.New(data)
	v := &Verifier{Src: src, Engine: &fakeEngine{outcome: passOutcome}, Opts: Options{
		Store: &receipt.Store{Dir: filepath.Join(dir, "receipts")}, Key: priv,
	}}
	if _, err := v.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	after := snapshot(t, data)
	if len(before) != len(after) {
		t.Fatalf("files added or removed in the source: %d → %d", len(before), len(after))
	}
	for p, s := range before {
		if after[p] != s {
			t.Errorf("source file changed: %s", p)
		}
	}
}

func TestS3EndToEnd(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")

	good := pgCustom()
	corrupt := append([]byte(nil), good...)
	corrupt[len(corrupt)-1] ^= 0xff // bit rot after upload: provider checksum no longer matches
	now := time.Now().Add(-time.Hour)
	bigGz := gzipped([]byte(strings.Replace(completePlain, "1\n2\n", strings.Repeat("123456789\n", 20_000), 1)))
	truncGz := bigGz[:len(bigGz)/2]
	srv := s3test.New("acme", map[string]s3test.Object{
		"pg/good.dump":    {Body: good, LastModified: now, ChecksumSHA256: b64(good)},
		"pg/rotted.dump":  {Body: corrupt, LastModified: now.Add(-time.Hour), ChecksumSHA256: b64(good)},
		"pg/trunc.sql.gz": {Body: truncGz, LastModified: now.Add(-2 * time.Hour)},
		"pg/readme.md":    {Body: []byte("# backups"), LastModified: now},
	})
	defer srv.Close()
	src, err := s3src.New(context.Background(), "acme", "pg/", s3src.Options{Endpoint: srv.URL, Region: "us-east-1", PathStyle: true})
	if err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	v := &Verifier{Src: src, Engine: &fakeEngine{outcome: passOutcome}, Opts: Options{
		Store: &receipt.Store{Dir: filepath.Join(dir, "receipts")}, Key: priv,
	}}
	results, err := v.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		status receipt.Result
		reason string
	}{
		"good.dump":    {receipt.Pass, ""},
		"rotted.dump":  {receipt.Fail, "checksum mismatch: provider SHA-256"},
		"trunc.sql.gz": {receipt.Fail, "gzip stream ends early"},
	}
	if len(results) != len(want) {
		t.Fatalf("%d results", len(results))
	}
	for _, r := range results {
		w := want[r.Object.Name]
		if r.Status != w.status || !strings.Contains(r.Reason, w.reason) {
			t.Errorf("%s: %s %q, want %s %q", r.Object.Name, r.Status, r.Reason, w.status, w.reason)
		}
		if !strings.HasPrefix(r.Receipt.Subject.Source, "s3://acme/pg/") {
			t.Errorf("receipt source %q", r.Receipt.Subject.Source)
		}
	}
	for _, req := range srv.Requests() {
		if req.Method != "GET" && req.Method != "HEAD" {
			t.Errorf("verifier sent a non-read request: %s %s", req.Method, req.Path)
		}
	}
}

func b64(b []byte) string {
	s := sha256.Sum256(b)
	return base64.StdEncoding.EncodeToString(s[:])
}
