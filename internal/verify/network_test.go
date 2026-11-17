package verify

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/praxin/xinproof/internal/receipt"
	s3src "github.com/praxin/xinproof/internal/source/s3"
	"github.com/praxin/xinproof/internal/source/s3/s3test"
)

// A connection that drops mid-download says nothing about the backup, so it
// must end in ERROR ("couldn't test"), never FAIL and never PASS — whatever
// the format, and even when a truncated stream would look like a corrupt one.
func TestNetworkCutDuringDownload(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")

	var rows strings.Builder // incompressible rows, so the gzip is far bigger than CutAfter
	for i := 0; i < 20_000; i++ {
		b := make([]byte, 16)
		rand.Read(b)
		fmt.Fprintf(&rows, "%x\n", b)
	}
	bigGz := gzipped([]byte(strings.Replace(completePlain, "1\n2\n", rows.String(), 1)))
	if len(bigGz) < 200_000 {
		t.Fatalf("test object too small (%d bytes) to be cut", len(bigGz))
	}
	now := time.Now().Add(-time.Hour)
	srv := s3test.New("acme", map[string]s3test.Object{
		"pg/custom.dump":  {Body: pgCustom(), LastModified: now},
		"pg/plain.sql.gz": {Body: bigGz, LastModified: now},
	})
	defer srv.Close()
	srv.CutAfter = 70_000 // past the sniffed head, well before the end

	src, err := s3src.New(context.Background(), "acme", "pg/", s3src.Options{Endpoint: srv.URL, Region: "us-east-1", PathStyle: true})
	if err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	eng := &fakeEngine{outcome: passOutcome}
	v := &Verifier{Src: src, Engine: eng, Opts: Options{Store: &receipt.Store{Dir: filepath.Join(dir, "receipts")}, Key: priv}}
	results, err := v.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("%d results", len(results))
	}
	for _, r := range results {
		t.Logf("%s: %s %s", r.Object.Name, r.Status, r.Reason)
		if r.Status != receipt.Error || !strings.Contains(r.Reason, "reading object") {
			t.Errorf("%s: %s %q, want ERROR while reading the object", r.Object.Name, r.Status, r.Reason)
		}
		if r.ReceiptPath == "" {
			t.Errorf("%s: no receipt", r.Object.Name)
		}
	}
	if eng.sessions != eng.closed {
		t.Errorf("sandbox leak: %d started, %d closed", eng.sessions, eng.closed)
	}
}
