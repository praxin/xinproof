package postgres_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/praxin/xinproof/internal/engine"
	"github.com/praxin/xinproof/internal/engine/postgres"
	"github.com/praxin/xinproof/internal/receipt"
	"github.com/praxin/xinproof/internal/sandbox"
	"github.com/praxin/xinproof/internal/source/local"
	"github.com/praxin/xinproof/internal/verify"
)

func TestTOCExtensions(t *testing.T) {
	toc := ";\n; Selected TOC Entries:\n;\n2; 3079 16385 EXTENSION - postgis\n4237; 0 0 COMMENT - EXTENSION postgis\n3; 3079 16390 EXTENSION - vector\n215; 1259 16400 TABLE public t app\n"
	if got := strings.Join(postgres.TOCExtensions(toc), ","); got != "postgis,vector" {
		t.Errorf("TOCExtensions = %q", got)
	}
	a := postgres.NewPlainAnalyzer()
	a.Write([]byte("CREATE EXTENSION IF NOT EXISTS postgis WITH SCHEMA public;\nCREATE EXTENSION \"uuid-ossp\";\nCOMMENT ON EXTENSION postgis IS 'x';\n"))
	if got := strings.Join(a.Extensions(), ","); got != "postgis,uuid-ossp" {
		t.Errorf("Extensions = %q", got)
	}
}

// A healthy dump that needs an extension the sandbox image lacks must be an
// ERROR with advice, never a FAIL; with the right image it must PASS.
func TestMissingExtensionIsNotTheBackupsFault(t *testing.T) {
	if testing.Short() {
		t.Skip("needs Docker")
	}
	ctx := context.Background()
	d := &sandbox.Docker{}
	if err := d.Available(ctx); err != nil {
		t.Skipf("skipping: %v", err)
	}
	const withExt, plain = "pgvector/pgvector:pg16", "postgres:16"
	for _, img := range []string{withExt, plain} {
		if _, err := d.EnsureImage(ctx, img); err != nil {
			t.Skipf("skipping: %v", err)
		}
	}
	name := "xinproof-extfix-" + randHex(4)
	docker(t, nil, "run", "-d", "--name", name, "--network", "none", "--label", "xinproof.managed=true",
		"--label", fmt.Sprintf("xinproof.expires=%d", time.Now().Add(20*time.Minute).Unix()), "-e", "POSTGRES_PASSWORD=x", withExt)
	defer exec.Command("docker", "rm", "-f", "-v", name).Run()
	for exec.Command("docker", "exec", "-e", "PGPASSWORD=x", name, "pg_isready", "-q", "-h", "127.0.0.1", "-U", "postgres").Run() != nil {
		time.Sleep(300 * time.Millisecond)
	}
	docker(t, []byte("CREATE EXTENSION vector; CREATE TABLE items (id int PRIMARY KEY, embedding vector(3)); INSERT INTO items SELECT g, ARRAY[g,g,g]::vector FROM generate_series(1,1000) g;"),
		"exec", "-i", name, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-U", "postgres")
	custom := docker(t, nil, "exec", name, "pg_dump", "-U", "postgres", "-Fc")
	plainSQL := docker(t, nil, "exec", name, "pg_dump", "-U", "postgres")

	dir := filepath.Join(t.TempDir(), "dumps")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "vec.dump"), custom, 0o644)
	os.WriteFile(filepath.Join(dir, "vec.sql"), plainSQL, 0o644)

	run := func(image string) []verify.Result {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		runID := "ext" + randHex(3)
		eng := &postgres.Engine{Docker: d, RunID: runID, Image: image, Memory: "1g", CPUs: "2", TTL: 20 * time.Minute}
		src, _ := local.New(dir)
		v := &verify.Verifier{Src: src, Engine: engine.Multi{eng}, Opts: verify.Options{Timeout: 5 * time.Minute,
			Store: &receipt.Store{Dir: filepath.Join(t.TempDir(), "receipts")}, Key: priv}}
		res, err := v.Run(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range res {
			t.Logf("%s on %s: %s %s", r.Object.Name, image, r.Status, r.Reason)
		}
		return res
	}
	for _, r := range run(plain) {
		if r.Status != receipt.Error || !strings.Contains(r.Reason, "extension(s) vector") || !strings.Contains(r.Reason, "--pg-image pgvector/pgvector:pg16") {
			t.Errorf("%s without the extension: %s %q, want ERROR naming the extension and an image", r.Object.Name, r.Status, r.Reason)
		}
	}
	for _, r := range run(withExt) {
		if r.Status != receipt.Pass || r.Rows != 1000 {
			t.Errorf("%s with the extension: %s %q rows=%d, want PASS with 1000 rows", r.Object.Name, r.Status, r.Reason, r.Rows)
		}
	}
}
