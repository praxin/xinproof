package verify

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/praxin/xinproof/internal/discover"
	"github.com/praxin/xinproof/internal/engine"
	"github.com/praxin/xinproof/internal/engine/postgres"
	"github.com/praxin/xinproof/internal/receipt"
	"github.com/praxin/xinproof/internal/source/local"
)

// fakeEngine stands in for Docker + Postgres so the PASS/FAIL/ERROR contract
// can be tested without containers. The real engine is covered by the
// integration test in internal/engine/postgres.
type fakeEngine struct {
	startErr error
	outcome  engine.Outcome

	mu       sync.Mutex
	uploaded map[string][]byte
	sessions int
	closed   int
}

func (f *fakeEngine) Supports(d discover.Detection) bool {
	switch d.Format {
	case discover.FormatPGCustom, discover.FormatPGPlain, discover.FormatPGTar, discover.FormatPGDir:
		return true
	}
	return false
}

func (f *fakeEngine) Analyzer(d discover.Detection) engine.Analyzer {
	if d.Format == discover.FormatPGPlain {
		return postgres.NewPlainAnalyzer()
	}
	return nil
}

func (f *fakeEngine) Start(ctx context.Context, d discover.Detection) (engine.Session, error) {
	if f.startErr != nil {
		return nil, f.startErr
	}
	f.mu.Lock()
	f.sessions++
	f.mu.Unlock()
	return &fakeSession{f: f}, nil
}

type fakeSession struct {
	f   *fakeEngine
	buf bytes.Buffer
}

func (s *fakeSession) Image() string { return "postgres:16@sha256:fake" }

type nopWC struct{ io.Writer }

func (nopWC) Close() error { return nil }

func (s *fakeSession) Upload(ctx context.Context) (io.WriteCloser, func() error) {
	return nopWC{&s.buf}, func() error { return nil }
}

// UploadDir captures the tar stream; Restore stores it like a single upload.
func (s *fakeSession) UploadDir(ctx context.Context) (io.WriteCloser, func() error) {
	return nopWC{&s.buf}, func() error { return nil }
}

func (s *fakeSession) Restore(ctx context.Context, a engine.Analyzer) engine.Outcome {
	s.f.mu.Lock()
	defer s.f.mu.Unlock()
	if s.f.uploaded == nil {
		s.f.uploaded = map[string][]byte{}
	}
	s.f.uploaded[string(s.buf.Bytes()[:min(16, s.buf.Len())])] = append([]byte(nil), s.buf.Bytes()...)
	return s.f.outcome
}

func (s *fakeSession) Close() error {
	s.f.mu.Lock()
	s.f.closed++
	s.f.mu.Unlock()
	return nil
}

var passOutcome = engine.Outcome{
	Result: receipt.Pass, Tables: 3, Rows: 1234, RowsKnown: true, RestoreSeconds: 1.5,
	Checks: []receipt.Check{{ID: "l2.restore", Status: receipt.CheckPass, Detail: "exit 0"}},
}

const completePlain = "--\n-- PostgreSQL database dump\n--\n-- Dumped by pg_dump version 16.4\n\nCREATE TABLE public.t (id int);\nCOPY public.t (id) FROM stdin;\n1\n2\n\\.\n\n--\n-- PostgreSQL database dump complete\n--\n"

func pgCustom() []byte {
	var b bytes.Buffer
	b.WriteString("PGDMP")
	b.Write([]byte{1, 15, 0, 4, 8, 1, 0})
	for i := 0; i < 7; i++ {
		b.Write([]byte{0, 1, 0, 0, 0})
	}
	for _, s := range []string{"shop", "16.4", "16.4"} {
		b.Write([]byte{0, byte(len(s)), 0, 0, 0})
		b.WriteString(s)
	}
	b.Write(bytes.Repeat([]byte("data"), 50_000)) // larger than the sniff window
	return b.Bytes()
}

func gzipped(b []byte) []byte {
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	w.Write(b)
	w.Close()
	return out.Bytes()
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func TestContract(t *testing.T) {
	custom := pgCustom()
	gzPlain := gzipped([]byte(completePlain))
	bigPlain := []byte(strings.Replace(completePlain, "1\n2\n", strings.Repeat("123456789\n", 20_000), 1))
	gzBig := gzipped(bigPlain)

	tests := []struct {
		name       string
		file       string
		content    []byte
		sidecar    string // contents of <file>.sha256, if any
		eng        *fakeEngine
		want       receipt.Result
		reason     string // substring of the reason
		wantUpload []byte // what the sandbox must have received (decompressed)
	}{
		{name: "good custom dump", file: "pg_good.dump", content: custom, eng: &fakeEngine{outcome: passOutcome}, want: receipt.Pass, wantUpload: custom},
		{name: "good gzipped plain dump", file: "pg_good.sql.gz", content: gzPlain, eng: &fakeEngine{outcome: passOutcome}, want: receipt.Pass, wantUpload: []byte(completePlain)},
		{name: "truncated gzip", file: "pg_trunc.sql.gz", content: gzBig[:len(gzBig)*61/100], eng: &fakeEngine{outcome: passOutcome}, want: receipt.Fail, reason: "gzip stream ends early at byte"},
		{name: "truncated gzip, docker missing", file: "pg_trunc.sql.gz", content: gzBig[:len(gzBig)/2], eng: &fakeEngine{startErr: errors.New("docker is not available")}, want: receipt.Fail, reason: "gzip stream ends early"},
		{name: "truncated plain (no trailer)", file: "pg_trunc.sql", content: bigPlain[:len(bigPlain)*99/100], eng: &fakeEngine{outcome: passOutcome}, want: receipt.Fail, reason: "COPY data"},
		{name: "plain missing trailer", file: "pg_short.sql", content: []byte(completePlain[:strings.Index(completePlain, "\n--\n-- PostgreSQL database dump complete")]), eng: &fakeEngine{outcome: passOutcome}, want: receipt.Fail, reason: "trailer is missing"},
		{name: "empty file", file: "pg_empty.dump", content: nil, eng: &fakeEngine{outcome: passOutcome}, want: receipt.Fail, reason: "empty file"},
		{name: "flipped magic", file: "pg_flip.dump", content: append([]byte("XGDMP"), custom[5:]...), eng: &fakeEngine{outcome: passOutcome}, want: receipt.Fail, reason: "not a recognizable"},
		{name: "truncated header", file: "pg_hdr.dump", content: custom[:20], eng: &fakeEngine{outcome: passOutcome}, want: receipt.Fail, reason: "truncated"},
		{name: "restore fails in sandbox", file: "pg_bad.dump", content: custom, eng: &fakeEngine{outcome: engine.Outcome{Result: receipt.Fail, Reason: "pg_restore failed (exit 1): could not read from input file"}}, want: receipt.Fail, reason: "pg_restore failed"},
		{name: "docker missing on a good dump", file: "pg_good.dump", content: custom, eng: &fakeEngine{startErr: errors.New("docker is not available")}, want: receipt.Error, reason: "docker is not available"},
		{name: "mysql recognized but unsupported", file: "shop.sql", content: []byte("-- MySQL dump 10.13  Distrib 8.0.36, for Linux\n"), eng: &fakeEngine{outcome: passOutcome}, want: receipt.Error, reason: "MySQL"},
		{name: "sidecar matches", file: "pg_side.dump", content: custom, sidecar: sha(custom) + "  pg_side.dump\n", eng: &fakeEngine{outcome: passOutcome}, want: receipt.Pass},
		{name: "sidecar mismatch", file: "pg_side.dump", content: custom, sidecar: strings.Repeat("0", 64) + "\n", eng: &fakeEngine{outcome: passOutcome}, want: receipt.Fail, reason: "checksum mismatch"},
		{name: "engine returns nothing", file: "pg_good.dump", content: custom, eng: &fakeEngine{}, want: receipt.Error, reason: "no result"},
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			data := filepath.Join(dir, "data")
			os.MkdirAll(data, 0o755)
			os.WriteFile(filepath.Join(data, tt.file), tt.content, 0o644)
			if tt.sidecar != "" {
				os.WriteFile(filepath.Join(data, tt.file+".sha256"), []byte(tt.sidecar), 0o644)
			}
			os.WriteFile(filepath.Join(data, "README.txt"), []byte("not a backup"), 0o644)
			src, err := local.New(data)
			if err != nil {
				t.Fatal(err)
			}
			var plan Plan
			v := &Verifier{Src: src, Engine: tt.eng, Opts: Options{
				Store: &receipt.Store{Dir: filepath.Join(dir, "receipts")}, Key: priv, ToolVersion: "test",
				OnPlan: func(p Plan) { plan = p },
			}}
			results, err := v.Run(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(results) != 1 || plan.Found != 1 || plan.Skipped != 1 {
				t.Fatalf("got %d results, plan %+v; want exactly one backup and one skipped object", len(results), plan)
			}
			r := results[0]
			if r.Status != tt.want || !strings.Contains(r.Reason, tt.reason) {
				t.Fatalf("status %s (%q), want %s containing %q", r.Status, r.Reason, tt.want, tt.reason)
			}
			if tt.want == receipt.Pass && r.Reason != "" {
				t.Errorf("PASS with a reason: %q", r.Reason)
			}
			// Every backup gets a signed receipt, whatever the outcome.
			doc, err := os.ReadFile(r.ReceiptPath)
			if err != nil {
				t.Fatalf("no receipt: %v", err)
			}
			rv, err := receipt.Verify(doc, []ed25519.PublicKey{priv.Public().(ed25519.PublicKey)})
			if err != nil {
				t.Fatalf("receipt does not verify: %v", err)
			}
			if rv.Receipt.Result != tt.want || rv.Receipt.Subject.Size != int64(len(tt.content)) {
				t.Errorf("receipt result %s size %d", rv.Receipt.Result, rv.Receipt.Subject.Size)
			}
			if tt.want != receipt.Error && len(tt.content) > 0 && rv.Receipt.Subject.SHA256 != "" && rv.Receipt.Subject.SHA256 != sha(tt.content) {
				t.Errorf("receipt sha256 %s, want %s", rv.Receipt.Subject.SHA256, sha(tt.content))
			}
			if tt.eng.sessions != tt.eng.closed {
				t.Errorf("sandbox leak: %d started, %d closed", tt.eng.sessions, tt.eng.closed)
			}
			if tt.wantUpload != nil {
				got := tt.eng.uploaded[string(tt.wantUpload[:16])]
				if !bytes.Equal(got, tt.wantUpload) {
					t.Errorf("sandbox received %d bytes, want the %d decompressed bytes", len(got), len(tt.wantUpload))
				}
			}
		})
	}
}

func TestSelectionAndChain(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	os.MkdirAll(filepath.Join(data, "nested"), 0o755)
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	files := []struct {
		name string
		age  time.Duration
	}{
		{"pg_2026-11-16.dump", 1 * time.Hour},
		{"pg_2026-11-15.dump", 25 * time.Hour},
		{"nested/pg_2026-11-14.dump", 49 * time.Hour},
		{"pg_2026-11-01.dump", 15 * 24 * time.Hour},
	}
	custom := pgCustom()
	for _, f := range files {
		p := filepath.Join(data, filepath.FromSlash(f.name))
		os.WriteFile(p, custom, 0o644)
		os.Chtimes(p, now.Add(-f.age), now.Add(-f.age))
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	src, _ := local.New(data)
	store := &receipt.Store{Dir: filepath.Join(dir, "receipts")}
	run := func(o Options) ([]Result, Plan) {
		var plan Plan
		o.Store, o.Key, o.Now = store, priv, func() time.Time { return now }
		o.OnPlan = func(p Plan) { plan = p }
		v := &Verifier{Src: src, Engine: &fakeEngine{outcome: passOutcome}, Opts: o}
		res, err := v.Run(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return res, plan
	}

	res, plan := run(Options{Newest: 2})
	if plan.Found != 4 || plan.Testing != 2 || !plan.Newest {
		t.Errorf("plan %+v", plan)
	}
	if len(res) != 2 || res[0].Object.Name != "pg_2026-11-16.dump" || res[1].Object.Name != "pg_2026-11-15.dump" {
		t.Errorf("newest 2 = %v", names(res))
	}
	res, _ = run(Options{Since: 72 * time.Hour})
	if len(res) != 3 || res[2].Object.Name != "nested/pg_2026-11-14.dump" {
		t.Errorf("since 72h = %v", names(res))
	}

	// Five receipts across two runs form one unbroken chain.
	var prev *receipt.Verified
	for seq := int64(1); seq <= 5; seq++ {
		doc, err := os.ReadFile(filepath.Join(store.Dir, receipt.FileName(seq)))
		if err != nil {
			t.Fatal(err)
		}
		v, err := receipt.Verify(doc, nil)
		if err != nil {
			t.Fatal(err)
		}
		if prev != nil {
			if err := receipt.CheckLink(prev, v); err != nil {
				t.Errorf("seq %d: %v", seq, err)
			}
		}
		prev = v
	}

	// An empty location is an ERROR, not a silent success.
	empty := t.TempDir()
	esrc, _ := local.New(empty)
	v := &Verifier{Src: esrc, Engine: &fakeEngine{}, Opts: Options{}}
	if _, err := v.Run(context.Background()); !errors.Is(err, ErrNothingFound) {
		t.Errorf("empty location: err = %v", err)
	}
}

func names(rs []Result) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.Object.Name)
	}
	return out
}

func TestExitCode(t *testing.T) {
	mk := func(ss ...receipt.Result) []Result {
		var out []Result
		for _, s := range ss {
			out = append(out, Result{Status: s})
		}
		return out
	}
	tests := []struct {
		in   []Result
		want int
	}{
		{mk(receipt.Pass, receipt.Pass), 0},
		{mk(receipt.Pass, receipt.Fail), 1},
		{mk(receipt.Pass, receipt.Error), 2},
		{mk(receipt.Error, receipt.Fail), 1},
		{nil, 0},
	}
	for _, tt := range tests {
		if got := ExitCode(tt.in); got != tt.want {
			t.Errorf("ExitCode(%v) = %d, want %d", tt.in, got, tt.want)
		}
	}
}
