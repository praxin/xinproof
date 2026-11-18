package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeCloud hands out the queued jobs once and records everything sent back.
type fakeCloud struct {
	mu       sync.Mutex
	jobs     []agentJob
	receipts []string
	done     map[string]map[string]any
	headers  http.Header
	status   int
}

func (f *fakeCloud) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer xpr_test" || f.status != 0 {
		w.WriteHeader(max(f.status, http.StatusUnauthorized))
		io.WriteString(w, `{"error":"invalid or revoked runner key"}`)
		return
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/api/v1/agent/next":
		f.headers = r.Header.Clone()
		var j *agentJob
		if len(f.jobs) > 0 {
			j, f.jobs = &f.jobs[0], f.jobs[1:]
		}
		json.NewEncoder(w).Encode(agentNext{Job: j, PollSeconds: 60})
	case r.Method == "POST" && r.URL.Path == "/api/v1/receipts":
		b, _ := io.ReadAll(r.Body)
		f.receipts = append(f.receipts, string(b))
		w.WriteHeader(http.StatusCreated)
	case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/api/v1/agent/jobs/"):
		var m map[string]any
		json.NewDecoder(r.Body).Decode(&m)
		f.done[strings.TrimPrefix(r.URL.Path, "/api/v1/agent/jobs/")] = m
	default:
		http.NotFound(w, r)
	}
}

func newTestAgent(t *testing.T, url string) (*agent, *[][]string) {
	var calls [][]string
	a := &agent{
		url: url, token: "xpr_test", pub: "AAAA", host: "test", stateDir: t.TempDir(),
		client: http.DefaultClient, out: io.Discard,
	}
	// Stands in for `verify`: writes two receipts into --receipts, like a real run.
	a.verify = func(args []string) int {
		calls = append(calls, args)
		var dir string
		for i, s := range args {
			if s == "--receipts" {
				dir = args[i+1]
			}
		}
		n := len(receiptFiles(dir))
		for i := 1; i <= 2; i++ {
			os.WriteFile(filepath.Join(dir, "receipt-00000"+string(rune('0'+n+i))+".json"), []byte(`{"seq":`+string(rune('0'+n+i))+`}`), 0o600)
		}
		return exitFail
	}
	return a, &calls
}

func TestAgentRunsJobAndSendsReceiptsInOrder(t *testing.T) {
	cloud := &fakeCloud{done: map[string]map[string]any{}, jobs: []agentJob{{ID: "job_1", Location: "s3://b/pg/", Newest: 2}, {ID: "job_2", Location: "s3://b/pg/", Newest: 2}}}
	srv := httptest.NewServer(cloud)
	defer srv.Close()
	a, calls := newTestAgent(t, srv.URL)
	if err := a.loop(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 2 {
		t.Fatalf("verify ran %d times, want 2 (both queued jobs)", len(*calls))
	}
	if got := strings.Join((*calls)[0], " "); !strings.HasPrefix(got, "--newest 2 --receipts ") || !strings.HasSuffix(got, " --no-color s3://b/pg/") {
		t.Errorf("verify args = %q", got)
	}
	if (*calls)[0][3] != (*calls)[1][3] {
		t.Error("the same location should reuse its receipt folder, so receipts chain night to night")
	}
	want := []string{`{"seq":1}`, `{"seq":2}`, `{"seq":3}`, `{"seq":4}`}
	if strings.Join(cloud.receipts, ",") != strings.Join(want, ",") {
		t.Errorf("sent %v, want only new receipts, in chain order: %v", cloud.receipts, want)
	}
	if d := cloud.done["job_1"]; d["exit_code"] != float64(exitFail) || d["sent"] != float64(2) {
		t.Errorf("job_1 report = %v", d)
	}
	for _, h := range []string{"X-Xinproof-Key", "X-Xinproof-Version", "X-Xinproof-Host"} {
		if cloud.headers.Get(h) == "" {
			t.Errorf("missing %s header", h)
		}
	}
}

func TestAgentRefusesLocalFoldersUnlessAllowed(t *testing.T) {
	cloud := &fakeCloud{done: map[string]map[string]any{}, jobs: []agentJob{{ID: "job_1", Location: "/etc", Newest: 3}, {ID: "job_2", Location: "ftp://x/", Newest: 3}}}
	srv := httptest.NewServer(cloud)
	defer srv.Close()
	a, calls := newTestAgent(t, srv.URL)
	if err := a.loop(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 0 {
		t.Fatalf("verify ran for a refused location: %v", *calls)
	}
	if d := cloud.done["job_1"]; d["exit_code"] != float64(exitUsage) || !strings.Contains(d["message"].(string), "--allow-local") {
		t.Errorf("job_1 report = %v", d)
	}
	if d := cloud.done["job_2"]; d["exit_code"] != float64(exitUsage) {
		t.Errorf("job_2 report = %v", d)
	}
	a.allowLocal = true
	if a.acceptLocation(t.TempDir()) != nil {
		t.Error("--allow-local should accept an absolute path")
	}
}

func TestAgentStopsWhenRefused(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusConflict} {
		cloud := &fakeCloud{done: map[string]map[string]any{}, status: status}
		srv := httptest.NewServer(cloud)
		a, _ := newTestAgent(t, srv.URL)
		if err := a.loop(context.Background(), true); !errors.Is(err, errStop) {
			t.Errorf("HTTP %d: err = %v, want errStop", status, err)
		}
		srv.Close()
	}
}

func TestAgentOperatorFlags(t *testing.T) {
	if err := checkOperatorFlags([]string{"--memory", "4g", "--tmpfs=8g"}); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{"--receipts", "--output=/etc/x", "-newest"} {
		if checkOperatorFlags([]string{bad}) == nil {
			t.Errorf("%s should be refused", bad)
		}
	}
}

func TestAgentSwapsSetupCodeOnce(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var m map[string]string
		json.NewDecoder(r.Body).Decode(&m)
		if r.URL.Path != "/api/v1/agent/claim" || m["setup_code"] != "xps_one" {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"error":"this setup code was already used"}`)
			return
		}
		io.WriteString(w, `{"token":"xpr_saved"}`)
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "agent", "runner.key")
	tok, err := runnerKeyFromSetup(srv.URL, "xps_one", path)
	if err != nil || tok != "xpr_saved" {
		t.Fatalf("got %q, %v", tok, err)
	}
	// A restart reads the saved key; the (now used) code isn't sent again.
	tok, err = runnerKeyFromSetup(srv.URL, "xps_one", path)
	if err != nil || tok != "xpr_saved" || calls != 1 {
		t.Fatalf("restart: %q, %v, %d calls", tok, err, calls)
	}
	if _, err := runnerKeyFromSetup(srv.URL, "xps_used", filepath.Join(t.TempDir(), "k")); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Errorf("a used code should say why: %v", err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("runner key file mode %v", fi.Mode().Perm())
	}
}
