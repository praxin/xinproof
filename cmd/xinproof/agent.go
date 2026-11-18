package main

// xinproof agent: run as a runner for Xinproof Cloud. It asks the cloud for
// work over outbound HTTPS, restore-tests the backups here with `verify`, and
// sends back only the signed receipts. Backups never leave this machine's
// network; nothing has to connect in.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/praxin/xinproof/internal/receipt"
)

type agentJob struct {
	ID       string `json:"id"`
	Location string `json:"location"`
	Newest   int    `json:"newest"`
}

type agentNext struct {
	Job          *agentJob `json:"job"`
	PollSeconds  int       `json:"poll_seconds"`
	LicenseError string    `json:"license_error"` // a self-hosted server without a valid licence says why
	license      string    // the server's X-Xinproof-License header
}

// errStop means the cloud refused this runner (revoked key, changed signing
// key): retrying won't help, so the agent exits and says why.
var errStop = errors.New("stop")

type agent struct {
	url, token string
	pub        string // base64 raw Ed25519 public key
	host       string
	locations  string // what this runner was set up to test (XINPROOF_LOCATIONS); the cloud schedules them on first connect
	stateDir   string
	allowLocal bool
	extra      []string // operator-chosen verify flags (never from the cloud)
	client     *http.Client
	out        io.Writer
	verify     func(args []string) int // cmdVerify, swapped out in tests
	license    string                  // the licence the server last presented
	said       string                  // the last licence problem printed, to say it once
	now        func() time.Time        // time.Now, swapped out in tests
}

func cmdAgent(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	fs.SetOutput(stderr)
	url := fs.String("url", os.Getenv("XINPROOF_URL"), "Xinproof Cloud address (or XINPROOF_URL)")
	tokenFile := fs.String("token-file", "", "read the runner key from this file instead of XINPROOF_RUNNER_TOKEN")
	allowLocal := fs.Bool("allow-local", false, "also accept schedules that test folders on this machine (absolute paths)")
	verifyFlags := fs.String("verify-flags", os.Getenv("XINPROOF_VERIFY_FLAGS"), "extra flags for every test, chosen by you, e.g. \"--memory 4g --tmpfs 8g\" (or XINPROOF_VERIFY_FLAGS)")
	once := fs.Bool("once", false, "run whatever is queued now, then exit")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: XINPROOF_URL=https://… XINPROOF_RUNNER_TOKEN=xpr_… xinproof agent [flags]")
		fs.PrintDefaults()
	}
	if _, err := parseInterspersed(fs, args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitPass
		}
		return exitUsage
	}
	token := strings.TrimSpace(os.Getenv("XINPROOF_RUNNER_TOKEN"))
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			fmt.Fprintln(stderr, "xinproof agent:", err)
			return exitUsage
		}
		token = strings.TrimSpace(string(b))
	}
	// One-click setups pass a one-time setup code instead of the key: swap it
	// on first start and keep the key, so restarts don't need the code again.
	if token == "" && *url != "" {
		t, err := runnerKeyFromSetup(strings.TrimRight(*url, "/"), strings.TrimSpace(os.Getenv("XINPROOF_SETUP_CODE")), filepath.Join(home(), "agent", "runner.key"))
		if err != nil {
			fmt.Fprintln(stderr, "xinproof agent:", err)
			return exitUsage
		}
		token = t
	}
	if *url == "" || !strings.HasPrefix(token, "xpr_") {
		fmt.Fprintln(stderr, "xinproof agent: set XINPROOF_URL and XINPROOF_SETUP_CODE (from the dashboard's Runners page) or XINPROOF_RUNNER_TOKEN")
		return exitUsage
	}
	extra := strings.Fields(*verifyFlags)
	if err := checkOperatorFlags(extra); err != nil {
		fmt.Fprintln(stderr, "xinproof agent:", err)
		return exitUsage
	}
	priv, created, err := receipt.LoadOrCreateKey(filepath.Join(home(), "keys"))
	if err != nil {
		fmt.Fprintln(stderr, "xinproof agent:", err)
		return exitError
	}
	pub := priv.Public().(ed25519.PublicKey)
	if created {
		fmt.Fprintf(stdout, "created signing key %s\n", receipt.KeyID(pub))
	}
	hostname, _ := os.Hostname()
	a := &agent{
		url: strings.TrimRight(*url, "/"), token: token, pub: base64.StdEncoding.EncodeToString(pub), host: hostname,
		locations: strings.TrimSpace(os.Getenv("XINPROOF_LOCATIONS")),
		stateDir:  filepath.Join(home(), "agent"), allowLocal: *allowLocal, extra: extra,
		client: &http.Client{Timeout: 30 * time.Second}, out: stdout,
		verify: func(args []string) int { return cmdVerify(args, stdout, stdout) },
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Fprintf(stdout, "xinproof agent %s: signing as %s, asking %s for work\n", version, receipt.KeyID(pub), a.url)
	if err := a.loop(ctx, *once); err != nil {
		if errors.Is(err, errStop) {
			return exitUsage // systemd: RestartPreventExitStatus=3, so a revoked runner stays stopped
		}
		fmt.Fprintln(stderr, "xinproof agent:", err)
		return exitError
	}
	return exitPass
}

// checkOperatorFlags keeps local flags to tuning knobs: where receipts go and
// what is tested are the agent's and the dashboard's business.
func checkOperatorFlags(extra []string) error {
	allowed := map[string]bool{"--memory": true, "--cpus": true, "--tmpfs": true, "--timeout": true, "--amcheck-budget": true, "--docker": true,
		"--endpoint": true, "--region": true, "--profile": true, "--path-style": true, "--r2-account-id": true, "--engine": true,
		"--pg-image": true, "--mysql-image": true, "--mongo-image": true, "--log-level": true, "--check": true}
	for _, f := range extra {
		if !strings.HasPrefix(f, "-") {
			continue
		}
		name := strings.SplitN(f, "=", 2)[0]
		if !strings.HasPrefix(name, "--") {
			name = "-" + name
		}
		if !allowed[name] {
			return fmt.Errorf("--verify-flags can't include %s", name)
		}
	}
	return nil
}

func (a *agent) loop(ctx context.Context, once bool) error {
	wait := time.Duration(0)
	failures := 0
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
		next, err := a.next(ctx)
		if errors.Is(err, errStop) {
			return err
		}
		if err != nil {
			failures++
			wait = min(time.Duration(1<<min(failures, 8))*5*time.Second, 5*time.Minute)
			fmt.Fprintf(a.out, "can't reach %s (%v); trying again in %s\n", a.url, err, wait)
			continue
		}
		failures = 0
		wait = time.Duration(max(next.PollSeconds, 10)) * time.Second
		if next.LicenseError != "" && next.LicenseError != a.said {
			fmt.Fprintf(a.out, "This Xinproof server isn't testing anything: %s\n", next.LicenseError)
		}
		a.said = next.LicenseError
		if next.Job == nil {
			if once {
				return nil
			}
			continue
		}
		a.run(ctx, next.Job)
		wait = 0 // there may be more queued
	}
}

func (a *agent) request(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, a.url+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("X-Xinproof-Key", a.pub)
	req.Header.Set("X-Xinproof-Version", strings.TrimPrefix(version, "v"))
	req.Header.Set("X-Xinproof-Host", a.host)
	if a.locations != "" {
		req.Header.Set("X-Xinproof-Locations", a.locations)
	}
	req.Header.Set("User-Agent", "xinproof-agent/"+version)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return a.client.Do(req)
}

func (a *agent) next(ctx context.Context) (*agentNext, error) {
	res, err := a.request(ctx, http.MethodGet, "/api/v1/agent/next", nil)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	switch {
	case res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusConflict:
		fmt.Fprintf(a.out, "Xinproof Cloud refused this runner: %s\n", cloudError(b))
		return nil, errStop
	case res.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("HTTP %d: %s", res.StatusCode, cloudError(b))
	}
	var n agentNext
	if err := json.Unmarshal(b, &n); err != nil {
		return nil, fmt.Errorf("unexpected reply: %w", err)
	}
	n.license = res.Header.Get("X-Xinproof-License")
	a.license = n.license
	return &n, nil
}

func cloudError(b []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(b, &e) == nil && e.Error != "" {
		return e.Error
	}
	return strings.TrimSpace(string(b))
}

// acceptLocation: cloud storage always; folders on this machine only if the
// operator allowed them, so a dashboard user can't point it at local files.
func (a *agent) acceptLocation(loc string) error {
	for _, p := range []string{"s3://", "r2://", "azblob://", "gs://"} {
		if strings.HasPrefix(loc, p) && len(loc) > len(p) {
			return nil
		}
	}
	if filepath.IsAbs(loc) && a.allowLocal {
		return nil
	}
	if filepath.IsAbs(loc) {
		return fmt.Errorf("this runner isn't allowed to test folders on its own machine. To allow it, run the install command again with XINPROOF_ALLOW_LOCAL=1 (or start the runner with --allow-local)")
	}
	return fmt.Errorf("not a backup location this runner understands: %q", loc)
}

func (a *agent) run(ctx context.Context, j *agentJob) {
	start := time.Now()
	fmt.Fprintf(a.out, "\n== %s: testing the newest %d backups at %s\n", j.ID, j.Newest, j.Location)
	code, sent, msg := a.test(ctx, j)
	fmt.Fprintf(a.out, "== %s: done in %s, exit %d, %d results sent%s\n", j.ID, time.Since(start).Round(time.Second), code, sent, map[bool]string{true: " (" + msg + ")", false: ""}[msg != ""])
	body, _ := json.Marshal(map[string]any{"exit_code": code, "sent": sent, "message": msg})
	// Report even if we're shutting down, so the job doesn't sit at "testing now".
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if res, err := a.request(rctx, http.MethodPost, "/api/v1/agent/jobs/"+j.ID, body); err != nil {
		fmt.Fprintf(a.out, "couldn't report %s: %v\n", j.ID, err)
	} else {
		res.Body.Close()
	}
}

func (a *agent) test(ctx context.Context, j *agentJob) (code, sent int, msg string) {
	now := time.Now
	if a.now != nil {
		now = a.now
	}
	if err := serverLicense(a.url, a.license, now()); err != nil {
		return exitUsage, 0, err.Error()
	}
	if err := a.acceptLocation(j.Location); err != nil {
		return exitUsage, 0, err.Error()
	}
	newest := j.Newest
	if newest < 1 || newest > 20 {
		newest = 3
	}
	// One receipt folder per location, kept between runs, so each night's
	// receipt links to the one before it (the hash chain).
	sum := sha256.Sum256([]byte(j.Location))
	dir := filepath.Join(a.stateDir, "receipts", hex.EncodeToString(sum[:8]))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return exitError, 0, err.Error()
	}
	before := map[string]bool{}
	for _, f := range receiptFiles(dir) {
		before[f] = true
	}
	args := append([]string{"--newest", strconv.Itoa(newest), "--receipts", dir, "--no-color"}, a.extra...)
	code = a.verify(append(args, j.Location))
	if ctx.Err() != nil {
		msg = "stopped before it finished"
	}
	var failed []string
	for _, f := range receiptFiles(dir) {
		if before[f] {
			continue
		}
		if err := a.send(ctx, f); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", filepath.Base(f), err))
			continue
		}
		sent++
	}
	if len(failed) > 0 {
		msg = strings.Join(append([]string{fmt.Sprintf("%d results couldn't be sent", len(failed))}, failed...), "; ")
	}
	return code, sent, msg
}

// receiptFiles lists receipts in chain order (receipt-000001.json, …).
func receiptFiles(dir string) []string {
	m, _ := filepath.Glob(filepath.Join(dir, "receipt-*.json"))
	sort.Strings(m)
	return m
}

func (a *agent) send(ctx context.Context, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	res, err := a.request(context.WithoutCancel(ctx), http.MethodPost, "/api/v1/receipts", b)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		rb, _ := io.ReadAll(io.LimitReader(res.Body, 4<<10))
		return fmt.Errorf("HTTP %d: %s", res.StatusCode, cloudError(rb))
	}
	return nil
}

// runnerKeyFromSetup returns the runner key saved at path, or swaps the
// one-time setup code for it (POST /api/v1/agent/claim) and saves it there.
func runnerKeyFromSetup(url, setup, path string) (string, error) {
	if b, err := os.ReadFile(path); err == nil && strings.HasPrefix(strings.TrimSpace(string(b)), "xpr_") {
		return strings.TrimSpace(string(b)), nil
	}
	if !strings.HasPrefix(setup, "xps_") {
		return "", nil
	}
	body, _ := json.Marshal(map[string]string{"setup_code": setup})
	res, err := (&http.Client{Timeout: 30 * time.Second}).Post(url+"/api/v1/agent/claim", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("swapping the setup code: %w", err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("swapping the setup code: %s", cloudError(b))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(b, &out); err != nil || !strings.HasPrefix(out.Token, "xpr_") {
		return "", fmt.Errorf("swapping the setup code: unexpected reply")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(out.Token+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("saving the runner key: %w", err)
	}
	return out.Token, nil
}
