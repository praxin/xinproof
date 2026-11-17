//go:build unix

// Package chaos breaks things on purpose — sandboxes killed mid-restore,
// time budgets blown, disks full, the CLI SIGKILLed or interrupted — and
// checks that every backup still ends "completed" or "loudly failed": a
// result for each, a valid receipt chain, and no sandbox left behind.
//
// Needs Docker; skipped with -short.
package chaos_test

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
	"syscall"
	"testing"
	"time"

	"github.com/praxin/xinproof/internal/engine"
	mysqlengine "github.com/praxin/xinproof/internal/engine/mysql"
	"github.com/praxin/xinproof/internal/engine/postgres"
	"github.com/praxin/xinproof/internal/receipt"
	"github.com/praxin/xinproof/internal/sandbox"
	"github.com/praxin/xinproof/internal/source/local"
	"github.com/praxin/xinproof/internal/verify"
)

const pgImage = "postgres:16"

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func needDocker(t *testing.T) *sandbox.Docker {
	t.Helper()
	if testing.Short() {
		t.Skip("chaos test (needs Docker); skipped with -short")
	}
	d := &sandbox.Docker{}
	if err := d.Available(context.Background()); err != nil {
		t.Skipf("skipping: %v", err)
	}
	return d
}

func docker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args[:min(3, len(args))], " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func containers(t *testing.T, label string) []string {
	out := docker(t, "ps", "-a", "-q", "--filter", "label="+label)
	if out == "" {
		return nil
	}
	return strings.Fields(out)
}

// pgDump makes a small custom-format dump with a real pg_dump.
func pgDump(t *testing.T, d *sandbox.Docker) []byte {
	t.Helper()
	if _, err := d.EnsureImage(context.Background(), pgImage); err != nil {
		t.Skipf("skipping: %v", err)
	}
	name := "xinproof-chaosfix-" + randHex(4)
	docker(t, "run", "-d", "--name", name, "--network", "none", "--label", "xinproof.managed=true",
		"--label", fmt.Sprintf("xinproof.expires=%d", time.Now().Add(20*time.Minute).Unix()), "-e", "POSTGRES_PASSWORD=x", pgImage)
	defer exec.Command("docker", "rm", "-f", "-v", name).Run()
	deadline := time.Now().Add(2 * time.Minute)
	for exec.Command("docker", "exec", "-e", "PGPASSWORD=x", name, "pg_isready", "-q", "-h", "127.0.0.1", "-U", "postgres").Run() != nil {
		if time.Now().After(deadline) {
			t.Fatal("fixture postgres not ready")
		}
		time.Sleep(300 * time.Millisecond)
	}
	sql := "CREATE TABLE t (id int PRIMARY KEY, s text); INSERT INTO t SELECT g, md5(g::text) FROM generate_series(1, 20000) g;"
	cmd := exec.Command("docker", "exec", "-i", name, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-U", "postgres")
	cmd.Stdin = strings.NewReader(sql)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fixture: %v\n%s", err, out)
	}
	out, err := exec.Command("docker", "exec", name, "pg_dump", "-U", "postgres", "-Fc").Output()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func dumpsDir(t *testing.T, files map[string][]byte) string {
	dir := filepath.Join(t.TempDir(), "dumps")
	os.MkdirAll(dir, 0o755)
	for n, b := range files {
		os.WriteFile(filepath.Join(dir, n), b, 0o644)
	}
	return dir
}

// runVerifier runs the in-process pipeline and checks the invariants every
// chaos scenario shares: one result and one valid receipt per backup, and no
// sandbox of this run left behind.
func runVerifier(t *testing.T, eng engine.Engine, runID, dir string, timeout time.Duration) []verify.Result {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	src, _ := local.New(dir)
	v := &verify.Verifier{Src: src, Engine: eng, Opts: verify.Options{
		Timeout: timeout, Store: &receipt.Store{Dir: filepath.Join(t.TempDir(), "receipts")}, Key: priv,
	}}
	results, err := v.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(results) != len(entries) {
		t.Errorf("%d results for %d backups", len(results), len(entries))
	}
	for _, r := range results {
		t.Logf("%s: %s %s", r.Object.Name, r.Status, r.Reason)
		doc, err := os.ReadFile(r.ReceiptPath)
		if err != nil {
			t.Errorf("%s: no receipt", r.Object.Name)
			continue
		}
		if _, err := receipt.Verify(doc, []ed25519.PublicKey{priv.Public().(ed25519.PublicKey)}); err != nil {
			t.Errorf("%s: receipt: %v", r.Object.Name, err)
		}
	}
	if left := containers(t, sandbox.LabelRun+"="+runID); len(left) > 0 {
		t.Errorf("sandboxes left behind: %v", left)
	}
	return results
}

func TestSandboxKilledMidRestore(t *testing.T) {
	d := needDocker(t)
	dir := dumpsDir(t, map[string][]byte{"good.dump": pgDump(t, d)})
	runID := "chaos" + randHex(3)
	eng := &postgres.Engine{Docker: d, RunID: runID, Image: pgImage, Memory: "1g", CPUs: "2", TTL: 20 * time.Minute,
		Hooks: engine.Hooks{BeforeRestore: func(name string) { exec.Command("docker", "kill", name).Run() }}}
	res := runVerifier(t, engine.Multi{eng}, runID, dir, 5*time.Minute)
	if res[0].Status != receipt.Error || !strings.Contains(res[0].Reason, "sandbox") {
		t.Errorf("killed sandbox: %s %q, want ERROR naming the sandbox (the backup is not to blame)", res[0].Status, res[0].Reason)
	}
}

func TestTimeBudgetExceeded(t *testing.T) {
	d := needDocker(t)
	dir := dumpsDir(t, map[string][]byte{"a.dump": pgDump(t, d), "b.dump": pgDump(t, d)})
	runID := "chaos" + randHex(3)
	// The hook guarantees the budget runs out mid-test however fast the machine is.
	eng := &postgres.Engine{Docker: d, RunID: runID, Image: pgImage, Memory: "1g", CPUs: "2", TTL: 20 * time.Minute,
		Hooks: engine.Hooks{BeforeRestore: func(string) { time.Sleep(3 * time.Second) }}}
	for _, r := range runVerifier(t, engine.Multi{eng}, runID, dir, 2*time.Second) {
		if r.Status != receipt.Error || !strings.Contains(r.Reason, "budget") {
			t.Errorf("%s: %s %q, want ERROR for the exceeded budget", r.Object.Name, r.Status, r.Reason)
		}
	}
}

func TestSandboxDiskFull(t *testing.T) {
	d := needDocker(t)
	const image = "mysql:8.4"
	if _, err := d.EnsureImage(context.Background(), image); err != nil {
		t.Skipf("skipping: %v", err)
	}
	var b strings.Builder
	b.WriteString("-- MySQL dump 10.13  Distrib 8.4.3, for Linux (x86_64)\n-- Server version\t8.4.3\n")
	b.WriteString("CREATE TABLE `t` (`id` int, `s` varchar(64));\nINSERT INTO `t` VALUES ")
	for i := 0; i < 60_000; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "(%d,'%s')", i, randHex(16))
	}
	b.WriteString(";\n-- Dump completed on 2026-11-17 10:00:00\n")
	dir := dumpsDir(t, map[string][]byte{"big.sql": []byte(b.String())})
	runID := "chaos" + randHex(3)
	eng := &mysqlengine.Engine{Docker: d, RunID: runID, Image: image, Memory: "2g", CPUs: "2", TTL: 20 * time.Minute, TmpfsSize: "1m"}
	res := runVerifier(t, engine.Multi{eng}, runID, dir, 5*time.Minute)
	if res[0].Status != receipt.Error || !strings.Contains(strings.ToLower(res[0].Reason), "no space left") {
		t.Errorf("disk full: %s %q, want ERROR saying the sandbox ran out of space", res[0].Status, res[0].Reason)
	}
}

// buildCLI compiles the xinproof binary for the process-level scenarios.
func buildCLI(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "xinproof")
	cmd := exec.Command("go", "build", "-o", bin, "../../cmd/xinproof")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// startCLI starts `xinproof verify` and waits until it has a sandbox running.
func startCLI(t *testing.T, bin, home, receipts, dir string) (*exec.Cmd, *bytes.Buffer) {
	t.Helper()
	var out bytes.Buffer
	cmd := exec.Command(bin, "verify", "--receipts", receipts, "--pg-image", pgImage, dir)
	cmd.Env = append(os.Environ(), "XINPROOF_HOME="+home, "NO_COLOR=1")
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	label := fmt.Sprintf("%s=%d", sandbox.LabelPID, cmd.Process.Pid)
	deadline := time.Now().Add(2 * time.Minute)
	for len(containers(t, label)) == 0 {
		if time.Now().After(deadline) {
			cmd.Process.Kill()
			t.Fatalf("no sandbox appeared\n%s", out.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	return cmd, &out
}

func verifyAllReceipts(t *testing.T, bin, home, receipts string) int {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(receipts, "receipt-*.json"))
	if len(files) == 0 {
		return 0
	}
	cmd := exec.Command(bin, append([]string{"receipt", "verify"}, files...)...)
	cmd.Env = append(os.Environ(), "XINPROOF_HOME="+home, "NO_COLOR=1")
	out, err := cmd.CombinedOutput()
	if err != nil || strings.Contains(string(out), "BROKEN") {
		t.Errorf("receipts don't verify after the chaos: %v\n%s", err, out)
	}
	return len(files)
}

func TestCLIKilledLeavesNothingBehind(t *testing.T) {
	d := needDocker(t)
	dump := pgDump(t, d)
	bin := buildCLI(t)
	home, receipts := t.TempDir(), filepath.Join(t.TempDir(), "receipts")
	dir := dumpsDir(t, map[string][]byte{"a.dump": dump, "b.dump": dump, "c.dump": dump})

	cmd, out := startCLI(t, bin, home, receipts, dir)
	pid := cmd.Process.Pid
	cmd.Process.Signal(syscall.SIGKILL) // no chance to clean up
	cmd.Wait()
	orphan := fmt.Sprintf("%s=%d", sandbox.LabelPID, pid)
	if len(containers(t, orphan)) == 0 {
		t.Fatalf("expected the killed run to leave its sandbox (otherwise this test proves nothing)\n%s", out)
	}
	before := verifyAllReceipts(t, bin, home, receipts)

	// The next run reaps the orphan straight away (its owner is dead), even
	// though its TTL is hours away, and continues the receipt chain.
	cmd2 := exec.Command(bin, "verify", "--receipts", receipts, "--pg-image", pgImage, dir)
	cmd2.Env = append(os.Environ(), "XINPROOF_HOME="+home, "NO_COLOR=1")
	out2, _ := cmd2.CombinedOutput()
	t.Logf("second run:\n%s", out2)
	if left := containers(t, orphan); len(left) > 0 {
		t.Errorf("orphaned sandbox not reaped by the next run: %v", left)
	}
	after := verifyAllReceipts(t, bin, home, receipts)
	if after != before+3 {
		t.Errorf("receipts before %d, after %d; want 3 more\n%s", before, after, out2)
	}
}

func TestCLIInterruptedReportsEverything(t *testing.T) {
	d := needDocker(t)
	dump := pgDump(t, d)
	bin := buildCLI(t)
	home, receipts := t.TempDir(), filepath.Join(t.TempDir(), "receipts")
	dir := dumpsDir(t, map[string][]byte{"a.dump": dump, "b.dump": dump, "c.dump": dump})

	cmd, out := startCLI(t, bin, home, receipts, dir)
	pid := cmd.Process.Pid
	cmd.Process.Signal(os.Interrupt) // Ctrl-C
	err := cmd.Wait()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	}
	if code != 2 {
		t.Errorf("exit code %d, want 2 (ERROR: not everything was tested)\n%s", code, out)
	}
	if left := containers(t, fmt.Sprintf("%s=%d", sandbox.LabelPID, pid)); len(left) > 0 {
		t.Errorf("interrupted run left sandboxes: %v", left)
	}
	if n := verifyAllReceipts(t, bin, home, receipts); n != 3 {
		t.Errorf("%d receipts, want one per backup (3)\n%s", n, out)
	}
	if !strings.Contains(out.String(), "interrupted") {
		t.Errorf("output doesn't say the run was interrupted:\n%s", out)
	}
}
