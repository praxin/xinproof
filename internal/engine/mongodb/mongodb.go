// Package mongodb restores mongodump --archive output (optionally gzip) into
// a sandboxed mongo container and checks the result.
package mongodb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/praxin/xinproof/internal/discover"
	"github.com/praxin/xinproof/internal/engine"
	"github.com/praxin/xinproof/internal/receipt"
	"github.com/praxin/xinproof/internal/sandbox"
)

// DefaultImage is the sandbox image unless overridden.
const DefaultImage = "mongo:7"

const (
	dbDir    = "/xinproof"
	dumpPath = "/xinproof/dump"
)

type Engine struct {
	Docker    *sandbox.Docker
	RunID     string
	Image     string // override DefaultImage
	Memory    string
	CPUs      string
	TmpfsSize string // if set, keep the dump and the database files on a tmpfs of this size
	TTL       time.Duration
	Hooks     engine.Hooks // fault injection for tests

	seq       atomic.Int64
	availOnce sync.Once
	availErr  error
}

func (e *Engine) Supports(d discover.Detection) bool { return d.Format == discover.FormatMongoArchive }

func (e *Engine) Analyzer(d discover.Detection) engine.Analyzer {
	if d.Format == discover.FormatMongoArchive {
		return NewArchiveAnalyzer()
	}
	return nil
}

func (e *Engine) image() string {
	if e.Image != "" {
		return e.Image
	}
	return DefaultImage
}

func (e *Engine) Start(ctx context.Context, d discover.Detection) (engine.Session, error) {
	e.availOnce.Do(func() { e.availErr = e.Docker.Available(ctx) })
	if e.availErr != nil {
		return nil, e.availErr
	}
	img := e.image()
	digest, err := e.Docker.EnsureImage(ctx, img)
	if err != nil {
		return nil, err
	}
	ref := img
	if _, dg, ok := strings.Cut(digest, "@"); ok {
		ref = img + "@" + dg
	}
	spec := sandbox.Spec{
		Name:      fmt.Sprintf("xinproof-%s-g%d", e.RunID, e.seq.Add(1)),
		Image:     img,
		RunID:     e.RunID,
		TTL:       e.TTL,
		Memory:    e.Memory,
		CPUs:      e.CPUs,
		PidsLimit: 1024,
		// Enough for the image entrypoint to chown the data directory and drop to the mongodb user.
		CapAdd: []string{"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"},
		Args:   []string{"--bind_ip", "127.0.0.1"},
	}
	if e.TmpfsSize != "" {
		spec.TmpfsPath, spec.TmpfsSize = dbDir, e.TmpfsSize
		spec.Args = append(spec.Args, "--dbpath", dbDir)
	}
	c, err := e.Docker.Run(ctx, spec)
	s := &session{c: c, image: ref, hooks: e.Hooks, workers: workers(e.CPUs)}
	if err != nil {
		s.Close()
		return nil, err
	}
	if err := s.waitReady(ctx, 3*time.Minute); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// workers is mongorestore's collection parallelism: the sandbox's CPU limit, 1–8.
func workers(cpus string) int {
	f, err := strconv.ParseFloat(strings.TrimSpace(cpus), 64)
	if err != nil || f < 1 {
		return 1
	}
	return min(int(f), 8)
}

type session struct {
	c       *sandbox.Container
	image   string
	hooks   engine.Hooks
	workers int
	once    sync.Once
}

func (s *session) Image() string { return s.image }

func (s *session) Close() error {
	var err error
	s.once.Do(func() { err = s.c.Remove() })
	return err
}

func (s *session) exec(ctx context.Context, args ...string) (sandbox.ExecResult, error) {
	return s.c.Exec(ctx, sandbox.ExecOpts{Args: args})
}

func (s *session) mongosh(ctx context.Context, js string) (sandbox.ExecResult, error) {
	return s.exec(ctx, "mongosh", "--quiet", "--norc", "mongodb://127.0.0.1:27017/admin", "--eval", js)
}

func (s *session) waitReady(ctx context.Context, max time.Duration) error {
	deadline := time.Now().Add(max)
	for {
		res, err := s.mongosh(ctx, "print('xinproof-ready:' + db.runCommand({ping: 1}).ok)")
		if err != nil {
			return err
		}
		if res.ExitCode == 0 && strings.Contains(string(res.Stdout), "xinproof-ready:1") {
			return nil
		}
		if !s.c.Running(ctx) {
			return fmt.Errorf("sandbox mongod exited during startup: %s", lastLines(s.c.Logs(ctx, 5), 2))
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("sandbox mongod not ready after %s", max)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func (s *session) Upload(ctx context.Context) (io.WriteCloser, func() error) {
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		res, err := s.c.Exec(ctx, sandbox.ExecOpts{Args: []string{"sh", "-c", "mkdir -p " + dbDir + " && cat > " + dumpPath}, Stdin: pr})
		if err == nil && res.ExitCode != 0 {
			err = fmt.Errorf("storing the dump in the sandbox failed: %s", lastLines(res.Stderr, 2))
		}
		if err != nil {
			pr.CloseWithError(err)
		} else {
			pr.CloseWithError(errors.New("sandbox upload already finished"))
		}
		done <- err
	}()
	return pw, func() error { return <-done }
}

func (s *session) UploadDir(ctx context.Context) (io.WriteCloser, func() error) {
	pr, pw := io.Pipe()
	pr.CloseWithError(errors.New("mongodump archives are single files"))
	return pw, func() error { return errors.New("mongodump archives are single files") }
}

var reRestored = regexp.MustCompile(`(\d+) document\(s\) restored successfully\. (\d+) document\(s\) failed to restore`)

func (s *session) Restore(ctx context.Context, a engine.Analyzer) engine.Outcome {
	var out engine.Outcome
	errOut := func(reason string) engine.Outcome {
		out.Result, out.Reason = receipt.Error, reason
		return out
	}
	failOut := func(id, reason string) engine.Outcome {
		out.Checks = append(out.Checks, receipt.Check{ID: id, Status: receipt.CheckFail, Detail: reason})
		out.Result, out.Reason = receipt.Fail, reason
		return out
	}
	execErr := func(err error, what string) engine.Outcome {
		if errors.Is(err, context.DeadlineExceeded) {
			return errOut(what + " exceeded the time budget")
		}
		return errOut(what + ": " + err.Error())
	}
	an, _ := a.(*ArchiveAnalyzer)

	if s.hooks.BeforeRestore != nil {
		s.hooks.BeforeRestore(s.c.Name)
	}
	start := time.Now()
	res, err := s.exec(ctx, "mongorestore", "--uri=mongodb://127.0.0.1:27017", "--archive="+dumpPath,
		"--stopOnError", "--numParallelCollections="+strconv.Itoa(s.workers))
	dur := time.Since(start)
	out.RestoreSeconds = engine.Seconds(dur)
	if err != nil {
		return execErr(err, "restore")
	}
	if res.DaemonError() {
		return errOut("sandbox failed during restore: " + lastLines(res.Stderr, 1))
	}
	// mongorestore reports some failures (a CRC mismatch, for one) with exit
	// status 0, so its "Failed:" lines count too.
	failed := failedLines(res.Stderr)
	m := reRestored.FindStringSubmatch(res.Stderr)
	if res.ExitCode != 0 || failed != "" || (m != nil && m[2] != "0") {
		if why := s.c.Died(); why != "" {
			return errOut(why + " · " + firstErrors(res.Stderr))
		}
		if why := engine.SandboxFault(res.Stderr); why != "" {
			return errOut(why + " · " + firstErrors(res.Stderr))
		}
		return failOut("l2.restore", fmt.Sprintf("mongorestore failed (exit %d): %s", res.ExitCode, firstErrors(res.Stderr)))
	}
	detail := fmt.Sprintf("exit 0 in %.1fs", dur.Seconds())
	if m != nil {
		detail += fmt.Sprintf(", %s documents restored", m[1])
	}
	out.Checks = append(out.Checks, receipt.Check{ID: "l2.restore", Status: receipt.CheckPass, Detail: detail})

	tables, err := s.inspect(ctx)
	if err != nil {
		return execErr(err, "inspecting the restored database")
	}
	out.Tables = len(tables)
	out.TableCounts = tables
	for _, t := range tables {
		out.Rows += t.Rows
	}
	out.RowsKnown = true

	expected := -1
	var dumpRows map[string]int64
	if an != nil {
		expected, dumpRows = an.Collections, an.Rows
	}
	switch {
	case expected < 0:
		out.Checks = append(out.Checks, receipt.Check{ID: "l2.objects", Status: receipt.CheckInfo, Detail: fmt.Sprintf("%d collections", out.Tables)})
	case out.Tables < expected:
		return failOut("l2.objects", fmt.Sprintf("only %d of %d collections restored · %d collections lost", out.Tables, expected, expected-out.Tables))
	case out.Tables == expected:
		out.Checks = append(out.Checks, receipt.Check{ID: "l2.objects", Status: receipt.CheckPass, Detail: fmt.Sprintf("%d/%d collections", out.Tables, expected)})
	default:
		out.Checks = append(out.Checks, receipt.Check{ID: "l2.objects", Status: receipt.CheckPass, Detail: fmt.Sprintf("%d collections (%d in dump)", out.Tables, expected)})
	}

	if problems := engine.AuditRows(dumpRows, tables); len(problems) > 0 {
		return failOut("l2.rows", "restored data doesn't match the dump: "+engine.SummarizeProblems(problems))
	}
	withData := 0
	for _, n := range dumpRows {
		if n > 0 {
			withData++
		}
	}
	out.Checks = append(out.Checks, receipt.Check{ID: "l2.rows", Status: receipt.CheckPass,
		Detail: fmt.Sprintf("%d documents (exact count); all %d collections with data match the dump", out.Rows, withData)})
	out.Result = receipt.Pass
	return out
}

// inspectJS lists user collections (not views, time series or system
// collections) in user databases with exact document counts.
const inspectJS = `const out = [];
for (const name of db.getMongo().getDBNames()) {
  if (["admin", "config", "local"].includes(name)) continue;
  const d = db.getSiblingDB(name);
  for (const c of d.getCollectionInfos({type: "collection"}, {nameOnly: true})) {
    if (c.name.startsWith("system.")) continue;
    out.push([name + "." + c.name, d.getCollection(c.name).countDocuments({})]);
  }
}
print("xinproof-counts:" + JSON.stringify(out));`

func (s *session) inspect(ctx context.Context) ([]engine.TableCount, error) {
	res, err := s.mongosh(ctx, inspectJS)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		if why := s.c.Died(); why != "" {
			return nil, errors.New(why)
		}
		return nil, errors.New(firstErrors(res.Stderr + "\n" + string(res.Stdout)))
	}
	return parseCounts(string(res.Stdout))
}

func parseCounts(stdout string) ([]engine.TableCount, error) {
	const marker = "xinproof-counts:"
	i := strings.LastIndex(stdout, marker)
	if i < 0 {
		return nil, fmt.Errorf("unexpected mongosh output %q", clip(stdout, 200))
	}
	line, _, _ := strings.Cut(stdout[i+len(marker):], "\n")
	dec := json.NewDecoder(strings.NewReader(line))
	dec.UseNumber()
	var raw [][]any
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("unexpected mongosh output %q: %v", clip(line, 200), err)
	}
	var tables []engine.TableCount
	for _, r := range raw {
		if len(r) != 2 {
			return nil, fmt.Errorf("unexpected mongosh output %q", clip(line, 200))
		}
		ns, ok1 := r[0].(string)
		num, ok2 := r[1].(json.Number)
		n, err := num.Int64()
		if !ok1 || !ok2 || err != nil {
			return nil, fmt.Errorf("unexpected mongosh output %q", clip(line, 200))
		}
		tables = append(tables, engine.TableCount{Qualified: ns, Rows: n})
	}
	return tables, nil
}

// failedLines returns mongorestore's "Failed: …" lines.
func failedLines(stderr string) string {
	var picked []string
	for _, l := range strings.Split(stderr, "\n") {
		if _, after, ok := strings.Cut(l, "\tFailed: "); ok {
			picked = append(picked, "Failed: "+strings.TrimSpace(after))
		}
	}
	return strings.Join(picked, " · ")
}

// firstErrors extracts the most useful lines from mongorestore/mongosh stderr.
func firstErrors(stderr string) string {
	if f := failedLines(stderr); f != "" {
		return clip(f, 300)
	}
	var picked []string
	for _, l := range strings.Split(stderr, "\n") {
		l = strings.TrimSpace(l)
		low := strings.ToLower(l)
		if l != "" && (strings.Contains(low, "error") || strings.Contains(low, "fail")) {
			picked = append(picked, l)
		}
		if len(picked) == 2 {
			break
		}
	}
	if len(picked) == 0 {
		return lastLines(stderr, 2)
	}
	return clip(strings.Join(picked, " · "), 300)
}

func lastLines(s string, n int) string {
	var ls []string
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			ls = append(ls, l)
		}
	}
	if len(ls) > n {
		ls = ls[len(ls)-n:]
	}
	if len(ls) == 0 {
		return "(no output)"
	}
	return clip(strings.Join(ls, " · "), 300)
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
