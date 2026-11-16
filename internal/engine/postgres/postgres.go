// Package postgres restores PostgreSQL dumps (custom format and plain SQL)
// into a sandboxed postgres container and checks the result.
package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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

// DefaultMajor is used when a dump doesn't say which pg_dump produced it.
const DefaultMajor = "17"

const (
	superuser = "xinproof"
	restoreDB = "xinproof_restore"
	dumpPath  = "/xinproof/dump"
)

type Engine struct {
	Docker    *sandbox.Docker
	RunID     string
	Image     string        // override the image chosen from the dump version
	Memory    string        // container memory limit, e.g. "2g"
	CPUs      string        // e.g. "2"
	TmpfsSize string        // if set, keep the dump and data directory on a tmpfs of this size
	TTL       time.Duration // reaper deadline for containers

	seq       atomic.Int64
	availOnce sync.Once
	availErr  error
}

func (e *Engine) Supports(d discover.Detection) bool {
	return d.Format == discover.FormatPGCustom || d.Format == discover.FormatPGPlain
}

func (e *Engine) Analyzer(d discover.Detection) engine.Analyzer {
	if d.Format == discover.FormatPGPlain {
		return NewPlainAnalyzer()
	}
	return nil
}

// ImageFor picks postgres:<major> matching the pg_dump that wrote the dump.
// pg_restore/psql must be at least as new as pg_dump, and plain dumps can use
// syntax only that major understands.
func (e *Engine) ImageFor(d discover.Detection) string {
	if e.Image != "" {
		return e.Image
	}
	v := d.DumpVersion
	if v == "" {
		v = d.ServerVersion
	}
	m := MajorOf(v)
	if m == "" {
		m = DefaultMajor
	}
	return "postgres:" + m
}

// MajorOf returns "16" for "16.4", "9.6" for "9.6.24", "" if unparseable.
func MajorOf(v string) string {
	parts := strings.Split(strings.TrimSpace(v), ".")
	n, err := strconv.Atoi(parts[0])
	if err != nil || n <= 0 {
		return ""
	}
	if n < 10 && len(parts) > 1 {
		return parts[0] + "." + parts[1]
	}
	return parts[0]
}

func (e *Engine) Start(ctx context.Context, d discover.Detection) (engine.Session, error) {
	e.availOnce.Do(func() { e.availErr = e.Docker.Available(ctx) })
	if e.availErr != nil {
		return nil, e.availErr
	}
	img := e.ImageFor(d)
	digest, err := e.Docker.EnsureImage(ctx, img)
	if err != nil {
		return nil, err
	}
	ref := img
	if _, dg, ok := strings.Cut(digest, "@"); ok {
		ref = img + "@" + dg
	}
	pass := randomHex(16)
	env := []string{
		"POSTGRES_USER=" + superuser,
		"POSTGRES_PASSWORD=" + pass,
		"PGPASSWORD=" + pass,
		"POSTGRES_DB=" + restoreDB,
	}
	spec := sandbox.Spec{
		Name:      fmt.Sprintf("xinproof-%s-%d", e.RunID, e.seq.Add(1)),
		Image:     img,
		RunID:     e.RunID,
		TTL:       e.TTL,
		Memory:    e.Memory,
		CPUs:      e.CPUs,
		PidsLimit: 512,
		// Enough for the image entrypoint to initdb and drop to the postgres user.
		CapAdd: []string{"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"},
	}
	if e.TmpfsSize != "" {
		spec.TmpfsPath, spec.TmpfsSize = "/xinproof", e.TmpfsSize
		env = append(env, "PGDATA=/xinproof/pgdata")
	}
	spec.Env = env
	c, err := e.Docker.Run(ctx, spec)
	s := &session{c: c, image: ref, det: d}
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

type session struct {
	c     *sandbox.Container
	image string
	det   discover.Detection
	once  sync.Once
}

func (s *session) Image() string { return s.image }

func (s *session) Close() error {
	var err error
	s.once.Do(func() { err = s.c.Remove() })
	return err
}

func (s *session) waitReady(ctx context.Context, max time.Duration) error {
	deadline := time.Now().Add(max)
	for {
		// TCP, not the socket: the image's init-time server listens only on the
		// socket, so TCP readiness means the final server is up.
		res, err := s.c.Exec(ctx, sandbox.ExecOpts{Args: []string{"pg_isready", "-q", "-h", "127.0.0.1", "-U", superuser, "-d", restoreDB}})
		if err != nil {
			return err
		}
		if res.ExitCode == 0 {
			return nil
		}
		if !s.c.Running(ctx) {
			return fmt.Errorf("sandbox postgres exited during startup: %s", lastLines(s.c.Logs(ctx, 5), 2))
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("sandbox postgres not ready after %s", max)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (s *session) Upload(ctx context.Context) (io.WriteCloser, func() error) {
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		res, err := s.c.Exec(ctx, sandbox.ExecOpts{
			Args:  []string{"sh", "-c", "mkdir -p /xinproof && cat > " + dumpPath},
			Stdin: pr,
		})
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

func (s *session) exec(ctx context.Context, args ...string) (sandbox.ExecResult, error) {
	return s.c.Exec(ctx, sandbox.ExecOpts{Args: args})
}

func (s *session) psql(ctx context.Context, db, sql string) (sandbox.ExecResult, error) {
	return s.exec(ctx, "psql", "-X", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1", "-F", "\t",
		"-h", "127.0.0.1", "-U", superuser, "-d", db, "-c", sql)
}

func (s *session) Restore(ctx context.Context, a engine.Analyzer) engine.Outcome {
	var out engine.Outcome
	expected := -1

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

	var restoreArgs []string
	switch s.det.Format {
	case discover.FormatPGCustom:
		res, err := s.exec(ctx, "pg_restore", "-l", dumpPath)
		if err != nil {
			return execErr(err, "reading the archive TOC")
		}
		if res.DaemonError() {
			return errOut("sandbox failed: " + lastLines(res.Stderr, 1))
		}
		if res.ExitCode != 0 {
			return failOut("l2.toc", "archive TOC unreadable: "+firstErrors(res.Stderr))
		}
		tables, entries := CountTOC(string(res.Stdout))
		expected = tables
		out.Checks = append(out.Checks, receipt.Check{ID: "l2.toc", Status: receipt.CheckPass,
			Detail: fmt.Sprintf("%d TOC entries, %d tables", entries, tables)})
		restoreArgs = []string{"pg_restore", "--exit-on-error", "--no-owner", "--no-acl",
			"-h", "127.0.0.1", "-U", superuser, "-d", restoreDB, dumpPath}

	case discover.FormatPGPlain:
		pa, _ := a.(*PlainAnalyzer)
		if pa != nil {
			expected = pa.Tables
			if roles := pa.PlaceholderRoles(superuser); len(roles) > 0 {
				var sql strings.Builder
				for _, r := range roles {
					fmt.Fprintf(&sql, "CREATE ROLE %s NOLOGIN;", quoteIdent(r))
				}
				res, err := s.psql(ctx, restoreDB, sql.String())
				if err != nil {
					return execErr(err, "creating placeholder roles")
				}
				if res.ExitCode != 0 {
					return errOut("creating placeholder roles failed: " + firstErrors(res.Stderr))
				}
				out.Checks = append(out.Checks, receipt.Check{ID: "l2.roles", Status: receipt.CheckInfo,
					Detail: fmt.Sprintf("created %d placeholder role(s) the dump references", len(roles))})
			}
		}
		restoreArgs = []string{"psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-o", "/dev/null",
			"-h", "127.0.0.1", "-U", superuser, "-d", restoreDB, "-f", dumpPath}

	default:
		return errOut("unsupported format " + string(s.det.Format))
	}

	start := time.Now()
	res, err := s.exec(ctx, restoreArgs...)
	dur := time.Since(start)
	out.RestoreSeconds = engine.Seconds(dur)
	if err != nil {
		return execErr(err, "restore")
	}
	if res.DaemonError() {
		return errOut("sandbox failed during restore: " + lastLines(res.Stderr, 1))
	}
	if res.ExitCode != 0 {
		return failOut("l2.restore", fmt.Sprintf("%s failed (exit %d): %s", restoreArgs[0], res.ExitCode, firstErrors(res.Stderr)))
	}
	out.Checks = append(out.Checks, receipt.Check{ID: "l2.restore", Status: receipt.CheckPass,
		Detail: fmt.Sprintf("exit 0 in %.1fs", dur.Seconds())})

	tables, rows, err := s.inspect(ctx)
	if err != nil {
		return execErr(err, "inspecting the restored database")
	}
	out.Tables, out.Rows, out.RowsKnown = tables, rows, true

	switch {
	case expected < 0:
		out.Checks = append(out.Checks, receipt.Check{ID: "l2.objects", Status: receipt.CheckInfo, Detail: fmt.Sprintf("%d tables", tables)})
	case tables < expected:
		return failOut("l2.objects", fmt.Sprintf("only %d of %d tables restored · %d tables lost", tables, expected, expected-tables))
	case tables == expected:
		out.Checks = append(out.Checks, receipt.Check{ID: "l2.objects", Status: receipt.CheckPass, Detail: fmt.Sprintf("%d/%d tables", tables, expected)})
	default:
		out.Checks = append(out.Checks, receipt.Check{ID: "l2.objects", Status: receipt.CheckPass, Detail: fmt.Sprintf("%d tables (%d in dump)", tables, expected)})
	}
	out.Checks = append(out.Checks, receipt.Check{ID: "l2.rows", Status: receipt.CheckPass, Detail: fmt.Sprintf("%d rows (exact count)", rows)})
	out.Result = receipt.Pass
	return out
}

const inspectSQL = `SELECT count(*),
  coalesce(sum(CASE WHEN c.relkind = 'r' THEN
    (xpath('/row/c/text()', query_to_xml(format('SELECT count(*) AS c FROM %I.%I', n.nspname, c.relname), false, true, '')))[1]::text::bigint
  END), 0)
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND n.nspname NOT LIKE 'pg\_toast%'
  AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')`

// inspect counts user tables and exact rows across every database in the
// sandbox (plain dumps made with -C or pg_dumpall create their own databases).
func (s *session) inspect(ctx context.Context) (tables int, rows int64, err error) {
	res, err := s.psql(ctx, restoreDB, "SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate ORDER BY 1")
	if err != nil {
		return 0, 0, err
	}
	if res.ExitCode != 0 {
		return 0, 0, errors.New(firstErrors(res.Stderr))
	}
	for _, db := range strings.Split(strings.TrimSpace(string(res.Stdout)), "\n") {
		if db = strings.TrimSpace(db); db == "" {
			continue
		}
		r, err := s.psql(ctx, db, inspectSQL)
		if err != nil {
			return 0, 0, err
		}
		if r.ExitCode != 0 {
			return 0, 0, fmt.Errorf("database %s: %s", db, firstErrors(r.Stderr))
		}
		t, n, ok := strings.Cut(strings.TrimSpace(string(r.Stdout)), "\t")
		if !ok {
			return 0, 0, fmt.Errorf("unexpected inspection output %q", r.Stdout)
		}
		ti, err1 := strconv.Atoi(t)
		ni, err2 := strconv.ParseInt(n, 10, 64)
		if err1 != nil || err2 != nil {
			return 0, 0, fmt.Errorf("unexpected inspection output %q", r.Stdout)
		}
		tables += ti
		rows += ni
	}
	return tables, rows, nil
}

// CountTOC counts table definitions and total entries in `pg_restore -l` output.
func CountTOC(toc string) (tables, entries int) {
	for _, line := range strings.Split(toc, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == ';' {
			continue
		}
		entries++
		f := strings.Fields(line)
		// "215; 1259 16385 TABLE public accounts owner"
		if len(f) >= 5 && f[3] == "TABLE" && f[4] != "DATA" && f[4] != "ATTACH" {
			tables++
		}
	}
	return tables, entries
}

// firstErrors extracts the most useful lines from tool stderr.
func firstErrors(stderr string) string {
	var picked []string
	for _, l := range strings.Split(stderr, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		low := strings.ToLower(l)
		if strings.Contains(low, "error") || strings.Contains(low, "fatal") {
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

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
