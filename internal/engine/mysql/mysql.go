// Package mysql restores mysqldump / mariadb-dump output into a sandboxed
// MySQL or MariaDB container and checks the result.
package mysql

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
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

// Default images when a dump doesn't say which server it came from.
const (
	DefaultMySQL   = "8.4"
	DefaultMariaDB = "11.4"
)

const (
	restoreDB = "xinproof_restore"
	dumpPath  = "/xinproof/dump"
)

type Engine struct {
	Docker    *sandbox.Docker
	RunID     string
	Image     string // override the image chosen from the dump
	Memory    string
	CPUs      string
	TmpfsSize string // if set, keep the uploaded dump on a tmpfs of this size
	TTL       time.Duration
	// CheckBudget limits CHECK TABLE (table and index consistency) per run; 0 disables it.
	CheckBudget time.Duration

	seq       atomic.Int64
	availOnce sync.Once
	availErr  error
}

func (e *Engine) Supports(d discover.Detection) bool { return d.Format == discover.FormatMySQL }

func (e *Engine) Analyzer(d discover.Detection) engine.Analyzer {
	if d.Format == discover.FormatMySQL {
		return NewAnalyzer()
	}
	return nil
}

var reMajorMinor = regexp.MustCompile(`^(\d+)\.(\d+)`)

// ImageFor picks mysql:<major.minor> or mariadb:<major.minor> matching the
// server the dump came from (or, failing that, the dump tool's version).
func (e *Engine) ImageFor(flavor, dumpVersion, serverVersion string) string {
	if e.Image != "" {
		return e.Image
	}
	v := serverVersion
	if v == "" {
		v = dumpVersion
	}
	mm := ""
	if m := reMajorMinor.FindStringSubmatch(v); m != nil {
		mm = m[1] + "." + m[2]
	}
	if flavor == "mariadb" {
		if mm == "" {
			mm = DefaultMariaDB
		}
		return "mariadb:" + mm
	}
	if mm == "" {
		mm = DefaultMySQL
	}
	return "mysql:" + mm
}

func isMariaDB(image string) bool { return strings.Contains(strings.ToLower(image), "mariadb") }

func (e *Engine) Start(ctx context.Context, d discover.Detection) (engine.Session, error) {
	e.availOnce.Do(func() { e.availErr = e.Docker.Available(ctx) })
	if e.availErr != nil {
		return nil, e.availErr
	}
	img := e.ImageFor(d.Flavor, d.DumpVersion, d.ServerVersion)
	digest, err := e.Docker.EnsureImage(ctx, img)
	if err != nil {
		return nil, err
	}
	ref := img
	if _, dg, ok := strings.Cut(digest, "@"); ok {
		ref = img + "@" + dg
	}
	maria := isMariaDB(img)
	pass := randomHex(16)
	spec := sandbox.Spec{
		Name:      fmt.Sprintf("xinproof-%s-m%d", e.RunID, e.seq.Add(1)),
		Image:     img,
		RunID:     e.RunID,
		TTL:       e.TTL,
		Memory:    e.Memory,
		CPUs:      e.CPUs,
		PidsLimit: 1024,
		CapAdd:    []string{"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"},
		Env: []string{
			"MYSQL_ROOT_PASSWORD=" + pass, "MARIADB_ROOT_PASSWORD=" + pass,
			"MYSQL_DATABASE=" + restoreDB, "MARIADB_DATABASE=" + restoreDB,
		},
		// Options that make real-world dumps restorable on a fresh server:
		// functions without DETERMINISTIC (binary logging is on by default),
		// big extended INSERTs, and (MySQL) the GTID_PURGED line mysqldump writes.
		// The sandbox is thrown away, so durability is off: restores run much faster.
		Args: []string{"--log-bin-trust-function-creators=1", "--max-allowed-packet=1G", "--local-infile=0", "--skip-name-resolve",
			"--innodb-flush-log-at-trx-commit=0", "--sync-binlog=0"},
	}
	if !maria {
		spec.Args = append(spec.Args, "--gtid-mode=ON", "--enforce-gtid-consistency=ON")
	}
	if e.TmpfsSize != "" {
		spec.TmpfsPath, spec.TmpfsSize = "/xinproof", e.TmpfsSize
	}
	c, err := e.Docker.Run(ctx, spec)
	s := &session{c: c, image: ref, maria: maria, budget: e.CheckBudget, pass: pass}
	if err != nil {
		s.Close()
		return nil, err
	}
	if err := s.waitReady(ctx, 4*time.Minute); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

type session struct {
	c      *sandbox.Container
	image  string
	maria  bool
	budget time.Duration
	pass   string
	once   sync.Once
}

// exec runs a command in the sandbox with the root password in MYSQL_PWD
// (read by the mysql/mariadb clients). It is set per command, not on the
// container, because the image's own init scripts must not see it.
func (s *session) exec(ctx context.Context, o sandbox.ExecOpts) (sandbox.ExecResult, error) {
	o.Env = append(o.Env, "MYSQL_PWD="+s.pass)
	return s.c.Exec(ctx, o)
}

func (s *session) Image() string { return s.image }

func (s *session) Close() error {
	var err error
	s.once.Do(func() { err = s.c.Remove() })
	return err
}

func (s *session) client() string {
	if s.maria {
		return "mariadb" // MariaDB 11 images no longer ship the mysql* names
	}
	return "mysql"
}

func (s *session) clientArgs() []string {
	return []string{s.client(), "--protocol=tcp", "-h127.0.0.1", "-uroot", "--default-character-set=utf8mb4"}
}

// sql runs a query and returns its rows as tab-separated lines.
func (s *session) sql(ctx context.Context, db, query string) (sandbox.ExecResult, error) {
	args := append(s.clientArgs(), "-N", "-B", "-e", query)
	if db != "" {
		args = append(args, db)
	}
	return s.exec(ctx, sandbox.ExecOpts{Args: args})
}

func (s *session) waitReady(ctx context.Context, max time.Duration) error {
	deadline := time.Now().Add(max)
	for {
		// TCP: the image's init-time server runs with networking off.
		res, err := s.sql(ctx, "", "SELECT 1")
		if err != nil {
			return err
		}
		if res.ExitCode == 0 {
			return nil
		}
		if !s.c.Running(ctx) {
			return fmt.Errorf("sandbox database exited during startup: %s", lastLines(s.c.Logs(ctx, 8), 2))
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("sandbox database not ready after %s: %s", max, lastLines(res.Stderr, 1))
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
		res, err := s.c.Exec(ctx, sandbox.ExecOpts{Args: []string{"sh", "-c", "mkdir -p /xinproof && cat > " + dumpPath}, Stdin: pr})
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
	pr.CloseWithError(errors.New("MySQL dumps are single files"))
	return pw, func() error { return errors.New("MySQL dumps are single files") }
}

var systemSchemas = "'mysql','information_schema','performance_schema','sys'"

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
	an, _ := a.(*Analyzer)

	// The client stops at the first error (no --force), so any failing
	// statement fails the restore, like psql's ON_ERROR_STOP.
	cmd := strings.Join(s.clientArgs(), " ") + " --max-allowed-packet=1G " + restoreDB + " < " + dumpPath
	start := time.Now()
	res, err := s.exec(ctx, sandbox.ExecOpts{Args: []string{"sh", "-c", cmd}})
	dur := time.Since(start)
	out.RestoreSeconds = engine.Seconds(dur)
	if err != nil {
		return execErr(err, "restore")
	}
	if res.DaemonError() {
		return errOut("sandbox failed during restore: " + lastLines(res.Stderr, 1))
	}
	if res.ExitCode != 0 {
		return failOut("l2.restore", fmt.Sprintf("%s failed (exit %d): %s", s.client(), res.ExitCode, firstErrors(res.Stderr)))
	}
	out.Checks = append(out.Checks, receipt.Check{ID: "l2.restore", Status: receipt.CheckPass, Detail: fmt.Sprintf("exit 0 in %.1fs", dur.Seconds())})

	tables, err := s.inspect(ctx)
	if err != nil {
		return execErr(err, "inspecting the restored database")
	}
	out.Tables = len(tables)
	for _, t := range tables {
		out.Rows += t.Rows
	}
	out.RowsKnown = true

	expected := -1
	var dumpRows map[string]int64
	if an != nil {
		expected, dumpRows = an.Tables, an.Rows
	}
	switch {
	case expected < 0:
		out.Checks = append(out.Checks, receipt.Check{ID: "l2.objects", Status: receipt.CheckInfo, Detail: fmt.Sprintf("%d tables", out.Tables)})
	case out.Tables < expected:
		return failOut("l2.objects", fmt.Sprintf("only %d of %d tables restored · %d tables lost", out.Tables, expected, expected-out.Tables))
	case out.Tables == expected:
		out.Checks = append(out.Checks, receipt.Check{ID: "l2.objects", Status: receipt.CheckPass, Detail: fmt.Sprintf("%d/%d tables", out.Tables, expected)})
	default:
		out.Checks = append(out.Checks, receipt.Check{ID: "l2.objects", Status: receipt.CheckPass, Detail: fmt.Sprintf("%d tables (%d in dump)", out.Tables, expected)})
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
		Detail: fmt.Sprintf("%d rows (exact count); all %d tables with data match the dump", out.Rows, withData)})

	if h, err := s.schemaHash(ctx); err != nil {
		out.Checks = append(out.Checks, receipt.Check{ID: "l2.schema_hash", Status: receipt.CheckError, Detail: "could not compute: " + err.Error()})
	} else {
		out.Checks = append(out.Checks, receipt.Check{ID: "l2.schema_hash", Status: receipt.CheckPass, Detail: "sha256:" + h})
	}

	if s.budget <= 0 {
		out.Checks = append(out.Checks, receipt.Check{ID: "l2.check_table", Status: receipt.CheckSkip, Detail: "disabled"})
	} else {
		checked, skipped, bad, err := s.checkTables(ctx, tables)
		switch {
		case err != nil:
			out.Checks = append(out.Checks, receipt.Check{ID: "l2.check_table", Status: receipt.CheckError, Detail: "could not run: " + err.Error()})
		case bad != "":
			return failOut("l2.check_table", "CHECK TABLE found problems: "+clip(bad, 300))
		default:
			d := fmt.Sprintf("%d tables passed CHECK TABLE", checked)
			if skipped > 0 {
				d += fmt.Sprintf("; %d skipped over the %s budget", skipped, s.budget)
			}
			out.Checks = append(out.Checks, receipt.Check{ID: "l2.check_table", Status: receipt.CheckPass, Detail: d})
		}
	}
	out.Result = receipt.Pass
	return out
}

func quoteIdent(s string) string { return "`" + strings.ReplaceAll(s, "`", "``") + "`" }

func schemaOf(db string) string {
	if db == "" {
		return restoreDB
	}
	return db
}

// inspect lists base tables with exact row counts in every user database.
func (s *session) inspect(ctx context.Context) ([]engine.TableCount, error) {
	res, err := s.sql(ctx, "", "SELECT table_schema, table_name FROM information_schema.tables WHERE table_type = 'BASE TABLE' AND table_schema NOT IN ("+systemSchemas+") ORDER BY 1, 2")
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, errors.New(firstErrors(res.Stderr))
	}
	var tables []engine.TableCount
	for _, line := range strings.Split(strings.TrimRight(string(res.Stdout), "\n"), "\n") {
		if line == "" {
			continue
		}
		db, name, ok := strings.Cut(line, "\t")
		if !ok {
			return nil, fmt.Errorf("unexpected output %q", line)
		}
		if db == restoreDB {
			db = ""
		}
		tables = append(tables, engine.TableCount{DB: db, Qualified: unescapeBatch(name)})
	}
	const batch = 100
	for i := 0; i < len(tables); i += batch {
		var parts []string
		for j := i; j < min(i+batch, len(tables)); j++ {
			t := tables[j]
			parts = append(parts, fmt.Sprintf("SELECT %d, COUNT(*) FROM %s.%s", j, quoteIdent(schemaOf(t.DB)), quoteIdent(t.Qualified)))
		}
		r, err := s.sql(ctx, "", strings.Join(parts, " UNION ALL "))
		if err != nil {
			return nil, err
		}
		if r.ExitCode != 0 {
			return nil, errors.New(firstErrors(r.Stderr))
		}
		for _, line := range strings.Split(strings.TrimRight(string(r.Stdout), "\n"), "\n") {
			a, b, ok := strings.Cut(line, "\t")
			idx, err1 := strconv.Atoi(a)
			n, err2 := strconv.ParseInt(b, 10, 64)
			if !ok || err1 != nil || err2 != nil || idx < 0 || idx >= len(tables) {
				return nil, fmt.Errorf("unexpected count output %q", line)
			}
			tables[idx].Rows = n
		}
	}
	return tables, nil
}

// schemaHash fingerprints columns, indexes and constraints of every user
// database, with the restore database's name normalized away.
func (s *session) schemaHash(ctx context.Context) (string, error) {
	q := `SELECT CONCAT_WS(' ', 'col', table_schema, table_name, ordinal_position, column_name, column_type, is_nullable, IFNULL(column_default, '<null>'), extra)
	        FROM information_schema.columns WHERE table_schema NOT IN (` + systemSchemas + `)
	      UNION ALL
	      SELECT CONCAT_WS(' ', 'idx', table_schema, table_name, index_name, non_unique, seq_in_index, IFNULL(column_name, ''), IFNULL(sub_part, ''), index_type)
	        FROM information_schema.statistics WHERE table_schema NOT IN (` + systemSchemas + `)
	      UNION ALL
	      SELECT CONCAT_WS(' ', 'con', constraint_schema, table_name, constraint_name, constraint_type)
	        FROM information_schema.table_constraints WHERE constraint_schema NOT IN (` + systemSchemas + `)`
	r, err := s.sql(ctx, "", q)
	if err != nil {
		return "", err
	}
	if r.ExitCode != 0 {
		return "", errors.New(firstErrors(r.Stderr))
	}
	var lines []string
	for _, l := range strings.Split(strings.TrimRight(string(r.Stdout), "\n"), "\n") {
		if l == "" {
			continue
		}
		f := strings.SplitN(l, " ", 3)
		if len(f) == 3 && f[1] == restoreDB {
			f[1] = ""
		}
		lines = append(lines, strings.Join(f, " "))
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:]), nil
}

// checkTables runs CHECK TABLE (data and index consistency) on every table,
// in batches, until the budget runs out.
func (s *session) checkTables(ctx context.Context, tables []engine.TableCount) (checked, skipped int, bad string, err error) {
	start := time.Now()
	var bads []string
	const batch = 20
	for i := 0; i < len(tables); i += batch {
		if time.Since(start) > s.budget {
			skipped += len(tables) - i
			break
		}
		var names []string
		for _, t := range tables[i:min(i+batch, len(tables))] {
			names = append(names, quoteIdent(schemaOf(t.DB))+"."+quoteIdent(t.Qualified))
		}
		r, err := s.sql(ctx, "", "CHECK TABLE "+strings.Join(names, ", "))
		if err != nil {
			return 0, 0, "", err
		}
		if r.ExitCode != 0 {
			return 0, 0, "", errors.New(firstErrors(r.Stderr))
		}
		for _, line := range strings.Split(strings.TrimRight(string(r.Stdout), "\n"), "\n") {
			f := strings.Split(line, "\t") // Table, Op, Msg_type, Msg_text
			if len(f) < 4 {
				continue
			}
			typ, text := strings.ToLower(f[2]), f[3]
			if typ == "error" || (typ == "status" && !strings.EqualFold(text, "OK")) {
				bads = append(bads, strings.TrimPrefix(f[0], restoreDB+".")+": "+text)
			}
		}
		checked += len(names)
	}
	return checked, skipped, strings.Join(bads, " | "), nil
}

// unescapeBatch undoes the mysql client's batch-mode escaping (\t, \n, \\).
func unescapeBatch(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	r := strings.NewReplacer(`\t`, "\t", `\n`, "\n", `\0`, "\x00", `\\`, `\`)
	return r.Replace(s)
}

func firstErrors(stderr string) string {
	var picked []string
	for _, l := range strings.Split(stderr, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.Contains(l, "Using a password on the command line") {
			continue
		}
		if strings.HasPrefix(l, "ERROR") || strings.Contains(strings.ToLower(l), "error") {
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
