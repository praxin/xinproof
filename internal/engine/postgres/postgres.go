// Package postgres restores PostgreSQL dumps (custom, tar, directory and plain SQL)
// into a sandboxed postgres container and checks the result.
package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
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
	// AmcheckBudget limits B-tree index verification (amcheck) per database;
	// 0 disables it. Indexes are checked largest first.
	AmcheckBudget time.Duration
	Hooks         engine.Hooks // fault injection for tests

	seq       atomic.Int64
	availOnce sync.Once
	availErr  error
}

func (e *Engine) Supports(d discover.Detection) bool {
	switch d.Format {
	case discover.FormatPGCustom, discover.FormatPGPlain, discover.FormatPGTar, discover.FormatPGDir:
		return true
	}
	return false
}

func (e *Engine) Analyzer(d discover.Detection) engine.Analyzer {
	switch d.Format {
	case discover.FormatPGPlain:
		return NewPlainAnalyzer()
	case discover.FormatPGTar:
		return NewTarAnalyzer()
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
		// The sandbox is thrown away, so durability is off: restores run much faster.
		Args: []string{"-c", "fsync=off", "-c", "synchronous_commit=off", "-c", "full_page_writes=off"},
	}
	if e.TmpfsSize != "" {
		spec.TmpfsPath, spec.TmpfsSize = "/xinproof", e.TmpfsSize
		env = append(env, "PGDATA=/xinproof/pgdata")
	}
	spec.Env = env
	c, err := e.Docker.Run(ctx, spec)
	s := &session{c: c, image: ref, det: d, amcheck: e.AmcheckBudget, hooks: e.Hooks, jobs: restoreJobs(e.CPUs)}
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
	c       *sandbox.Container
	image   string
	det     discover.Detection
	amcheck time.Duration
	hooks   engine.Hooks
	jobs    int // pg_restore -j for formats that support parallel restore
	once    sync.Once
}

// restoreJobs is the parallelism for pg_restore: the sandbox's CPU limit, 1–8.
func restoreJobs(cpus string) int {
	f, err := strconv.ParseFloat(strings.TrimSpace(cpus), 64)
	if err != nil || f < 1 {
		return 1
	}
	return min(int(f), 8)
}

// sandboxBroke reports, as an ERROR reason, whether a failed command failed
// because the sandbox broke (container died, out of memory or disk, server
// crashed) rather than because of the backup.
func (s *session) sandboxBroke(res sandbox.ExecResult) string {
	if why := s.c.Died(); why != "" {
		return why
	}
	if res.DaemonError() {
		return "sandbox failed: " + lastLines(res.Stderr, 1)
	}
	return engine.SandboxFault(res.Stderr)
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
	return s.upload(ctx, "mkdir -p /xinproof && cat > "+dumpPath)
}

func (s *session) UploadDir(ctx context.Context) (io.WriteCloser, func() error) {
	return s.upload(ctx, "mkdir -p "+dumpPath+" && tar -x -f - -C "+dumpPath)
}

func (s *session) upload(ctx context.Context, script string) (io.WriteCloser, func() error) {
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		res, err := s.c.Exec(ctx, sandbox.ExecOpts{
			Args:  []string{"sh", "-c", script},
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
	expectedTables := -1
	var dumpRows map[string]int64 // rows per table in the dump; nil until known

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
	var required []string // extensions the dump creates
	switch s.det.Format {
	case discover.FormatPGCustom, discover.FormatPGTar, discover.FormatPGDir:
		res, err := s.exec(ctx, "pg_restore", "-l", dumpPath)
		if err != nil {
			return execErr(err, "reading the archive TOC")
		}
		if res.DaemonError() {
			return errOut("sandbox failed: " + lastLines(res.Stderr, 1))
		}
		if res.ExitCode != 0 {
			if why := s.sandboxBroke(res); why != "" {
				return errOut(why)
			}
			return failOut("l2.toc", "archive TOC unreadable: "+firstErrors(res.Stderr))
		}
		tables, entries := CountTOC(string(res.Stdout))
		expectedTables = tables
		out.Checks = append(out.Checks, receipt.Check{ID: "l2.toc", Status: receipt.CheckPass,
			Detail: fmt.Sprintf("%d TOC entries, %d tables", entries, tables)})
		required = TOCExtensions(string(res.Stdout))
		restoreArgs = []string{"pg_restore", "--exit-on-error", "--no-owner", "--no-acl",
			"-h", "127.0.0.1", "-U", superuser, "-d", restoreDB}
		if s.jobs > 1 && s.det.Format != discover.FormatPGTar { // tar archives can't be restored in parallel
			restoreArgs = append(restoreArgs, "-j", strconv.Itoa(s.jobs))
		}
		restoreArgs = append(restoreArgs, dumpPath)

	case discover.FormatPGPlain:
		pa, _ := a.(*PlainAnalyzer)
		if pa != nil {
			expectedTables, dumpRows = pa.Tables, pa.Rows
			required = pa.Extensions()
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

	// A dump that needs an extension the sandbox image lacks (PostGIS,
	// TimescaleDB, pgvector, …) can't be tested here. That's the sandbox's
	// limitation, not a broken backup, so it's an ERROR with advice.
	if missing, err := s.missingExtensions(ctx, required); err != nil {
		return execErr(err, "checking available extensions")
	} else if len(missing) > 0 {
		return errOut(missingExtensionsReason(missing, s.image, s.det))
	}

	if s.hooks.BeforeRestore != nil {
		s.hooks.BeforeRestore(s.c.Name)
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
		if why := s.sandboxBroke(res); why != "" {
			return errOut(why + " · " + firstErrors(res.Stderr))
		}
		return failOut("l2.restore", fmt.Sprintf("%s failed (exit %d): %s", restoreArgs[0], res.ExitCode, firstErrors(res.Stderr)))
	}
	out.Checks = append(out.Checks, receipt.Check{ID: "l2.restore", Status: receipt.CheckPass,
		Detail: fmt.Sprintf("exit 0 in %.1fs", dur.Seconds())})

	// For archive formats, count the rows the dump holds by replaying its data
	// section as SQL (no restore, just decompression and counting).
	if dumpRows == nil {
		counter := NewPlainAnalyzer()
		res, err := s.c.Exec(ctx, sandbox.ExecOpts{Args: []string{"pg_restore", "--data-only", "-f", "-", dumpPath}, Stdout: counter})
		if err != nil {
			return execErr(err, "reading the dump's data for the row audit")
		}
		if res.ExitCode != 0 {
			if why := s.sandboxBroke(res); why != "" {
				return errOut(why)
			}
			return failOut("l2.rows", "the dump's data section can't be read: "+firstErrors(res.Stderr))
		}
		dumpRows = counter.Rows
	}

	dbs, tables, err := s.inspect(ctx)
	if err != nil {
		return execErr(err, "inspecting the restored database")
	}
	out.Tables = len(tables)
	out.TableCounts = tables
	for _, t := range tables {
		if t.Kind == 'r' {
			out.Rows += t.Rows
		}
	}
	out.RowsKnown = true

	switch {
	case expectedTables < 0:
		out.Checks = append(out.Checks, receipt.Check{ID: "l2.objects", Status: receipt.CheckInfo, Detail: fmt.Sprintf("%d tables", out.Tables)})
	case out.Tables < expectedTables:
		return failOut("l2.objects", fmt.Sprintf("only %d of %d tables restored · %d tables lost", out.Tables, expectedTables, expectedTables-out.Tables))
	case out.Tables == expectedTables:
		out.Checks = append(out.Checks, receipt.Check{ID: "l2.objects", Status: receipt.CheckPass, Detail: fmt.Sprintf("%d/%d tables", out.Tables, expectedTables)})
	default:
		out.Checks = append(out.Checks, receipt.Check{ID: "l2.objects", Status: receipt.CheckPass, Detail: fmt.Sprintf("%d tables (%d in dump)", out.Tables, expectedTables)})
	}

	if problems := AuditRows(dumpRows, tables); len(problems) > 0 {
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

	if h, err := s.schemaHash(ctx, dbs); err != nil {
		out.Checks = append(out.Checks, receipt.Check{ID: "l2.schema_hash", Status: receipt.CheckError, Detail: "could not compute: " + err.Error()})
	} else {
		out.Checks = append(out.Checks, receipt.Check{ID: "l2.schema_hash", Status: receipt.CheckPass, Detail: "sha256:" + h})
	}

	if s.amcheck <= 0 {
		out.Checks = append(out.Checks, receipt.Check{ID: "l2.amcheck", Status: receipt.CheckSkip, Detail: "disabled"})
	} else {
		checked, skipped, bad, err := s.runAmcheck(ctx, dbs)
		switch {
		case err != nil:
			out.Checks = append(out.Checks, receipt.Check{ID: "l2.amcheck", Status: receipt.CheckError, Detail: "could not run: " + err.Error()})
		case bad != "":
			return failOut("l2.amcheck", "index corruption found by amcheck: "+clip(bad, 300))
		default:
			detail := fmt.Sprintf("%d B-tree indexes verified (bt_index_check with heapallindexed)", checked)
			if skipped > 0 {
				detail += fmt.Sprintf("; %d skipped over the %s budget", skipped, s.amcheck)
			}
			out.Checks = append(out.Checks, receipt.Check{ID: "l2.amcheck", Status: receipt.CheckPass, Detail: detail})
		}
	}

	out.Result = receipt.Pass
	return out
}

const userSchemas = `n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\_toast%' AND n.nspname NOT LIKE 'pg\_temp%' AND n.nspname <> 'xinproof_amcheck'`

const inspectSQL = `SELECT n.nspname, c.relname, c.relkind,
  (xpath('/row/c/text()', query_to_xml(format(CASE WHEN c.relkind = 'r' THEN 'SELECT count(*) AS c FROM ONLY %I.%I' ELSE 'SELECT count(*) AS c FROM %I.%I' END,
     n.nspname, c.relname), false, true, '')))[1]::text::bigint
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p') AND ` + userSchemas + `
  AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')
ORDER BY 1, 2`

// inspect lists user tables with exact row counts in every database in the
// sandbox (plain dumps made with -C or pg_dumpall create their own databases).
func (s *session) inspect(ctx context.Context) (dbs []string, tables []TableCount, err error) {
	res, err := s.psql(ctx, restoreDB, "SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate ORDER BY 1")
	if err != nil {
		return nil, nil, err
	}
	if res.ExitCode != 0 {
		return nil, nil, errors.New(firstErrors(res.Stderr))
	}
	for _, db := range strings.Split(strings.TrimSpace(string(res.Stdout)), "\n") {
		if db = strings.TrimSpace(db); db != "" {
			dbs = append(dbs, db)
		}
	}
	for _, db := range dbs {
		r, err := s.psql(ctx, db, inspectSQL)
		if err != nil {
			return nil, nil, err
		}
		if r.ExitCode != 0 {
			return nil, nil, fmt.Errorf("database %s: %s", db, firstErrors(r.Stderr))
		}
		key := db
		if db == restoreDB {
			key = ""
		}
		for _, line := range strings.Split(strings.TrimRight(string(r.Stdout), "\n"), "\n") {
			if line == "" {
				continue
			}
			f := strings.Split(line, "\t")
			if len(f) != 4 || len(f[2]) != 1 {
				return nil, nil, fmt.Errorf("unexpected inspection output %q", line)
			}
			n, err := strconv.ParseInt(f[3], 10, 64)
			if err != nil {
				return nil, nil, fmt.Errorf("unexpected inspection output %q", line)
			}
			tables = append(tables, TableCount{DB: key, Qualified: f[0] + "." + f[1], Kind: f[2][0], Rows: n})
		}
	}
	return dbs, tables, nil
}

const schemaHashSQL = `SELECT coalesce(encode(sha256(convert_to(string_agg(line, E'\n' ORDER BY line), 'UTF8')), 'hex'), '') FROM (
  SELECT format('col %I.%I %s %I %s %s', n.nspname, c.relname, a.attnum, a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull) AS line
    FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE a.attnum > 0 AND NOT a.attisdropped AND c.relkind IN ('r', 'p', 'v', 'm', 'f') AND ` + userSchemas + `
  UNION ALL
  SELECT format('con %I.%I %I %s', n.nspname, c.relname, co.conname, pg_get_constraintdef(co.oid))
    FROM pg_constraint co JOIN pg_class c ON c.oid = co.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE ` + userSchemas + `
  UNION ALL
  SELECT format('idx %s', pg_get_indexdef(i.indexrelid))
    FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE ` + userSchemas + `
) s`

// schemaHash fingerprints the restored schema (columns, types, constraints,
// indexes) across all databases. The same dump always yields the same hash,
// so a change between backups shows up as a different hash.
func (s *session) schemaHash(ctx context.Context, dbs []string) (string, error) {
	var lines []string
	for _, db := range dbs {
		r, err := s.psql(ctx, db, schemaHashSQL)
		if err != nil {
			return "", err
		}
		if r.ExitCode != 0 {
			return "", fmt.Errorf("database %s: %s", db, firstErrors(r.Stderr))
		}
		h := strings.TrimSpace(string(r.Stdout))
		if h == "" {
			continue // no user objects
		}
		name := db
		if db == restoreDB {
			name = ""
		}
		lines = append(lines, name+" "+h)
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:]), nil
}

const amcheckSQL = `CREATE SCHEMA IF NOT EXISTS xinproof_amcheck;
CREATE EXTENSION IF NOT EXISTS amcheck SCHEMA xinproof_amcheck;
CREATE FUNCTION pg_temp.xinproof_amcheck(budget interval) RETURNS TABLE(checked int, skipped int, failed text) LANGUAGE plpgsql AS $fn$
DECLARE
  r record; t0 timestamptz := clock_timestamp(); bad text[] := '{}'; n int := 0; s int := 0;
  ext text := (SELECT ns.nspname FROM pg_extension e JOIN pg_namespace ns ON ns.oid = e.extnamespace WHERE e.extname = 'amcheck');
BEGIN
  FOR r IN SELECT c.oid, c.oid::regclass::text AS name
      FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid JOIN pg_am am ON am.oid = c.relam JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE am.amname = 'btree' AND c.relpersistence <> 't' AND i.indisready AND i.indisvalid AND ` + userSchemas + `
      ORDER BY c.relpages DESC, 2
  LOOP
    IF clock_timestamp() - t0 > budget THEN s := s + 1; CONTINUE; END IF;
    BEGIN
      EXECUTE format('SELECT %I.bt_index_check($1, true)', ext) USING r.oid;
    EXCEPTION WHEN others THEN
      bad := bad || (r.name || ': ' || SQLERRM);
    END;
    n := n + 1;
  END LOOP;
  RETURN QUERY SELECT n, s, array_to_string(bad, ' | ');
END
$fn$;
SELECT * FROM pg_temp.xinproof_amcheck(make_interval(secs => BUDGET_SECONDS));`

// runAmcheck verifies every B-tree index (structure and that every heap tuple
// is indexed) in every database, within the time budget.
func (s *session) runAmcheck(ctx context.Context, dbs []string) (checked, skipped int, bad string, err error) {
	var bads []string
	for _, db := range dbs {
		r, err := s.psql(ctx, db, strings.Replace(amcheckSQL, "BUDGET_SECONDS", strconv.Itoa(int(s.amcheck.Seconds())), 1))
		if err != nil {
			return 0, 0, "", err
		}
		if r.ExitCode != 0 {
			return 0, 0, "", fmt.Errorf("database %s: %s", db, firstErrors(r.Stderr))
		}
		f := strings.SplitN(strings.TrimRight(string(r.Stdout), "\n"), "\t", 3)
		if len(f) != 3 {
			return 0, 0, "", fmt.Errorf("unexpected amcheck output %q", r.Stdout)
		}
		c, _ := strconv.Atoi(f[0])
		sk, _ := strconv.Atoi(f[1])
		checked += c
		skipped += sk
		if f[2] != "" {
			if db != restoreDB {
				f[2] = db + ": " + f[2]
			}
			bads = append(bads, f[2])
		}
	}
	return checked, skipped, strings.Join(bads, " | "), nil
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
		if (strings.Contains(low, "error") || strings.Contains(low, "fatal")) && !slices.Contains(picked, l) {
			picked = append(picked, l) // parallel workers often repeat the same error
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
