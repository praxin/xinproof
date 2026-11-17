// Package verify runs the verifier pipeline for every backup at a location:
// discover → L1 integrity → sandbox restore → checks → signed receipt.
// Every discovered backup ends in exactly one of PASS, FAIL or ERROR.
package verify

import (
	"archive/tar"
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/praxin/xinproof/internal/discover"
	"github.com/praxin/xinproof/internal/engine"
	"github.com/praxin/xinproof/internal/receipt"
	"github.com/praxin/xinproof/internal/source"
)

type Options struct {
	Since       time.Duration // only backups modified within this window (0 = all)
	Newest      int           // only the newest N backups (0 = all)
	Timeout     time.Duration // per-backup budget (default 2h)
	Store       *receipt.Store
	Key         ed25519.PrivateKey
	ToolVersion string
	ToolCommit  string
	Now         func() time.Time
	Log         *slog.Logger // structured logs; nil discards

	// OnPlan is called once the candidates are known; OnStart before and
	// OnResult after each backup is processed.
	OnPlan   func(Plan)
	OnStart  func(source.Object)
	OnResult func(Result)
}

type Plan struct {
	Found   int // backup candidates found
	Testing int // how many will be tested
	Newest  bool
	Skipped int // other objects that don't look like backups
}

type Result struct {
	Object      source.Object
	Status      receipt.Result
	Reason      string
	Tables      int
	Rows        int64
	RowsKnown   bool
	Restore     time.Duration
	Total       time.Duration
	Receipt     *receipt.Receipt
	ReceiptPath string
}

type Verifier struct {
	Src    source.Source
	Engine engine.Engine
	Opts   Options
}

// ErrNothingFound is returned when the location holds no backups at all.
var ErrNothingFound = errors.New("no backups found")

func (v *Verifier) log() *slog.Logger {
	if v.Opts.Log != nil {
		return v.Opts.Log
	}
	return slog.New(slog.DiscardHandler)
}

func (v *Verifier) now() time.Time {
	if v.Opts.Now != nil {
		return v.Opts.Now()
	}
	return time.Now()
}

// Run verifies every backup at the location and returns one Result per backup.
func (v *Verifier) Run(ctx context.Context) ([]Result, error) {
	objs, err := v.Src.List(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("listing %s: %w", v.Src, err)
	}
	cands, skipped := v.plan(ctx, objs)
	if v.Opts.Since > 0 {
		cut := v.now().Add(-v.Opts.Since)
		kept := cands[:0]
		for _, u := range cands {
			if u.obj.LastModified.IsZero() || u.obj.LastModified.After(cut) {
				kept = append(kept, u)
			}
		}
		cands = kept
	}
	if len(cands) == 0 {
		if v.Opts.OnPlan != nil {
			v.Opts.OnPlan(Plan{Skipped: skipped})
		}
		return nil, ErrNothingFound
	}
	sort.SliceStable(cands, func(i, j int) bool {
		if !cands[i].obj.LastModified.Equal(cands[j].obj.LastModified) {
			return cands[i].obj.LastModified.After(cands[j].obj.LastModified)
		}
		return cands[i].obj.Name < cands[j].obj.Name
	})
	plan := Plan{Found: len(cands), Testing: len(cands), Skipped: skipped}
	if v.Opts.Newest > 0 && v.Opts.Newest < len(cands) {
		cands = cands[:v.Opts.Newest]
		plan.Testing, plan.Newest = len(cands), true
	}
	if v.Opts.OnPlan != nil {
		v.Opts.OnPlan(plan)
	}

	v.log().Info("plan", "location", v.Src.String(), "found", plan.Found, "testing", plan.Testing, "skipped", plan.Skipped)

	var results []Result
	for _, u := range cands {
		o := u.obj
		var r Result
		if ctx.Err() != nil {
			// Never silently partial: backups we didn't get to still end in ERROR, with a receipt.
			r = v.notTested(o, "the run was interrupted before this backup was tested")
		} else {
			if v.Opts.OnStart != nil {
				v.Opts.OnStart(o)
			}
			r = v.one(ctx, u)
		}
		if err := v.issue(&r); err != nil {
			return results, fmt.Errorf("writing receipt for %s: %w", o.Name, err)
		}
		v.log().Info("result", "backup", o.URL, "status", string(r.Status), "reason", r.Reason,
			"tables", r.Tables, "rows", r.Rows, "restore_s", r.Restore.Seconds(), "total_s", r.Total.Seconds(), "receipt", r.ReceiptPath)
		results = append(results, r)
		if v.Opts.OnResult != nil {
			v.Opts.OnResult(r)
		}
	}
	return results, ctx.Err()
}

// unit is one backup: a single object, or a pg_dump -Fd directory.
type unit struct {
	obj     source.Object   // the object, or for a directory a synthetic object for the whole folder
	sidecar string          // key of a .sha256 sidecar, if any
	toc     source.Object   // directory format: its toc.dat
	members []source.Object // directory format: every file in the folder (toc.dat included)
}

func (u unit) isDir() bool { return len(u.members) > 0 }

// plan turns a listing into backups. Directory-format dumps (a folder holding
// toc.dat) become one backup each; tar files count only if their content is a
// pg_dump tar archive; everything else that doesn't look like a dump is skipped.
func (v *Verifier) plan(ctx context.Context, objs []source.Object) (units []unit, skipped int) {
	sidecars := map[string]string{}
	dirs := map[string]*unit{}
	for _, o := range objs {
		if discover.IsDirectoryTOC(o.Key) {
			dir := path.Dir(o.Key)
			name := path.Dir(o.Name)
			if name == "." {
				name = path.Base(strings.TrimRight(v.Src.String(), "/"))
			}
			url := strings.TrimSuffix(o.URL, "toc.dat")
			dirs[dir] = &unit{obj: source.Object{Key: o.Key, Name: name + "/", URL: url}, toc: o}
		}
	}
	for _, o := range objs {
		if u, ok := dirs[path.Dir(o.Key)]; ok {
			u.members = append(u.members, o)
			u.obj.Size += o.Size
			if o.LastModified.After(u.obj.LastModified) {
				u.obj.LastModified = o.LastModified
			}
			continue
		}
		if target, ok := discover.IsSidecar(o.Key); ok {
			sidecars[target] = o.Key
			continue
		}
		switch {
		case discover.IsCandidate(o.Name):
			units = append(units, unit{obj: o})
		case discover.IsTarCandidate(o.Name):
			// Only a pg_dump tar archive is a backup; other tarballs are skipped.
			if det, err := v.sniff(ctx, o.Key); err != nil || det.Format == discover.FormatPGTar {
				units = append(units, unit{obj: o}) // read errors still end as ERROR, never silently skipped
			} else {
				skipped++
			}
		default:
			skipped++
		}
	}
	for i := range units {
		units[i].sidecar = sidecars[units[i].obj.Key]
	}
	for _, u := range dirs {
		sort.Slice(u.members, func(i, j int) bool { return u.members[i].Key < u.members[j].Key })
		units = append(units, *u)
	}
	return units, skipped
}

func (v *Verifier) notTested(o source.Object, reason string) Result {
	d := &draft{obj: o, out: errorOutcome(reason)}
	return Result{Object: o, Status: receipt.Error, Reason: reason, Receipt: v.build(d, 0)}
}

// draft collects what we learn about one backup.
type draft struct {
	obj    source.Object
	det    discover.Detection
	sha    string
	image  string
	checks []receipt.Check
	out    engine.Outcome
}

func (d *draft) check(id, status, detail string) {
	d.checks = append(d.checks, receipt.Check{ID: id, Status: status, Detail: detail})
}

func (v *Verifier) one(parent context.Context, u unit) (res Result) {
	obj, sidecar := u.obj, u.sidecar
	start := time.Now()
	d := &draft{obj: obj}
	lg := v.log().With("backup", obj.URL)
	lg.Debug("start")
	res.Object = obj
	defer func() {
		if p := recover(); p != nil { // never silent, even on a bug
			d.out = engine.Outcome{Result: receipt.Error, Reason: fmt.Sprintf("internal error: %v", p)}
		}
		res.Status, res.Reason = d.out.Result, d.out.Reason
		res.Tables, res.Rows, res.RowsKnown = d.out.Tables, d.out.Rows, d.out.RowsKnown
		res.Restore = time.Duration(d.out.RestoreSeconds * float64(time.Second))
		res.Total = time.Since(start)
		res.Receipt = v.build(d, res.Total)
	}()

	timeout := v.Opts.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Hour
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	budget := func(err error, what string) string {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Sprintf("%s exceeded the %s budget", what, timeout)
		}
		if errors.Is(err, context.Canceled) {
			return what + " was interrupted"
		}
		return what + ": " + err.Error()
	}

	if u.isDir() {
		v.oneDir(ctx, d, u, budget)
		return
	}
	if st, err := v.Src.Stat(ctx, obj.Key); err == nil {
		d.obj = st
		d.obj.Name = obj.Name
	} else {
		d.out = errorOutcome(budget(err, "reading object metadata"))
		return
	}
	res.Object = d.obj

	// Discover: sniff the format from the first bytes.
	det, srcErr := v.sniff(ctx, d.obj.Key)
	d.det = det
	lg.Debug("detected", "format", string(det.Format), "compression", string(det.Compression),
		"dump_version", det.DumpVersion, "problem", det.Problem)
	if srcErr != nil {
		d.out = errorOutcome(budget(srcErr, "reading object"))
		return
	}
	if det.Format == discover.FormatEmpty || (det.Problem != "" && det.Format != discover.FormatMySQL) {
		d.check("l1.format", receipt.CheckFail, det.Problem)
		d.out = failOutcome(det.Problem)
		return
	}
	if det.Format == discover.FormatPGDir {
		// A lone toc.dat (or a file holding one) is only the index of a directory dump.
		reason := "this is the toc.dat of a directory-format dump, not a complete backup on its own"
		d.check("l1.format", receipt.CheckFail, reason)
		d.out = failOutcome(reason)
		return
	}
	d.check("l1.format", receipt.CheckPass, describe(det))

	supported := v.Engine.Supports(det)
	var sess engine.Session
	var startErr error
	if supported {
		sess, startErr = v.Engine.Start(ctx, det)
		if sess != nil {
			defer sess.Close()
			d.image = sess.Image()
		}
	}

	// L1: stream the whole object once: hash it, decompress it fully, run the
	// structural analyzer, and (if we have a sandbox) upload it.
	an := v.Engine.Analyzer(det)
	if !supported {
		an = nil
	}
	var sink io.WriteCloser
	var wait func() error
	if sess != nil {
		sink, wait = sess.Upload(ctx)
	}
	l1 := v.stream(ctx, d.obj, det.Compression, sink, an)
	// Finish the analyzer right away (it may hold a goroutine) and use its checks below.
	var anChecks []receipt.Check
	if an != nil {
		anChecks = an.Finish()
	}
	var uploadErr error
	if sink != nil {
		sink.Close()
		uploadErr = wait()
	}
	if l1.sourceErr != nil {
		d.out = errorOutcome(budget(l1.sourceErr, "reading object"))
		return
	}
	d.sha = l1.sha256
	lg.Debug("l1 streamed", "sha256", l1.sha256, "bytes", l1.size, "uncompressed", l1.inner,
		"corrupt", errString(l1.corruptErr), "sink", errString(firstErr(l1.sinkErr, uploadErr)))
	d.check("l1.sha256", receipt.CheckPass, fmt.Sprintf("sha256:%s (%d bytes)", l1.sha256, l1.size))
	if l1.corruptErr != nil {
		reason := fmt.Sprintf("%s stream ends early or is corrupt at byte %d of %d: %v", det.Compression, l1.size, d.obj.Size, l1.corruptErr)
		if errors.Is(l1.corruptErr, io.ErrUnexpectedEOF) {
			reason = fmt.Sprintf("%s stream ends early at byte %d (truncated)", det.Compression, l1.size)
		}
		d.check("l1.decompress", receipt.CheckFail, reason)
		d.out = failOutcome(reason)
		return
	}
	if det.Compression != discover.None {
		d.check("l1.decompress", receipt.CheckPass, fmt.Sprintf("%s ok, %d bytes uncompressed", det.Compression, l1.inner))
	}
	if d.obj.Size > 0 && l1.size != d.obj.Size {
		d.out = errorOutcome(fmt.Sprintf("read %d bytes but the object is %d bytes (changed while reading?)", l1.size, d.obj.Size))
		return
	}
	cks, mismatch := v.compareChecksums(ctx, d.obj, sidecar, l1.sums)
	d.checks = append(d.checks, cks...)
	if mismatch != "" {
		d.out = failOutcome(mismatch)
		return
	}
	for _, c := range anChecks {
		d.checks = append(d.checks, c)
		if c.Status == receipt.CheckFail {
			d.out = failOutcome(c.Detail)
			return
		}
	}

	if !supported {
		d.out = errorOutcome(unsupported(det))
		return
	}
	if startErr != nil {
		d.out = errorOutcome(budget(startErr, "sandbox"))
		return
	}
	if err := firstErr(l1.sinkErr, uploadErr); err != nil {
		d.out = errorOutcome(budget(err, "uploading to the sandbox"))
		return
	}

	d.out = sess.Restore(ctx, an)
	if d.out.Result == "" {
		d.out = errorOutcome("engine returned no result")
	}
	d.checks = append(d.checks, d.out.Checks...)
	return
}

// oneDir verifies a pg_dump -Fd directory: every file is read once, hashed,
// checked for compression integrity, and streamed into the sandbox as a tar.
// The subject hash is the SHA-256 of the sorted per-file manifest.
func (v *Verifier) oneDir(ctx context.Context, d *draft, u unit, budget func(error, string) string) {
	det, srcErr := v.sniff(ctx, u.toc.Key)
	d.det = det
	if srcErr != nil {
		d.out = errorOutcome(budget(srcErr, "reading toc.dat"))
		return
	}
	if det.Format != discover.FormatPGDir || det.Problem != "" {
		reason := det.Problem
		if reason == "" {
			reason = fmt.Sprintf("toc.dat is not a pg_dump directory-format TOC (looks like %s)", det.Format)
		}
		reason = "toc.dat: " + reason
		d.check("l1.format", receipt.CheckFail, reason)
		d.out = failOutcome(reason)
		return
	}
	d.check("l1.format", receipt.CheckPass, fmt.Sprintf("%s, %d files", describe(det), len(u.members)))

	var sess engine.Session
	var startErr error
	if v.Engine.Supports(det) {
		sess, startErr = v.Engine.Start(ctx, det)
		if sess != nil {
			defer sess.Close()
			d.image = sess.Image()
		}
	}
	var sink io.WriteCloser
	var wait func() error
	var sw *errWriter
	var tw *tar.Writer
	if sess != nil {
		sink, wait = sess.UploadDir(ctx)
		sw = &errWriter{w: sink}
		tw = tar.NewWriter(sw)
	}

	dir := path.Dir(u.toc.Key)
	var manifest strings.Builder
	var total int64
	for _, m := range u.members {
		rel := strings.TrimPrefix(strings.TrimPrefix(m.Key, dir), "/")
		if dir == "." {
			rel = m.Key
		}
		sum, n, corrupt, err := v.streamMember(ctx, m, rel, tw)
		if err != nil {
			if sink != nil {
				sink.Close()
				wait()
			}
			d.out = errorOutcome(budget(err, "reading "+rel))
			return
		}
		if corrupt != "" {
			if sink != nil {
				sink.Close()
				wait()
			}
			reason := rel + ": " + corrupt
			d.check("l1.decompress", receipt.CheckFail, reason)
			d.out = failOutcome(reason)
			return
		}
		fmt.Fprintf(&manifest, "%s  %s\n", sum, rel)
		total += n
	}
	var uploadErr error
	if tw != nil {
		if err := tw.Close(); err != nil && sw.err == nil {
			uploadErr = err
		}
		sink.Close()
		uploadErr = firstErr(uploadErr, wait())
	}
	ms := sha256.Sum256([]byte(manifest.String()))
	d.sha = hex.EncodeToString(ms[:])
	d.check("l1.sha256", receipt.CheckPass, fmt.Sprintf("manifest sha256:%s over %d files (%d bytes)", d.sha, len(u.members), total))

	if !v.Engine.Supports(det) {
		d.out = errorOutcome(unsupported(det))
		return
	}
	if startErr != nil {
		d.out = errorOutcome(budget(startErr, "sandbox"))
		return
	}
	if sw != nil && sw.err != nil {
		uploadErr = firstErr(sw.err, uploadErr)
	}
	if uploadErr != nil {
		d.out = errorOutcome(budget(uploadErr, "uploading to the sandbox"))
		return
	}
	d.out = sess.Restore(ctx, nil)
	if d.out.Result == "" {
		d.out = errorOutcome("engine returned no result")
	}
	d.checks = append(d.checks, d.out.Checks...)
}

// streamMember reads one file of a directory dump, adds it to the tar (if
// any), and returns its SHA-256. corrupt is set when a compressed data file
// fails to decompress (FAIL); err when the source fails (ERROR).
func (v *Verifier) streamMember(ctx context.Context, m source.Object, rel string, tw *tar.Writer) (sum string, n int64, corrupt string, err error) {
	rc, err := v.Src.Open(ctx, m.Key)
	if err != nil {
		return "", 0, "", err
	}
	defer rc.Close()
	dg := newDigests()
	src := &errReader{r: rc}
	raw := &countReader{r: io.TeeReader(&ctxReader{ctx: ctx, r: src}, dg)}
	var r io.Reader = raw
	if tw != nil {
		hdr := &tar.Header{Name: rel, Mode: 0o644, Size: m.Size, Typeflag: tar.TypeReg, ModTime: m.LastModified}
		if err := tw.WriteHeader(hdr); err == nil {
			r = io.TeeReader(raw, tw)
		}
	}
	comp := discover.MemberCompression(rel)
	var cerr error
	if comp != discover.None {
		dec, derr := discover.NewDecompressor(comp, r)
		if derr != nil {
			cerr = derr
		} else {
			_, cerr = io.Copy(io.Discard, dec)
			dec.Close()
		}
	}
	if _, err := io.Copy(io.Discard, r); err != nil && src.err == nil && ctx.Err() == nil {
		cerr = firstErr(cerr, err)
	}
	if src.err != nil {
		return "", raw.n, "", src.err
	}
	if ctx.Err() != nil {
		return "", raw.n, "", ctx.Err()
	}
	if raw.n != m.Size {
		return "", raw.n, "", fmt.Errorf("read %d bytes but the listing says %d (changed while reading?)", raw.n, m.Size)
	}
	if cerr != nil {
		if errors.Is(cerr, io.ErrUnexpectedEOF) {
			return "", raw.n, fmt.Sprintf("%s stream ends early at byte %d (truncated)", comp, raw.n), nil
		}
		return "", raw.n, fmt.Sprintf("%s data is corrupt: %v", comp, cerr), nil
	}
	got := dg.sums()
	if _, mismatch := v.compareChecksums(ctx, m, "", got); mismatch != "" {
		return "", raw.n, mismatch, nil
	}
	return got.SHA256, raw.n, "", nil
}

func errorOutcome(reason string) engine.Outcome {
	return engine.Outcome{Result: receipt.Error, Reason: reason}
}

func failOutcome(reason string) engine.Outcome {
	return engine.Outcome{Result: receipt.Fail, Reason: reason}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

func unsupported(det discover.Detection) string {
	return fmt.Sprintf("no enabled engine restores %s dumps (see --engine), so nothing was restored", det.Format)
}

func describe(det discover.Detection) string {
	s := string(det.Format)
	if det.Compression != discover.None {
		s += " (" + string(det.Compression) + ")"
	}
	if det.DumpVersion != "" {
		s += ", dumped by version " + det.DumpVersion
	}
	return s
}

// sniff reads the beginning of the object and detects its format. A non-nil
// error means the source itself failed (ERROR), not that the content is bad.
func (v *Verifier) sniff(ctx context.Context, key string) (discover.Detection, error) {
	rc, err := v.Src.Open(ctx, key)
	if err != nil {
		return discover.Detection{}, err
	}
	defer rc.Close()
	er := &errReader{r: rc}
	det := discover.SniffStream(er)
	if er.err != nil {
		return det, er.err
	}
	return det, nil
}

type l1Result struct {
	sha256     string
	sums       sums
	size       int64 // raw bytes read
	inner      int64 // decompressed bytes
	sourceErr  error // the source failed → ERROR
	corruptErr error // decompression failed → FAIL
	sinkErr    error // the sandbox stopped accepting data → ERROR
}

func (v *Verifier) stream(ctx context.Context, obj source.Object, comp discover.Compression, sink io.Writer, an engine.Analyzer) (r l1Result) {
	rc, err := v.Src.Open(ctx, obj.Key)
	if err != nil {
		r.sourceErr = err
		return
	}
	defer rc.Close()
	dg := newDigests()
	src := &errReader{r: rc}
	raw := &countReader{r: io.TeeReader(src, dg)}
	defer func() {
		r.size = raw.n
		if r.sourceErr == nil && src.err != nil {
			r.sourceErr, r.corruptErr = src.err, nil
		}
		if r.sourceErr == nil {
			r.sums = dg.sums()
			r.sha256 = r.sums.SHA256
		}
	}()

	var dec io.Reader = bufio.NewReaderSize(raw, 1<<20)
	if comp != discover.None {
		d, err := discover.NewDecompressor(comp, dec)
		if err != nil {
			r.corruptErr = err
			return
		}
		defer d.Close()
		dec = d
	}
	var sinks []io.Writer
	var sw *errWriter
	if sink != nil {
		sw = &errWriter{w: sink}
		sinks = append(sinks, sw)
	}
	if an != nil {
		sinks = append(sinks, an)
	}
	var dst io.Writer = io.Discard
	if len(sinks) > 0 {
		dst = io.MultiWriter(sinks...)
	}
	n, err := io.Copy(dst, &ctxReader{ctx: ctx, r: dec})
	r.inner = n
	if sw != nil {
		r.sinkErr = sw.err
	}
	switch {
	case err == nil:
		// Consume anything after the end of the compressed stream so the hash covers the whole object.
		if _, err := io.Copy(io.Discard, raw); err != nil && src.err == nil {
			r.corruptErr = err
		}
	case ctx.Err() != nil:
		r.sourceErr = ctx.Err()
	case src.err != nil:
		r.sourceErr = src.err
	default:
		r.corruptErr = err
	}
	return
}

func (v *Verifier) build(d *draft, total time.Duration) *receipt.Receipt {
	r := receipt.New(v.now())
	r.Subject = receipt.Subject{
		Source:      d.obj.URL,
		Size:        d.obj.Size,
		SHA256:      d.sha,
		ETag:        d.obj.ETag,
		Format:      string(d.det.Format),
		Compression: string(d.det.Compression),
	}
	if !d.obj.LastModified.IsZero() {
		r.Subject.LastModified = d.obj.LastModified.UTC().Format(time.RFC3339)
	}
	r.Engine = receipt.Engine{
		Kind:          d.det.Engine,
		DumpVersion:   d.det.DumpVersion,
		ServerVersion: d.det.ServerVersion,
		SandboxImage:  d.image,
	}
	r.Result, r.Reason = d.out.Result, d.out.Reason
	r.Measured = receipt.Measured{RestoreSeconds: d.out.RestoreSeconds, TotalSeconds: engine.Seconds(total)}
	if d.checks != nil {
		r.Checks = append([]receipt.Check(nil), d.checks...)
	}
	if tables, total := engine.ReceiptTables(d.out.TableCounts); len(tables) > 0 {
		r.Tables = tables
		if total > len(tables) {
			r.Checks = append(r.Checks, receipt.Check{ID: "l2.tables", Status: receipt.CheckInfo,
				Detail: fmt.Sprintf("tables list capped: first %d of %d tables by name", len(tables), total)})
		}
	}
	r.Tool = receipt.Tool{Name: "xinproof", Version: v.Opts.ToolVersion, Commit: v.Opts.ToolCommit}
	return r
}

func (v *Verifier) issue(r *Result) error {
	if v.Opts.Store == nil || v.Opts.Key == nil {
		return nil
	}
	path, err := v.Opts.Store.Append(r.Receipt, v.Opts.Key)
	if err != nil {
		return err
	}
	r.ReceiptPath = path
	return nil
}

// ExitCode maps results to the documented exit codes: 0 all PASS, 1 any FAIL,
// 2 any ERROR (and no FAIL). A definite FAIL outranks "couldn't test".
func ExitCode(results []Result) int {
	code := 0
	for _, r := range results {
		switch r.Status {
		case receipt.Fail:
			return 1
		case receipt.Error:
			code = 2
		}
	}
	return code
}

type errReader struct {
	r   io.Reader
	err error
}

func (e *errReader) Read(p []byte) (int, error) {
	n, err := e.r.Read(p)
	if err != nil && err != io.EOF && e.err == nil {
		e.err = err
	}
	return n, err
}

type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// errWriter forwards to w until the first error, then records it and quietly
// drops the rest, so the L1 hash and analyzer still see the whole stream.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) Write(p []byte) (int, error) {
	if e.err == nil {
		if _, err := e.w.Write(p); err != nil {
			e.err = err
		}
	}
	return len(p), nil
}

type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}
