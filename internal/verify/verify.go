// Package verify runs the verifier pipeline for every backup at a location:
// discover → L1 integrity → sandbox restore → checks → signed receipt.
// Every discovered backup ends in exactly one of PASS, FAIL or ERROR.
package verify

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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
	sidecars := map[string]string{}
	var cands []source.Object
	skipped := 0
	for _, o := range objs {
		if target, ok := discover.IsSidecar(o.Key); ok {
			sidecars[target] = o.Key
			continue
		}
		if discover.IsCandidate(o.Name) {
			cands = append(cands, o)
		} else {
			skipped++
		}
	}
	if v.Opts.Since > 0 {
		cut := v.now().Add(-v.Opts.Since)
		kept := cands[:0]
		for _, o := range cands {
			if o.LastModified.IsZero() || o.LastModified.After(cut) {
				kept = append(kept, o)
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
		if !cands[i].LastModified.Equal(cands[j].LastModified) {
			return cands[i].LastModified.After(cands[j].LastModified)
		}
		return cands[i].Name < cands[j].Name
	})
	plan := Plan{Found: len(cands), Testing: len(cands), Skipped: skipped}
	if v.Opts.Newest > 0 && v.Opts.Newest < len(cands) {
		cands = cands[:v.Opts.Newest]
		plan.Testing, plan.Newest = len(cands), true
	}
	if v.Opts.OnPlan != nil {
		v.Opts.OnPlan(plan)
	}

	var results []Result
	for _, o := range cands {
		if v.Opts.OnStart != nil {
			v.Opts.OnStart(o)
		}
		r := v.one(ctx, o, sidecars[o.Key])
		if err := v.issue(&r); err != nil {
			return results, fmt.Errorf("writing receipt for %s: %w", o.Name, err)
		}
		results = append(results, r)
		if v.Opts.OnResult != nil {
			v.Opts.OnResult(r)
		}
		if ctx.Err() != nil {
			return results, ctx.Err()
		}
	}
	return results, nil
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

func (v *Verifier) one(parent context.Context, obj source.Object, sidecar string) (res Result) {
	start := time.Now()
	d := &draft{obj: obj}
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
	if srcErr != nil {
		d.out = errorOutcome(budget(srcErr, "reading object"))
		return
	}
	if det.Format == discover.FormatEmpty || (det.Problem != "" && det.Format != discover.FormatMySQL) {
		d.check("l1.format", receipt.CheckFail, det.Problem)
		d.out = failOutcome(det.Problem)
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
	if want, from := v.expectedSHA(ctx, d.obj, sidecar); want != "" {
		if !strings.EqualFold(want, l1.sha256) {
			reason := fmt.Sprintf("checksum mismatch: %s says %s…, content is %s…", from, want[:12], l1.sha256[:12])
			d.check("l1.checksum", receipt.CheckFail, reason)
			d.out = failOutcome(reason)
			return
		}
		d.check("l1.checksum", receipt.CheckPass, "matches "+from)
	}
	if an != nil {
		for _, c := range an.Finish() {
			d.checks = append(d.checks, c)
			if c.Status == receipt.CheckFail {
				d.out = failOutcome(c.Detail)
				return
			}
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

func errorOutcome(reason string) engine.Outcome {
	return engine.Outcome{Result: receipt.Error, Reason: reason}
}

func failOutcome(reason string) engine.Outcome {
	return engine.Outcome{Result: receipt.Fail, Reason: reason}
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
	if det.Format == discover.FormatMySQL {
		return "MySQL dumps are recognized but the MySQL engine isn't in this release yet, so nothing was restored"
	}
	return fmt.Sprintf("no engine for format %s", det.Format)
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
	h := sha256.New()
	src := &errReader{r: rc}
	raw := &countReader{r: io.TeeReader(src, h)}
	defer func() {
		r.size = raw.n
		if r.sourceErr == nil && src.err != nil {
			r.sourceErr, r.corruptErr = src.err, nil
		}
		if r.sourceErr == nil {
			r.sha256 = hex.EncodeToString(h.Sum(nil))
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

func (v *Verifier) expectedSHA(ctx context.Context, obj source.Object, sidecar string) (sum, from string) {
	if sidecar != "" {
		if rc, err := v.Src.Open(ctx, sidecar); err == nil {
			defer rc.Close()
			b, _ := io.ReadAll(io.LimitReader(rc, 4096))
			if f := strings.Fields(string(b)); len(f) > 0 && len(f[0]) == 64 {
				if _, err := hex.DecodeString(f[0]); err == nil {
					return strings.ToLower(f[0]), "sidecar " + sidecar
				}
			}
		}
	}
	if obj.SHA256 != "" {
		return obj.SHA256, "provider checksum"
	}
	return "", ""
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
		r.Checks = d.checks
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
