// Command xinproof proves whether database backups actually restore, and
// issues signed, hash-chained proof receipts that anyone can check offline.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/praxin/xinproof/internal/engine"
	mysqlengine "github.com/praxin/xinproof/internal/engine/mysql"
	"github.com/praxin/xinproof/internal/engine/postgres"
	"github.com/praxin/xinproof/internal/receipt"
	"github.com/praxin/xinproof/internal/report"
	"github.com/praxin/xinproof/internal/sandbox"
	"github.com/praxin/xinproof/internal/source"
	"github.com/praxin/xinproof/internal/source/local"
	s3src "github.com/praxin/xinproof/internal/source/s3"
	"github.com/praxin/xinproof/internal/verify"
)

const version = "0.1.0"

// Exit codes (design doc §6).
const (
	exitPass  = 0
	exitFail  = 1
	exitError = 2
	exitUsage = 3
)

const usageText = `xinproof proves whether your database backups actually restore.

Usage:
  xinproof verify [flags] <location>        restore-test every backup at a location
  xinproof receipt verify [--pubkey K] <receipt.json>...
                                            check receipt signatures and chain offline
  xinproof key                              show (or create) this machine's signing key
  xinproof version

Locations:
  ./dumps/  /mnt/backups/pg.dump            local folder (recursive) or one file
                                            (pg_dump custom, tar, directory and plain SQL;
                                             mysqldump / mariadb-dump; optionally gzip/zstd/lz4)
  s3://bucket/prefix/                       AWS S3 (standard AWS credential chain)
  s3://bucket/prefix/ --endpoint URL        any S3-compatible store (MinIO, B2, Wasabi, …)
  r2://bucket/prefix/                       Cloudflare R2 (needs --r2-account-id or R2_ACCOUNT_ID)

Exit codes: 0 all PASS · 1 any FAIL · 2 any ERROR (could not test) · 3 usage error

Run "xinproof verify -h" for verify flags.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return exitUsage
	}
	switch args[0] {
	case "verify":
		return cmdVerify(args[1:], stdout, stderr)
	case "receipt":
		if len(args) > 1 && args[1] == "verify" {
			return cmdReceiptVerify(args[2:], stdout, stderr)
		}
		fmt.Fprintln(stderr, "usage: xinproof receipt verify [--pubkey K] <receipt.json>...")
		return exitUsage
	case "key":
		return cmdKey(stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "xinproof %s %s\n", version, commit())
		return exitPass
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usageText)
		return exitPass
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usageText)
	return exitUsage
}

// parseInterspersed lets flags appear before or after positional arguments.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func cmdVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	since := fs.String("since", "", "only backups modified within this window, e.g. 7d or 36h")
	newest := fs.Int("newest", 0, "only test the newest N backups (0 = all)")
	engineName := fs.String("engine", "auto", "database engines to use: auto (all), postgres or mysql")
	receiptsDir := fs.String("receipts", "receipts", "directory for signed receipts (hash-chained)")
	timeout := fs.Duration("timeout", 2*time.Hour, "per-backup time budget")
	memory := fs.String("memory", "2g", "sandbox memory limit")
	cpus := fs.String("cpus", "2", "sandbox CPU limit")
	tmpfs := fs.String("tmpfs", "", "keep the dump and restored data on a tmpfs of this size (e.g. 2g) instead of disk")
	amcheck := fs.Duration("amcheck-budget", 10*time.Minute, "time budget for index verification: amcheck per Postgres database, CHECK TABLE per MySQL restore; 0 disables")
	mysqlImage := fs.String("mysql-image", "", "override the MySQL/MariaDB sandbox image (default: mysql:<major.minor> or mariadb:<major.minor> of the dumped server)")
	pgImage := fs.String("pg-image", "", "override the postgres sandbox image (default: postgres:<major of pg_dump>)")
	dockerBin := fs.String("docker", "docker", "docker CLI binary")
	endpoint := fs.String("endpoint", "", "S3-compatible endpoint URL (MinIO, B2, Wasabi, Ceph, …)")
	region := fs.String("region", "", "S3 region (default from AWS config, else us-east-1)")
	profile := fs.String("profile", "", "AWS shared-config profile")
	pathStyle := fs.Bool("path-style", false, "use path-style S3 addressing (MinIO and most self-hosted stores)")
	r2Account := fs.String("r2-account-id", "", "Cloudflare account ID for r2:// (or R2_ACCOUNT_ID)")
	noColor := fs.Bool("no-color", false, "disable colored output (NO_COLOR is honored too)")
	format := fs.String("format", "human", "report format: human, json or junit")
	output := fs.String("output", "", "write the json/junit report to this file (human output stays on stdout)")
	logLevel := fs.String("log-level", "warn", "structured log level on stderr: debug, info, warn, error, off")
	logFormat := fs.String("log-format", "text", "structured log format: text or json")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: xinproof verify [flags] <location>")
		fs.PrintDefaults()
	}
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitPass
		}
		return exitUsage
	}
	if len(pos) != 1 {
		fs.Usage()
		return exitUsage
	}
	if *engineName != "auto" && *engineName != "postgres" && *engineName != "mysql" {
		fmt.Fprintf(stderr, "unknown --engine %q (auto, postgres or mysql)\n", *engineName)
		return exitUsage
	}
	sinceDur, err := parseSince(*since)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	if *format != "human" && *format != "json" && *format != "junit" {
		fmt.Fprintf(stderr, "unknown --format %q (human, json or junit)\n", *format)
		return exitUsage
	}
	logger, err := newLogger(stderr, *logLevel, *logFormat)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	// Human progress goes to stdout unless stdout carries the machine report.
	humanOut, reportOut := stdout, io.Writer(nil)
	if *format != "human" {
		if *output == "" {
			humanOut, reportOut = stderr, stdout
		} else {
			f, err := os.Create(*output)
			if err != nil {
				fmt.Fprintln(stderr, "xinproof:", err)
				return exitUsage
			}
			defer f.Close()
			reportOut = f
		}
	}
	started := time.Now()
	writeReport := func(results []verify.Result, code int, runErr error) int {
		if reportOut == nil {
			return code
		}
		run := report.Run{Tool: receipt.Tool{Name: "xinproof", Version: version, Commit: commit()}, Location: pos[0],
			StartedAt: started, Results: results, ExitCode: code, Err: runErr}
		var werr error
		if *format == "json" {
			werr = report.WriteJSON(reportOut, run)
		} else {
			werr = report.WriteJUnit(reportOut, run)
		}
		if werr != nil {
			fmt.Fprintln(stderr, "xinproof: writing report:", werr)
			return exitError
		}
		return code
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	src, code, err := openSource(ctx, pos[0], s3src.Options{Endpoint: *endpoint, Region: *region, Profile: *profile, PathStyle: *pathStyle}, *r2Account)
	if err != nil {
		fmt.Fprintln(stderr, "xinproof:", err)
		return writeReport(nil, code, err)
	}

	keysDir := filepath.Join(home(), "keys")
	priv, created, err := receipt.LoadOrCreateKey(keysDir)
	if err != nil {
		fmt.Fprintln(stderr, "xinproof: signing key:", err)
		return writeReport(nil, exitError, fmt.Errorf("signing key: %w", err))
	}

	tty := false
	if f, ok := humanOut.(*os.File); ok {
		tty = report.IsTerminal(f)
	}
	_, noColorEnv := os.LookupEnv("NO_COLOR")
	h := &report.Human{W: humanOut, Color: tty && !*noColor && !noColorEnv, TTY: tty}
	if created {
		fmt.Fprintf(humanOut, "  new signing key %s created in %s\n", receipt.KeyID(priv.Public().(ed25519.PublicKey)), keysDir)
	}

	docker := &sandbox.Docker{Bin: *dockerBin, Log: logger}
	if docker.Available(ctx) == nil {
		if n, _ := docker.Reap(ctx); n > 0 {
			fmt.Fprintf(humanOut, "  removed %d expired sandbox container(s) from an earlier run\n", n)
		}
	}
	runID := randomID()
	pg := &postgres.Engine{
		Docker:    docker,
		RunID:     runID,
		Image:     *pgImage,
		Memory:    *memory,
		CPUs:      *cpus,
		TmpfsSize: *tmpfs,
		TTL:       *timeout + 15*time.Minute,

		AmcheckBudget: *amcheck,
	}
	my := &mysqlengine.Engine{
		Docker:      docker,
		RunID:       runID,
		Image:       *mysqlImage,
		Memory:      *memory,
		CPUs:        *cpus,
		TmpfsSize:   *tmpfs,
		TTL:         *timeout + 15*time.Minute,
		CheckBudget: *amcheck,
	}
	var eng engine.Multi
	switch *engineName {
	case "postgres":
		eng = engine.Multi{pg}
	case "mysql":
		eng = engine.Multi{my}
	default:
		eng = engine.Multi{pg, my}
	}
	v := &verify.Verifier{
		Src:    src,
		Engine: eng,
		Opts: verify.Options{
			Since:       sinceDur,
			Newest:      *newest,
			Timeout:     *timeout,
			Store:       &receipt.Store{Dir: *receiptsDir},
			Key:         priv,
			ToolVersion: version,
			ToolCommit:  commit(),
			OnPlan:      h.Plan,
			OnStart:     func(o source.Object) { h.Start(o.Name) },
			OnResult:    h.Result,
			Log:         logger,
		},
	}
	results, err := v.Run(ctx)
	if errors.Is(err, verify.ErrNothingFound) {
		fmt.Fprintf(humanOut, "  ! no backups found at %s (looked for .dump .sql .backup .bak …, optionally .gz/.zst/.lz4)\n", src)
		return writeReport(nil, exitError, err)
	}
	h.Footer(results, *receiptsDir)
	switch {
	case errors.Is(err, context.Canceled):
		// Every backup still has a result (untested ones are ERROR), so exit by results.
		fmt.Fprintln(stderr, "xinproof: interrupted; backups not reached are reported as ERROR")
		code := verify.ExitCode(results)
		if code == exitPass {
			code = exitError
		}
		return writeReport(results, code, err)
	case err != nil:
		fmt.Fprintln(stderr, "xinproof:", err)
		return writeReport(results, exitError, err)
	}
	return writeReport(results, verify.ExitCode(results), nil)
}

func newLogger(w io.Writer, level, format string) (*slog.Logger, error) {
	var lv slog.Level
	switch level {
	case "off", "none":
		return slog.New(slog.DiscardHandler), nil
	case "debug":
		lv = slog.LevelDebug
	case "info":
		lv = slog.LevelInfo
	case "warn", "warning":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		return nil, fmt.Errorf("unknown --log-level %q", level)
	}
	opts := &slog.HandlerOptions{Level: lv}
	switch format {
	case "text":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	case "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	}
	return nil, fmt.Errorf("unknown --log-format %q (text or json)", format)
}

func openSource(ctx context.Context, loc string, o s3src.Options, r2Account string) (source.Source, int, error) {
	scheme, rest, hasScheme := strings.Cut(loc, "://")
	if !hasScheme {
		s, err := local.New(loc)
		if err != nil {
			return nil, exitError, err
		}
		return s, 0, nil
	}
	switch scheme {
	case "file":
		s, err := local.New(rest)
		if err != nil {
			return nil, exitError, err
		}
		return s, 0, nil
	case "s3", "r2":
		bucket, prefix, _ := strings.Cut(rest, "/")
		o.Scheme = scheme
		if scheme == "r2" {
			if r2Account == "" {
				r2Account = firstEnv("R2_ACCOUNT_ID", "CLOUDFLARE_ACCOUNT_ID")
			}
			if r2Account == "" && o.Endpoint == "" {
				return nil, exitUsage, errors.New("r2:// needs --r2-account-id (or R2_ACCOUNT_ID); credentials come from AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY or --profile")
			}
			if o.Endpoint == "" {
				o.Endpoint = "https://" + r2Account + ".r2.cloudflarestorage.com"
			}
			if o.Region == "" {
				o.Region = "auto"
			}
		}
		s, err := s3src.New(ctx, bucket, prefix, o)
		if err != nil {
			return nil, exitError, err
		}
		return s, 0, nil
	case "azblob", "gs":
		return nil, exitUsage, fmt.Errorf("%s:// sources are designed but not in this release yet (local folders, S3 and R2 work today)", scheme)
	}
	return nil, exitUsage, fmt.Errorf("unknown location scheme %q", scheme)
}

func cmdReceiptVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("receipt verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pubkey := fs.String("pubkey", "", "trusted public key to pin: a PEM file, or a base64 Ed25519 key")
	noColor := fs.Bool("no-color", false, "disable colored output")
	files, err := parseInterspersed(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitPass
		}
		return exitUsage
	}
	if len(files) == 0 {
		fmt.Fprintln(stderr, "usage: xinproof receipt verify [--pubkey K] <receipt.json>...")
		return exitUsage
	}
	var pinned ed25519.PublicKey
	if *pubkey != "" {
		b, err := os.ReadFile(*pubkey)
		if err != nil {
			b = []byte(*pubkey)
		}
		if pinned, err = receipt.ParsePublicKey(b); err != nil {
			fmt.Fprintln(stderr, "xinproof: --pubkey:", err)
			return exitUsage
		}
	}
	localPub, _ := receipt.LoadLocalPublicKey(filepath.Join(home(), "keys"))

	tty := false
	if f, ok := stdout.(*os.File); ok {
		tty = report.IsTerminal(f)
	}
	_, noColorEnv := os.LookupEnv("NO_COLOR")
	color := tty && !*noColor && !noColorEnv
	paint := func(code, s string) string {
		if !color {
			return s
		}
		return code + s + "\033[0m"
	}

	check := func(path string) checked {
		it := checked{path: path}
		doc, err := os.ReadFile(path)
		if err != nil {
			it.err = err
			return it
		}
		if pinned != nil {
			it.v, it.err = receipt.Verify(doc, []ed25519.PublicKey{pinned})
			it.pinBy = "--pubkey"
			return it
		}
		it.v, it.err = receipt.Verify(doc, nil)
		if it.err == nil && localPub != nil {
			if emb, err := base64.StdEncoding.DecodeString(it.v.Receipt.Signature.PublicKey); err == nil && bytes.Equal(emb, localPub) {
				it.v.Pinned, it.pinBy = true, "this machine's key"
			}
		}
		return it
	}

	items := make([]checked, 0, len(files))
	for _, f := range files {
		items = append(items, check(f))
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].v == nil || items[j].v == nil {
			return false
		}
		return items[i].v.Receipt.Chain.Seq < items[j].v.Receipt.Chain.Seq
	})

	bad := false
	var prev *checked
	for i := range items {
		it := &items[i]
		name := filepath.Base(it.path)
		if it.err != nil {
			bad = true
			fmt.Fprintln(stdout, paint("\033[31m", fmt.Sprintf("✗ %s  %v", name, it.err)))
			prev = nil
			continue
		}
		chain := chainStatus(it.v, it.path, prev, check)
		if strings.HasPrefix(chain, "chain BROKEN") {
			bad = true
		}
		sig := "signature valid"
		if it.v.Pinned {
			sig += " (pinned: " + it.pinBy + ")"
		} else {
			sig += fmt.Sprintf(" (key %s, not pinned: pass --pubkey to pin it)", it.v.KeyID)
		}
		mark := paint("\033[32m", "✓")
		if strings.HasPrefix(chain, "chain BROKEN") {
			mark = paint("\033[31m", "✗")
		}
		fmt.Fprintf(stdout, "%s %s  %s · %s\n", mark, name, sig, chain)
		r := it.v.Receipt
		line := fmt.Sprintf("    %s · %s · issued %s · seq %d", r.Result, r.Subject.Source, r.IssuedAt, r.Chain.Seq)
		if r.Reason != "" {
			line += " · " + r.Reason
		}
		fmt.Fprintln(stdout, paint("\033[2m", line))
		prev = it
	}
	if bad {
		return exitFail
	}
	return exitPass
}

// chainStatus checks the link from a receipt to its predecessor: the previous
// receipt given on the command line, or receipt-<seq-1>.json next to it.
func chainStatus(v *receipt.Verified, path string, prev *checked, check func(string) checked) string {
	seq := v.Receipt.Chain.Seq
	if seq == 1 {
		if v.Receipt.Chain.Prev == receipt.GenesisPrev {
			return "chain intact (first receipt)"
		}
		return "chain BROKEN: first receipt has a non-genesis prev"
	}
	var pv *receipt.Verified
	if prev != nil && prev.v != nil && prev.v.Receipt.Chain.Seq == seq-1 {
		pv = prev.v
	} else {
		pp := filepath.Join(filepath.Dir(path), receipt.FileName(seq-1))
		if _, err := os.Stat(pp); err != nil {
			return "chain: predecessor not available, link not checked"
		}
		c := check(pp)
		if c.err != nil {
			return "chain BROKEN: predecessor " + filepath.Base(pp) + " does not verify: " + c.err.Error()
		}
		pv = c.v
	}
	if err := receipt.CheckLink(pv, v); err != nil {
		return "chain BROKEN: " + err.Error()
	}
	return "chain intact"
}

type checked struct {
	path  string
	v     *receipt.Verified
	err   error
	pinBy string
}

func cmdKey(stdout, stderr io.Writer) int {
	dir := filepath.Join(home(), "keys")
	priv, created, err := receipt.LoadOrCreateKey(dir)
	if err != nil {
		fmt.Fprintln(stderr, "xinproof:", err)
		return exitError
	}
	pub := priv.Public().(ed25519.PublicKey)
	pem, _ := receipt.EncodePublicKey(pub)
	if created {
		fmt.Fprintln(stdout, "created a new signing key")
	}
	fmt.Fprintf(stdout, "key id:      %s\npublic key:  %s\nbase64:      %s\n\n%s", receipt.KeyID(pub), receipt.PublicKeyPath(dir),
		base64.StdEncoding.EncodeToString(pub), pem)
	fmt.Fprintln(stdout, "Share the public key so others can run: xinproof receipt verify --pubkey ed25519.pub receipt.json")
	return exitPass
}

func parseSince(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || n < 0 {
			return 0, fmt.Errorf("bad --since %q (use e.g. 7d or 36h)", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("bad --since %q (use e.g. 7d or 36h)", s)
	}
	return d, nil
}

func home() string {
	if h := os.Getenv("XINPROOF_HOME"); h != "" {
		return h
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".xinproof")
	}
	return ".xinproof"
}

func firstEnv(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}

func randomID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func commit() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 12 {
				return s.Value[:12]
			}
		}
	}
	return ""
}
