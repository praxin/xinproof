// Package report renders verifier results for people (and, later, CI formats).
package report

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/praxin/xinproof/internal/receipt"
	"github.com/praxin/xinproof/internal/verify"
)

type Human struct {
	W     io.Writer
	Color bool
	TTY   bool // allow a transient "restoring…" line
}

const (
	green  = "\033[32m"
	red    = "\033[31m"
	yellow = "\033[33m"
	faint  = "\033[2m"
	cyan   = "\033[36m"
	reset  = "\033[0m"
)

// IsTerminal reports whether f is an interactive terminal.
func IsTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func (h *Human) c(code, s string) string {
	if !h.Color {
		return s
	}
	return code + s + reset
}

func (h *Human) Plan(p verify.Plan) {
	if p.Found == 0 {
		fmt.Fprintln(h.W, h.c(faint, fmt.Sprintf("  found 0 dumps%s", skippedNote(p.Skipped))))
		return
	}
	what := fmt.Sprintf("restoring %d in sandboxes…", p.Testing)
	if p.Newest {
		what = fmt.Sprintf("restoring newest %d in sandboxes…", p.Testing)
	}
	fmt.Fprintln(h.W, h.c(faint, fmt.Sprintf("  found %s · %s%s", plural(p.Found, "dump"), what, skippedNote(p.Skipped))))
}

func skippedNote(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf(" (skipped %s that don't look like backups)", plural(n, "other object"))
}

func (h *Human) Start(name string) {
	if h.TTY {
		fmt.Fprint(h.W, h.c(faint, "  … "+name+"  restoring"))
	}
}

func (h *Human) Result(r verify.Result) {
	if h.TTY {
		fmt.Fprint(h.W, "\r\033[K")
	}
	name := r.Object.Name
	switch r.Status {
	case receipt.Pass:
		parts := []string{}
		if r.RowsKnown {
			parts = append(parts, plural(r.Tables, "table"), HumanRows(r.Rows)+" rows")
		}
		parts = append(parts, Duration(r.Restore))
		fmt.Fprintf(h.W, "  %s %s  %s\n", h.c(green, "✓"), name, strings.Join(parts, "  "))
	case receipt.Fail:
		fmt.Fprintln(h.W, h.c(red, fmt.Sprintf("  ✗ %s  %s", name, r.Reason)))
	default:
		fmt.Fprintln(h.W, h.c(yellow, fmt.Sprintf("  ! %s  not tested · %s", name, r.Reason)))
	}
}

func (h *Human) Footer(results []verify.Result, receiptsDir string) {
	var first, last string
	for _, r := range results {
		if r.ReceiptPath == "" {
			continue
		}
		if first == "" {
			first = r.ReceiptPath
		}
		last = r.ReceiptPath
	}
	if first != "" {
		span := rel(first)
		if last != first {
			span += " … " + filepath.Base(last)
		}
		fmt.Fprintln(h.W, h.c(faint, "  signed receipts → "+span))
		fmt.Fprintln(h.W, h.c(faint, "  check one: xinproof receipt verify "+rel(last)))
	}
	// One hint after a failure, for people running the CLI by hand. Hidden in
	// runners (XINPROOF_URL is set: they already report somewhere) and when
	// built with an empty CloudURL (e.g. for self-hosted installs).
	if verify.ExitCode(results) == 1 && CloudURL != "" && os.Getenv("XINPROOF_URL") == "" {
		fmt.Fprintln(h.W, h.c(cyan, "  → Have this checked every night, with fix guidance: "+CloudURL))
	}
}

// CloudURL is Xinproof Cloud's address, shown in the hint above. Set at build
// time with -ldflags "-X github.com/praxin/xinproof/internal/report.CloudURL=...";
// empty hides the hint.
var CloudURL = "https://xinproof-cloud.xinproof.workers.dev"

func rel(p string) string {
	// Under systemd the working directory is "/": a relative path would just
	// drop the leading slash, so keep it absolute.
	if wd, err := os.Getwd(); err == nil && wd != string(filepath.Separator) {
		if r, err := filepath.Rel(wd, p); err == nil && !strings.HasPrefix(r, "..") {
			return r
		}
	}
	return p
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return strconv.Itoa(n) + " " + word + "s"
}

// HumanRows formats a row count like the landing page: 9,812 · 412.5K · 38.1M · 2.4B.
func HumanRows(n int64) string {
	switch {
	case n < 10_000:
		return commas(n)
	case n < 1_000_000:
		return fmt.Sprintf("%.1fK", float64(n)/1e3)
	case n < 1_000_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	default:
		return fmt.Sprintf("%.1fB", float64(n)/1e9)
	}
}

func commas(n int64) string {
	s := strconv.FormatInt(n, 10)
	if n < 0 {
		return "-" + commas(-n)
	}
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// Duration formats like 4m02s, or 1h04m for long restores.
func Duration(d time.Duration) string {
	d = d.Round(time.Second)
	if d >= time.Hour {
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
}
