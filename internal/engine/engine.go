// Package engine defines how a database engine restores and checks a backup
// inside a sandbox. Implementations live in subpackages (postgres; mysql later).
package engine

import (
	"context"
	"io"
	"time"

	"github.com/praxin/xinproof/internal/discover"
	"github.com/praxin/xinproof/internal/receipt"
)

type Engine interface {
	// Supports reports whether this engine can restore the detected format.
	Supports(d discover.Detection) bool
	// Analyzer returns a structural checker fed with the decompressed dump
	// while it streams, or nil. It runs even when no sandbox is available, so
	// structural problems are FAILs regardless of Docker.
	Analyzer(d discover.Detection) Analyzer
	// Start creates a ready-to-use sandbox for this backup.
	Start(ctx context.Context, d discover.Detection) (Session, error)
}

type Analyzer interface {
	io.Writer
	// Finish returns the structural checks; any with status "fail" fails the backup.
	Finish() []receipt.Check
}

type Session interface {
	// Image is the sandbox image reference, pinned by digest when known.
	Image() string
	// Upload returns a writer for the decompressed dump and a wait function
	// that returns once the sandbox has stored it.
	Upload(ctx context.Context) (io.WriteCloser, func() error)
	// UploadDir is like Upload, but takes a tar stream of a dump directory
	// (pg_dump -Fd), which the sandbox unpacks.
	UploadDir(ctx context.Context) (io.WriteCloser, func() error)
	// Restore restores the uploaded dump and runs the checks.
	Restore(ctx context.Context, a Analyzer) Outcome
	// Close destroys the sandbox. It must be safe to call on any path.
	Close() error
}

type Outcome struct {
	Result         receipt.Result
	Reason         string
	Checks         []receipt.Check
	RestoreSeconds float64
	Tables         int
	Rows           int64
	RowsKnown      bool
	// TableCounts are the restored tables with exact row counts, when the
	// engine got as far as counting them; they become the receipt's "tables".
	TableCounts []TableCount
}

// Seconds rounds a duration to milliseconds for receipts.
func Seconds(d time.Duration) float64 { return float64(d.Milliseconds()) / 1000 }
