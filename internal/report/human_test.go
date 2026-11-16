package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/praxin/xinproof/internal/receipt"
	"github.com/praxin/xinproof/internal/source"
	"github.com/praxin/xinproof/internal/verify"
)

func TestFormatting(t *testing.T) {
	rows := map[int64]string{0: "0", 9812: "9,812", 12300: "12.3K", 38_100_000: "38.1M", 2_400_000_000: "2.4B"}
	for n, want := range rows {
		if got := HumanRows(n); got != want {
			t.Errorf("HumanRows(%d) = %s, want %s", n, got, want)
		}
	}
	durs := map[time.Duration]string{242 * time.Second: "4m02s", 4 * time.Second: "0m04s", 64 * time.Minute: "1h04m"}
	for d, want := range durs {
		if got := Duration(d); got != want {
			t.Errorf("Duration(%s) = %s, want %s", d, got, want)
		}
	}
}

func TestLines(t *testing.T) {
	var b bytes.Buffer
	h := &Human{W: &b}
	h.Plan(verify.Plan{Found: 30, Testing: 4, Newest: true})
	h.Result(verify.Result{Object: source.Object{Name: "pg_2026-11-14.dump"}, Status: receipt.Pass, Tables: 214, Rows: 38_100_000, RowsKnown: true, Restore: 242 * time.Second})
	h.Result(verify.Result{Object: source.Object{Name: "pg_2026-11-15.dump"}, Status: receipt.Fail, Reason: "gzip stream ends early at byte 812 (truncated)"})
	h.Result(verify.Result{Object: source.Object{Name: "shop.sql"}, Status: receipt.Error, Reason: "docker is not available"})
	want := `  found 30 dumps · restoring newest 4 in sandboxes…
  ✓ pg_2026-11-14.dump  214 tables  38.1M rows  4m02s
  ✗ pg_2026-11-15.dump  gzip stream ends early at byte 812 (truncated)
  ! shop.sql  not tested · docker is not available
`
	if got := b.String(); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	if strings.Contains(b.String(), "\033") {
		t.Error("color codes without Color")
	}
}
