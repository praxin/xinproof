package mongodb

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/praxin/xinproof/internal/engine"
	"github.com/praxin/xinproof/internal/receipt"
)

// testdata/sample.archive is `mongodump --archive` (mongodump 100.20.1,
// MongoDB 7.0) of: shop.customers (5 documents), shop.orders (3), a view
// shop.bigorders, and other.things (1), plus admin.system.version.
func sample(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "sample.archive"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func analyze(b []byte, chunk int) (*ArchiveAnalyzer, receipt.Check) {
	a := NewArchiveAnalyzer()
	for len(b) > 0 {
		n := min(chunk, len(b))
		a.Write(b[:n])
		b = b[n:]
	}
	return a, a.Finish()[0]
}

func TestArchiveAnalyzer(t *testing.T) {
	b := sample(t)
	want := map[string]int64{
		engine.TableKey("", "shop.customers"): 5,
		engine.TableKey("", "shop.orders"):    3,
		engine.TableKey("", "other.things"):   1,
	}
	for _, chunk := range []int{1, 3, 7, 64, 1 << 20} {
		a, c := analyze(b, chunk)
		if c.Status != receipt.CheckPass {
			t.Fatalf("chunk %d: %s %s", chunk, c.Status, c.Detail)
		}
		if fmt.Sprint(a.Rows) != fmt.Sprint(want) || a.Collections != 3 {
			t.Errorf("chunk %d: rows %v collections %d", chunk, a.Rows, a.Collections)
		}
		if chunk == 1 {
			t.Logf("%s", c.Detail)
		}
	}
}

// Every proper prefix of an archive is a truncated archive and must fail.
func TestArchiveAnalyzerTruncated(t *testing.T) {
	b := sample(t)
	for n := 0; n < len(b); n++ {
		_, c := analyze(b[:n], 512)
		if c.Status != receipt.CheckFail || !strings.Contains(c.Detail, "truncated") {
			t.Fatalf("prefix of %d/%d bytes: %s %q", n, len(b), c.Status, c.Detail)
		}
	}
}

func TestArchiveAnalyzerCorrupt(t *testing.T) {
	b := sample(t)
	i := strings.Index(string(b), "c0\x00") // a value inside shop.customers' data
	flipped := append([]byte(nil), b...)
	flipped[i] = 'A'
	_, c := analyze(flipped, 100)
	if c.Status != receipt.CheckFail || !strings.Contains(c.Detail, "shop.customers: data is corrupt (CRC mismatch") {
		t.Errorf("flipped data byte: %s %q", c.Status, c.Detail)
	}

	bad := append([]byte(nil), b...)
	bad[0] = 'X'
	if _, c := analyze(bad, 100); c.Status != receipt.CheckFail {
		t.Errorf("bad magic: %s %q", c.Status, c.Detail)
	}

	// A document length that makes no sense.
	j := strings.Index(string(b), "\xff\xff\xff\xff") + 4
	huge := append([]byte(nil), b...)
	copy(huge[j:], []byte{0xff, 0xff, 0xff, 0x7f})
	if _, c := analyze(huge, 100); c.Status != receipt.CheckFail || !strings.Contains(c.Detail, "corrupt archive") {
		t.Errorf("bad length: %s %q", c.Status, c.Detail)
	}
}

func TestParseCounts(t *testing.T) {
	out := "some warning\nxinproof-counts:[[\"shop.customers\",5000],[\"other.big\",12345678901]]\n"
	got, err := parseCounts(out)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got) != fmt.Sprint([]engine.TableCount{{Qualified: "shop.customers", Rows: 5000}, {Qualified: "other.big", Rows: 12345678901}}) {
		t.Errorf("got %v", got)
	}
	if got, err := parseCounts("xinproof-counts:[]\n"); err != nil || len(got) != 0 {
		t.Errorf("empty: %v %v", got, err)
	}
	for _, bad := range []string{"", "xinproof-counts:{", `xinproof-counts:[["a"]]`, `xinproof-counts:[["a",1.5]]`} {
		if _, err := parseCounts(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestFailedLines(t *testing.T) {
	stderr := "2026-11-17T14:53:55.842+0000\tno indexes to restore\n" +
		"2026-11-17T14:53:55.842+0000\tFailed: corruption found in archive; CRC mismatch for namespace `shop.customers`\n" +
		"2026-11-17T14:53:55.842+0000\t8 document(s) restored successfully. 0 document(s) failed to restore.\n"
	if got := failedLines(stderr); got != "Failed: corruption found in archive; CRC mismatch for namespace `shop.customers`" {
		t.Errorf("got %q", got)
	}
	if m := reRestored.FindStringSubmatch(stderr); m == nil || m[1] != "8" || m[2] != "0" {
		t.Errorf("restored counts: %v", m)
	}

	// A sandbox too small for MongoDB's index builds is the sandbox's fault (ERROR), not the backup's.
	disk := "2026-11-17T15:01:38.000+0000\tFailed: shop.orders: error creating indexes for shop.orders: createIndex error: (OutOfDiskSpace) available disk space of 323080192 bytes is less than required minimum of 524288000\n"
	if why := engine.SandboxFault(disk); !strings.Contains(why, "out of disk space") {
		t.Errorf("SandboxFault = %q", why)
	}
}
