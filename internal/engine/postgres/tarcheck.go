package postgres

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"

	"github.com/praxin/xinproof/internal/receipt"
)

// TarAnalyzer checks the structure of a pg_dump tar-format archive as it
// streams past: every entry must be complete and the archive must end with
// tar's end-of-archive marker. pg_restore will happily restore a truncated tar
// archive up to the point where it stops, so this check is what turns
// "restored most of it" into an explicit FAIL.
type TarAnalyzer struct {
	pw      *io.PipeWriter
	done    chan struct{}
	entries int
	last    string
	err     error
	total   int64
	tail    []byte
}

func NewTarAnalyzer() *TarAnalyzer {
	pr, pw := io.Pipe()
	a := &TarAnalyzer{pw: pw, done: make(chan struct{})}
	go func() {
		defer close(a.done)
		tr := tar.NewReader(pr)
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err == nil {
				_, err = io.Copy(io.Discard, tr)
			}
			if err != nil {
				a.err = err
				io.Copy(io.Discard, pr) // keep accepting writes
				return
			}
			a.entries++
			a.last = h.Name
		}
		io.Copy(io.Discard, pr) // padding after the end-of-archive marker
	}()
	return a
}

func (a *TarAnalyzer) Write(p []byte) (int, error) {
	a.total += int64(len(p))
	a.tail = append(a.tail, p...)
	if len(a.tail) > 4096 {
		a.tail = append(a.tail[:0], a.tail[len(a.tail)-1024:]...)
	}
	return a.pw.Write(p)
}

func (a *TarAnalyzer) Finish() []receipt.Check {
	a.pw.Close()
	<-a.done
	fail := func(detail string) []receipt.Check {
		return []receipt.Check{{ID: "l1.structure", Status: receipt.CheckFail, Detail: detail}}
	}
	if a.err != nil {
		if errors.Is(a.err, io.ErrUnexpectedEOF) {
			return fail(fmt.Sprintf("tar archive is truncated at byte %d (after %d complete entries, last %q)", a.total, a.entries, a.last))
		}
		return fail(fmt.Sprintf("tar archive is corrupt after %d entries: %v", a.entries, a.err))
	}
	if !endsWithZeroBlocks(a.tail) {
		return fail(fmt.Sprintf("tar archive is missing its end-of-archive marker (truncated at byte %d?)", a.total))
	}
	return []receipt.Check{{ID: "l1.structure", Status: receipt.CheckPass, Detail: fmt.Sprintf("complete tar archive, %d entries", a.entries)}}
}

// endsWithZeroBlocks reports whether b ends with tar's end-of-archive marker
// (two 512-byte zero blocks).
func endsWithZeroBlocks(b []byte) bool {
	if len(b) < 1024 {
		return false
	}
	for _, c := range b[len(b)-1024:] {
		if c != 0 {
			return false
		}
	}
	return true
}
