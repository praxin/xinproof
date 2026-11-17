package postgres

import (
	"archive/tar"
	"bytes"
	"strings"
	"testing"

	"github.com/praxin/xinproof/internal/receipt"
)

func sampleTar() []byte {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, f := range []struct {
		name string
		size int
	}{{"toc.dat", 700}, {"3301.dat", 5000}, {"3302.dat", 1200}, {"restore.sql", 300}} {
		tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o600, Size: int64(f.size), Typeflag: tar.TypeReg})
		tw.Write(bytes.Repeat([]byte{'x'}, f.size))
	}
	tw.Close()
	return b.Bytes()
}

func TestTarAnalyzer(t *testing.T) {
	full := sampleTar()
	corrupt := append([]byte(nil), full...)
	copy(corrupt[1536:], bytes.Repeat([]byte{0xff}, 200)) // smash the second entry's header
	tests := []struct {
		name   string
		in     []byte
		status string
		detail string
	}{
		{"complete", full, receipt.CheckPass, "4 entries"},
		{"truncated inside an entry", full[:len(full)*61/100], receipt.CheckFail, "truncated"},
		{"truncated at a block boundary", full[:512*4], receipt.CheckFail, "truncated"},
		{"end marker missing", full[:len(full)-1024], receipt.CheckFail, "end-of-archive marker"},
		{"corrupt header", corrupt, receipt.CheckFail, "corrupt"},
		{"empty", nil, receipt.CheckFail, "end-of-archive marker"},
	}
	for _, tt := range tests {
		for _, chunk := range []int{1, 333, 1 << 16} {
			a := NewTarAnalyzer()
			for in := tt.in; len(in) > 0; {
				n := min(chunk, len(in))
				a.Write(in[:n])
				in = in[n:]
			}
			c := a.Finish()
			if len(c) != 1 || c[0].Status != tt.status || !strings.Contains(c[0].Detail, tt.detail) {
				t.Errorf("%s (chunk %d): %+v, want %s containing %q", tt.name, chunk, c, tt.status, tt.detail)
			}
		}
	}
}
