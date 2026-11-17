package local_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/praxin/xinproof/internal/source"
	"github.com/praxin/xinproof/internal/source/conformance"
	"github.com/praxin/xinproof/internal/source/local"
)

func TestConformance(t *testing.T) {
	conformance.Run(t, conformance.Backend{
		Name: "local",
		Setup: func(t *testing.T, objs map[string][]byte) source.Source {
			dir := t.TempDir()
			write := func(rel string, b []byte) {
				p := filepath.Join(dir, filepath.FromSlash(rel))
				os.MkdirAll(filepath.Dir(p), 0o755)
				if err := os.WriteFile(p, b, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			for k, b := range objs {
				write("pg/"+k, b)
			}
			write("other/outside.dump", []byte("not under the location"))
			write("pg/.hidden/skip.dump", []byte("dot directories are skipped"))
			s, err := local.New(filepath.Join(dir, "pg"))
			if err != nil {
				t.Fatal(err)
			}
			return s
		},
	})
}
