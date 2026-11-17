package verify

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/praxin/xinproof/internal/receipt"
	"github.com/praxin/xinproof/internal/source/local"
)

// pgHeader builds a PGDMP header with the given archive format byte
// (1 custom, 3 tar, 5 directory).
func pgHeader(format byte) []byte {
	var b bytes.Buffer
	b.WriteString("PGDMP")
	b.Write([]byte{1, 15, 0, 4, 8, format, 0})
	for i := 0; i < 7; i++ {
		b.Write([]byte{0, 1, 0, 0, 0})
	}
	for _, s := range []string{"shop", "16.4", "16.4"} {
		b.Write([]byte{0, byte(len(s)), 0, 0, 0})
		b.WriteString(s)
	}
	b.WriteString("…rest of the TOC…")
	return b.Bytes()
}

func pgTar(files map[string][]byte) []byte {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	var names []string
	if _, ok := files["toc.dat"]; ok {
		names = append(names, "toc.dat") // pg_dump writes toc.dat first
	}
	for n := range files {
		if n != "toc.dat" {
			names = append(names, n)
		}
	}
	for _, n := range names {
		tw.WriteHeader(&tar.Header{Name: n, Mode: 0o600, Size: int64(len(files[n])), Typeflag: tar.TypeReg})
		tw.Write(files[n])
	}
	tw.Close()
	return b.Bytes()
}

func writeFiles(t *testing.T, root string, files map[string][]byte) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func untar(t *testing.T, b []byte) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(b))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatalf("sandbox received an invalid tar: %v", err)
		}
		body, _ := io.ReadAll(tr)
		out[h.Name] = body
	}
}

func TestDirectoryAndTarFormats(t *testing.T) {
	dataGz := gzipped(bytes.Repeat([]byte("1\tcustomer\n"), 5000))
	dirFiles := map[string][]byte{
		"nightly/shop.dir/toc.dat":     pgHeader(5),
		"nightly/shop.dir/3301.dat.gz": dataGz,
		"nightly/shop.dir/3302.dat":    []byte("1\t2\n"),
	}
	tests := []struct {
		name    string
		files   map[string][]byte
		want    map[string]receipt.Result // by result name
		skipped int
	}{
		{
			name:  "directory dump is one backup",
			files: dirFiles,
			want:  map[string]receipt.Result{"nightly/shop.dir/": receipt.Pass},
		},
		{
			name: "directory dump with a truncated data file",
			files: map[string][]byte{
				"d/toc.dat":     pgHeader(5),
				"d/3301.dat.gz": dataGz[:len(dataGz)/2],
			},
			want: map[string]receipt.Result{"d/": receipt.Fail},
		},
		{
			name: "toc.dat that is not a directory TOC",
			files: map[string][]byte{
				"d/toc.dat": []byte("garbage"),
			},
			want: map[string]receipt.Result{"d/": receipt.Fail},
		},
		{
			name: "pg_dump tar archive",
			files: map[string][]byte{
				"shop.tar":        pgTar(map[string][]byte{"toc.dat": pgHeader(3), "3301.dat": []byte("x")}),
				"shop.tar.gz":     gzipped(pgTar(map[string][]byte{"toc.dat": pgHeader(3)})),
				"photos.tar":      pgTar(map[string][]byte{"toc.dat": []byte("not pg")})[0:0], // empty: not a pg tar
				"site-backup.tar": pgTar(map[string][]byte{"index.html": []byte("<html>")}),
				"plain.dump":      pgHeader(1),
			},
			want: map[string]receipt.Result{"shop.tar": receipt.Pass, "shop.tar.gz": receipt.Pass, "plain.dump": receipt.Pass},
			// photos.tar (empty) and site-backup.tar (not pg_dump) are other tarballs, not backups.
			skipped: 2,
		},
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			data := filepath.Join(dir, "data")
			writeFiles(t, data, tt.files)
			src, _ := local.New(data)
			eng := &fakeEngine{outcome: passOutcome}
			var plan Plan
			v := &Verifier{Src: src, Engine: eng, Opts: Options{
				Store: &receipt.Store{Dir: filepath.Join(dir, "receipts")}, Key: priv,
				OnPlan: func(p Plan) { plan = p },
			}}
			results, err := v.Run(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]receipt.Result{}
			for _, r := range results {
				got[r.Object.Name] = r.Status
				if r.ReceiptPath == "" {
					t.Errorf("%s: no receipt", r.Object.Name)
				}
				t.Logf("%s: %s %s", r.Object.Name, r.Status, r.Reason)
			}
			if len(got) != len(tt.want) {
				t.Errorf("results %v, want %v", got, tt.want)
			}
			for name, w := range tt.want {
				if got[name] != w {
					t.Errorf("%s = %q, want %s", name, got[name], w)
				}
			}
			if plan.Skipped != tt.skipped {
				t.Errorf("skipped %d, want %d", plan.Skipped, tt.skipped)
			}
			if eng.sessions != eng.closed {
				t.Errorf("sandbox leak: %d started, %d closed", eng.sessions, eng.closed)
			}
		})
	}

	// The sandbox receives the directory as a tar with every file intact.
	dir := t.TempDir()
	writeFiles(t, dir, dirFiles)
	src, _ := local.New(dir)
	eng := &fakeEngine{outcome: passOutcome}
	v := &Verifier{Src: src, Engine: eng, Opts: Options{}}
	results, err := v.Run(context.Background())
	if err != nil || len(results) != 1 {
		t.Fatalf("results %v err %v", results, err)
	}
	var uploaded []byte
	for _, b := range eng.uploaded {
		uploaded = b
	}
	files := untar(t, uploaded)
	var names []string
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "3301.dat.gz,3302.dat,toc.dat" {
		t.Errorf("tar entries %v", names)
	}
	if !bytes.Equal(files["3301.dat.gz"], dataGz) || !bytes.Equal(files["toc.dat"], pgHeader(5)) {
		t.Error("tar contents differ from the source files")
	}
	if rc := results[0].Receipt; rc.Subject.Format != "postgres-directory" || len(rc.Subject.SHA256) != 64 || rc.Subject.Size != int64(len(dataGz)+len(pgHeader(5))+4) {
		t.Errorf("receipt subject %+v", rc.Subject)
	}
}
