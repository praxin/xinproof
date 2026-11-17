// Package conformance is the one test suite every storage backend must pass,
// against its emulator in CI (MinIO, Azurite, fake-gcs-server) and the local
// filesystem. A backend feature isn't done until it passes here.
package conformance

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"io"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/praxin/xinproof/internal/source"
)

// Backend describes one storage backend under test.
type Backend struct {
	Name string
	// Setup stores objects (keys relative to the location) in a fresh, empty
	// location and returns a read-only Source for it. Test code may write;
	// the Source itself never does.
	Setup func(t *testing.T, objects map[string][]byte) source.Source
	// Published lists the checksums the backend's Stat must report: "sha256", "md5", "crc32c".
	Published []string
}

// Objects is the fixture every backend is tested with.
func Objects() map[string][]byte {
	big := make([]byte, 6<<20+123) // over typical multipart / chunking thresholds
	rand.Read(big)
	return map[string][]byte{
		"pg_2026-11-14.dump":        []byte("PGDMP" + strings.Repeat("a", 1000)),
		"nested/deeper/shop.sql.gz": {0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3},
		"with space é.dump":         []byte("unicode and spaces in names"),
		"empty.dump":                {},
		"big.dump":                  big,
	}
}

func Run(t *testing.T, b Backend) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	objs := Objects()
	start := time.Now().Add(-time.Hour)
	src := b.Setup(t, objs)

	t.Run(b.Name+"/List", func(t *testing.T) {
		list, err := src.List(ctx, "")
		if err != nil {
			t.Fatal(err)
		}
		var got, want []string
		byName := map[string]source.Object{}
		for _, o := range list {
			got = append(got, o.Name)
			byName[o.Name] = o
		}
		for k := range objs {
			want = append(want, k)
		}
		sort.Strings(got)
		sort.Strings(want)
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Fatalf("listed %q, want %q", got, want)
		}
		for name, body := range objs {
			o := byName[name]
			if o.Size != int64(len(body)) {
				t.Errorf("%s: size %d, want %d", name, o.Size, len(body))
			}
			if o.LastModified.IsZero() || o.LastModified.Before(start) || o.LastModified.After(time.Now().Add(time.Hour)) {
				t.Errorf("%s: implausible LastModified %v", name, o.LastModified)
			}
			if o.Key == "" || !strings.Contains(o.URL, strings.TrimPrefix(name, "/")) {
				t.Errorf("%s: key %q url %q", name, o.Key, o.URL)
			}
		}
		sub, err := src.List(ctx, "nested/")
		if err != nil {
			t.Fatal(err)
		}
		if len(sub) != 1 || sub[0].Name != "nested/deeper/shop.sql.gz" {
			t.Errorf("List(nested/) = %+v", sub)
		}
	})

	t.Run(b.Name+"/OpenAndStat", func(t *testing.T) {
		list, err := src.List(ctx, "")
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range list {
			want := objs[o.Name]
			rc, err := src.Open(ctx, o.Key)
			if err != nil {
				t.Fatalf("%s: open: %v", o.Name, err)
			}
			got, err := io.ReadAll(rc)
			rc.Close()
			if err != nil || !bytes.Equal(got, want) {
				t.Errorf("%s: read %d bytes (err %v), want %d", o.Name, len(got), err, len(want))
			}
			st, err := src.Stat(ctx, o.Key)
			if err != nil {
				t.Fatalf("%s: stat: %v", o.Name, err)
			}
			if st.Size != int64(len(want)) {
				t.Errorf("%s: stat size %d", o.Name, st.Size)
			}
			s := sha256.Sum256(want)
			m := md5.Sum(want)
			c := crc32.Checksum(want, crc32.MakeTable(crc32.Castagnoli))
			for _, alg := range b.Published {
				var have, exp string
				switch alg {
				case "sha256":
					have, exp = st.SHA256, hex.EncodeToString(s[:])
				case "md5":
					have, exp = st.MD5, hex.EncodeToString(m[:])
				case "crc32c":
					have, exp = st.CRC32C, fmt.Sprintf("%08x", c)
				}
				if have != exp {
					t.Errorf("%s: provider %s = %q, want %q", o.Name, alg, have, exp)
				}
			}
		}
	})

	t.Run(b.Name+"/Missing", func(t *testing.T) {
		missing := "does-not-exist.dump"
		if list, err := src.List(ctx, ""); err == nil && len(list) > 0 {
			k := list[0].Key
			missing = k[:len(k)-len(list[0].Name)] + missing
		}
		if _, err := src.Stat(ctx, missing); err == nil {
			t.Error("Stat of a missing object succeeded")
		}
		if rc, err := src.Open(ctx, missing); err == nil {
			_, rerr := io.ReadAll(rc)
			rc.Close()
			if rerr == nil {
				t.Error("Open of a missing object succeeded")
			}
		}
	})
}
