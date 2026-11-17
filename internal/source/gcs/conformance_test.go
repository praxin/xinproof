package gcs_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/option"

	"github.com/praxin/xinproof/internal/source"
	"github.com/praxin/xinproof/internal/source/conformance"
	gcssrc "github.com/praxin/xinproof/internal/source/gcs"
)

func TestConformanceFakeGCS(t *testing.T) {
	base := conformance.StartEmulator(t, conformance.FakeGCSImage, 0, "/storage/v1/b",
		"-scheme", "http", "-port", "{PORT}", "-external-url", "http://127.0.0.1:{PORT}", "-backend", "memory")
	ctx := context.Background()
	admin, err := storage.NewClient(ctx, option.WithEndpoint(base+"/storage/v1/"), option.WithoutAuthentication())
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	seed := func(t *testing.T, objs map[string][]byte) string {
		n++
		bucket := fmt.Sprintf("conf-%d-%d", time.Now().UnixNano()%1e6, n)
		if err := admin.Bucket(bucket).Create(ctx, "test-project", nil); err != nil {
			t.Fatal(err)
		}
		put := func(k string, b []byte) {
			w := admin.Bucket(bucket).Object(k).NewWriter(ctx)
			w.ChunkSize = 0 // single-request upload; the emulator drops large chunked ones
			w.Write(b)
			if err := w.Close(); err != nil {
				t.Fatalf("upload %s: %v", k, err)
			}
		}
		for k, b := range objs {
			put("pg/"+k, b)
		}
		put("other/outside.dump", []byte("not under the location"))
		return bucket
	}
	// Via --endpoint.
	conformance.Run(t, conformance.Backend{
		Name:      "gcs-endpoint",
		Published: []string{"md5", "crc32c"},
		Setup: func(t *testing.T, objs map[string][]byte) source.Source {
			s, err := gcssrc.New(ctx, seed(t, objs), "pg/", gcssrc.Options{Endpoint: base})
			if err != nil {
				t.Fatal(err)
			}
			return s
		},
	})
	// Via STORAGE_EMULATOR_HOST, as the Google client libraries document.
	t.Setenv("STORAGE_EMULATOR_HOST", strings.TrimPrefix(base, "http://"))
	conformance.Run(t, conformance.Backend{
		Name:      "gcs-emulator-host",
		Published: []string{"md5", "crc32c"},
		Setup: func(t *testing.T, objs map[string][]byte) source.Source {
			s, err := gcssrc.New(ctx, seed(t, objs), "pg/", gcssrc.Options{})
			if err != nil {
				t.Fatal(err)
			}
			return s
		},
	})

	s, _ := gcssrc.New(ctx, "no-such-bucket", "", gcssrc.Options{Endpoint: base})
	if _, err := s.List(ctx, ""); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("missing bucket: err = %v", err)
	}
}
