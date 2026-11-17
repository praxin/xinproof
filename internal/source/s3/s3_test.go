package s3_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	s3src "github.com/praxin/xinproof/internal/source/s3"
	"github.com/praxin/xinproof/internal/source/s3/s3test"
)

// IsolateAWS keeps tests away from the developer's real AWS config and credentials.
func isolateAWS(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
}

func b64sha(b []byte) string { s := sha256.Sum256(b); return base64.StdEncoding.EncodeToString(s[:]) }

func TestS3Source(t *testing.T) {
	isolateAWS(t)
	now := time.Date(2026, 11, 16, 2, 0, 0, 0, time.UTC)
	body := []byte("PGDMP pretend dump bytes")
	objs := map[string]s3test.Object{
		"postgres/pg_2026-11-14.dump": {Body: body, LastModified: now, ChecksumSHA256: b64sha(body)},
		"postgres/pg_2026-11-15.dump": {Body: []byte("x"), LastModified: now, ChecksumSHA256: b64sha([]byte("x")) + "-3"}, // multipart: composite
		"postgres/nested/pg.sql.gz":   {Body: []byte("y"), LastModified: now},
		"postgres/":                   {Body: nil, LastModified: now}, // folder placeholder
		"other/ignored.dump":          {Body: []byte("z"), LastModified: now},
		"postgres/pg_2026-11-13.dump": {Body: []byte("w"), LastModified: now},
		"postgres/pg_2026-11-12.dump": {Body: []byte("v"), LastModified: now},
	}
	srv := s3test.New("acme", objs)
	defer srv.Close()
	srv.PageSize = 2 // force pagination

	ctx := context.Background()
	src, err := s3src.New(ctx, "acme", "postgres/", s3src.Options{Endpoint: srv.URL, Region: "us-east-1", PathStyle: true})
	if err != nil {
		t.Fatal(err)
	}
	list, err := src.List(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, o := range list {
		names = append(names, o.Name)
	}
	if got, want := strings.Join(names, ","), "nested/pg.sql.gz,pg_2026-11-12.dump,pg_2026-11-13.dump,pg_2026-11-14.dump,pg_2026-11-15.dump"; got != want {
		t.Errorf("listed %s\nwant   %s", got, want)
	}
	if list[3].URL != "s3://acme/postgres/pg_2026-11-14.dump" || list[3].Size != int64(len(body)) || !list[3].LastModified.Equal(now) {
		t.Errorf("object = %+v", list[3])
	}

	st, err := src.Stat(ctx, "postgres/pg_2026-11-14.dump")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	if st.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("provider sha256 = %q", st.SHA256)
	}
	st2, err := src.Stat(ctx, "postgres/pg_2026-11-15.dump")
	if err != nil {
		t.Fatal(err)
	}
	if st2.SHA256 != "" {
		t.Errorf("composite multipart checksum used as a full-object hash: %q", st2.SHA256)
	}

	rc, err := src.Open(ctx, "postgres/pg_2026-11-14.dump")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if string(got) != string(body) {
		t.Errorf("Open returned %q", got)
	}

	// Read-only guarantee: only list (GET ?list-type=2), HEAD and GET object.
	for _, r := range srv.Requests() {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			t.Errorf("non-read request: %s %s?%s", r.Method, r.Path, r.Query)
		}
	}
}

func TestS3Errors(t *testing.T) {
	isolateAWS(t)
	ctx := context.Background()
	tests := []struct {
		deny, bucket, want string
	}{
		{deny: "AccessDenied", bucket: "acme", want: "s3:ListBucket"},
		{bucket: "missing", want: `bucket "missing" does not exist`},
		{deny: "InvalidAccessKeyId", bucket: "acme", want: "credentials rejected"},
	}
	for _, tt := range tests {
		srv := s3test.New("acme", map[string]s3test.Object{})
		srv.Deny = tt.deny
		src, err := s3src.New(ctx, tt.bucket, "", s3src.Options{Endpoint: srv.URL, Region: "us-east-1", PathStyle: true})
		if err != nil {
			t.Fatal(err)
		}
		_, err = src.List(ctx, "")
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("deny=%q bucket=%q: err = %v, want it to mention %q", tt.deny, tt.bucket, err, tt.want)
		}
	}
}
