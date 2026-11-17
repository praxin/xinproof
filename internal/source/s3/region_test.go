package s3

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestBucketRegion(t *testing.T) {
	for _, status := range []int{200, 301, 403} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodHead || r.Header.Get("Authorization") != "" {
				t.Errorf("probe sent %s with auth %q; want an unsigned HEAD", r.Method, r.Header.Get("Authorization"))
			}
			w.Header().Set("x-amz-bucket-region", "eu-central-1")
			w.WriteHeader(status)
		}))
		old := regionProbeURL
		regionProbeURL = func(string) string { return srv.URL }
		r, err := BucketRegion(context.Background(), "b")
		regionProbeURL = old
		srv.Close()
		if err != nil || r != "eu-central-1" {
			t.Errorf("status %d: region %q err %v", status, r, err)
		}
	}
	if !strings.HasPrefix(regionProbeURL("my.dotted.bucket"), "https://s3.amazonaws.com/") {
		t.Error("dotted bucket names must use path-style probing")
	}
}

// TestRealAWSPublicBucket reads a public AWS Open Data bucket in eu-central-1,
// without credentials and without --region: listing, Stat and Open must work
// against real S3 in a region other than the default. Opt in with
// XINPROOF_REAL_AWS=1 (needs internet).
func TestRealAWSPublicBucket(t *testing.T) {
	if os.Getenv("XINPROOF_REAL_AWS") != "1" {
		t.Skip("set XINPROOF_REAL_AWS=1 to run against real AWS")
	}
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	ctx := context.Background()
	const bucket, prefix = "copernicus-dem-30m", "Copernicus_DSM_COG_10_N00_00_E006_00_DEM/AUXFILES/"
	if r, err := BucketRegion(ctx, bucket); err != nil || r != "eu-central-1" {
		t.Fatalf("BucketRegion = %q, %v", r, err)
	}
	src, err := New(ctx, bucket, prefix, Options{Anonymous: true})
	if err != nil {
		t.Fatal(err)
	}
	list, err := src.List(ctx, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) == 0 {
		t.Fatal("no objects listed")
	}
	var small = list[0]
	for _, o := range list {
		if o.Size > 0 && o.Size < small.Size {
			small = o
		}
	}
	st, err := src.Stat(ctx, small.Key)
	if err != nil || st.Size != small.Size || st.LastModified.IsZero() {
		t.Fatalf("stat %s: %+v %v", small.Key, st, err)
	}
	rc, err := src.Open(ctx, small.Key)
	if err != nil {
		t.Fatal(err)
	}
	n, err := io.Copy(io.Discard, rc)
	rc.Close()
	if err != nil || n != small.Size {
		t.Fatalf("read %d of %d bytes: %v", n, small.Size, err)
	}
	t.Logf("real AWS: listed %d objects in s3://%s/%s (eu-central-1), read %s (%d bytes)", len(list), bucket, prefix, small.Name, n)

	// Forcing the wrong region gives an actionable message, not a raw redirect.
	wrong, _ := New(ctx, bucket, prefix, Options{Anonymous: true, Region: "us-east-1"})
	if _, err := wrong.List(ctx, ""); err == nil || !strings.Contains(err.Error(), "region") {
		t.Errorf("wrong region: err = %v, want a hint about --region", err)
	}
}
