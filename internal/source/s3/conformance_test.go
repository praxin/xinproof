package s3_test

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/praxin/xinproof/internal/source"
	"github.com/praxin/xinproof/internal/source/conformance"
	s3src "github.com/praxin/xinproof/internal/source/s3"
)

// TestConformanceS3Compatible runs the shared backend suite against a real
// S3-compatible store (SeaweedFS). The S3 SHA-256 checksum header is covered
// by the in-process S3 API test server in s3_test.go.
func TestConformanceS3Compatible(t *testing.T) {
	base := conformance.StartEmulator(t, conformance.S3Image, 8333, "/", "server", "-s3", "-dir=/data")
	isolateAWS(t)
	admin := s3.NewFromConfig(aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("test", "test", "")},
		func(o *s3.Options) { o.BaseEndpoint = aws.String(base); o.UsePathStyle = true })
	n := 0
	conformance.Run(t, conformance.Backend{
		Name: "s3-compatible",
		Setup: func(t *testing.T, objs map[string][]byte) source.Source {
			ctx := context.Background()
			n++
			bucket := fmt.Sprintf("conf-%d-%d", time.Now().UnixNano()%1e6, n)
			if _, err := admin.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
				t.Fatal(err)
			}
			put := func(key string, b []byte) {
				_, err := admin.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(key),
					Body: bytes.NewReader(b)})
				if err != nil {
					t.Fatalf("put %s: %v", key, err)
				}
			}
			for k, b := range objs {
				put("pg/"+k, b)
			}
			put("other/outside.dump", []byte("not under the location"))
			s, err := s3src.New(ctx, bucket, "pg/", s3src.Options{Endpoint: base, Region: "us-east-1", PathStyle: true})
			if err != nil {
				t.Fatal(err)
			}
			return s
		},
	})
}
