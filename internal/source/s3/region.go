package s3

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

// regionProbeURL is where BucketRegion asks; tests point it elsewhere.
var regionProbeURL = func(bucket string) string {
	if strings.Contains(bucket, ".") { // dotted names don't match the wildcard TLS certificate
		return "https://s3.amazonaws.com/" + bucket
	}
	return "https://" + bucket + ".s3.amazonaws.com/"
}

// BucketRegion asks AWS which region a bucket is in. S3 reports it in the
// x-amz-bucket-region header of an unauthenticated HEAD, whether the answer is
// 200, 301 or 403, so this works for private buckets without credentials.
func BucketRegion(ctx context.Context, bucket string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, regionProbeURL(bucket), nil)
	if err != nil {
		return "", err
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	if r := resp.Header.Get("x-amz-bucket-region"); r != "" {
		return r, nil
	}
	return "", errors.New("S3 did not report the bucket's region")
}
