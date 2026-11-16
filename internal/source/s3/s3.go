// Package s3 reads backups from AWS S3 and S3-compatible stores
// (Cloudflare R2, MinIO, Backblaze B2, Wasabi, Ceph, …). It only ever calls
// ListObjectsV2, HeadObject and GetObject.
package s3

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/praxin/xinproof/internal/source"
)

type Options struct {
	Scheme    string // "s3" or "r2", used in URLs
	Endpoint  string // custom endpoint for S3-compatible stores
	Region    string
	Profile   string
	PathStyle bool
}

type Source struct {
	client *s3.Client
	bucket string
	prefix string
	scheme string
}

// New creates a source for bucket/prefix using the standard AWS credential chain
// (env vars, shared profiles, SSO, instance/task roles, IRSA).
func New(ctx context.Context, bucket, prefix string, o Options) (*Source, error) {
	if bucket == "" {
		return nil, errors.New("s3: missing bucket name")
	}
	var lo []func(*config.LoadOptions) error
	if o.Region != "" {
		lo = append(lo, config.WithRegion(o.Region))
	}
	if o.Profile != "" {
		lo = append(lo, config.WithSharedConfigProfile(o.Profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, lo...)
	if err != nil {
		return nil, fmt.Errorf("s3: loading AWS config: %w", err)
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	client := s3.NewFromConfig(cfg, func(so *s3.Options) {
		if o.Endpoint != "" {
			so.BaseEndpoint = aws.String(o.Endpoint)
		}
		so.UsePathStyle = o.PathStyle
		// Third-party S3-compatible stores don't all support the newer default checksums.
		so.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		so.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	})
	scheme := o.Scheme
	if scheme == "" {
		scheme = "s3"
	}
	return &Source{client: client, bucket: bucket, prefix: prefix, scheme: scheme}, nil
}

func (s *Source) String() string { return fmt.Sprintf("%s://%s/%s", s.scheme, s.bucket, s.prefix) }

func (s *Source) List(ctx context.Context, prefix string) ([]source.Object, error) {
	p := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(s.prefix + prefix),
	})
	var out []source.Object
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, explain(err, "s3:ListBucket", s.bucket, s.prefix)
		}
		for _, o := range page.Contents {
			key := aws.ToString(o.Key)
			if strings.HasSuffix(key, "/") {
				continue // folder placeholder
			}
			out = append(out, source.Object{
				Key:          key,
				Name:         s.name(key),
				URL:          fmt.Sprintf("%s://%s/%s", s.scheme, s.bucket, key),
				Size:         aws.ToInt64(o.Size),
				ETag:         strings.Trim(aws.ToString(o.ETag), `"`),
				LastModified: aws.ToTime(o.LastModified),
			})
		}
	}
	return out, nil
}

func (s *Source) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
	if err != nil {
		return nil, explain(err, "s3:GetObject", s.bucket, key)
	}
	return out.Body, nil
}

func (s *Source) Stat(ctx context.Context, key string) (source.Object, error) {
	out, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket:       aws.String(s.bucket),
		Key:          aws.String(key),
		ChecksumMode: types.ChecksumModeEnabled,
	})
	if err != nil {
		return source.Object{}, explain(err, "s3:GetObject", s.bucket, key)
	}
	o := source.Object{
		Key:          key,
		Name:         s.name(key),
		URL:          fmt.Sprintf("%s://%s/%s", s.scheme, s.bucket, key),
		Size:         aws.ToInt64(out.ContentLength),
		ETag:         strings.Trim(aws.ToString(out.ETag), `"`),
		LastModified: aws.ToTime(out.LastModified),
	}
	// ChecksumSHA256 is a full-object hash only for single-part uploads;
	// multipart "composite" checksums look like "<base64>-<parts>" and are skipped.
	if c := aws.ToString(out.ChecksumSHA256); c != "" && !strings.Contains(c, "-") {
		if raw, err := base64.StdEncoding.DecodeString(c); err == nil && len(raw) == 32 {
			o.SHA256 = hex.EncodeToString(raw)
		}
	}
	return o, nil
}

func (s *Source) name(key string) string {
	n := strings.TrimPrefix(strings.TrimPrefix(key, s.prefix), "/")
	if n == "" {
		n = path.Base(key)
	}
	return n
}

// explain turns common API errors into actionable messages naming the missing permission.
func explain(err error, perm, bucket, key string) error {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		switch ae.ErrorCode() {
		case "AccessDenied", "Forbidden", "403":
			return fmt.Errorf("access denied to %s/%s: the credentials need %s (%s)", bucket, key, perm, ae.ErrorMessage())
		case "NoSuchBucket":
			return fmt.Errorf("bucket %q does not exist (or is in another account/endpoint)", bucket)
		case "InvalidAccessKeyId", "SignatureDoesNotMatch", "ExpiredToken":
			return fmt.Errorf("credentials rejected (%s): check AWS_PROFILE / AWS_ACCESS_KEY_ID or the endpoint", ae.ErrorCode())
		}
	}
	return err
}
