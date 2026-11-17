// Package gcs reads backups from Google Cloud Storage. The client asks for the
// read-only OAuth scope, so even an over-privileged identity can't write
// through it.
package gcs

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"

	"cloud.google.com/go/storage"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"

	"github.com/praxin/xinproof/internal/source"
)

type Options struct {
	// Endpoint overrides the JSON API endpoint (e.g. fake-gcs-server); no
	// authentication is used with a custom endpoint. STORAGE_EMULATOR_HOST is
	// honored too.
	Endpoint string
}

type Source struct {
	client *storage.Client
	bucket string
	prefix string
}

// New uses Application Default Credentials (GOOGLE_APPLICATION_CREDENTIALS,
// gcloud auth application-default login, workload identity, the metadata server).
func New(ctx context.Context, bucket, prefix string, o Options) (*Source, error) {
	if bucket == "" {
		return nil, errors.New("gcs: location must be gs://<bucket>/<prefix>")
	}
	// JSON API reads (rather than XML) behave the same on GCS and its emulators.
	opts := []option.ClientOption{option.WithScopes(storage.ScopeReadOnly), storage.WithJSONReads()}
	if o.Endpoint != "" {
		opts = append(opts, option.WithEndpoint(strings.TrimSuffix(o.Endpoint, "/")+"/storage/v1/"), option.WithoutAuthentication())
	}
	c, err := storage.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("gcs: setting up credentials (gcloud auth application-default login?): %w", err)
	}
	return &Source{client: c, bucket: bucket, prefix: prefix}, nil
}

func (s *Source) String() string      { return fmt.Sprintf("gs://%s/%s", s.bucket, s.prefix) }
func (s *Source) url(k string) string { return fmt.Sprintf("gs://%s/%s", s.bucket, k) }

func (s *Source) name(key string) string {
	n := strings.TrimPrefix(strings.TrimPrefix(key, s.prefix), "/")
	if n == "" {
		n = path.Base(key)
	}
	return n
}

func (s *Source) object(a *storage.ObjectAttrs) source.Object {
	o := source.Object{Key: a.Name, Name: s.name(a.Name), URL: s.url(a.Name), Size: a.Size, ETag: a.Etag, LastModified: a.Updated.UTC()}
	if len(a.MD5) == 16 { // absent for composite objects
		o.MD5 = hex.EncodeToString(a.MD5)
	}
	o.CRC32C = fmt.Sprintf("%08x", a.CRC32C)
	return o
}

func (s *Source) List(ctx context.Context, prefix string) ([]source.Object, error) {
	it := s.client.Bucket(s.bucket).Objects(ctx, &storage.Query{Prefix: s.prefix + prefix})
	var out []source.Object
	for {
		a, err := it.Next()
		if err == iterator.Done {
			return out, nil
		}
		if err != nil {
			return nil, s.explain(err, "storage.objects.list")
		}
		if strings.HasSuffix(a.Name, "/") {
			continue // folder placeholder
		}
		out = append(out, s.object(a))
	}
}

func (s *Source) Stat(ctx context.Context, key string) (source.Object, error) {
	a, err := s.client.Bucket(s.bucket).Object(key).Attrs(ctx)
	if err != nil {
		return source.Object{}, s.explain(err, "storage.objects.get")
	}
	return s.object(a), nil
}

func (s *Source) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	r, err := s.client.Bucket(s.bucket).Object(key).NewReader(ctx)
	if err != nil {
		return nil, s.explain(err, "storage.objects.get")
	}
	return r, nil
}

func (s *Source) explain(err error, perm string) error {
	var ge *googleapi.Error
	switch {
	case errors.Is(err, storage.ErrBucketNotExist):
		return fmt.Errorf("bucket %q does not exist (or the project can't see it)", s.bucket)
	case errors.Is(err, storage.ErrObjectNotExist):
		return fmt.Errorf("object not found: %w", err)
	case errors.As(err, &ge) && ge.Code == http.StatusForbidden:
		return fmt.Errorf("access denied to gs://%s: the identity needs %s (e.g. roles/storage.objectViewer)", s.bucket, perm)
	case errors.As(err, &ge) && ge.Code == http.StatusUnauthorized:
		return fmt.Errorf("credentials rejected: run `gcloud auth application-default login` or set GOOGLE_APPLICATION_CREDENTIALS")
	}
	return err
}
