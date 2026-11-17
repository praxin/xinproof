// Package source abstracts where backups live. Every backend is read-only:
// it needs list and read permission, and never writes to the source.
package source

import (
	"context"
	"io"
	"time"
)

// Object is one stored object under a location.
type Object struct {
	Key          string    // backend key used with Open/Stat (full S3 key, path relative to a local root)
	Name         string    // display name, relative to the location the user gave
	URL          string    // canonical address, recorded in receipts
	Size         int64     // bytes
	ETag         string    // provider ETag (S3) if any
	LastModified time.Time // zero if unknown
	SHA256       string    // full-object SHA-256 (hex) supplied by the provider, if any
	MD5          string    // full-object MD5 (hex) supplied by the provider (Azure Content-MD5, GCS md5Hash), if any
	CRC32C       string    // full-object CRC32C (hex, big-endian) supplied by the provider (GCS), if any
}

// Source is a read-only view of a backup location.
type Source interface {
	// List returns every object under the location whose name starts with prefix.
	List(ctx context.Context, prefix string) ([]Object, error)
	// Open streams an object's bytes.
	Open(ctx context.Context, key string) (io.ReadCloser, error)
	// Stat returns fresh metadata, including provider checksums where available.
	Stat(ctx context.Context, key string) (Object, error)
	// String is the location as the user should see it.
	String() string
}
