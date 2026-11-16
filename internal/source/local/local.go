// Package local reads backups from a local directory (or a single file),
// including NFS/SMB mounts.
package local

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/praxin/xinproof/internal/source"
)

type Source struct {
	root string // absolute directory
	only string // if set, the location is this single file within root
	disp string // as given by the user
}

// New opens path, which may be a directory (searched recursively) or one file.
func New(path string) (*Source, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return &Source{root: filepath.Dir(abs), only: filepath.Base(abs), disp: path}, nil
	}
	return &Source{root: abs, disp: path}, nil
}

func (s *Source) String() string { return s.disp }

func (s *Source) List(ctx context.Context, prefix string) ([]source.Object, error) {
	if s.only != "" {
		o, err := s.Stat(ctx, s.only)
		if err != nil {
			return nil, err
		}
		return []source.Object{o}, nil
	}
	var out []source.Object
	err := filepath.WalkDir(s.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() {
			if p != s.root && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir // .git, .xinproof, …
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(s.root, p)
		if err != nil {
			return err
		}
		key := filepath.ToSlash(rel)
		if !strings.HasPrefix(key, prefix) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		out = append(out, s.object(key, info))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func (s *Source) Open(_ context.Context, key string) (io.ReadCloser, error) {
	return os.Open(s.path(key))
}

func (s *Source) Stat(_ context.Context, key string) (source.Object, error) {
	info, err := os.Stat(s.path(key))
	if err != nil {
		return source.Object{}, err
	}
	return s.object(key, info), nil
}

func (s *Source) path(key string) string { return filepath.Join(s.root, filepath.FromSlash(key)) }

func (s *Source) object(key string, info fs.FileInfo) source.Object {
	return source.Object{
		Key:          key,
		Name:         key,
		URL:          filepath.ToSlash(s.path(key)),
		Size:         info.Size(),
		LastModified: info.ModTime().UTC(),
	}
}
