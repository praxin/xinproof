package receipt

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
)

// Store is a local directory of receipts plus a HEAD file recording the chain head.
type Store struct {
	Dir string
}

type head struct {
	Seq  int64  `json:"seq"`
	Hash string `json:"hash"`
	File string `json:"file"`
}

var receiptName = regexp.MustCompile(`^receipt-(\d+)\.json$`)

// FileName is the on-disk name of the receipt with sequence number seq.
func FileName(seq int64) string { return fmt.Sprintf("receipt-%06d.json", seq) }

// Append chains r onto the store's head, signs it, and writes it. It returns the written path.
func (s *Store) Append(r *Receipt, priv ed25519.PrivateKey) (string, error) {
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return "", err
	}
	// Concurrent runs writing to the same directory must not fork the chain:
	// read HEAD, write the receipt and update HEAD under one lock.
	unlock, err := lockDir(s.Dir)
	if err != nil {
		return "", fmt.Errorf("locking %s: %w", s.Dir, err)
	}
	defer unlock()
	h, err := s.head()
	if err != nil {
		return "", err
	}
	r.Chain = Chain{Prev: h.Hash, Seq: h.Seq + 1}
	if err := r.Sign(priv); err != nil {
		return "", err
	}
	hash, err := r.Hash()
	if err != nil {
		return "", err
	}
	doc, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	name := FileName(r.Chain.Seq)
	path := filepath.Join(s.Dir, name)
	if err := writeAtomic(path, append(doc, '\n'), true); err != nil {
		return "", err
	}
	hb, _ := json.MarshalIndent(head{Seq: r.Chain.Seq, Hash: hash, File: name}, "", "  ")
	if err := writeAtomic(filepath.Join(s.Dir, "HEAD"), append(hb, '\n'), false); err != nil {
		return "", err
	}
	return path, nil
}

// head reads HEAD, or rebuilds it from the highest-numbered receipt if HEAD is missing.
func (s *Store) head() (head, error) {
	b, err := os.ReadFile(filepath.Join(s.Dir, "HEAD"))
	if err == nil {
		var h head
		if err := json.Unmarshal(b, &h); err != nil {
			return head{}, fmt.Errorf("receipts HEAD is corrupt: %w", err)
		}
		return h, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return head{}, err
	}
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return head{}, err
	}
	var best int64
	var bestName string
	for _, e := range entries {
		m := receiptName.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		n, _ := strconv.ParseInt(m[1], 10, 64)
		if n > best {
			best, bestName = n, e.Name()
		}
	}
	if bestName == "" {
		return head{Seq: 0, Hash: GenesisPrev}, nil
	}
	doc, err := os.ReadFile(filepath.Join(s.Dir, bestName))
	if err != nil {
		return head{}, err
	}
	v, err := Verify(doc, nil)
	if err != nil {
		return head{}, fmt.Errorf("cannot continue chain from %s: %w", bestName, err)
	}
	return head{Seq: v.Receipt.Chain.Seq, Hash: v.Hash, File: bestName}, nil
}

func writeAtomic(path string, data []byte, exclusive bool) error {
	if exclusive {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists; refusing to overwrite a receipt", path)
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_ = tmp.Chmod(0o644) // receipts are meant to be shared
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
