//go:build !unix

package receipt

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// lockDir creates dir/.lock exclusively, retrying until it can. Appending a
// receipt takes milliseconds, so a lock file older than staleAfter was left by
// a process that died mid-append and is removed.
func lockDir(dir string) (unlock func(), err error) {
	const staleAfter = 2 * time.Minute
	path := filepath.Join(dir, ".lock")
	deadline := time.Now().Add(staleAfter + 30*time.Second)
	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err == nil {
			fmt.Fprintf(f, "%d\n", os.Getpid())
			f.Close()
			return func() { _ = os.Remove(path) }, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
		if fi, serr := os.Stat(path); serr == nil && time.Since(fi.ModTime()) > staleAfter {
			_ = os.Remove(path)
			continue
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("receipts directory is locked by another xinproof process (%s)", path)
		}
		time.Sleep(25 * time.Millisecond)
	}
}
