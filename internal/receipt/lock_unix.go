//go:build unix

package receipt

import (
	"os"
	"path/filepath"
	"syscall"
)

// lockDir takes an exclusive advisory lock on dir/.lock (flock), blocking until
// it is free. The kernel releases it if the process dies, so it can't go stale.
func lockDir(dir string) (unlock func(), err error) {
	f, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if err != syscall.EINTR {
			break
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
