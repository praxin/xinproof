package receipt

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A run killed between writing a receipt and updating HEAD must not break
// the chain or block the next run.
func TestStaleHEADAfterCrash(t *testing.T) {
	dir := t.TempDir()
	s := &Store{Dir: dir}
	priv := testKey(t)
	if _, err := s.Append(sample(Pass), priv); err != nil {
		t.Fatal(err)
	}
	staleHead, _ := os.ReadFile(filepath.Join(dir, "HEAD"))
	if _, err := s.Append(sample(Fail), priv); err != nil {
		t.Fatal(err)
	}
	// Simulate the crash: receipt 2 is on disk, HEAD still points at 1.
	os.WriteFile(filepath.Join(dir, "HEAD"), staleHead, 0o644)
	// And a half-written temp file from the killed process.
	tmp := filepath.Join(dir, ".tmp-123")
	os.WriteFile(tmp, []byte(`{"schema": "xinproof.rec`), 0o644)
	old := time.Now().Add(-time.Hour)
	os.Chtimes(tmp, old, old)

	p3, err := s.Append(sample(Error), priv)
	if err != nil {
		t.Fatalf("next run after a crash: %v", err)
	}
	if filepath.Base(p3) != FileName(3) {
		t.Errorf("wrote %s, want %s", filepath.Base(p3), FileName(3))
	}
	var prev *Verified
	for seq := int64(1); seq <= 3; seq++ {
		doc, _ := os.ReadFile(filepath.Join(dir, FileName(seq)))
		v, err := Verify(doc, nil)
		if err != nil {
			t.Fatal(err)
		}
		if prev != nil {
			if err := CheckLink(prev, v); err != nil {
				t.Errorf("seq %d: %v", seq, err)
			}
		}
		prev = v
	}
	if _, err := os.Stat(tmp); err == nil {
		t.Error("stale temp file not cleaned up")
	}
}
