package verify

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"strings"

	"github.com/praxin/xinproof/internal/receipt"
	"github.com/praxin/xinproof/internal/source"
)

// digests computes every checksum a storage provider might publish, in one pass.
type digests struct{ sha, md5, crc hash.Hash }

func newDigests() *digests {
	return &digests{sha: sha256.New(), md5: md5.New(), crc: crc32.New(crc32.MakeTable(crc32.Castagnoli))}
}

func (d *digests) Write(p []byte) (int, error) {
	d.sha.Write(p)
	d.md5.Write(p)
	d.crc.Write(p)
	return len(p), nil
}

type sums struct{ SHA256, MD5, CRC32C string }

func (d *digests) sums() sums {
	return sums{SHA256: hex.EncodeToString(d.sha.Sum(nil)), MD5: hex.EncodeToString(d.md5.Sum(nil)), CRC32C: hex.EncodeToString(d.crc.Sum(nil))}
}

// compareChecksums checks the content against every checksum we know for it:
// a .sha256 sidecar and whatever the provider published (S3 SHA-256, Azure
// Content-MD5, GCS MD5/CRC32C). fail is set on the first mismatch.
func (v *Verifier) compareChecksums(ctx context.Context, obj source.Object, sidecar string, got sums) (checks []receipt.Check, fail string) {
	type want struct{ alg, sum, from, have string }
	var wants []want
	if sum := v.readSidecar(ctx, sidecar); sum != "" {
		wants = append(wants, want{"sha256", sum, "sidecar " + sidecar, got.SHA256})
	}
	if obj.SHA256 != "" {
		wants = append(wants, want{"sha256", obj.SHA256, "provider SHA-256", got.SHA256})
	}
	if obj.MD5 != "" {
		wants = append(wants, want{"md5", obj.MD5, "provider MD5", got.MD5})
	}
	if obj.CRC32C != "" {
		wants = append(wants, want{"crc32c", obj.CRC32C, "provider CRC32C", got.CRC32C})
	}
	for _, w := range wants {
		if !strings.EqualFold(w.sum, w.have) {
			reason := fmt.Sprintf("checksum mismatch: %s says %s %s…, content is %s…", w.from, w.alg, short(w.sum), short(w.have))
			return append(checks, receipt.Check{ID: "l1.checksum", Status: receipt.CheckFail, Detail: reason}), reason
		}
		checks = append(checks, receipt.Check{ID: "l1.checksum", Status: receipt.CheckPass, Detail: "matches " + w.from + " (" + w.alg + ")"})
	}
	return checks, ""
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func (v *Verifier) readSidecar(ctx context.Context, key string) string {
	if key == "" {
		return ""
	}
	rc, err := v.Src.Open(ctx, key)
	if err != nil {
		return ""
	}
	defer rc.Close()
	b, _ := io.ReadAll(io.LimitReader(rc, 4096))
	if f := strings.Fields(string(b)); len(f) > 0 && len(f[0]) == 64 {
		if _, err := hex.DecodeString(f[0]); err == nil {
			return strings.ToLower(f[0])
		}
	}
	return ""
}
