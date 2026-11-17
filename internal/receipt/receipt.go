// Package receipt builds, signs, chains and verifies xinproof proof receipts.
//
// A receipt is signed with Ed25519 over the RFC 8785 canonical form of the
// receipt without its "signature" member. Receipts are hash-chained: each
// receipt's chain.prev is the SHA-256 of the previous receipt's canonical
// bytes, signature included.
package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"
)

const Schema = "xinproof.receipt/v1"

// Result is the overall outcome for one backup. Every backup ends in exactly one.
type Result string

const (
	Pass  Result = "PASS"
	Fail  Result = "FAIL"
	Error Result = "ERROR" // could not be tested; Reason says why
)

// Check statuses (lower case, as in the design doc).
const (
	CheckPass  = "pass"
	CheckFail  = "fail"
	CheckError = "error"
	CheckSkip  = "skip"
	CheckInfo  = "info"
)

// GenesisPrev is chain.prev for the first receipt in a chain.
const GenesisPrev = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

type Receipt struct {
	Schema    string     `json:"schema"`
	ID        string     `json:"id"`
	IssuedAt  string     `json:"issued_at"`
	Subject   Subject    `json:"subject"`
	Engine    Engine     `json:"engine"`
	Result    Result     `json:"result"`
	Reason    string     `json:"reason,omitempty"`
	Measured  Measured   `json:"measured"`
	Checks    []Check    `json:"checks"`
	Tables    []Table    `json:"tables,omitempty"` // optional (added in v1): restored tables with exact row counts
	Tool      Tool       `json:"tool"`
	Chain     Chain      `json:"chain"`
	Signature *Signature `json:"signature,omitempty"`
}

type Subject struct {
	Source       string `json:"source"`
	Size         int64  `json:"size"`
	SHA256       string `json:"sha256,omitempty"`
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
	Format       string `json:"format,omitempty"`
	Compression  string `json:"compression,omitempty"`
}

type Engine struct {
	Kind          string `json:"kind,omitempty"`
	DumpVersion   string `json:"dump_version,omitempty"`
	ServerVersion string `json:"server_version,omitempty"`
	SandboxImage  string `json:"sandbox_image,omitempty"`
}

type Measured struct {
	RestoreSeconds float64 `json:"restore_seconds"`
	TotalSeconds   float64 `json:"total_seconds"`
}

type Check struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Table is one restored table (or collection) and its exact row (document)
// count after restore. Names and counts only, never row data.
type Table struct {
	Name string `json:"name"`
	Rows int64  `json:"rows"`
}

// MaxTables caps the tables list in a receipt; the first MaxTables by name are kept.
const MaxTables = 2000

type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
}

type Chain struct {
	Prev string `json:"prev"`
	Seq  int64  `json:"seq"`
}

type Signature struct {
	Alg       string `json:"alg"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"` // base64 raw 32-byte key; a hint, pin keys with --pubkey
	Sig       string `json:"sig"`
}

// New returns an unsigned receipt with schema, id and issue time filled in.
func New(now time.Time) *Receipt {
	return &Receipt{
		Schema:   Schema,
		ID:       "rcpt_" + NewULID(now),
		IssuedAt: now.UTC().Format(time.RFC3339),
		Checks:   []Check{},
	}
}

// SigningBytes returns the canonical bytes that the signature covers.
func (r *Receipt) SigningBytes() ([]byte, error) {
	c := *r
	c.Signature = nil
	return CanonicalOf(&c)
}

// Sign signs r in place.
func (r *Receipt) Sign(priv ed25519.PrivateKey) error {
	msg, err := r.SigningBytes()
	if err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	r.Signature = &Signature{
		Alg:       "ed25519",
		KeyID:     KeyID(pub),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Sig:       base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg)),
	}
	return nil
}

// Hash returns "sha256:<hex>" of the receipt's full canonical bytes (signature included).
func (r *Receipt) Hash() (string, error) {
	b, err := CanonicalOf(r)
	if err != nil {
		return "", err
	}
	return hashBytes(b), nil
}

func hashBytes(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// KeyID is a short, stable fingerprint of a public key.
func KeyID(pub ed25519.PublicKey) string {
	s := sha256.Sum256(pub)
	return "ed25519:" + hex.EncodeToString(s[:8])
}

// Verified is the outcome of checking one receipt document.
type Verified struct {
	Receipt *Receipt
	Hash    string // chain hash of this receipt
	KeyID   string
	Pinned  bool // signature checked against a caller-trusted key (not just the embedded one)
}

var ErrBadSignature = errors.New("signature does not verify")

// Verify checks a receipt document's signature. The document is verified as
// it is on disk: every member except "signature" is covered, including ones
// this version of the tool does not know about. If trusted keys are given, the
// signature must verify against one of them; otherwise the embedded public key
// is used and the result is reported as not pinned.
func Verify(doc []byte, trusted []ed25519.PublicKey) (*Verified, error) {
	var generic map[string]any
	if err := unmarshalNumbers(doc, &generic); err != nil {
		return nil, fmt.Errorf("not a JSON receipt: %w", err)
	}
	var r Receipt
	if err := json.Unmarshal(doc, &r); err != nil {
		return nil, fmt.Errorf("not a receipt: %w", err)
	}
	if r.Schema != Schema {
		return nil, fmt.Errorf("unknown receipt schema %q", r.Schema)
	}
	if r.Signature == nil {
		return nil, errors.New("receipt is not signed")
	}
	if r.Signature.Alg != "ed25519" {
		return nil, fmt.Errorf("unsupported signature algorithm %q", r.Signature.Alg)
	}
	sig, err := base64.StdEncoding.DecodeString(r.Signature.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("malformed signature")
	}
	full, err := canonicalGeneric(generic)
	if err != nil {
		return nil, err
	}
	delete(generic, "signature")
	msg, err := canonicalGeneric(generic)
	if err != nil {
		return nil, err
	}

	v := &Verified{Receipt: &r, Hash: hashBytes(full)}
	if len(trusted) > 0 {
		for _, k := range trusted {
			if ed25519.Verify(k, msg, sig) {
				v.KeyID, v.Pinned = KeyID(k), true
				return v, nil
			}
		}
		return v, fmt.Errorf("%w against the pinned key(s)", ErrBadSignature)
	}
	pub, err := base64.StdEncoding.DecodeString(r.Signature.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return v, errors.New("receipt has no usable embedded public key; pass --pubkey")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		return v, ErrBadSignature
	}
	v.KeyID = KeyID(pub)
	if v.KeyID != r.Signature.KeyID {
		return v, fmt.Errorf("key_id %s does not match embedded key %s", r.Signature.KeyID, v.KeyID)
	}
	return v, nil
}

func unmarshalNumbers(doc []byte, v any) error {
	c, err := Canonicalize(doc) // also rejects trailing data and non-finite numbers
	if err != nil {
		return err
	}
	return json.Unmarshal(c, v)
}

func canonicalGeneric(m map[string]any) ([]byte, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return Canonicalize(b)
}

// CheckLink reports whether next correctly follows prev in a chain.
func CheckLink(prev, next *Verified) error {
	if next.Receipt.Chain.Seq != prev.Receipt.Chain.Seq+1 {
		return fmt.Errorf("sequence gap: %d follows %d", next.Receipt.Chain.Seq, prev.Receipt.Chain.Seq)
	}
	if next.Receipt.Chain.Prev != prev.Hash {
		return fmt.Errorf("receipt %d does not link to receipt %d (prev %s, expected %s)",
			next.Receipt.Chain.Seq, prev.Receipt.Chain.Seq, short(next.Receipt.Chain.Prev), short(prev.Hash))
	}
	return nil
}

func short(h string) string {
	if len(h) > 19 {
		return h[:19] + "…"
	}
	return h
}

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewULID returns a ULID: 48-bit millisecond timestamp plus 80 random bits,
// Crockford base32 encoded (26 characters, lexicographically time-ordered).
func NewULID(t time.Time) string {
	var b [16]byte
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(t.UnixMilli()))
	copy(b[:6], ts[2:])
	if _, err := rand.Read(b[6:]); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	n := new(big.Int).SetBytes(b[:])
	mask := big.NewInt(31)
	out := make([]byte, 26)
	for i := 25; i >= 0; i-- {
		out[i] = crockford[new(big.Int).And(n, mask).Int64()]
		n.Rsh(n, 5)
	}
	return string(out)
}
