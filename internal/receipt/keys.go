package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	privFile = "ed25519.key"
	pubFile  = "ed25519.pub"
)

// LoadOrCreateKey loads the signing key from dir, generating a new key pair on
// first use. created reports whether a new key was generated.
func LoadOrCreateKey(dir string) (priv ed25519.PrivateKey, created bool, err error) {
	path := filepath.Join(dir, privFile)
	b, err := os.ReadFile(path)
	if err == nil {
		priv, err = parsePrivate(b)
		if err != nil {
			return nil, false, fmt.Errorf("%s: %w", path, err)
		}
		return priv, false, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, false, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, false, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, false, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, false, err
	}
	if err := writeExclusive(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, false, err
	}
	pubPEM, err := EncodePublicKey(pub)
	if err != nil {
		return nil, false, err
	}
	if err := os.WriteFile(filepath.Join(dir, pubFile), pubPEM, 0o644); err != nil {
		return nil, false, err
	}
	return priv, true, nil
}

// LoadLocalPublicKey returns the public key in dir, or nil if none exists.
func LoadLocalPublicKey(dir string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(filepath.Join(dir, pubFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return ParsePublicKey(b)
}

// PublicKeyPath is where the public key for dir lives.
func PublicKeyPath(dir string) string { return filepath.Join(dir, pubFile) }

func EncodePublicKey(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// ParsePublicKey accepts a PEM "PUBLIC KEY" block or a bare base64 32-byte key.
func ParsePublicKey(b []byte) (ed25519.PublicKey, error) {
	if blk, _ := pem.Decode(b); blk != nil {
		k, err := x509.ParsePKIXPublicKey(blk.Bytes)
		if err != nil {
			return nil, err
		}
		pub, ok := k.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("public key is not Ed25519")
		}
		return pub, nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("not a PEM or base64 Ed25519 public key")
	}
	return ed25519.PublicKey(raw), nil
}

func parsePrivate(b []byte) (ed25519.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("not a PEM private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not Ed25519")
	}
	return priv, nil
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
