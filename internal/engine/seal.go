package engine

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// Sealer seals refs and cursors (AEAD) and computes the keyed digests plans
// are bound to (HMAC), each under its own subkey derived from K_ref with
// HKDF-SHA256 (info "locklog/aead/v1" and "locklog/hmac/v1"): one key is
// never used by two primitives. Nothing it produces can be
// opened, forged or guessed offline without K_ref, which never leaves the
// console's home volume: an agent holding a ref or a cursor learns nothing
// from it, and plan hashes and record digests are never returned on the
// agent socket at all.
type Sealer struct {
	aeadKey []byte
	hmacKey []byte
	aead    interface {
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
		NonceSize() int
	}
}

// NewSealer uses a 32-byte key.
func NewSealer(key []byte) (*Sealer, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, errors.New("engine: K_ref must be 32 bytes")
	}
	aeadKey, err := hkdf.Key(sha256.New, key, nil, "locklog/aead/v1", chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	hmacKey, err := hkdf.Key(sha256.New, key, nil, "locklog/hmac/v1", sha256.Size)
	if err != nil {
		return nil, err
	}
	a, err := chacha20poly1305.NewX(aeadKey)
	if err != nil {
		return nil, err
	}
	return &Sealer{aeadKey: aeadKey, hmacKey: hmacKey, aead: a}, nil
}

// Digest is HMAC-SHA256(K_hmac, domain ‖ (0 ‖ len ‖ part)…), base64url
// (unpadded); K_hmac is derived from K_ref. It is
// the only hash used for plan binding and record identity (round-6
// amendment: never an unkeyed hash of a record).
func (s *Sealer) Digest(domain string, parts ...[]byte) string {
	m := hmac.New(sha256.New, s.hmacKey)
	m.Write([]byte(domain))
	for _, p := range parts {
		m.Write([]byte{0})
		var n [8]byte
		l := uint64(len(p))
		for i := range n {
			n[i] = byte(l >> (8 * i))
		}
		m.Write(n[:])
		m.Write(p)
	}
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// Seal encrypts v (JSON) under a prefix that names its type ("Lr1", "Lc1").
func (s *Sealer) Seal(prefix string, v any) (string, error) {
	pt, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := s.aead.Seal(nonce, nonce, pt, []byte(prefix))
	return prefix + "." + base64.RawURLEncoding.EncodeToString(ct), nil
}

// ErrSealed is returned for a ref or cursor that does not open: wrong type,
// forged, from another key (console reinstalled), corrupt.
var ErrSealed = errors.New("engine: invalid or expired reference")

// Open decrypts a sealed value of the given prefix into v.
func (s *Sealer) Open(prefix, sealed string, v any) error {
	p, b64, ok := strings.Cut(sealed, ".")
	if !ok || p != prefix || len(b64) > 4096 {
		return ErrSealed
	}
	ct, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil || len(ct) < s.aead.NonceSize() {
		return ErrSealed
	}
	pt, err := s.aead.Open(nil, ct[:s.aead.NonceSize()], ct[s.aead.NonceSize():], []byte(prefix))
	if err != nil {
		return ErrSealed
	}
	if json.Unmarshal(pt, v) != nil {
		return ErrSealed
	}
	return nil
}
