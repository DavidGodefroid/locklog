package engine

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// TestSealerSubkeys: the AEAD and the HMAC run under separate subkeys
// derived from K_ref, never under K_ref itself.
func TestSealerSubkeys(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	s, err := NewSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	// A value sealed under K_ref directly does not open.
	a, _ := chacha20poly1305.NewX(key)
	nonce := make([]byte, a.NonceSize())
	ct := a.Seal(nonce, nonce, []byte(`{"s":"x"}`), []byte("Lr1"))
	var st refState
	if err := s.Open("Lr1", "Lr1."+base64.RawURLEncoding.EncodeToString(ct), &st); err == nil {
		t.Fatal("the AEAD runs under K_ref itself")
	}
	// The digest is not HMAC under K_ref.
	m := hmac.New(sha256.New, key)
	m.Write([]byte("d"))
	if s.Digest("d") == base64.RawURLEncoding.EncodeToString(m.Sum(nil)) {
		t.Fatal("the HMAC runs under K_ref itself")
	}
	if string(s.aeadKey) == string(s.hmacKey) || string(s.aeadKey) == string(key) || string(s.hmacKey) == string(key) {
		t.Fatal("subkeys not separate")
	}
	// Round trip still works.
	sealed, err := s.Seal("Lc1", cursorState{Plan: "p"})
	if err != nil || !strings.HasPrefix(sealed, "Lc1.") {
		t.Fatal(err)
	}
	var cs cursorState
	if err := s.Open("Lc1", sealed, &cs); err != nil || cs.Plan != "p" {
		t.Fatal(err)
	}
}
