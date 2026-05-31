package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// The security-critical relay invariant: an issued sender certificate binds
// the AUTHENTICATED userID and the identity key from THAT user's own
// registered bundle — never a client-supplied value — and is refused entirely
// when the user has no registered bundle.
func TestBuildSenderCertBinding(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewSealedCA(filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("NewSealedCA: %v", err)
	}
	ps, err := NewPrekeyStore(filepath.Join(dir, "pk.enc"), quietLogger())
	if err != nil {
		t.Fatalf("NewPrekeyStore: %v", err)
	}
	s := &Server{prekeys: ps, sealedCA: ca, log: quietLogger()}
	now := time.Unix(1_700_000_000, 0)

	// No registered bundle -> refuse to issue.
	if _, _, ok := s.buildSenderCert("alice", now); ok {
		t.Fatal("issued a cert for a user with no registered bundle")
	}

	// Register alice's bundle with a known identity key.
	ikRaw := bytes.Repeat([]byte{0x11}, 32)
	ikB64 := base64.StdEncoding.EncodeToString(ikRaw)
	bundle := PrekeyBundle{
		IdentityKey:     ikB64,
		SignedPrekey:    base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32)),
		SignedPrekeySig: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x33}, 64)),
		SignedPrekeyID:  1, // 1-based; validated by registerBundle
	}
	if err := ps.registerBundle("alice", bundle); err != nil {
		t.Fatalf("registerBundle: %v", err)
	}

	cert, sig, ok := s.buildSenderCert("alice", now)
	if !ok {
		t.Fatal("expected a cert once a bundle is registered")
	}

	// Signature must verify against the published CA public key.
	pub, err := base64.StdEncoding.DecodeString(ca.PublicKeyB64())
	if err != nil {
		t.Fatalf("decode CA pub: %v", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), cert, sig) {
		t.Fatal("cert signature did not verify against the published CA key")
	}

	var c senderCert
	if err := json.Unmarshal(cert, &c); err != nil {
		t.Fatalf("cert parse: %v", err)
	}
	if c.UID != "alice" {
		t.Errorf("uid: got %q, want the authenticated userID 'alice'", c.UID)
	}
	if c.IK != ikB64 {
		t.Error("ik not bound to the user's registered bundle key")
	}
	if want := now.Add(defaultCertTTL).UnixMilli(); c.Exp != want {
		t.Errorf("exp: got %d want %d", c.Exp, want)
	}

	// A different user's id must NOT be certifiable just because alice has a
	// bundle — issuance is per the requested (authenticated) userID.
	if _, _, ok := s.buildSenderCert("mallory", now); ok {
		t.Fatal("issued a cert for an unregistered user 'mallory'")
	}
}

func TestCertRateLimiter(t *testing.T) {
	l := newRateLimiter(3)
	now := time.Unix(1_700_000_000, 0)

	allowed := 0
	for i := 0; i < 6; i++ {
		if l.allow("u", now) {
			allowed++
		}
	}
	if allowed != 3 {
		t.Fatalf("allowed %d within the window, want 3", allowed)
	}

	// A different key has its own budget.
	if !l.allow("other", now) {
		t.Fatal("limiter leaked one user's budget onto another key")
	}

	// After the 1-minute window the budget resets.
	if !l.allow("u", now.Add(61*time.Second)) {
		t.Fatal("limiter did not reset after the window elapsed")
	}
}
