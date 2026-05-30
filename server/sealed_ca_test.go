package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func TestSealedCAIssueAndVerify(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sealed_ca.key")

	ca, err := NewSealedCA(path)
	if err != nil {
		t.Fatalf("NewSealedCA: %v", err)
	}

	pub, err := base64.StdEncoding.DecodeString(ca.PublicKeyB64())
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("bad public key: err=%v len=%d", err, len(pub))
	}

	uid := "sender-uid-AAAA"
	ik := base64.StdEncoding.EncodeToString(make([]byte, 32))
	now := time.Unix(1_700_000_000, 0)

	cert, sig, err := ca.IssueCert(uid, ik, now)
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	// The signature must verify against the published public key over the
	// EXACT issued bytes (this is what the client does).
	if !ed25519.Verify(ed25519.PublicKey(pub), cert, sig) {
		t.Fatal("signature did not verify against published public key")
	}

	var c senderCert
	if err := json.Unmarshal(cert, &c); err != nil {
		t.Fatalf("cert not parseable: %v", err)
	}
	if c.UID != uid {
		t.Errorf("uid: got %q want %q", c.UID, uid)
	}
	if c.IK != ik {
		t.Errorf("ik mismatch")
	}
	if want := now.Add(defaultCertTTL).UnixMilli(); c.Exp != want {
		t.Errorf("exp: got %d want %d", c.Exp, want)
	}

	// Tampering with the cert bytes must break verification.
	tampered := make([]byte, len(cert))
	copy(tampered, cert)
	tampered[len(tampered)-2] ^= 0xFF
	if ed25519.Verify(ed25519.PublicKey(pub), tampered, sig) {
		t.Fatal("tampered cert unexpectedly verified")
	}
}

func TestSealedCAPersistsKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sealed_ca.key")

	ca1, err := NewSealedCA(path)
	if err != nil {
		t.Fatalf("first NewSealedCA: %v", err)
	}
	ca2, err := NewSealedCA(path)
	if err != nil {
		t.Fatalf("second NewSealedCA: %v", err)
	}
	if ca1.PublicKeyB64() != ca2.PublicKeyB64() {
		t.Fatal("CA key not stable across reloads — clients would have to re-pin")
	}
}
