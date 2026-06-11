package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
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

	cert, sig, err := ca.IssueCert(uid, ik, "test.local", now)
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

// R3-2: a fresh CA key minted while a <path>.prev exists must carry a rotation
// proof — Ed25519(prevPriv, newPub) — that verifies under the OLD public key.
// This is what lets a pinned client follow an operator's rotation instead of
// failing closed, WITHOUT letting the relay introduce a new CA the client
// honours unless it possesses the old private key.
func TestSealedCASignedRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sealed_ca.key")

	// First-generation CA. No rotation proof expected.
	ca1, err := NewSealedCA(path)
	if err != nil {
		t.Fatalf("first NewSealedCA: %v", err)
	}
	if prev, sig := ca1.RotationProofB64(); prev != "" || sig != "" {
		t.Fatal("first-generation CA unexpectedly advertised a rotation proof")
	}
	oldPub, _ := base64.StdEncoding.DecodeString(ca1.PublicKeyB64())

	// Operator rotates: move the current key to <path>.prev, remove the main
	// key, restart. NewSealedCA mints a new key + a rotation proof.
	oldPriv, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read old key: %v", err)
	}
	if err := os.WriteFile(path+".prev", oldPriv, 0o600); err != nil {
		t.Fatalf("write .prev: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove main key: %v", err)
	}

	ca2, err := NewSealedCA(path)
	if err != nil {
		t.Fatalf("rotated NewSealedCA: %v", err)
	}
	newPub, _ := base64.StdEncoding.DecodeString(ca2.PublicKeyB64())
	if string(newPub) == string(oldPub) {
		t.Fatal("rotation did not produce a new key")
	}

	prevB64, sigB64 := ca2.RotationProofB64()
	if prevB64 == "" || sigB64 == "" {
		t.Fatal("rotated CA did not advertise a rotation proof")
	}
	prev, err := base64.StdEncoding.DecodeString(prevB64)
	if err != nil {
		t.Fatalf("decode prev: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}

	// prev_public_key must be exactly the key clients pinned before.
	if string(prev) != string(oldPub) {
		t.Fatal("rotation proof prev key != the original pinned key")
	}
	// The proof must verify: old key signed the new key. This is the check the
	// client performs before adopting the new CA.
	if !ed25519.Verify(ed25519.PublicKey(oldPub), newPub, sig) {
		t.Fatal("rotation proof did not verify under the old (pinned) key")
	}
	// And it must NOT verify under the new key (that would be circular and
	// would let the relay self-authorise a rotation).
	if ed25519.Verify(ed25519.PublicKey(newPub), newPub, sig) {
		t.Fatal("rotation proof verified under the new key — not a chain from the old key")
	}

	// The proof is stable across a restart (deterministic for old priv + new
	// pub), so /sealed-ca keeps serving it while the .prev file remains.
	ca3, err := NewSealedCA(path)
	if err != nil {
		t.Fatalf("reload rotated NewSealedCA: %v", err)
	}
	prevB64b, sigB64b := ca3.RotationProofB64()
	if prevB64b != prevB64 || sigB64b != sigB64 {
		t.Fatal("rotation proof not stable across reload")
	}
}
