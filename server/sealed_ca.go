package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// SealedCA is the relay's long-term signing authority for Sealed Sender
// certificates.
//
// WHY: under sealed sender the relay never sees who sent a message — the
// sender id rides INSIDE the recipient-encrypted envelope. For the recipient
// to trust that sender id, it must be attested by something the recipient
// can verify offline. That attestation is a short-lived certificate signed
// by this key. The recipient pins this key's public half (served at
// /sealed-ca) on first fetch.
//
// The CA key is INTENTIONALLY independent of TLS and of the per-user
// relay-auth keys: its only job is to bind (userID, identity-key, expiry).
//
// CUSTODY WARNING — this key is HIGH sensitivity, not "same as the AES data
// keys". Because the relay both runs the transport AND holds this key, a
// leak (or a malicious operator) can forge sender attribution for ANY user
// and MITM FIRST-CONTACT sessions: the holder mints cert{uid:victim,
// ik:attacker_key} and satisfies the client's cert.ik == PreKeySignalMessage
// identity-key binding itself, since it controls both. It still cannot read
// content (needs the recipient's identity private key) nor speak inside an
// already fingerprint-verified session. The ONLY defense against this
// forgery is out-of-band safety-number verification on the client — the cert
// is metadata-hiding + honest-relay integrity, NOT sender authentication.
// Store this key in an HSM / sealed store in production and document a
// rotation-with-overlap + pin-change-alert flow (TOFU re-pin alone lets a
// relay serve a fresh CA pub to an unpinned client and forge freely).
type SealedCA struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// senderCert is the exact JSON structure that gets signed. Go's
// encoding/json emits struct fields in declaration order deterministically,
// so the bytes we sign here are the bytes the client verifies over — no
// canonicalization step, no signed-vs-parsed mismatch surface.
type senderCert struct {
	UID string `json:"uid"` // authenticated relay handle of the sender
	IK  string `json:"ik"`  // b64 32B Signal identity public key (from bundle)
	Exp int64  `json:"exp"` // unix milliseconds; recipient rejects if now >= exp
}

// defaultCertTTL bounds how long a forged-after-leak or stolen certificate
// stays useful. Short enough to limit damage, long enough that a client
// does not have to round-trip for a cert on every single send.
const defaultCertTTL = 24 * time.Hour

// NewSealedCA loads the Ed25519 signing key from `path`, generating and
// persisting one on first run. File is the 64-byte ed25519 private key,
// mode 0600 — same custody posture as the AES key files.
func NewSealedCA(path string) (*SealedCA, error) {
	if data, err := os.ReadFile(path); err == nil {
		if len(data) != ed25519.PrivateKeySize {
			return nil, errors.New("invalid sealed-ca key length")
		}
		priv := ed25519.PrivateKey(data)
		return &SealedCA{priv: priv, pub: priv.Public().(ed25519.PublicKey)}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, priv, 0o600); err != nil {
		return nil, err
	}
	return &SealedCA{priv: priv, pub: pub}, nil
}

// PublicKeyB64 returns the standard-base64 raw 32-byte public key, served
// to clients at /sealed-ca for pinning.
func (ca *SealedCA) PublicKeyB64() string {
	return base64.StdEncoding.EncodeToString(ca.pub)
}

// IssueCert builds and signs a sender certificate binding `uid` to its
// `identityKeyB64`. The caller MUST pass the AUTHENTICATED userID and an
// identity key it has independently established as belonging to that user
// (in the relay, the identity key from the user's own registered prekey
// bundle). Returns the exact signed bytes and the signature over them.
func (ca *SealedCA) IssueCert(uid, identityKeyB64 string, now time.Time) (cert []byte, sig []byte, err error) {
	c := senderCert{
		UID: uid,
		IK:  identityKeyB64,
		Exp: now.Add(defaultCertTTL).UnixMilli(),
	}
	cert, err = json.Marshal(c)
	if err != nil {
		return nil, nil, err
	}
	sig = ed25519.Sign(ca.priv, cert)
	return cert, sig, nil
}
