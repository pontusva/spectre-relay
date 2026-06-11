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
// Store this key in an HSM / sealed store in production.
//
// ROTATION (finding R3-2): a client that has pinned this key fails closed if
// /sealed-ca later serves a DIFFERENT key (SealedCaException → sealed sender
// UNAVAILABLE). That is correct against a silent swap, but it also means a
// naive rotation bricks every existing client, AND a malicious relay could
// rotate as a deniable network-wide kill switch. The mitigation is a SIGNED
// rotation: when the operator rotates, the relay signs the NEW public key
// with the OLD private key and serves that proof at /sealed-ca. A pinned
// client accepts the new key ONLY if the proof verifies under the key it
// already trusts — so the relay cannot introduce a new CA the client honours
// without possession of the old private key, and an honest operator can
// rotate without bricking anyone. To rotate: move the current key file to
// <path>.prev and restart; NewSealedCA mints a fresh key and a rotation
// proof. (For the strongest posture, clients should ALSO be able to pin the
// CA key out-of-band via build config so the relay is never its own pinned
// authority on first run — see SealedCaService.)
type SealedCA struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey

	// prevPub is the immediately-previous CA public key, if this key was
	// minted as a rotation (i.e. a <path>.prev file existed at load). nil
	// when this is a first-generation key.
	prevPub ed25519.PublicKey
	// rotationSig is Ed25519(prevPriv, pub): a proof, verifiable by anyone
	// holding prevPub, that the holder of the OLD private key authorised
	// THIS new public key. Empty when prevPub is nil.
	rotationSig []byte
}

// senderCert is the exact JSON structure that gets signed. Go's
// encoding/json emits struct fields in declaration order deterministically,
// so the bytes we sign here are the bytes the client verifies over — no
// canonicalization step, no signed-vs-parsed mismatch surface.
type senderCert struct {
	Iss string `json:"iss"` // issuer domain
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
//
// ROTATION: if `path` does not exist but `<path>.prev` does, NewSealedCA
// mints a fresh key AND a rotation proof — Ed25519(prevPriv, newPub) — so
// already-pinned clients can verify the new key was authorised by the old
// one (finding R3-2). The .prev file is left in place (read-only to this
// process after load); operators may remove it once all clients have
// migrated. A standalone .prev with no main key is treated as the rotation
// trigger exactly once: the new key is written to `path`.
func NewSealedCA(path string) (*SealedCA, error) {
	if data, err := os.ReadFile(path); err == nil {
		if len(data) != ed25519.PrivateKeySize {
			return nil, errors.New("invalid sealed-ca key length")
		}
		priv := ed25519.PrivateKey(data)
		ca := &SealedCA{priv: priv, pub: priv.Public().(ed25519.PublicKey)}
		// If a .prev exists alongside an established key, reconstruct the
		// rotation proof so /sealed-ca can keep serving it across restarts
		// (the proof is deterministic for a given old priv + new pub).
		if prevPriv, ok := readPrevKey(path); ok {
			ca.prevPub = prevPriv.Public().(ed25519.PublicKey)
			ca.rotationSig = ed25519.Sign(prevPriv, ca.pub)
		}
		return ca, nil
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
	ca := &SealedCA{priv: priv, pub: pub}
	// First-run-after-rotation: a .prev key file signals "this fresh key
	// replaces the old one" — sign the new pub with the old priv so pinned
	// clients can follow the rotation instead of failing closed.
	if prevPriv, ok := readPrevKey(path); ok {
		ca.prevPub = prevPriv.Public().(ed25519.PublicKey)
		ca.rotationSig = ed25519.Sign(prevPriv, ca.pub)
	}
	return ca, nil
}

// readPrevKey loads <path>.prev as a raw ed25519 private key if present and
// well-formed. Returns ok=false (and no error) when absent or malformed — a
// broken .prev must not block startup, it just means no rotation proof is
// served and pinned clients will fail closed on the change (the safe default).
func readPrevKey(path string) (ed25519.PrivateKey, bool) {
	data, err := os.ReadFile(path + ".prev")
	if err != nil || len(data) != ed25519.PrivateKeySize {
		return nil, false
	}
	return ed25519.PrivateKey(data), true
}

// PublicKeyB64 returns the standard-base64 raw 32-byte public key, served
// to clients at /sealed-ca for pinning.
func (ca *SealedCA) PublicKeyB64() string {
	return base64.StdEncoding.EncodeToString(ca.pub)
}

// RotationProofB64 returns the previous public key and the rotation
// signature (both standard-base64), or empty strings when this CA key was
// not minted as a rotation. Served at /sealed-ca so a pinned client can
// verify Ed25519(prevPub, sig over newPub) before adopting the new key.
func (ca *SealedCA) RotationProofB64() (prevPub, sig string) {
	if ca.prevPub == nil || len(ca.rotationSig) == 0 {
		return "", ""
	}
	return base64.StdEncoding.EncodeToString(ca.prevPub),
		base64.StdEncoding.EncodeToString(ca.rotationSig)
}

// IssueCert builds and signs a sender certificate binding `uid` to its
// `identityKeyB64`. The caller MUST pass the AUTHENTICATED userID and an
// identity key it has independently established as belonging to that user
// (in the relay, the identity key from the user's own registered prekey
// bundle). Returns the exact signed bytes and the signature over them.
func (ca *SealedCA) IssueCert(uid, identityKeyB64, issuer string, now time.Time) (cert []byte, sig []byte, err error) {
	c := senderCert{
		Iss: issuer,
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
