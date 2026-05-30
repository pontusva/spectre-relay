package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

// Prekey-bundle wire formats and constants.
//
// The Signal-style trust model places verification on the RECIPIENT of a
// bundle, not on the server: a recipient who fetches Alice's bundle must
// verify SignedPrekeySig against IdentityKey before deriving session state.
// The relay is intentionally a dumb-store: it MUST NOT pretend to verify
// the signature, because (1) Spectre's IdentityKey is libsignal's
// Curve25519 / XEdDSA, which Go's stdlib does not implement, and adding
// an XEdDSA implementation on the server would be added attack surface
// for a check the recipient client has to repeat anyway; and (2) a
// "server says ok" stamp would create a false trust anchor that recipients
// might be tempted to short-circuit on. The relay therefore does STRICT
// STRUCTURAL validation only — lengths, base64 decodability, no duplicate
// one-time-prekey IDs — and refuses bundles that fail any of those checks.
const (
	// Curve25519 / Ed25519 public key length in bytes.
	prekeyPubKeyLen = 32
	// XEdDSA / Ed25519 signature length in bytes.
	prekeySigLen = 64
	// Hard cap per-user OTPK count. 100 * ~32B = a few KB per user; large
	// enough for realistic prekey rotation, small enough that a malicious
	// client cannot use bundle upload as a memory-amplification primitive.
	maxOneTimePrekeys = 100
)

// OneTimePrekey is a single-use Curve25519 prekey. Once served via
// /prekeys/{userId} the relay drops it from the bundle so the next caller
// cannot reuse it — that single-use property is what gives the Signal
// X3DH handshake its forward-secrecy guarantee on first message.
type OneTimePrekey struct {
	ID  uint32 `json:"id"`
	Key string `json:"key"` // base64-encoded 32-byte public key
}

// PrekeyBundle is the full per-user record stored by the relay.
// All key/signature fields are base64-encoded raw bytes. The relay never
// decodes them past length validation — it stores the strings verbatim
// so the recipient client sees the exact bytes the publisher uploaded.
type PrekeyBundle struct {
	IdentityKey     string          `json:"identity_key"`      // b64 32B
	SignedPrekey    string          `json:"signed_prekey"`     // b64 32B
	SignedPrekeySig string          `json:"signed_prekey_sig"` // b64 64B
	OneTimePrekeys  []OneTimePrekey `json:"one_time_prekeys"`
}

// PrekeyResponse is the served form of a bundle: zero or one OTPK,
// consumed atomically at serve time. omitempty on OneTimePrekey covers
// the "user is out of one-time prekeys" fallback that the Signal spec
// explicitly permits (the recipient proceeds with SignedPrekey only,
// trading off some forward secrecy for liveness).
type PrekeyResponse struct {
	IdentityKey     string         `json:"identity_key"`
	SignedPrekey    string         `json:"signed_prekey"`
	SignedPrekeySig string         `json:"signed_prekey_sig"`
	OneTimePrekey   *OneTimePrekey `json:"one_time_prekey,omitempty"`
}

// PrekeyStore persists per-user prekey bundles. Mirrors Store's
// AES-256-GCM encrypted-on-disk pattern so an operator who exfiltrates
// the data volume cannot read who has registered or recover the
// one-time prekey list (which would otherwise be a pseudonym graph
// across recipients).
type PrekeyStore struct {
	mu        sync.Mutex
	bundles   map[string]*PrekeyBundle
	storePath string
	key       []byte
	log       *slog.Logger
}

// NewPrekeyStore initializes (or restores) the encrypted bundle store.
// Same key-file convention as Store: <storePath>.key, mode 0600, generated
// on first run. Separate key from the offline-queue key so a compromise
// of one doesn't grant the other — defense in depth across data classes.
func NewPrekeyStore(storePath string, log *slog.Logger) (*PrekeyStore, error) {
	if err := os.MkdirAll(filepath.Dir(storePath), 0o700); err != nil {
		return nil, err
	}
	key, err := loadOrCreateKey(storePath + keyFileSuffix)
	if err != nil {
		return nil, err
	}
	ps := &PrekeyStore{
		bundles:   make(map[string]*PrekeyBundle),
		storePath: storePath,
		key:       key,
		log:       log,
	}
	if err := ps.loadFromDisk(); err != nil {
		return nil, err
	}
	return ps, nil
}

// registerBundle replaces userID's stored bundle with `bundle`.
//
// SECURITY:
//   - Strict structural validation: lengths, base64 decodability, no
//     duplicate OTPK IDs, OTPK list cap. Failure -> error, bundle is NOT
//     persisted. Caller (server WS dispatch) drops silently on error.
//   - Cryptographic signature verification of SignedPrekeySig is
//     DELIBERATELY NOT performed here. See the package-level comment.
//   - Replacement is atomic under ps.mu — a concurrent getBundle on the
//     same user will see either the old bundle in full or the new bundle
//     in full, never a half-replaced record.
//   - The caller is expected to authenticate the WebSocket session
//     before invoking this; the relay treats `userID` as authoritative
//     for who owns the slot.
func (ps *PrekeyStore) registerBundle(userID string, bundle PrekeyBundle) error {
	if userID == "" {
		return errors.New("empty user id")
	}
	if err := validatePrekeyBundle(bundle); err != nil {
		return err
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	// Deep-copy the OTPK slice so a later mutation by the caller can't
	// reach in and modify our stored state.
	cp := bundle
	cp.OneTimePrekeys = append([]OneTimePrekey(nil), bundle.OneTimePrekeys...)
	ps.bundles[userID] = &cp
	if err := ps.persistLocked(); err != nil {
		ps.log.Error("prekey persist failed", "err_type", classifyErr(err))
		return err
	}
	return nil
}

// getBundle returns a serve-ready bundle for userID and atomically
// consumes one one-time prekey (if any remain) under ps.mu.
//
// Atomicity guarantee: two concurrent recipients fetching the same
// userID will receive DIFFERENT one-time prekeys, or one will receive
// an OTPK and the other will receive the no-OTPK fallback. They will
// never both receive the same OTPK — that would break the single-use
// invariant the X3DH handshake relies on for forward secrecy.
func (ps *PrekeyStore) getBundle(userID string) (*PrekeyResponse, bool) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	b, ok := ps.bundles[userID]
	if !ok {
		return nil, false
	}
	resp := &PrekeyResponse{
		IdentityKey:     b.IdentityKey,
		SignedPrekey:    b.SignedPrekey,
		SignedPrekeySig: b.SignedPrekeySig,
	}
	if len(b.OneTimePrekeys) > 0 {
		// Pop head; bundle is now mutated, persist immediately so a
		// crash cannot resurrect a consumed OTPK on restart.
		consumed := b.OneTimePrekeys[0]
		b.OneTimePrekeys = b.OneTimePrekeys[1:]
		resp.OneTimePrekey = &consumed
		if err := ps.persistLocked(); err != nil {
			ps.log.Error("prekey persist failed", "err_type", classifyErr(err))
		}
	}
	return resp, true
}

// consumeOneTimePrekey pops a single one-time prekey for userID without
// returning the rest of the bundle. Exposed for callers that already
// have the static bundle fields cached and only need a fresh OTPK.
// Returns nil,false when no OTPK is available (or the user has never
// registered) — caller must NOT distinguish those two states externally.
//
// identityKeyOf returns the base64 identity public key from userID's
// registered bundle WITHOUT consuming a one-time prekey. Used by
// sealed-sender certificate issuance to bind a cert's `ik` to the key the
// user actually published — never to a key supplied in the request. Returns
// false if the user has never registered a bundle (caller must then refuse
// to issue a cert).
func (ps *PrekeyStore) identityKeyOf(userID string) (string, bool) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	b, ok := ps.bundles[userID]
	if !ok {
		return "", false
	}
	return b.IdentityKey, true
}

func (ps *PrekeyStore) consumeOneTimePrekey(userID string) (*OneTimePrekey, bool) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	b, ok := ps.bundles[userID]
	if !ok || len(b.OneTimePrekeys) == 0 {
		return nil, false
	}
	consumed := b.OneTimePrekeys[0]
	b.OneTimePrekeys = b.OneTimePrekeys[1:]
	if err := ps.persistLocked(); err != nil {
		ps.log.Error("prekey persist failed", "err_type", classifyErr(err))
	}
	return &consumed, true
}

// validatePrekeyBundle enforces the structural invariants documented at
// the top of this file. NEVER bypass: a malformed bundle that slips
// through will be served to a recipient who then derives session state
// against garbage, producing a stuck conversation that looks like a
// crypto bug from the user's perspective.
func validatePrekeyBundle(b PrekeyBundle) error {
	if err := checkBase64Len(b.IdentityKey, prekeyPubKeyLen); err != nil {
		return errors.New("invalid identity_key")
	}
	if err := checkBase64Len(b.SignedPrekey, prekeyPubKeyLen); err != nil {
		return errors.New("invalid signed_prekey")
	}
	if err := checkBase64Len(b.SignedPrekeySig, prekeySigLen); err != nil {
		return errors.New("invalid signed_prekey_sig")
	}
	if len(b.OneTimePrekeys) > maxOneTimePrekeys {
		return errors.New("too many one_time_prekeys")
	}
	seen := make(map[uint32]struct{}, len(b.OneTimePrekeys))
	for _, otpk := range b.OneTimePrekeys {
		if err := checkBase64Len(otpk.Key, prekeyPubKeyLen); err != nil {
			return errors.New("invalid one_time_prekey key")
		}
		if _, dup := seen[otpk.ID]; dup {
			return errors.New("duplicate one_time_prekey id")
		}
		seen[otpk.ID] = struct{}{}
	}
	return nil
}

// checkBase64Len decodes s as standard base64 and confirms the decoded
// length matches `want`. Used to validate raw-bytes-as-string fields
// without retaining the decoded bytes (which the relay never needs to
// inspect — it forwards the original strings verbatim to recipients).
func checkBase64Len(s string, want int) error {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	if len(decoded) != want {
		return errors.New("bad length")
	}
	return nil
}

// persistLocked encrypts the in-memory bundle map and writes it to disk
// atomically. Caller MUST hold ps.mu. Layout on disk matches Store's:
// [12-byte GCM nonce][ciphertext||tag]. Atomic via tempfile + rename
// so a crash mid-write cannot produce a torn file that fails GCM
// authentication and bricks restart.
func (ps *PrekeyStore) persistLocked() error {
	plaintext, err := json.Marshal(ps.bundles)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(ps.key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, nil)

	dir := filepath.Dir(ps.storePath)
	tmp, err := os.CreateTemp(dir, "prekeys-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(sealed); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, ps.storePath)
}

// loadFromDisk reads the encrypted bundle file (if present) and restores
// the in-memory map. GCM authentication failure is fatal: refuse to start
// rather than serve possibly-tampered prekey bundles, which would let an
// attacker substitute their own keys into the X3DH handshake.
func (ps *PrekeyStore) loadFromDisk() error {
	data, err := os.ReadFile(ps.storePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(data) == 0 {
		return nil
	}
	block, err := aes.NewCipher(ps.key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	if len(data) < gcm.NonceSize() {
		return errors.New("prekey file truncated")
	}
	nonce, ct := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return errors.New("prekey authentication failed")
	}
	var loaded map[string]*PrekeyBundle
	if err := json.Unmarshal(plain, &loaded); err != nil {
		return err
	}
	for uid, b := range loaded {
		if b == nil {
			continue
		}
		ps.bundles[uid] = b
	}
	return nil
}
