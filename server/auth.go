package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"

	"spectre-relay/model"
)

// ErrAuthFailed is the ONLY error returned from Authenticate.
//
// SECURITY: We deliberately do not distinguish "user not found",
// "bad signature", "rate limited", "malformed request", or "timeout"
// to the caller, and never to the client. Detailed responses would create:
//   - a user-enumeration oracle (does this UserID exist?),
//   - a signature-validation oracle (is the key format correct?),
//   - timing/error-code side channels.
//
// On failure the caller MUST close the connection without sending a body.
var ErrAuthFailed = errors.New("auth failed")

// authLimiter is a per-IP sliding window for auth attempts.
// Limit: 5 attempts per minute. Scanning behavior exceeds this trivially
// and is dropped silently — the offender never learns it is throttled.
type authLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
}

func newAuthLimiter() *authLimiter {
	return &authLimiter{attempts: make(map[string][]time.Time)}
}

func (l *authLimiter) allow(ip string) bool {
	const max = 5
	const window = time.Minute
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-window)
	xs := l.attempts[ip]
	kept := xs[:0]
	for _, t := range xs {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= max {
		l.attempts[ip] = kept
		return false
	}
	kept = append(kept, now)
	l.attempts[ip] = kept
	return true
}

type Authenticator struct {
	limiter *authLimiter
	log     *slog.Logger
	// debug gates the verbose handshake trace below. Sampled once at
	// construction from SPECTRE_DEBUG so flipping the env var requires
	// a process restart — we don't want a flag flip mid-flight to start
	// emitting key lengths while a hostile observer is connected.
	//
	// TEMPORARY: this whole code path exists to diagnose a specific
	// Dart/Go ed25519 wire mismatch. Remove it once relay-auth is green
	// in CI; it has no business shipping in a production binary.
	debug bool
}

func NewAuthenticator(log *slog.Logger) *Authenticator {
	return &Authenticator{
		limiter: newAuthLimiter(),
		log:     log,
		debug:   os.Getenv("SPECTRE_DEBUG") == "true",
	}
}

// dbg emits a slog.Debug line only when SPECTRE_DEBUG=true was set at
// process start. Callers pass key lengths and step names, NEVER the
// raw key bytes, signature bytes, nonce, UserID, or remote IP — those
// would defeat the no-PII guarantees the rest of the relay enforces.
func (a *Authenticator) dbg(msg string, args ...any) {
	if !a.debug || a.log == nil {
		return
	}
	a.log.Debug(msg, args...)
}

// Authenticate runs the challenge/response handshake over an upgraded WebSocket.
//
// Wire sequence:
//  1. server -> Challenge{Nonce: 32 CSPRNG bytes}
//  2. client -> AuthRequest{UserID, IdentityPublicKey(b64), Signature(b64)}
//  3. server verifies Signature over the raw Nonce using ed25519.
//  4. on success: AuthResponse{Success: true}; on failure: connection closed.
//
// Every error returns ErrAuthFailed with no further information.
func (a *Authenticator) Authenticate(ctx context.Context, c *websocket.Conn, remoteIP string) (string, error) {
	if !a.limiter.allow(remoteIP) {
		return "", ErrAuthFailed
	}
	a.dbg("auth: rate limit check passed")

	// 32 bytes is well above ed25519's required input entropy and large
	// enough to make collisions across the relay's lifetime negligible.
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return "", ErrAuthFailed
	}
	a.dbg("auth: nonce generated")

	hsCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := wsjson.Write(hsCtx, c, model.Challenge{Nonce: nonce}); err != nil {
		return "", ErrAuthFailed
	}
	a.dbg("auth: challenge sent")

	var req model.AuthRequest
	if err := wsjson.Read(hsCtx, c, &req); err != nil {
		return "", ErrAuthFailed
	}

	// Decode both fields before the structural checks below so the
	// "request received" line can report the *decoded* lengths — that
	// is what tells us whether the client base64'd the right thing.
	// Decode errors are swallowed here on purpose: invalid base64 falls
	// through to the length check, which fails closed and returns the
	// same ErrAuthFailed as every other path.
	pub, _ := base64.StdEncoding.DecodeString(req.IdentityPublicKey)
	sig, _ := base64.StdEncoding.DecodeString(req.Signature)

	a.dbg("auth: request received",
		"user_id_len", len(req.UserID),
		"pub_key_len", len(pub),
		"sig_len", len(sig),
	)

	if len(pub) != ed25519.PublicKeySize {
		return "", ErrAuthFailed
	}
	a.dbg("auth: pub key decoded")

	if len(sig) != ed25519.SignatureSize {
		return "", ErrAuthFailed
	}
	a.dbg("auth: sig decoded")

	if !ed25519.Verify(ed25519.PublicKey(pub), nonce, sig) {
		a.dbg("auth: signature FAILED")
		return "", ErrAuthFailed
	}
	a.dbg("auth: signature verified")

	if req.UserID == "" {
		return "", ErrAuthFailed
	}

	// The only success response we ever send. No diagnostics included.
	if err := wsjson.Write(hsCtx, c, model.AuthResponse{Success: true}); err != nil {
		return "", ErrAuthFailed
	}
	// TODO: remove before production
	// (Authenticator has its own logger; the user-facing spec referenced
	//  `s.log`, but auth.go runs before serveConn assigns `s` — `a.log`
	//  is the equivalent and is unconditional, unlike the SPECTRE_DEBUG-
	//  gated a.dbg().)
	if a.log != nil {
		uidPrefix := req.UserID
		if len(uidPrefix) > 8 {
			uidPrefix = uidPrefix[:8]
		}
		a.log.Info("DEV auth success", "uid_prefix", uidPrefix)
	}
	return req.UserID, nil
}

// ExtractIP returns just the host portion of a net.Conn-style RemoteAddr.
// IP is retained ONLY for the duration of the auth handshake to drive
// per-IP rate limiting; after authentication succeeds, the IP must not
// be passed into any logger or persistent store.
func ExtractIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}
