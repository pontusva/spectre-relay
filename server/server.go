package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"nhooyr.io/websocket"

	"spectre-relay/config"
	"spectre-relay/model"
)

// Server wires the WebSocket entrypoint, the auth handshake, the router,
// and the offline store together.
type Server struct {
	cfg     *config.Config
	store   *Store
	prekeys *PrekeyStore
	router      *Router
	auth        *Authenticator
	sealedCA    *SealedCA
	certLimiter *rateLimiter
	log         *slog.Logger
	hs          *http.Server
	active      int64
}

// Max sealed-sender certificate requests per authenticated user per minute.
// Certs are valid ~24h and cached client-side, so a legitimate client asks
// roughly once per connect — a small ceiling is plenty and bounds CA-signing
// abuse.
const certRequestsPerMin = 6

func New(cfg *config.Config, log *slog.Logger) (*Server, error) {
	store, err := NewStore(cfg.OfflineQueuePath, cfg.MessageTTLSeconds, log)
	if err != nil {
		return nil, err
	}
	prekeys, err := NewPrekeyStore(cfg.PrekeyStorePath, log)
	if err != nil {
		return nil, err
	}
	sealedCA, err := NewSealedCA(cfg.SealedCAPath)
	if err != nil {
		return nil, err
	}
	router := NewRouter(store, cfg.MaxMessageSize, cfg.RateLimitPerMin, cfg.RelayID)
	return &Server{
		cfg:      cfg,
		store:    store,
		prekeys:  prekeys,
		router:   router,
		auth:        NewAuthenticator(log),
		sealedCA:    sealedCA,
		certLimiter: newRateLimiter(certRequestsPerMin),
		log:         log,
	}, nil
}

func (s *Server) ConnectedClients() int { return s.store.ConnectedClients() }
func (s *Server) QueuedMessages() int   { return s.store.QueuedMessages() }

// Run starts the HTTPS server and blocks until ctx is cancelled or the
// listener fails. On shutdown it gives in-flight connections 30 seconds to
// drain before forcing exit.
func (s *Server) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/ws", s.handleWS)
	// /prekeys/<userId> — PUBLIC, no auth. Prekey BUNDLES contain only
	// public keys, which by definition are not secret. Gating this on
	// auth would also break the bootstrap case: the SENDER fetches the
	// recipient's bundle BEFORE any session has been established, so
	// there is no shared credential to authenticate against. The
	// authentication that matters here is on the WRITE side: only the
	// owning client (over an authenticated WebSocket) can replace its
	// own bundle, which is what binds the published keys to a userID.
	mux.HandleFunc("/prekeys/", s.handlePrekeysGet)
	// /sealed-ca — PUBLIC, no auth. Returns the sealed-sender CA public
	// key for clients to pin. It is a public key by definition; gating it
	// on auth would, like /prekeys, break the bootstrap case (a client
	// needs it to validate the very first sealed message it receives).
	mux.HandleFunc("/sealed-ca", s.handleSealedCA)
	mux.HandleFunc("/federation/deliver", s.handleFederationDeliver)

	// TLS 1.3 only. We pin both Min and Max to 1.3:
	//   - 1.2 still permits RSA key exchange (no PFS) and CBC modes
	//     that have historically been a source of padding-oracle issues.
	//   - 1.3 mandates AEAD ciphers and forward secrecy.
	// Spectre's threat model assumes nation-state observers, so the
	// downgrade resistance of 1.3-only is non-negotiable.
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}

	s.hs = &http.Server{
		Addr:              s.cfg.ListenAddr,
		Handler:           mux,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 15 * time.Second,
		// Deliberately no ReadTimeout/WriteTimeout: WebSocket connections
		// are long-lived and per-message timeouts are applied at the conn
		// layer via context.WithTimeout.
	}

	errCh := make(chan error, 1)
	go func() {
		s.log.Info("relay starting", "config", s.cfg.SafeSummary())
		var err error
		if s.cfg.DevMode && (s.cfg.TLSCertFile == "" || s.cfg.TLSKeyFile == "") {
			// Dev only: plain HTTP. Production refuses to start without TLS
			// (enforced in config.Load).
			err = s.hs.ListenAndServe()
		} else {
			err = s.hs.ListenAndServeTLS(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		s.log.Info("relay shutdown initiated")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		shutdownErr := s.hs.Shutdown(shutdownCtx)
		s.store.Stop()
		return shutdownErr
	case err := <-errCh:
		s.store.Stop()
		return err
	}
}

// handleHealth answers 200 with a single byte "." — no version, no uptime,
// no client count. The endpoint MUST NOT leak deployment fingerprints.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("."))
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	if atomic.LoadInt64(&s.active) >= int64(s.cfg.MaxClients) {
		// Generic 503; no body. Don't expose capacity numbers.
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// Compression disabled: compression-on-encrypted-payloads is a
		// known CRIME-style risk and offers no real bandwidth win when
		// the payload is already an encrypted ciphertext blob.
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		// err_type only — no body of the rejected request.
		s.log.Warn("ws upgrade failed", "err_type", "upgrade")
		return
	}
	// Cap a single frame to the configured ceiling. The websocket library
	// will close the connection if the client tries to exceed this.
	c.SetReadLimit(int64(s.cfg.MaxMessageSize))

	atomic.AddInt64(&s.active, 1)
	defer atomic.AddInt64(&s.active, -1)

	s.serveConn(r.Context(), c, r.RemoteAddr)
}

func (s *Server) serveConn(parentCtx context.Context, c *websocket.Conn, remoteAddr string) {
	// Per-connection panic recovery. We deliberately do NOT log the panic
	// value: it could contain envelope bytes copied into a stack trace or
	// formatted error. Coarse class only.
	defer func() {
		if rec := recover(); rec != nil {
			s.log.Error("connection panic", "err_type", "panic")
			_ = c.Close(websocket.StatusInternalError, "")
			_ = rec
		}
	}()

	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	ip := ExtractIP(remoteAddr)
	userID, err := s.auth.Authenticate(ctx, c, ip)
	if err != nil {
		// SECURITY: log only that auth failed. No IP, no UserID, no reason.
		// Per-IP rate limiting handles abuse internally and quietly.
		s.log.Warn("auth failed")
		_ = c.Close(websocket.StatusPolicyViolation, "")
		return
	}
	// From here on, neither `ip` nor `userID` may appear in any log line.

	// Normalize namespaced userID for registration/local matching if it's local
	parts := strings.SplitN(userID, "@", 2)
	if len(parts) == 2 {
		domain := parts[1]
		if isLocalRelay(domain, s.cfg.RelayID) {
			userID = parts[0]
		}
	}

	if prev := s.store.Register(userID, c); prev != nil {
		_ = prev.Close(websocket.StatusNormalClosure, "")
	}
	defer s.store.Unregister(userID, c)

	s.router.FlushQueue(ctx, userID, c)

	for {
		typ, data, err := c.Read(ctx)
		if err != nil {
			// Could be normal close, network drop, or read-limit violation.
			// We intentionally use a coarse classifier — never the raw err string.
			s.log.Debug("read end", "err_type", classifyWSErr(err))
			return
		}
		if typ != websocket.MessageText && typ != websocket.MessageBinary {
			continue
		}
		s.handleAuthedFrame(ctx, userID, c, data)
	}
}

// handleAuthedFrame is the inbound dispatch for an already-authenticated
// WebSocket frame. The relay's normal payloads (SealedEnvelope /
// OpenEnvelope) are untagged — they are identified by SHAPE, not by a
// `type` field — and routed through r.router.Route. Control messages
// like prekey bundle registration ARE tagged, with `type`, because there
// is no envelope-shape ambiguity to inherit. Order matters: type-sniff
// first, fall through to envelope routing on miss.
func (s *Server) handleAuthedFrame(ctx context.Context, userID string, c *websocket.Conn, data []byte) {
	var hdr struct {
		Type string `json:"type"`
	}
	// Best-effort decode of the discriminator. A parse error here is not
	// itself diagnostic — the envelope branch below will try its own
	// unmarshal and silently drop on malformed input, matching the
	// existing no-feedback policy for invalid client frames.
	if err := json.Unmarshal(data, &hdr); err == nil && hdr.Type == "request_sender_cert" {
		s.issueSenderCert(ctx, userID, c)
		return
	}
	if hdr.Type == "register_prekeys" {
		var msg struct {
			Bundle PrekeyBundle `json:"bundle"`
		}
		if err := json.Unmarshal(data, &msg); err != nil {
			// Silent drop. No structured error response: a body would
			// be a validation oracle for malformed-bundle probing.
			return
		}
		// Bind the bundle to the AUTHENTICATED userID, never to any
		// userID the client supplied in the payload. The WebSocket
		// session is the only authority for ownership.
		if err := s.prekeys.registerBundle(userID, msg.Bundle); err != nil {
			s.log.Warn("prekey register rejected", "err_type", "validate")
			return
		}
		// Debug level + no identifier: the fact that *a* bundle registered is
		// fine for ops; WHICH user registered is metadata we must not log.
		s.log.Debug("prekey bundle registered")
		return
	}
	s.router.Route(ctx, userID, data)
}

// issueSenderCert signs and returns a sealed-sender certificate for the
// authenticated user.
//
// SECURITY: cert.uid is the AUTHENTICATED userID and cert.ik is taken from
// that user's OWN registered prekey bundle — never from anything the client
// put in the request. If the user has not registered a bundle yet there is
// no authoritative identity key to certify, so we drop silently (no error
// body — same no-oracle policy as the rest of the authed frame path).
func (s *Server) issueSenderCert(ctx context.Context, userID string, c *websocket.Conn) {
	// Bound CA-signing abuse per user. Silent drop on exceed — no feedback,
	// consistent with the rest of the authed-frame path.
	if !s.certLimiter.allow(userID, time.Now()) {
		return
	}
	cert, sig, ok := s.buildSenderCert(userID, time.Now())
	if !ok {
		return
	}
	resp, err := json.Marshal(struct {
		Type      string `json:"type"`
		Cert      []byte `json:"cert"`
		Signature []byte `json:"signature"`
	}{Type: "sender_cert", Cert: cert, Signature: sig})
	if err != nil {
		return
	}
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_ = c.Write(wctx, websocket.MessageText, resp)
}

// buildSenderCert builds and signs a sealed-sender certificate for the
// AUTHENTICATED userID, binding it to the identity key from THAT user's own
// registered prekey bundle (never anything the client supplied). Returns
// ok=false if the user has no registered bundle — there is then no
// authoritative identity key to certify. Pure of WS I/O so it is unit-testable.
func (s *Server) buildSenderCert(userID string, now time.Time) (cert, sig []byte, ok bool) {
	ik, found := s.prekeys.identityKeyOf(userID)
	if !found {
		return nil, nil, false
	}
	cert, sig, err := s.sealedCA.IssueCert(userID, ik, s.cfg.RelayID, now)
	if err != nil {
		s.log.Error("sender cert issue failed", "err_type", "sign")
		return nil, nil, false
	}
	return cert, sig, true
}

// handleSealedCA serves the sealed-sender CA public key for client pinning.
// Public, GET-only, no-store — analogous to /prekeys but a single static
// value. No body on the wrong method, consistent with the no-fingerprint
// policy on /health.
func (s *Server) handleSealedCA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(struct {
		PublicKey string `json:"public_key"`
	}{PublicKey: s.sealedCA.PublicKeyB64()}); err != nil {
		s.log.Error("sealed-ca response write failed", "err_type", classifyErr(err))
	}
}

// handlePrekeysGet serves a per-user prekey bundle, consuming one
// one-time prekey atomically. Public endpoint by design — see the
// note at the mux registration.
//
// 404 semantics: returned ONLY when no bundle was ever registered for
// the requested userID. The OTPK-exhausted state is NOT a 404 — it
// returns 200 with `one_time_prekey` omitted, per the Signal protocol
// fallback. Conflating these would let a probe distinguish "never
// registered" from "registered but OTPKs empty", which is a presence
// oracle the relay otherwise prevents.
func (s *Server) handlePrekeysGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// Manual suffix extraction — go1.21 here, no path-pattern params.
	userID := strings.TrimPrefix(r.URL.Path, "/prekeys/")
	if userID == "" || strings.ContainsAny(userID, "/?#") {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	resp, ok := s.prekeys.getBundle(userID)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// Don't cache: each GET MUST round-trip to the relay so the next
	// caller doesn't reuse a one-time prekey served from an intermediate
	// cache. The relay's atomic-consume guarantee depends on this.
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		// Header is already flushed at this point on most error paths;
		// nothing useful we can return. Log class only.
		s.log.Error("prekey response write failed", "err_type", classifyErr(err))
	}
}

func classifyWSErr(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "ctx"
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return "net"
	}
	return "ws"
}

func (s *Server) handleFederationDeliver(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	relayID := r.Header.Get("X-Spectre-Relay-ID")
	if relayID == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var sealed model.SealedEnvelope
	if err := json.NewDecoder(r.Body).Decode(&sealed); err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if sealed.RecipientID == "" || len(sealed.Ciphertext) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// RecipientID must be a local user (no @ or domain matches local RELAY_ID)
	parts := strings.SplitN(sealed.RecipientID, "@", 2)
	if len(parts) == 2 {
		domain := parts[1]
		if !isLocalRelay(domain, s.cfg.RelayID) {
			// Drop silently
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}

	// Preserve the original RecipientID on the sealed envelope so the recipient client
	// can verify the cryptographic commitments/AAD. We only pass the local username
	// (parts[0]) to the router for local delivery routing.
	sealed.FederationSenderRelay = relayID

	s.router.deliver(r.Context(), parts[0], queuedMessage{Sealed: &sealed})
	w.WriteHeader(http.StatusNoContent)
}
