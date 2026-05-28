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
)

// Server wires the WebSocket entrypoint, the auth handshake, the router,
// and the offline store together.
type Server struct {
	cfg     *config.Config
	store   *Store
	prekeys *PrekeyStore
	router  *Router
	auth    *Authenticator
	log     *slog.Logger
	hs      *http.Server
	active  int64
}

func New(cfg *config.Config, log *slog.Logger) (*Server, error) {
	store, err := NewStore(cfg.OfflineQueuePath, cfg.MessageTTLSeconds, log)
	if err != nil {
		return nil, err
	}
	prekeys, err := NewPrekeyStore(cfg.PrekeyStorePath, log)
	if err != nil {
		return nil, err
	}
	router := NewRouter(store, cfg.MaxMessageSize, cfg.RateLimitPerMin)
	return &Server{
		cfg:     cfg,
		store:   store,
		prekeys: prekeys,
		router:  router,
		auth:    NewAuthenticator(log),
		log:     log,
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
		s.handleAuthedFrame(ctx, userID, data)
	}
}

// handleAuthedFrame is the inbound dispatch for an already-authenticated
// WebSocket frame. The relay's normal payloads (SealedEnvelope /
// OpenEnvelope) are untagged — they are identified by SHAPE, not by a
// `type` field — and routed through r.router.Route. Control messages
// like prekey bundle registration ARE tagged, with `type`, because there
// is no envelope-shape ambiguity to inherit. Order matters: type-sniff
// first, fall through to envelope routing on miss.
func (s *Server) handleAuthedFrame(ctx context.Context, userID string, data []byte) {
	var hdr struct {
		Type string `json:"type"`
	}
	// Best-effort decode of the discriminator. A parse error here is not
	// itself diagnostic — the envelope branch below will try its own
	// unmarshal and silently drop on malformed input, matching the
	// existing no-feedback policy for invalid client frames.
	if err := json.Unmarshal(data, &hdr); err == nil && hdr.Type == "register_prekeys" {
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
		s.log.Info("prekey bundle registered")
		// TODO: remove before production
		uidPrefix := userID
		if len(uidPrefix) > 8 {
			// uidPrefix = uidPrefix[:8] — DEV: show full ID
		}
		s.log.Info("DEV prekey registered", "uid_prefix", uidPrefix)
		return
	}
	s.router.Route(ctx, userID, data)
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
