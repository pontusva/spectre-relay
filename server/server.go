package server

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"nhooyr.io/websocket"

	"spectre-relay/config"
)

// Server wires the WebSocket entrypoint, the auth handshake, the router,
// and the offline store together.
type Server struct {
	cfg    *config.Config
	store  *Store
	router *Router
	auth   *Authenticator
	log    *slog.Logger
	hs     *http.Server
	active int64
}

func New(cfg *config.Config, log *slog.Logger) (*Server, error) {
	store, err := NewStore(cfg.OfflineQueuePath, cfg.MessageTTLSeconds, log)
	if err != nil {
		return nil, err
	}
	router := NewRouter(store, cfg.MaxMessageSize, cfg.RateLimitPerMin)
	return &Server{
		cfg:    cfg,
		store:  store,
		router: router,
		auth:   NewAuthenticator(),
		log:    log,
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
		s.router.Route(ctx, userID, data)
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
