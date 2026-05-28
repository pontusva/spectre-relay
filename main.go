package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"spectre-relay/config"
	"spectre-relay/server"
)

func main() {
	// JSON-structured logs to stdout. The slog handler is the ONLY log
	// surface — any package that needs to emit info routes through here.
	//
	// SPECTRE_DEBUG=true lowers the handler floor to Debug so the
	// temporary auth-handshake trace in server/auth.go actually reaches
	// stdout. Same env var the Authenticator samples, so the two stay
	// in lockstep — no scenario where dbg() fires but the handler drops
	// the line, or vice versa.
	level := slog.LevelInfo
	if os.Getenv("SPECTRE_DEBUG") == "true" {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

	cfg, err := config.Load()
	if err != nil {
		// Don't surface the raw error (it may contain a misconfigured path);
		// just log the class and exit.
		log.Error("config load failed", "err_type", "config")
		os.Exit(1)
	}

	// Startup banner. Only fields that have already been deemed safe to
	// emit are printed (see Config.SafeSummary).
	fmt.Fprintln(os.Stderr, "==============================================")
	fmt.Fprintln(os.Stderr, "spectre-relay")
	fmt.Fprintln(os.Stderr, cfg.SafeSummary())
	if cfg.DevMode {
		fmt.Fprintln(os.Stderr, "WARNING: dev mode enabled — DO NOT USE IN PRODUCTION")
	}
	fmt.Fprintln(os.Stderr, "==============================================")

	srv, err := server.New(cfg, log)
	if err != nil {
		log.Error("server init failed", "err_type", "init")
		os.Exit(1)
	}

	// SIGINT and SIGTERM trigger a graceful drain (30s inside Server.Run).
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	if err := srv.Run(ctx); err != nil {
		log.Error("server exit", "err_type", "run")
		os.Exit(1)
	}
	log.Info("relay stopped cleanly")
}
