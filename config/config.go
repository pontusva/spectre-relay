package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
)

// Config is loaded exclusively from environment variables.
// No on-disk config files: reduces blast radius if the container image
// is exfiltrated and keeps secrets out of layered filesystems.
type Config struct {
	ListenAddr        string
	TLSCertFile       string
	TLSKeyFile        string
	MaxClients        int
	MessageTTLSeconds int64
	MaxMessageSize    int
	RateLimitPerMin   int
	OfflineQueuePath  string
	DevMode           bool
}

// Load reads the environment and applies secure defaults.
// In production (SPECTRE_DEV != "true") TLS cert and key are mandatory:
// plaintext WebSocket is unacceptable under Spectre's threat model
// (nation-state adversaries observing journalist/activist traffic).
func Load() (*Config, error) {
	cfg := &Config{
		ListenAddr:        getEnv("SPECTRE_LISTEN_ADDR", ":443"),
		TLSCertFile:       os.Getenv("SPECTRE_TLS_CERT"),
		TLSKeyFile:        os.Getenv("SPECTRE_TLS_KEY"),
		MaxClients:        getEnvInt("SPECTRE_MAX_CLIENTS", 10000),
		MessageTTLSeconds: int64(getEnvInt("SPECTRE_MESSAGE_TTL", 604800)),
		MaxMessageSize:    getEnvInt("SPECTRE_MAX_MESSAGE_SIZE", 65536),
		RateLimitPerMin:   getEnvInt("SPECTRE_RATE_LIMIT_PER_MIN", 60),
		OfflineQueuePath:  getEnv("SPECTRE_QUEUE_PATH", "/data/offline_queue.enc"),
		DevMode:           os.Getenv("SPECTRE_DEV") == "true",
	}

	if !cfg.DevMode {
		if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
			// Fail closed: never start an unencrypted relay outside dev.
			return nil, errors.New("SPECTRE_TLS_CERT and SPECTRE_TLS_KEY are required in production")
		}
	}

	if cfg.MaxClients <= 0 || cfg.MaxMessageSize <= 0 || cfg.RateLimitPerMin <= 0 || cfg.MessageTTLSeconds <= 0 {
		return nil, errors.New("invalid config: numeric fields must be positive")
	}
	return cfg, nil
}

// SafeSummary returns a one-line description of non-sensitive config fields.
// Cert paths are omitted: a path leak can reveal deployment layout.
func (c *Config) SafeSummary() string {
	return fmt.Sprintf(
		"listen=%s max_clients=%d msg_ttl_s=%d max_msg_size=%d rate_limit_per_min=%d dev=%t",
		c.ListenAddr, c.MaxClients, c.MessageTTLSeconds, c.MaxMessageSize, c.RateLimitPerMin, c.DevMode,
	)
}

func getEnv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func getEnvInt(k string, def int) int {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}
