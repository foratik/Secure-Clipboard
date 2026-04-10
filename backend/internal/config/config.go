package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all runtime configuration loaded from environment variables.
type Config struct {
	DatabaseURL     string
	RedisURL        string        // optional; disables cache/rate-limit if empty
	EncryptionKey   string        // 64-char hex string representing 32 bytes
	Port            string
	RateLimitMax    int
	RateLimitWindow time.Duration
	AllowedOrigins  []string
	LogLevel        string
	CleanupInterval time.Duration
	MaxContentBytes int64
}

// Load reads configuration from environment variables.
// Required: DATABASE_URL, ENCRYPTION_KEY
func Load() (*Config, error) {
	cfg := &Config{
		DatabaseURL:     os.Getenv("DATABASE_URL"),
		RedisURL:        os.Getenv("REDIS_URL"),
		EncryptionKey:   os.Getenv("ENCRYPTION_KEY"),
		Port:            envOr("PORT", "8080"),
		LogLevel:        envOr("LOG_LEVEL", "info"),
		CleanupInterval: 5 * time.Minute,
		MaxContentBytes: 1 << 20, // 1 MiB
	}

	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}
	if cfg.EncryptionKey == "" {
		return nil, fmt.Errorf("ENCRYPTION_KEY is required (64 hex chars = 32 bytes)")
	}
	if len(cfg.EncryptionKey) != 64 {
		return nil, fmt.Errorf("ENCRYPTION_KEY must be exactly 64 hex characters (got %d)", len(cfg.EncryptionKey))
	}

	maxReq, err := strconv.Atoi(envOr("RATE_LIMIT_MAX", "40"))
	if err != nil {
		return nil, fmt.Errorf("RATE_LIMIT_MAX must be an integer: %w", err)
	}
	cfg.RateLimitMax = maxReq

	windowSec, err := strconv.Atoi(envOr("RATE_LIMIT_WINDOW_SEC", "60"))
	if err != nil {
		return nil, fmt.Errorf("RATE_LIMIT_WINDOW_SEC must be an integer: %w", err)
	}
	cfg.RateLimitWindow = time.Duration(windowSec) * time.Second

	originsRaw := envOr("ALLOWED_ORIGINS", "*")
	for _, o := range strings.Split(originsRaw, ",") {
		if t := strings.TrimSpace(o); t != "" {
			cfg.AllowedOrigins = append(cfg.AllowedOrigins, t)
		}
	}

	return cfg, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
