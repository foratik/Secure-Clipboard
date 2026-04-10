package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"

	"github.com/foratik/secure-clipboard/backend/internal/cache"
	"github.com/foratik/secure-clipboard/backend/internal/config"
	appCrypto "github.com/foratik/secure-clipboard/backend/internal/crypto"
	"github.com/foratik/secure-clipboard/backend/internal/handler"
	appMiddleware "github.com/foratik/secure-clipboard/backend/internal/middleware"
	"github.com/foratik/secure-clipboard/backend/internal/repository"
	"github.com/foratik/secure-clipboard/backend/internal/service"
)

func main() {
	// Load .env if present (ignored in production where env vars are injected).
	_ = godotenv.Load()

	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	// ---- Config ----
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// ---- Logger ----
	log := buildLogger(cfg.LogLevel)
	slog.SetDefault(log)

	// ---- Postgres ----
	pool, err := buildDBPool(cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("connecting to postgres: %w", err)
	}
	defer pool.Close()
	log.Info("postgres connected", "url", sanitizeURL(cfg.DatabaseURL))

	// ---- Redis (optional) ----
	redisClient, err := cache.NewRedisClient(cfg.RedisURL)
	if err != nil {
		return fmt.Errorf("connecting to redis: %w", err)
	}

	var clipCache cache.ClipCache
	var rateLimiter appMiddleware.RateLimiterMiddleware

	if redisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if pingErr := cache.Ping(ctx, redisClient); pingErr != nil {
			cancel()
			log.Warn("redis ping failed — cache and rate limiting disabled", "error", pingErr)
			clipCache = cache.NoopCache{}
			rateLimiter = appMiddleware.NoopRateLimiter{}
		} else {
			cancel()
			log.Info("redis connected", "url", cfg.RedisURL)
			clipCache = cache.NewRedisCache(redisClient)
			rateLimiter = appMiddleware.NewRateLimiter(redisClient, cfg.RateLimitMax, cfg.RateLimitWindow)
		}
		defer redisClient.Close()
	} else {
		log.Warn("REDIS_URL not set — cache and rate limiting disabled")
		clipCache = cache.NoopCache{}
		rateLimiter = appMiddleware.NoopRateLimiter{}
	}

	// ---- Crypto ----
	cipher, err := appCrypto.NewCipher(cfg.EncryptionKey)
	if err != nil {
		return fmt.Errorf("initialising cipher: %w", err)
	}

	// ---- Wire dependencies ----
	repo := repository.NewPostgres(pool)
	svc := service.New(repo, clipCache, cipher, log)

	clipHandler := handler.NewClipHandler(svc, log, cfg.MaxContentBytes)
	healthHandler := handler.NewHealthHandler(pool, redisClient)

	// ---- Router ----
	r := buildRouter(cfg, clipHandler, healthHandler, rateLimiter, log)

	// ---- Background cleanup goroutine ----
	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())
	defer cleanupCancel()
	go runCleanup(cleanupCtx, svc, cfg.CleanupInterval, log)

	// ---- HTTP Server ----
	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// ---- Graceful shutdown ----
	shutdownCh := make(chan os.Signal, 1)
	signal.Notify(shutdownCh, syscall.SIGINT, syscall.SIGTERM)

	serverErr := make(chan error, 1)
	go func() {
		log.Info("server listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	select {
	case err := <-serverErr:
		return fmt.Errorf("server error: %w", err)
	case sig := <-shutdownCh:
		log.Info("shutdown signal received", "signal", sig)
	}

	cleanupCancel()

	shutdownCtx, shutdownRelease := context.WithTimeout(context.Background(), 20*time.Second)
	defer shutdownRelease()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	log.Info("server stopped cleanly")
	return nil
}

// buildRouter wires all routes and middleware.
func buildRouter(
	cfg *config.Config,
	clipH *handler.ClipHandler,
	healthH *handler.HealthHandler,
	rl appMiddleware.RateLimiterMiddleware,
	log *slog.Logger,
) *chi.Mux {
	r := chi.NewRouter()

	// Global middleware
	r.Use(appMiddleware.RequestID)
	r.Use(appMiddleware.CORS(cfg.AllowedOrigins))
	r.Use(chiMiddleware.RealIP)
	r.Use(chiMiddleware.Recoverer)
	r.Use(requestLogger(log))

	// Health (no rate limiting)
	r.Get("/health", healthH.Health)

	// API v1
	r.Route("/api/v1", func(r chi.Router) {
		r.Route("/clips", func(r chi.Router) {
			r.With(rl.Middleware("create")).Post("/", clipH.CreateClip)

			r.Route("/{code:[0-9]{6}}", func(r chi.Router) {
				r.With(rl.Middleware("view")).Get("/", clipH.GetClip)
				r.With(rl.Middleware("unlock")).Post("/unlock", clipH.UnlockClip)
				r.With(rl.Middleware("consume")).Post("/consume", clipH.ConsumeClip)
			})
		})
	})

	return r
}

// buildDBPool creates a pgxpool connection pool with sane defaults.
func buildDBPool(dsn string) (*pgxpool.Pool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parsing DATABASE_URL: %w", err)
	}

	poolCfg.MaxConns = 20
	poolCfg.MinConns = 2
	poolCfg.MaxConnLifetime = 30 * time.Minute
	poolCfg.MaxConnIdleTime = 5 * time.Minute
	poolCfg.HealthCheckPeriod = time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, err
	}
	if err = pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging postgres: %w", err)
	}
	return pool, nil
}

// runCleanup periodically deletes expired clips.
func runCleanup(ctx context.Context, svc *service.ClipService, interval time.Duration, log *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			svc.DeleteExpired(ctx)
		}
	}
}

// buildLogger returns a structured logger based on the configured log level.
func buildLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}

// requestLogger returns a chi-compatible middleware that emits structured access logs.
func requestLogger(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := chiMiddleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			log.InfoContext(r.Context(), "request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", ww.Status(),
				"bytes", ww.BytesWritten(),
				"duration_ms", time.Since(start).Milliseconds(),
				"request_id", appMiddleware.GetRequestID(r.Context()),
				"ip", r.RemoteAddr,
			)
		})
	}
}

// sanitizeURL strips credentials from a connection string for logging.
func sanitizeURL(raw string) string {
	// Simple approach: hide everything between :// and @ if it exists.
	if i := indexAfter(raw, "://"); i >= 0 {
		if j := lastIndex(raw[i:], "@"); j >= 0 {
			return raw[:i] + "***@" + raw[i+j+1:]
		}
	}
	return raw
}

func indexAfter(s, sep string) int {
	for i := 0; i <= len(s)-len(sep); i++ {
		if s[i:i+len(sep)] == sep {
			return i + len(sep)
		}
	}
	return -1
}

func lastIndex(s, substr string) int {
	last := -1
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			last = i
		}
	}
	return last
}
