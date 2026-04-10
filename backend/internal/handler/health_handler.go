package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

type healthResponse struct {
	Status   string            `json:"status"`
	Checks   map[string]string `json:"checks"`
	Uptime   string            `json:"uptime"`
}

// HealthHandler exposes a liveness + readiness probe.
type HealthHandler struct {
	db      *pgxpool.Pool
	redis   *redis.Client // may be nil
	startAt time.Time
}

// NewHealthHandler creates a HealthHandler.
func NewHealthHandler(db *pgxpool.Pool, redisClient *redis.Client) *HealthHandler {
	return &HealthHandler{db: db, redis: redisClient, startAt: time.Now()}
}

// Health handles GET /health.
// Returns 200 when all required dependencies are reachable, 503 otherwise.
func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	checks := make(map[string]string)
	healthy := true

	// --- PostgreSQL ---
	if err := h.db.Ping(ctx); err != nil {
		checks["postgres"] = "unhealthy: " + err.Error()
		healthy = false
	} else {
		checks["postgres"] = "ok"
	}

	// --- Redis (optional) ---
	if h.redis != nil {
		if err := h.redis.Ping(ctx).Err(); err != nil {
			checks["redis"] = "unhealthy: " + err.Error()
			// Redis is used for caching/rate-limiting — degrade gracefully rather
			// than marking the whole service as unhealthy.
		} else {
			checks["redis"] = "ok"
		}
	}

	status := "ok"
	httpStatus := http.StatusOK
	if !healthy {
		status = "degraded"
		httpStatus = http.StatusServiceUnavailable
	}

	writeJSON(w, httpStatus, healthResponse{
		Status: status,
		Checks: checks,
		Uptime: time.Since(h.startAt).Round(time.Second).String(),
	})
}
