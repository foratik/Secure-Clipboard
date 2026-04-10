// Package middleware provides reusable HTTP middleware components.
package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// rateLimitScript is a Redis Lua script that atomically implements a sliding
// window rate limiter using a sorted set per (scope, IP) key.
//
// KEYS[1]  – Redis key for this bucket
// ARGV[1]  – current timestamp in milliseconds (string)
// ARGV[2]  – window start timestamp in milliseconds (now - window)
// ARGV[3]  – maximum allowed requests in the window
// ARGV[4]  – window length in milliseconds (used as TTL)
//
// Returns 1 if the request is allowed, 0 if rate-limited.
var rateLimitScript = redis.NewScript(`
local key         = KEYS[1]
local now         = tonumber(ARGV[1])
local window_start= tonumber(ARGV[2])
local max_req     = tonumber(ARGV[3])
local window_ms   = tonumber(ARGV[4])

redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)
local count = redis.call('ZCARD', key)
if count >= max_req then
    return 0
end
redis.call('ZADD', key, now, tostring(now))
redis.call('PEXPIRE', key, window_ms)
return 1
`)

// RateLimiter enforces per-IP sliding-window rate limits using Redis.
type RateLimiter struct {
	client  *redis.Client
	max     int
	window  time.Duration
}

// NewRateLimiter creates a RateLimiter.
func NewRateLimiter(client *redis.Client, max int, window time.Duration) *RateLimiter {
	return &RateLimiter{client: client, max: max, window: window}
}

// Middleware returns an http.Handler middleware that enforces rate limiting
// for the given scope label (e.g. "create", "view").
// Requests that exceed the limit receive 429 Too Many Requests.
// If Redis is unavailable the middleware fails open (request is allowed).
func (rl *RateLimiter) Middleware(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)
			key := fmt.Sprintf("rl:%s:%s", scope, ip)

			allowed, err := rl.allow(r.Context(), key)
			if err != nil {
				// Fail open: let the request through on Redis errors.
				next.ServeHTTP(w, r)
				return
			}
			if !allowed {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"code":    "RATE_LIMITED",
					"message": "too many requests — please slow down",
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (rl *RateLimiter) allow(ctx context.Context, key string) (bool, error) {
	now := time.Now().UnixMilli()
	windowStart := now - rl.window.Milliseconds()

	result, err := rateLimitScript.Run(ctx, rl.client,
		[]string{key},
		now,
		windowStart,
		rl.max,
		rl.window.Milliseconds(),
	).Int()
	if err != nil {
		return true, fmt.Errorf("rate limit script: %w", err)
	}
	return result == 1, nil
}

// NoopRateLimiter always allows requests; used when Redis is not configured.
type NoopRateLimiter struct{}

func (NoopRateLimiter) Middleware(_ string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler { return next }
}

// RateLimiterMiddleware is the common interface satisfied by both implementations.
type RateLimiterMiddleware interface {
	Middleware(scope string) func(http.Handler) http.Handler
}

// clientIP extracts the real client IP, honoring X-Forwarded-For when set
// (as populated by reverse proxies such as nginx or Caddy).
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if ip := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0]); ip != "" {
			return ip
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	// Strip port from RemoteAddr.
	addr := r.RemoteAddr
	if i := strings.LastIndex(addr, ":"); i != -1 {
		addr = addr[:i]
	}
	return addr
}
