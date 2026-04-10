// Package cache wraps Redis to provide a typed clip cache layer.
// The encrypted content is cached verbatim (never plaintext), so Redis
// exposure does not leak clip content.
package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/foratik/secure-clipboard/backend/internal/model"
)

const keyPrefix = "clip:"

// ErrMiss is returned when the requested key is not in the cache.
var ErrMiss = errors.New("cache miss")

// ClipCache defines the caching contract used by the service layer.
type ClipCache interface {
	Get(ctx context.Context, code string) (*model.Clip, error)
	Set(ctx context.Context, clip *model.Clip) error
	Delete(ctx context.Context, code string) error
}

// RedisCache is the Redis-backed implementation of ClipCache.
type RedisCache struct {
	client *redis.Client
}

// NewRedisCache creates a new RedisCache backed by the provided client.
func NewRedisCache(client *redis.Client) *RedisCache {
	return &RedisCache{client: client}
}

// Get retrieves a cached clip. Returns ErrMiss if the key does not exist.
func (c *RedisCache) Get(ctx context.Context, code string) (*model.Clip, error) {
	data, err := c.client.Get(ctx, keyPrefix+code).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrMiss
	}
	if err != nil {
		return nil, fmt.Errorf("redis GET: %w", err)
	}

	var clip model.Clip
	if err = json.Unmarshal(data, &clip); err != nil {
		return nil, fmt.Errorf("unmarshal cached clip: %w", err)
	}
	return &clip, nil
}

// Set stores a clip in Redis with a TTL derived from its expiry.
// One-time clips must NOT be cached; callers are responsible for this guard.
func (c *RedisCache) Set(ctx context.Context, clip *model.Clip) error {
	ttl := clip.CacheTTL()
	if ttl <= 0 {
		// Clip is already expired; skip caching.
		return nil
	}

	data, err := json.Marshal(clip)
	if err != nil {
		return fmt.Errorf("marshal clip: %w", err)
	}

	if err = c.client.Set(ctx, keyPrefix+clip.Code, data, ttl).Err(); err != nil {
		return fmt.Errorf("redis SET: %w", err)
	}
	return nil
}

// Delete removes a clip from the cache (idempotent).
func (c *RedisCache) Delete(ctx context.Context, code string) error {
	if err := c.client.Del(ctx, keyPrefix+code).Err(); err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("redis DEL: %w", err)
	}
	return nil
}

// NoopCache is a no-op implementation used when Redis is not configured.
// It always reports a miss on Get and silently drops Set/Delete calls.
type NoopCache struct{}

func (NoopCache) Get(_ context.Context, _ string) (*model.Clip, error) { return nil, ErrMiss }
func (NoopCache) Set(_ context.Context, _ *model.Clip) error           { return nil }
func (NoopCache) Delete(_ context.Context, _ string) error             { return nil }

// NewRedisClient creates a Redis client from a URL such as redis://localhost:6379/0.
// Returns (nil, nil) if url is empty so callers can fall back to NoopCache.
func NewRedisClient(url string) (*redis.Client, error) {
	if url == "" {
		return nil, nil
	}
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("parsing REDIS_URL: %w", err)
	}
	return redis.NewClient(opts), nil
}

// Ping verifies connectivity to Redis. Use during startup health checks.
func Ping(ctx context.Context, client *redis.Client) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return client.Ping(ctx).Err()
}
