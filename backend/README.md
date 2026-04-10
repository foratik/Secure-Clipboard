# Secure Clipboard — Go Backend

Production-ready REST API backend for [Secure Clipboard](https://paste.sforati.ir), a privacy-first temporary pastebin with server-side and client-side end-to-end encryption.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Go 1.22 |
| Router | [chi v5](https://github.com/go-chi/chi) |
| Database | PostgreSQL (via [pgx/v5](https://github.com/jackc/pgx)) |
| Cache / Rate-limit | Redis (via [go-redis/v9](https://github.com/redis/go-redis)) |
| Encryption at rest | AES-256-GCM |
| Password hashing | Argon2id |
| Structured logging | `log/slog` (stdlib) |
| Config | Environment variables + `.env` file |

---

## Quick Start

```bash
cd backend

# 1. Copy and edit configuration
cp .env.example .env
# set DATABASE_URL, ENCRYPTION_KEY (see below), optionally REDIS_URL

# 2. Generate a fresh 32-byte AES key
make keygen        # prints a hex string — paste into ENCRYPTION_KEY

# 3. Apply the database schema
make migrate       # requires psql in PATH and DATABASE_URL set in shell

# 4. Build and run
make run
```

Server starts on `http://localhost:8080` (or `PORT` from env).

---

## Configuration

All configuration is read from **environment variables** (or a `.env` file in the working directory).

| Variable | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | ✅ | — | PostgreSQL DSN, e.g. `postgres://user:pass@host:5432/db?sslmode=disable` |
| `ENCRYPTION_KEY` | ✅ | — | 64-char lowercase hex string (32 bytes). Generate with `openssl rand -hex 32` |
| `REDIS_URL` | — | — | Redis URL, e.g. `redis://localhost:6379/0`. Omit to disable cache & rate limiting |
| `PORT` | — | `8080` | TCP port to listen on |
| `LOG_LEVEL` | — | `info` | `debug` \| `info` \| `warn` \| `error` |
| `RATE_LIMIT_MAX` | — | `40` | Maximum requests per IP per window |
| `RATE_LIMIT_WINDOW_SEC` | — | `60` | Sliding window size in seconds |
| `ALLOWED_ORIGINS` | — | `*` | Comma-separated CORS origins, or `*` for wildcard |

---

## Database Schema

```sql
CREATE TABLE clips (
    id                  BIGSERIAL    PRIMARY KEY,
    code                CHAR(6)      NOT NULL UNIQUE,  -- zero-padded 6-digit code
    content_encrypted   TEXT         NOT NULL,          -- AES-256-GCM ciphertext (server) or AES-GCM JSON blob (client)
    password_hash       TEXT,                           -- Argon2id PHC string (server-side password)
    expire_at           TIMESTAMPTZ,                    -- NULL = never expires
    is_one_time         BOOLEAN      NOT NULL DEFAULT FALSE,
    is_client_encrypted BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
```

See `migrations/001_init.sql` for indexes.

---

## API Reference

**Base URL:** `/api/v1`

All request and response bodies are `application/json`.
Every response includes an `X-Request-ID` header for tracing.

---

### Create a clip

```
POST /api/v1/clips
```

#### Request body

| Field | Type | Required | Description |
|---|---|---|---|
| `content` | string | ✅ | Plaintext (server-encrypted) **or** AES-GCM JSON payload (client-encrypted) |
| `password` | string | — | Server-side password. Only valid when `is_client_encrypted=false` |
| `duration` | string | — | Expiry duration. See table below. Omit for no expiry |
| `is_one_time` | bool | — | Delete after first successful retrieval (default `false`) |
| `is_client_encrypted` | bool | — | `true` when `content` is a client-side AES-GCM JSON blob |

**Valid `duration` values**

| Value | Meaning |
|---|---|
| `5m` | 5 minutes |
| `10m` | 10 minutes |
| `30m` | 30 minutes |
| `1h` | 1 hour |
| `12h` | 12 hours |
| `1d` | 1 day |
| `1w` | 1 week |
| `1M` | 30 days |

#### Response `201 Created`

```json
{
  "code": "042817",
  "expire_at": "2026-04-11T10:00:00Z"
}
```

`expire_at` is omitted when no duration was specified.

#### Error responses

| Status | `code` | Cause |
|---|---|---|
| `400` | `INVALID_REQUEST` | Empty content, bad duration, malformed client payload |
| `429` | `RATE_LIMITED` | Too many requests from this IP |

#### Example — plain text, 1 hour, one-time

```bash
curl -X POST http://localhost:8080/api/v1/clips \
  -H 'Content-Type: application/json' \
  -d '{
    "content": "my secret message",
    "duration": "1h",
    "is_one_time": true
  }'
```

#### Example — client-encrypted (browser sends AES-GCM blob)

```bash
curl -X POST http://localhost:8080/api/v1/clips \
  -H 'Content-Type: application/json' \
  -d '{
    "content": "{\"v\":1,\"alg\":\"AES-GCM\",\"kdf\":\"PBKDF2\",\"iter\":250000,\"salt\":\"...\",\"iv\":\"...\",\"ct\":\"...\"}",
    "duration": "1d",
    "is_client_encrypted": true
  }'
```

---

### Get a clip

```
GET /api/v1/clips/{code}
```

`{code}` must be exactly 6 numeric digits.

#### Possible responses

**`200 OK` — plaintext (server-decrypted)**

Returned for server-encrypted clips with no password.

```json
{
  "code": "042817",
  "content": "my secret message",
  "requires_password": false,
  "is_client_encrypted": false,
  "is_one_time": false,
  "expire_at": "2026-04-11T10:00:00Z"
}
```

**`200 OK` — password required**

Returned when the clip is protected by a server-side password. Submit the password to `/unlock`.

```json
{
  "code": "042817",
  "requires_password": true,
  "is_client_encrypted": false,
  "is_one_time": false,
  "expire_at": "2026-04-11T10:00:00Z"
}
```

**`200 OK` — client-encrypted payload**

The server returns the opaque blob; decryption happens in the browser.

```json
{
  "code": "042817",
  "payload": "{\"v\":1,\"alg\":\"AES-GCM\",\"kdf\":\"PBKDF2\",\"iter\":250000,\"salt\":\"...\",\"iv\":\"...\",\"ct\":\"...\"}",
  "requires_password": false,
  "is_client_encrypted": true,
  "is_one_time": true,
  "expire_at": null
}
```

#### Error responses

| Status | `code` | Cause |
|---|---|---|
| `404` | `CLIP_NOT_FOUND` | No clip exists for that code |
| `410` | `CLIP_EXPIRED` | Clip existed but has expired |
| `429` | `RATE_LIMITED` | Too many requests |

---

### Unlock a password-protected clip

```
POST /api/v1/clips/{code}/unlock
```

#### Request body

```json
{ "password": "my passphrase" }
```

#### Response `200 OK`

```json
{ "content": "my secret message" }
```

#### Error responses

| Status | `code` | Cause |
|---|---|---|
| `400` | `NOT_PASSWORD_PROTECTED` | Clip does not require a password |
| `400` | `INVALID_REQUEST` | Empty password |
| `401` | `WRONG_PASSWORD` | Password is incorrect |
| `404` | `CLIP_NOT_FOUND` | Clip does not exist |
| `410` | `CLIP_EXPIRED` | Clip has expired |
| `429` | `RATE_LIMITED` | Too many requests |

---

### Consume a one-time client-encrypted clip

```
POST /api/v1/clips/{code}/consume
```

Called by the browser **after** it has successfully decrypted a one-time client-encrypted clip. This permanently deletes the clip from storage.

The endpoint is **idempotent** — calling it on an already-consumed or non-existent code returns `200 OK`.

#### Response `200 OK`

```json
{ "ok": true }
```

---

### Health check

```
GET /health
```

No authentication required. Returns `200` when all required dependencies are reachable, `503` otherwise.

#### Response `200 OK`

```json
{
  "status": "ok",
  "checks": {
    "postgres": "ok",
    "redis": "ok"
  },
  "uptime": "4h32m10s"
}
```

---

## Error Envelope

All error responses share the same JSON shape:

```json
{
  "code": "CLIP_NOT_FOUND",
  "message": "clip not found"
}
```

| `code` | HTTP status | Meaning |
|---|---|---|
| `CLIP_NOT_FOUND` | 404 | No clip for that code |
| `CLIP_EXPIRED` | 410 | Clip has passed its expiry |
| `WRONG_PASSWORD` | 401 | Incorrect password |
| `NOT_PASSWORD_PROTECTED` | 400 | Clip has no server-side password |
| `INVALID_REQUEST` | 400 | Malformed JSON, missing fields, invalid duration |
| `RATE_LIMITED` | 429 | Per-IP sliding-window limit exceeded |
| `INTERNAL_ERROR` | 500 | Unexpected server error (check `X-Request-ID` in logs) |

---

## Architecture

```
cmd/server/main.go          ← entry point, DI wiring, graceful shutdown
internal/
  config/     config.go     ← env-var loading & validation
  crypto/     crypto.go     ← AES-256-GCM encrypt/decrypt, Argon2id hash/verify
  model/      clip.go       ← domain types, request/response DTOs, validation
  repository/ clip_repository.go  ← PostgreSQL queries via pgx/v5
  cache/      cache.go      ← Redis clip cache (NoopCache fallback)
  service/    clip_service.go     ← business logic, cache-aside strategy
  handler/    clip_handler.go     ← HTTP handlers (chi router)
              health_handler.go   ← /health liveness + readiness probe
              response.go         ← JSON helpers, error mapping
  middleware/ ratelimit.go  ← Redis sliding-window rate limiter (Lua script)
              cors.go       ← CORS header injection
              requestid.go  ← X-Request-ID propagation
migrations/   001_init.sql  ← initial PostgreSQL schema
```

### Read-heavy caching strategy

- **Cache-aside**: on `GET /clips/{code}`, the service checks Redis first; on a miss it queries Postgres and writes the result back to Redis.
- **What is cached**: the encrypted clip struct (never plaintext). AES-256-GCM decryption is performed on every serve — it is fast (~µs) and keeps Redis exposure-safe.
- **TTL**: `min(expire_at − now, 24 h)`. Non-expiring clips are cached for 24 hours.
- **One-time clips** are never cached. The atomic `SELECT … FOR UPDATE` + `DELETE` transaction in Postgres prevents double-reads under concurrent load.
- **Cache invalidation**: `DELETE /consume` and expiry cleanup both evict the Redis key.

### Rate limiting

Per-IP sliding-window rate limiting is implemented with a Redis **sorted set + Lua script** (atomic, no race conditions). Four independent scopes: `create`, `view`, `unlock`, `consume`. When Redis is unavailable the limiter fails open.

### Background cleanup

A goroutine ticks every 5 minutes and runs `DELETE FROM clips WHERE expire_at < NOW()`, keeping the table lean without a cron job.

---

## Running with Docker (example)

```bash
docker run -d \
  -e DATABASE_URL="postgres://user:pass@host:5432/db" \
  -e ENCRYPTION_KEY="$(openssl rand -hex 32)" \
  -e REDIS_URL="redis://redis:6379/0" \
  -p 8080:8080 \
  secure-clipboard-backend
```

---

## Development

```bash
make tidy     # go mod tidy
make build    # compile to bin/secure-clipboard
make test     # go test -race -cover ./...
make lint     # golangci-lint run ./...
make keygen   # generate a fresh ENCRYPTION_KEY
```
