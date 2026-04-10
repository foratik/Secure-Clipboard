package model

import (
	"encoding/json"
	"fmt"
	"time"
)

// Clip is the core domain entity stored in the database.
type Clip struct {
	ID                int64
	Code              string     // 6-digit zero-padded numeric code
	ContentEncrypted  string     // AES-256-GCM ciphertext (base64) or raw client payload JSON
	PasswordHash      *string    // argon2id hash; nil if no server-side password
	ExpireAt          *time.Time // nil means never expires
	IsOneTime         bool
	IsClientEncrypted bool // content is an opaque AES-GCM JSON blob from the browser
	CreatedAt         time.Time
}

// IsExpired reports whether the clip has passed its expiry time.
func (c *Clip) IsExpired() bool {
	return c.ExpireAt != nil && time.Now().UTC().After(*c.ExpireAt)
}

// CacheTTL returns how long this clip should remain cached.
// One-time clips should not be cached at all (caller must check IsOneTime).
func (c *Clip) CacheTTL() time.Duration {
	const maxTTL = 24 * time.Hour
	if c.ExpireAt == nil {
		return maxTTL
	}
	ttl := time.Until(*c.ExpireAt)
	if ttl <= 0 {
		return 0
	}
	if ttl > maxTTL {
		return maxTTL
	}
	return ttl
}

// ---- Valid durations ----

var validDurations = map[string]time.Duration{
	"5m":  5 * time.Minute,
	"10m": 10 * time.Minute,
	"30m": 30 * time.Minute,
	"1h":  time.Hour,
	"12h": 12 * time.Hour,
	"1d":  24 * time.Hour,
	"1w":  7 * 24 * time.Hour,
	"1M":  30 * 24 * time.Hour,
}

// ParseDuration converts a duration string to an expiry time.
// Returns nil if the string is empty (no expiry).
func ParseDuration(s string) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	d, ok := validDurations[s]
	if !ok {
		return nil, fmt.Errorf("unsupported duration %q; valid options: 5m 10m 30m 1h 12h 1d 1w 1M", s)
	}
	t := time.Now().UTC().Add(d)
	return &t, nil
}

// ---- Client-side encryption payload ----

// ClientPayload is the structured JSON object the browser sends when it performs
// AES-256-GCM encryption before uploading. The server stores it verbatim and
// never sees the plaintext.
type ClientPayload struct {
	V    int    `json:"v"`
	Alg  string `json:"alg"`
	Kdf  string `json:"kdf"`
	Iter int    `json:"iter"`
	Salt string `json:"salt"`
	IV   string `json:"iv"`
	CT   string `json:"ct"`
}

// ValidateClientPayload checks that content is a well-formed client-encrypted payload.
func ValidateClientPayload(content string) error {
	var p ClientPayload
	if err := json.Unmarshal([]byte(content), &p); err != nil {
		return fmt.Errorf("content is not valid JSON: %w", err)
	}
	if p.Alg != "AES-GCM" {
		return fmt.Errorf("unsupported alg %q (expected AES-GCM)", p.Alg)
	}
	if p.Kdf != "PBKDF2" {
		return fmt.Errorf("unsupported kdf %q (expected PBKDF2)", p.Kdf)
	}
	if p.Salt == "" || p.IV == "" || p.CT == "" {
		return fmt.Errorf("client payload is missing required fields (salt, iv, ct)")
	}
	return nil
}

// ---- API request / response types ----

type CreateClipRequest struct {
	Content           string `json:"content"`
	Password          string `json:"password"`
	Duration          string `json:"duration"`
	IsOneTime         bool   `json:"is_one_time"`
	IsClientEncrypted bool   `json:"is_client_encrypted"`
}

type CreateClipResponse struct {
	Code     string     `json:"code"`
	ExpireAt *time.Time `json:"expire_at,omitempty"`
}

// GetClipResponse is returned by GET /api/v1/clips/:code.
// Exactly one of Content or Payload will be populated, or neither when
// RequiresPassword is true.
type GetClipResponse struct {
	Code              string     `json:"code"`
	Content           *string    `json:"content,omitempty"`
	Payload           *string    `json:"payload,omitempty"` // client-encrypted JSON blob
	RequiresPassword  bool       `json:"requires_password"`
	IsClientEncrypted bool       `json:"is_client_encrypted"`
	IsOneTime         bool       `json:"is_one_time"`
	ExpireAt          *time.Time `json:"expire_at,omitempty"`
}

type UnlockClipRequest struct {
	Password string `json:"password"`
}

type UnlockClipResponse struct {
	Content string `json:"content"`
}

type ConsumeResponse struct {
	OK bool `json:"ok"`
}
