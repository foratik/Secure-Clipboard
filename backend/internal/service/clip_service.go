// Package service contains the application's core business logic.
package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"

	"github.com/foratik/secure-clipboard/backend/internal/cache"
	appCrypto "github.com/foratik/secure-clipboard/backend/internal/crypto"
	"github.com/foratik/secure-clipboard/backend/internal/model"
	"github.com/foratik/secure-clipboard/backend/internal/repository"
)

// ---- Sentinel errors ----

var (
	ErrNotFound      = errors.New("clip not found")
	ErrExpired       = errors.New("clip has expired")
	ErrWrongPassword = errors.New("incorrect password")
	ErrNotProtected  = errors.New("clip is not password-protected")
	ErrInvalidInput  = errors.New("invalid input")
)

// ---- Service ----

// ClipService orchestrates clip creation, retrieval, unlocking, and consumption.
type ClipService struct {
	repo   repository.ClipRepository
	cache  cache.ClipCache
	cipher *appCrypto.Cipher
	log    *slog.Logger
}

// New creates a ClipService.
func New(
	repo repository.ClipRepository,
	clipCache cache.ClipCache,
	cipher *appCrypto.Cipher,
	log *slog.Logger,
) *ClipService {
	return &ClipService{
		repo:   repo,
		cache:  clipCache,
		cipher: cipher,
		log:    log,
	}
}

// ---- CreateClip ----

// CreateClip validates the request, encrypts the content, generates a unique
// 6-digit code, and persists the clip. It retries code generation on collision.
func (s *ClipService) CreateClip(ctx context.Context, req *model.CreateClipRequest) (*model.CreateClipResponse, error) {
	// --- Validate input ---
	content := strings.TrimSpace(req.Content)
	if content == "" {
		return nil, fmt.Errorf("%w: content must not be empty", ErrInvalidInput)
	}

	if req.IsClientEncrypted {
		if err := model.ValidateClientPayload(content); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrInvalidInput, err.Error())
		}
	}

	expireAt, err := model.ParseDuration(req.Duration)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidInput, err.Error())
	}

	// --- Build clip ---
	clip := &model.Clip{
		ExpireAt:          expireAt,
		IsOneTime:         req.IsOneTime,
		IsClientEncrypted: req.IsClientEncrypted,
	}

	if req.IsClientEncrypted {
		// Content is the opaque AES-GCM JSON blob from the browser.
		// We store it verbatim; no server-side encryption layer on top.
		clip.ContentEncrypted = content
	} else {
		// Server-side encryption.
		encrypted, encErr := s.cipher.Encrypt(content)
		if encErr != nil {
			return nil, fmt.Errorf("encrypting content: %w", encErr)
		}
		clip.ContentEncrypted = encrypted

		if req.Password != "" {
			hashed, hashErr := appCrypto.HashPassword(req.Password)
			if hashErr != nil {
				return nil, fmt.Errorf("hashing password: %w", hashErr)
			}
			clip.PasswordHash = &hashed
		}
	}

	// --- Persist with retry on code collision ---
	const maxRetries = 10
	for i := 0; i < maxRetries; i++ {
		clip.Code, err = randomCode()
		if err != nil {
			return nil, fmt.Errorf("generating code: %w", err)
		}

		if err = s.repo.Create(ctx, clip); err != nil {
			if isDuplicateKeyError(err) {
				s.log.WarnContext(ctx, "code collision, retrying", "attempt", i+1)
				continue
			}
			return nil, fmt.Errorf("persisting clip: %w", err)
		}
		break
	}
	if err != nil {
		return nil, fmt.Errorf("failed to generate unique code after %d retries", maxRetries)
	}

	s.log.InfoContext(ctx, "clip created",
		"code", clip.Code,
		"is_one_time", clip.IsOneTime,
		"is_client_encrypted", clip.IsClientEncrypted,
		"has_password", clip.PasswordHash != nil,
	)

	return &model.CreateClipResponse{
		Code:     clip.Code,
		ExpireAt: clip.ExpireAt,
	}, nil
}

// ---- GetClip ----

// GetClip retrieves and (when appropriate) decrypts a clip identified by code.
//
// Behaviour by clip type:
//   - Server-encrypted, no password, NOT one-time: cache-first, decrypt, return content.
//   - Server-encrypted, no password, one-time: atomic SELECT+DELETE, return content.
//   - Server-encrypted, password-protected: return RequiresPassword=true (no content).
//   - Client-encrypted: return the opaque payload for browser-side decryption.
func (s *ClipService) GetClip(ctx context.Context, code string) (*model.GetClipResponse, error) {
	if !isValidCode(code) {
		return nil, ErrNotFound
	}

	// One-time server-encrypted clips bypass the cache entirely.
	clip, err := s.lookupClip(ctx, code, false)
	if err != nil {
		return nil, err
	}

	if clip.IsExpired() {
		_ = s.repo.DeleteByCode(ctx, code)
		_ = s.cache.Delete(ctx, code)
		return nil, ErrExpired
	}

	resp := &model.GetClipResponse{
		Code:              clip.Code,
		IsClientEncrypted: clip.IsClientEncrypted,
		IsOneTime:         clip.IsOneTime,
		ExpireAt:          clip.ExpireAt,
	}

	// --- Client-encrypted: return payload, no server decryption ---
	if clip.IsClientEncrypted {
		payload := clip.ContentEncrypted
		resp.Payload = &payload

		// Cache the clip unless it is one-time (consume endpoint handles deletion).
		if !clip.IsOneTime {
			s.cacheClip(ctx, clip)
		}
		return resp, nil
	}

	// --- Password-protected: caller must use /unlock ---
	if clip.PasswordHash != nil {
		resp.RequiresPassword = true
		// We can safely cache the clip here (the encrypted content stays encrypted).
		s.cacheClip(ctx, clip)
		return resp, nil
	}

	// --- One-time, server-encrypted: atomic read+delete ---
	if clip.IsOneTime {
		clip, err = s.repo.FindAndDeleteByCode(ctx, code)
		if err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				return nil, ErrNotFound // already consumed by a concurrent request
			}
			return nil, fmt.Errorf("atomic read+delete: %w", err)
		}
		if clip.IsExpired() {
			return nil, ErrExpired
		}
		_ = s.cache.Delete(ctx, code) // ensure any stale entry is removed
	}

	// --- Decrypt ---
	plaintext, err := s.cipher.Decrypt(clip.ContentEncrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypting content: %w", err)
	}
	resp.Content = &plaintext

	// Cache non-one-time clips for future reads.
	if !clip.IsOneTime {
		s.cacheClip(ctx, clip)
	}
	return resp, nil
}

// ---- UnlockClip ----

// UnlockClip verifies a password and returns the decrypted content of a
// password-protected clip.
func (s *ClipService) UnlockClip(ctx context.Context, code, password string) (*model.UnlockClipResponse, error) {
	if !isValidCode(code) {
		return nil, ErrNotFound
	}
	if password == "" {
		return nil, fmt.Errorf("%w: password must not be empty", ErrInvalidInput)
	}

	// Try cache first to avoid a round-trip for a frequently-unlocked clip.
	clip, err := s.lookupClip(ctx, code, false)
	if err != nil {
		return nil, err
	}

	if clip.IsExpired() {
		_ = s.repo.DeleteByCode(ctx, code)
		_ = s.cache.Delete(ctx, code)
		return nil, ErrExpired
	}

	if clip.PasswordHash == nil {
		return nil, ErrNotProtected
	}

	ok, err := appCrypto.VerifyPassword(password, *clip.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("verifying password: %w", err)
	}
	if !ok {
		return nil, ErrWrongPassword
	}

	// --- One-time: atomically delete after successful unlock ---
	if clip.IsOneTime {
		clip, err = s.repo.FindAndDeleteByCode(ctx, code)
		if err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				return nil, ErrNotFound
			}
			return nil, fmt.Errorf("atomic read+delete: %w", err)
		}
		// Re-verify expiry on the freshly-read copy.
		if clip.IsExpired() {
			return nil, ErrExpired
		}
		_ = s.cache.Delete(ctx, code)
	}

	plaintext, err := s.cipher.Decrypt(clip.ContentEncrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypting content: %w", err)
	}

	s.log.InfoContext(ctx, "clip unlocked", "code", code, "is_one_time", clip.IsOneTime)

	return &model.UnlockClipResponse{Content: plaintext}, nil
}

// ---- ConsumeClip ----

// ConsumeClip marks a one-time client-encrypted clip as consumed by deleting
// it from the database. The actual decryption happened in the browser.
func (s *ClipService) ConsumeClip(ctx context.Context, code string) error {
	if !isValidCode(code) {
		return ErrNotFound
	}

	clip, err := s.repo.FindByCode(ctx, code)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			// Already consumed or never existed — treat as success (idempotent).
			return nil
		}
		return fmt.Errorf("fetching clip: %w", err)
	}

	if !clip.IsClientEncrypted || !clip.IsOneTime {
		// Only client-encrypted one-time clips are consumed this way.
		return nil
	}

	if err = s.repo.DeleteByCode(ctx, code); err != nil {
		return fmt.Errorf("deleting clip: %w", err)
	}
	_ = s.cache.Delete(ctx, code)

	s.log.InfoContext(ctx, "client-encrypted one-time clip consumed", "code", code)
	return nil
}

// ---- Cleanup ----

// DeleteExpired removes all expired clips from the database.
// Intended to be called by a background ticker.
func (s *ClipService) DeleteExpired(ctx context.Context) {
	n, err := s.repo.DeleteExpired(ctx)
	if err != nil {
		s.log.ErrorContext(ctx, "deleting expired clips", "error", err)
		return
	}
	if n > 0 {
		s.log.InfoContext(ctx, "expired clips purged", "count", n)
	}
}

// ---- internal helpers ----

// lookupClip checks the cache first and falls through to the DB on a miss.
func (s *ClipService) lookupClip(ctx context.Context, code string, skipCache bool) (*model.Clip, error) {
	if !skipCache {
		if cached, err := s.cache.Get(ctx, code); err == nil {
			return cached, nil
		}
	}

	clip, err := s.repo.FindByCode(ctx, code)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("fetching clip: %w", err)
	}
	return clip, nil
}

func (s *ClipService) cacheClip(ctx context.Context, clip *model.Clip) {
	if err := s.cache.Set(ctx, clip); err != nil {
		s.log.WarnContext(ctx, "failed to cache clip", "code", clip.Code, "error", err)
	}
}

// randomCode generates a random zero-padded 6-digit numeric code (000000–999999).
func randomCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// isValidCode checks that code is exactly 6 ASCII digits.
func isValidCode(code string) bool {
	if len(code) != 6 {
		return false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// isDuplicateKeyError returns true for PostgreSQL unique constraint violations.
func isDuplicateKeyError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "23505") || // pgx error code
		strings.Contains(err.Error(), "duplicate key")
}
