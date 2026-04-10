// Package repository implements persistence logic using PostgreSQL via pgx/v5.
package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/foratik/secure-clipboard/backend/internal/model"
)

// ClipRepository defines the persistence contract for clips.
type ClipRepository interface {
	Create(ctx context.Context, clip *model.Clip) error
	FindByCode(ctx context.Context, code string) (*model.Clip, error)
	// FindAndDeleteByCode atomically reads a clip and deletes it within a
	// single serializable transaction. Used exclusively for one-time clips to
	// prevent duplicate reads under concurrent load.
	FindAndDeleteByCode(ctx context.Context, code string) (*model.Clip, error)
	DeleteByCode(ctx context.Context, code string) error
	DeleteExpired(ctx context.Context) (int64, error)
}

// Postgres is the PostgreSQL-backed implementation of ClipRepository.
type Postgres struct {
	pool *pgxpool.Pool
}

// NewPostgres creates a new Postgres repository.
func NewPostgres(pool *pgxpool.Pool) *Postgres {
	return &Postgres{pool: pool}
}

// Create inserts a new clip. On a duplicate-code conflict the caller should
// regenerate the code and retry.
func (r *Postgres) Create(ctx context.Context, clip *model.Clip) error {
	const q = `
		INSERT INTO clips (code, content_encrypted, password_hash, expire_at, is_one_time, is_client_encrypted)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at`

	return r.pool.QueryRow(ctx, q,
		clip.Code,
		clip.ContentEncrypted,
		clip.PasswordHash,
		clip.ExpireAt,
		clip.IsOneTime,
		clip.IsClientEncrypted,
	).Scan(&clip.ID, &clip.CreatedAt)
}

// FindByCode returns the clip with the given code, or ErrNotFound if absent.
func (r *Postgres) FindByCode(ctx context.Context, code string) (*model.Clip, error) {
	const q = `
		SELECT id, code, content_encrypted, password_hash, expire_at,
		       is_one_time, is_client_encrypted, created_at
		FROM clips
		WHERE code = $1`

	clip, err := scanClip(r.pool.QueryRow(ctx, q, code))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return clip, err
}

// FindAndDeleteByCode atomically reads and removes a clip using SELECT FOR UPDATE
// inside a transaction. Returns ErrNotFound if the clip does not exist.
func (r *Postgres) FindAndDeleteByCode(ctx context.Context, code string) (*model.Clip, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	const selectQ = `
		SELECT id, code, content_encrypted, password_hash, expire_at,
		       is_one_time, is_client_encrypted, created_at
		FROM clips
		WHERE code = $1
		FOR UPDATE`

	clip, err := scanClip(tx.QueryRow(ctx, selectQ, code))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	if _, err = tx.Exec(ctx, `DELETE FROM clips WHERE code = $1`, code); err != nil {
		return nil, fmt.Errorf("delete clip: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}
	return clip, nil
}

// DeleteByCode removes a clip by its code (idempotent — no error if absent).
func (r *Postgres) DeleteByCode(ctx context.Context, code string) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM clips WHERE code = $1`, code)
	return err
}

// DeleteExpired purges all clips whose expiry timestamp has passed.
// Returns the number of rows removed.
func (r *Postgres) DeleteExpired(ctx context.Context) (int64, error) {
	tag, err := r.pool.Exec(ctx, `DELETE FROM clips WHERE expire_at IS NOT NULL AND expire_at < $1`, time.Now().UTC())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ---- helpers ----

// rowScanner unifies pgx.Row and pgx.Rows under one interface so we can
// share the scan logic between pool queries and transaction queries.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanClip(row rowScanner) (*model.Clip, error) {
	var c model.Clip
	err := row.Scan(
		&c.ID,
		&c.Code,
		&c.ContentEncrypted,
		&c.PasswordHash,
		&c.ExpireAt,
		&c.IsOneTime,
		&c.IsClientEncrypted,
		&c.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// ---- sentinel errors ----

// ErrNotFound is returned when a requested clip does not exist.
var ErrNotFound = errors.New("clip not found")
