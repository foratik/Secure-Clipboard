-- Migration 001: initial schema
-- Run with: psql $DATABASE_URL -f migrations/001_init.sql

CREATE TABLE IF NOT EXISTS clips (
    id                  BIGSERIAL    PRIMARY KEY,
    code                CHAR(6)      NOT NULL,
    content_encrypted   TEXT         NOT NULL,
    password_hash       TEXT,
    expire_at           TIMESTAMPTZ,
    is_one_time         BOOLEAN      NOT NULL DEFAULT FALSE,
    is_client_encrypted BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT clips_code_unique UNIQUE (code)
);

-- Index for O(1) code lookups (the primary read path).
CREATE INDEX IF NOT EXISTS idx_clips_code ON clips (code);

-- Partial index for the background cleanup job that purges expired clips.
CREATE INDEX IF NOT EXISTS idx_clips_expire_at
    ON clips (expire_at)
    WHERE expire_at IS NOT NULL;
