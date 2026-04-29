package asyncjobs

import (
	"context"
	"database/sql"
	"fmt"
)

// Migrate creates async job tables; uses schema_migrations alongside api_keys migrations.
func Migrate(ctx context.Context, db *sql.DB, postgres bool) error {
	if postgres {
		return migratePostgres(ctx, db)
	}
	return migrateSQLite(ctx, db)
}

func migratePostgres(ctx context.Context, db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)`,
		`CREATE TABLE IF NOT EXISTS webhook_secrets (
			id TEXT PRIMARY KEY,
			api_key_id TEXT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
			signing_key TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			rotated_at TIMESTAMPTZ,
			status TEXT NOT NULL DEFAULT 'active'
		)`,
		`CREATE INDEX IF NOT EXISTS webhook_secrets_api_key_idx ON webhook_secrets (api_key_id)`,
		`CREATE TABLE IF NOT EXISTS jobs (
			id TEXT PRIMARY KEY,
			api_key_id TEXT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
			status TEXT NOT NULL,
			input JSONB NOT NULL,
			options JSONB NOT NULL,
			metadata JSONB,
			result JSONB,
			error JSONB,
			callback_url TEXT,
			callback_resolved_ip TEXT,
			callback_host_header TEXT,
			signing_secret_id TEXT,
			attempts INTEGER NOT NULL DEFAULT 0,
			lease_owner TEXT,
			lease_expires_at TIMESTAMPTZ,
			submitted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			started_at TIMESTAMPTZ,
			completed_at TIMESTAMPTZ,
			delivery_status TEXT NOT NULL DEFAULT 'pending',
			delivery_attempts INTEGER NOT NULL DEFAULT 0,
			delivery_next_attempt_at TIMESTAMPTZ,
			delivery_last_attempt_at TIMESTAMPTZ,
			delivery_last_response_code INTEGER,
			delivery_last_error TEXT,
			retention_expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '7 days'),
			queue_available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			idempotency_key TEXT,
			idempotency_body_hash TEXT,
			cancelled_not_deliverable BOOLEAN NOT NULL DEFAULT false,
			CONSTRAINT jobs_idem_unique UNIQUE (api_key_id, idempotency_key)
		)`,
		`CREATE INDEX IF NOT EXISTS jobs_queue_idx ON jobs (status, queue_available_at, submitted_at) WHERE status = 'queued'`,
		`CREATE INDEX IF NOT EXISTS jobs_lease_idx ON jobs (lease_expires_at) WHERE status = 'running'`,
		`CREATE INDEX IF NOT EXISTS jobs_delivery_idx ON jobs (delivery_next_attempt_at) WHERE delivery_status = 'pending' AND status IN ('succeeded', 'failed')`,
		`CREATE INDEX IF NOT EXISTS jobs_retention_idx ON jobs (retention_expires_at)`,
		`CREATE INDEX IF NOT EXISTS jobs_dead_letter_idx ON jobs (api_key_id, status) WHERE status = 'dead_lettered'`,
	}
	for _, st := range stmts {
		if _, err := db.ExecContext(ctx, st); err != nil {
			return fmt.Errorf("asyncjobs postgres migrate: %w\nstmt: %s", err, st)
		}
	}
	var v int
	_ = db.QueryRowContext(ctx, `SELECT version FROM schema_migrations WHERE version = 2`).Scan(&v)
	if v == 0 {
		if _, err := db.ExecContext(ctx, `INSERT INTO schema_migrations (version) VALUES (2)`); err != nil {
			return err
		}
	}
	_ = db.QueryRowContext(ctx, `SELECT version FROM schema_migrations WHERE version = 3`).Scan(&v)
	if v == 0 {
		if _, err := db.ExecContext(ctx, `ALTER TABLE jobs ADD COLUMN IF NOT EXISTS idempotency_body_hash TEXT`); err != nil {
			return err
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO schema_migrations (version) VALUES (3)`); err != nil {
			return err
		}
	}
	return nil
}

func migrateSQLite(ctx context.Context, db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)`,
		`CREATE TABLE IF NOT EXISTS webhook_secrets (
			id TEXT PRIMARY KEY,
			api_key_id TEXT NOT NULL,
			signing_key TEXT NOT NULL,
			created_at TEXT NOT NULL,
			rotated_at TEXT,
			status TEXT NOT NULL DEFAULT 'active'
		)`,
		`CREATE INDEX IF NOT EXISTS webhook_secrets_api_key_idx ON webhook_secrets (api_key_id)`,
		`CREATE TABLE IF NOT EXISTS jobs (
			id TEXT PRIMARY KEY,
			api_key_id TEXT NOT NULL,
			status TEXT NOT NULL,
			input TEXT NOT NULL,
			options TEXT NOT NULL,
			metadata TEXT,
			result TEXT,
			error TEXT,
			callback_url TEXT,
			callback_resolved_ip TEXT,
			callback_host_header TEXT,
			signing_secret_id TEXT,
			attempts INTEGER NOT NULL DEFAULT 0,
			lease_owner TEXT,
			lease_expires_at TEXT,
			submitted_at TEXT NOT NULL,
			started_at TEXT,
			completed_at TEXT,
			delivery_status TEXT NOT NULL DEFAULT 'pending',
			delivery_attempts INTEGER NOT NULL DEFAULT 0,
			delivery_next_attempt_at TEXT,
			delivery_last_attempt_at TEXT,
			delivery_last_response_code INTEGER,
			delivery_last_error TEXT,
			retention_expires_at TEXT NOT NULL,
			queue_available_at TEXT NOT NULL,
			idempotency_key TEXT,
			idempotency_body_hash TEXT,
			cancelled_not_deliverable INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS jobs_idem_unique ON jobs (api_key_id, idempotency_key) WHERE idempotency_key IS NOT NULL AND idempotency_key != ''`,
		`CREATE INDEX IF NOT EXISTS jobs_queue_idx ON jobs (status, queue_available_at, submitted_at) WHERE status = 'queued'`,
		`CREATE INDEX IF NOT EXISTS jobs_lease_idx ON jobs (lease_expires_at) WHERE status = 'running'`,
		`CREATE INDEX IF NOT EXISTS jobs_delivery_idx ON jobs (delivery_next_attempt_at) WHERE delivery_status = 'pending' AND status IN ('succeeded', 'failed')`,
		`CREATE INDEX IF NOT EXISTS jobs_retention_idx ON jobs (retention_expires_at)`,
	}
	for _, st := range stmts {
		if _, err := db.ExecContext(ctx, st); err != nil {
			return fmt.Errorf("asyncjobs sqlite migrate: %w", err)
		}
	}
	var v int
	_ = db.QueryRowContext(ctx, `SELECT version FROM schema_migrations WHERE version = 2`).Scan(&v)
	if v == 0 {
		if _, err := db.ExecContext(ctx, `INSERT INTO schema_migrations (version) VALUES (2)`); err != nil {
			return err
		}
	}
	_ = db.QueryRowContext(ctx, `SELECT version FROM schema_migrations WHERE version = 3`).Scan(&v)
	if v == 0 {
		_, _ = db.ExecContext(ctx, `ALTER TABLE jobs ADD COLUMN idempotency_body_hash TEXT`)
		if _, err := db.ExecContext(ctx, `INSERT INTO schema_migrations (version) VALUES (3)`); err != nil {
			return err
		}
	}
	return nil
}
