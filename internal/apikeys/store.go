package apikeys

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
)

var ErrNotFound = errors.New("api key not found")

// KeyRecord is a row from api_keys (no plaintext).
type KeyRecord struct {
	ID            string
	Prefix        string
	Hash          string
	Name          string
	Owner         string
	Status        string
	RPSLimit      int
	DailyQuota    int
	CreatedAt     time.Time
	CreatedBy     string
	LastUsedAt    *time.Time
	RevokedAt     *time.Time
	RevokedReason *string
}

// Store wraps DB access for API keys.
type Store struct {
	db       *sql.DB
	postgres bool
}

// OpenStore opens sqlite (file DSN or memory) or postgres from URL.
func OpenStore(ctx context.Context, sqlitePath, pgURL string) (*Store, error) {
	var (
		db  *sql.DB
		err error
	)
	if strings.TrimSpace(pgURL) != "" {
		db, err = sql.Open("pgx", pgURL)
		if err != nil {
			return nil, err
		}
		if err := db.PingContext(ctx); err != nil {
			_ = db.Close()
			return nil, err
		}
		return &Store{db: db, postgres: true}, nil
	}
	dsn := sqlitePath
	if dsn == "" {
		dsn = "file::memory:?cache=shared"
	} else if !strings.HasPrefix(dsn, "file:") {
		dsn = "file:" + dsn
	}
	db, err = sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db, postgres: false}, nil
}

func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Migrate(ctx context.Context) error {
	if s.postgres {
		return migratePostgres(ctx, s.db)
	}
	return migrateSQLite(ctx, s.db)
}

func ph(s *Store, idx int) string {
	if s.postgres {
		return fmt.Sprintf("$%d", idx)
	}
	return "?"
}

func parseAnyTime(v any) (time.Time, error) {
	switch t := v.(type) {
	case time.Time:
		return t.UTC(), nil
	case string:
		if t == "" {
			return time.Time{}, fmt.Errorf("empty time")
		}
		pt, err := time.Parse(time.RFC3339Nano, t)
		if err == nil {
			return pt.UTC(), nil
		}
		return time.Parse(time.RFC3339, t)
	default:
		return time.Time{}, fmt.Errorf("unsupported time type %T", v)
	}
}

func parseAnyTimePtr(v any) (*time.Time, error) {
	if v == nil {
		return nil, nil
	}
	switch x := v.(type) {
	case sql.NullTime:
		if !x.Valid {
			return nil, nil
		}
		t := x.Time.UTC()
		return &t, nil
	case sql.NullString:
		if !x.Valid || x.String == "" {
			return nil, nil
		}
		t, err := parseAnyTime(x.String)
		if err != nil {
			return nil, err
		}
		return &t, nil
	case string:
		if x == "" {
			return nil, nil
		}
		t, err := parseAnyTime(x)
		if err != nil {
			return nil, err
		}
		return &t, nil
	case []byte:
		if len(x) == 0 {
			return nil, nil
		}
		t, err := parseAnyTime(string(x))
		if err != nil {
			return nil, err
		}
		return &t, nil
	default:
		t, err := parseAnyTime(v)
		if err != nil {
			return nil, nil
		}
		return &t, nil
	}
}

func scanKeyRow(_ *Store, scanner interface {
	Scan(dest ...any) error
}) (*KeyRecord, error) {
	var r KeyRecord
	var createdRaw, lastRaw, revRaw any
	var revokedReason sql.NullString
	err := scanner.Scan(&r.ID, &r.Prefix, &r.Hash, &r.Name, &r.Owner, &r.Status, &r.RPSLimit, &r.DailyQuota,
		&createdRaw, &r.CreatedBy, &lastRaw, &revRaw, &revokedReason)
	if err != nil {
		return nil, err
	}
	cr, err := parseAnyTime(createdRaw)
	if err != nil {
		return nil, err
	}
	r.CreatedAt = cr
	r.LastUsedAt, _ = parseAnyTimePtr(lastRaw)
	r.RevokedAt, _ = parseAnyTimePtr(revRaw)
	if revokedReason.Valid {
		rs := revokedReason.String
		r.RevokedReason = &rs
	}
	return &r, nil
}

// LookupActiveByPrefix returns the key row for an active key with this 12-char prefix.
func (s *Store) LookupActiveByPrefix(ctx context.Context, prefix string) (*KeyRecord, error) {
	q := `SELECT id, prefix, hash, name, owner, status, rps_limit, daily_quota, created_at, created_by,
	    last_used_at, revoked_at, revoked_reason
	    FROM api_keys WHERE prefix = ` + ph(s, 1) + ` AND status = 'active'`
	row := s.db.QueryRowContext(ctx, q, prefix)
	r, err := scanKeyRow(s, row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return r, nil
}

func (s *Store) CountKeys(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_keys`).Scan(&n)
	return n, err
}

// InsertKey stores a new key (hash only).
func (s *Store) InsertKey(ctx context.Context, prefix, hash, name, owner, createdBy string, rps, daily int) (string, error) {
	id := ulid.Make().String()
	now := time.Now().UTC()
	q := `INSERT INTO api_keys (id, prefix, hash, name, owner, status, rps_limit, daily_quota, created_at, created_by)
		VALUES (` + ph(s, 1) + `,` + ph(s, 2) + `,` + ph(s, 3) + `,` + ph(s, 4) + `,` + ph(s, 5) + `,'active',` + ph(s, 6) + `,` + ph(s, 7) + `,` + ph(s, 8) + `,` + ph(s, 9) + `)`
	_, err := s.db.ExecContext(ctx, q, id, prefix, hash, name, owner, rps, daily, now, createdBy)
	if err != nil {
		return "", err
	}
	return id, nil
}

// GetByID returns a key row (any status).
func (s *Store) GetByID(ctx context.Context, id string) (*KeyRecord, error) {
	q := `SELECT id, prefix, hash, name, owner, status, rps_limit, daily_quota, created_at, created_by,
	    last_used_at, revoked_at, revoked_reason FROM api_keys WHERE id = ` + ph(s, 1)
	row := s.db.QueryRowContext(ctx, q, id)
	r, err := scanKeyRow(s, row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return r, nil
}

// ListKeys filters by optional owner and status (active|revoked|all).
func (s *Store) ListKeys(ctx context.Context, ownerFilter, status string) ([]KeyRecord, error) {
	var b strings.Builder
	b.WriteString(`SELECT id, prefix, hash, name, owner, status, rps_limit, daily_quota, created_at, created_by,
	    last_used_at, revoked_at, revoked_reason FROM api_keys WHERE 1=1`)
	args := []any{}
	n := 1
	if ownerFilter != "" {
		b.WriteString(` AND owner = ` + ph(s, n))
		args = append(args, ownerFilter)
		n++
	}
	switch status {
	case "active", "revoked":
		b.WriteString(` AND status = ` + ph(s, n))
		args = append(args, status)
	case "all", "":
	default:
		return nil, fmt.Errorf("invalid status filter")
	}
	b.WriteString(` ORDER BY created_at DESC`)

	rows, err := s.db.QueryContext(ctx, b.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KeyRecord
	for rows.Next() {
		r, err := scanKeyRow(s, rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// RevokeKey marks a key revoked.
func (s *Store) RevokeKey(ctx context.Context, id, reason string) error {
	now := time.Now().UTC()
	q := `UPDATE api_keys SET status = 'revoked', revoked_at = ` + ph(s, 1) + `, revoked_reason = ` + ph(s, 2) + ` WHERE id = ` + ph(s, 3)
	res, err := s.db.ExecContext(ctx, q, now, reason, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// BatchTouchLastUsed updates last_used_at for ids.
func (s *Store) BatchTouchLastUsed(ctx context.Context, ids []string, at time.Time) error {
	if len(ids) == 0 {
		return nil
	}
	ts := at.UTC()
	for _, id := range ids {
		q := `UPDATE api_keys SET last_used_at = ` + ph(s, 1) + ` WHERE id = ` + ph(s, 2)
		_, err := s.db.ExecContext(ctx, q, ts, id)
		if err != nil {
			return err
		}
	}
	return nil
}

func migrateSQLite(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)`); err != nil {
		return err
	}

	var tbl int
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='api_keys'`).Scan(&tbl)
	if tbl == 1 {
		var legacyCols int
		_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info('api_keys') WHERE name='key_id'`).Scan(&legacyCols)
		if legacyCols > 0 {
			if _, err := db.ExecContext(ctx, `DROP TABLE api_keys`); err != nil {
				return err
			}
		}
	}

	stmts := []string{
		`CREATE TABLE IF NOT EXISTS api_keys (
			id TEXT PRIMARY KEY,
			prefix TEXT NOT NULL UNIQUE,
			hash TEXT NOT NULL,
			name TEXT NOT NULL,
			owner TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'active',
			rps_limit INTEGER NOT NULL DEFAULT 10,
			daily_quota INTEGER NOT NULL DEFAULT 100000,
			created_at TEXT NOT NULL,
			created_by TEXT NOT NULL,
			last_used_at TEXT,
			revoked_at TEXT,
			revoked_reason TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS api_keys_prefix_idx ON api_keys(prefix) WHERE status = 'active'`,
	}
	for _, st := range stmts {
		if _, err := db.ExecContext(ctx, st); err != nil {
			return err
		}
	}
	var v int
	_ = db.QueryRowContext(ctx, `SELECT version FROM schema_migrations WHERE version = 1`).Scan(&v)
	if v == 0 {
		if _, err := db.ExecContext(ctx, `INSERT INTO schema_migrations (version) VALUES (1)`); err != nil {
			return err
		}
	}
	return nil
}

func migratePostgres(ctx context.Context, db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)`,
		`CREATE TABLE IF NOT EXISTS api_keys (
			id TEXT PRIMARY KEY,
			prefix TEXT NOT NULL,
			hash TEXT NOT NULL,
			name TEXT NOT NULL,
			owner TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'active',
			rps_limit INTEGER NOT NULL DEFAULT 10,
			daily_quota INTEGER NOT NULL DEFAULT 100000,
			created_at TIMESTAMPTZ NOT NULL,
			created_by TEXT NOT NULL,
			last_used_at TIMESTAMPTZ,
			revoked_at TIMESTAMPTZ,
			revoked_reason TEXT,
			CONSTRAINT api_keys_prefix_unique UNIQUE (prefix)
		)`,
		`CREATE INDEX IF NOT EXISTS api_keys_prefix_idx ON api_keys (prefix) WHERE status = 'active'`,
	}
	for _, st := range stmts {
		if _, err := db.ExecContext(ctx, st); err != nil {
			return err
		}
	}
	var v int
	_ = db.QueryRowContext(ctx, `SELECT version FROM schema_migrations WHERE version = 1`).Scan(&v)
	if v == 0 {
		if _, err := db.ExecContext(ctx, `INSERT INTO schema_migrations (version) VALUES (1)`); err != nil {
			return err
		}
	}
	return nil
}
