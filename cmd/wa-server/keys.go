package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/alexedwards/argon2id"
	_ "modernc.org/sqlite"
)

func openKeysDB(ctx context.Context, path string) (*sql.DB, error) {
	dsn := path
	if dsn == "" {
		dsn = "file::memory:?cache=shared"
	} else {
		if !strings.HasPrefix(dsn, "file:") {
			dsn = "file:" + dsn
		}
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func migrateKeys(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS api_keys (
	key_id TEXT PRIMARY KEY NOT NULL,
	hash TEXT NOT NULL
)`)
	return err
}

// seedAPIKeys parses WA_API_KEYS as comma-separated id:plaintext entries.
func seedAPIKeys(ctx context.Context, db *sql.DB, raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return errors.New("WA_API_KEYS is empty")
	}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kid, secret, ok := strings.Cut(part, ":")
		kid = strings.TrimSpace(kid)
		secret = strings.TrimSpace(secret)
		if !ok || kid == "" || secret == "" {
			return fmt.Errorf("invalid WA_API_KEYS entry (want id:secret): %q", part)
		}
		hash, err := argon2id.CreateHash(secret, argon2id.DefaultParams)
		if err != nil {
			return err
		}
		_, err = db.ExecContext(ctx, `INSERT OR REPLACE INTO api_keys (key_id, hash) VALUES (?, ?)`, kid, hash)
		if err != nil {
			return err
		}
	}
	return nil
}

// verifyBearer extracts kid:secret from "Bearer ...", verifies against DB.
func verifyBearer(ctx context.Context, db *sql.DB, authHeader string) (keyID string, err error) {
	const prefix = "Bearer "
	authHeader = strings.TrimSpace(authHeader)
	if !strings.HasPrefix(strings.ToLower(authHeader), strings.ToLower(prefix)) {
		return "", errors.New("missing bearer")
	}
	token := strings.TrimSpace(authHeader[len(prefix):])
	kid, secret, ok := strings.Cut(token, ":")
	kid = strings.TrimSpace(kid)
	secret = strings.TrimSpace(secret)
	if !ok || kid == "" || secret == "" {
		return "", errors.New("invalid token format (want kid:secret)")
	}
	var stored string
	err = db.QueryRowContext(ctx, `SELECT hash FROM api_keys WHERE key_id = ?`, kid).Scan(&stored)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", errors.New("unknown key id")
		}
		return "", err
	}
	match, err := argon2id.ComparePasswordAndHash(secret, stored)
	if err != nil || !match {
		return "", errors.New("invalid secret")
	}
	return kid, nil
}
