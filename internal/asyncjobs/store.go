package asyncjobs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
)

const (
	StatusQueued        = "queued"
	StatusRunning       = "running"
	StatusSucceeded     = "succeeded"
	StatusFailed        = "failed"
	StatusCancelled     = "cancelled"
	StatusDeadLettered  = "dead_lettered"
	DeliveryPending     = "pending"
	DeliveryDelivered   = "delivered"
	DeliveryExhausted   = "exhausted"
	DeliveryNA          = "n/a"
	SecretStatusActive  = "active"
	SecretStatusRotated = "rotated"
	SecretStatusRevoked = "revoked"
)

var ErrNotFound = errors.New("job not found")

type JobRow struct {
	ID                     string
	APIKeyID               string
	Status                 string
	InputJSON              []byte
	OptionsJSON            []byte
	MetadataJSON           []byte
	ResultJSON             []byte
	ErrorJSON              []byte
	CallbackURL            sql.NullString
	CallbackResolvedIP     sql.NullString
	CallbackHostHeader     sql.NullString
	SigningSecretID        sql.NullString
	Attempts               int
	LeaseOwner             sql.NullString
	LeaseExpiresAt         sql.NullTime
	SubmittedAt            time.Time
	StartedAt              sql.NullTime
	CompletedAt            sql.NullTime
	DeliveryStatus         string
	DeliveryAttempts       int
	DeliveryNextAttemptAt  sql.NullTime
	DeliveryLastAttemptAt  sql.NullTime
	DeliveryLastCode       sql.NullInt32
	DeliveryLastError      sql.NullString
	RetentionExpiresAt     time.Time
	QueueAvailableAt       time.Time
	IdempotencyKey         sql.NullString
	IdempotencyBodyHash    sql.NullString
	CancelledNotDeliverable bool
}

type Store struct {
	db       *sql.DB
	postgres bool
}

func NewStore(db *sql.DB, postgres bool) *Store {
	return &Store{db: db, postgres: postgres}
}

func ph(pg bool, i int) string {
	if pg {
		return fmt.Sprintf("$%d", i)
	}
	return "?"
}

// --- Webhook secrets ---

func (s *Store) InsertWebhookSecret(ctx context.Context, apiKeyID, signingKeyPlain string) (id string, err error) {
	id = "wsec_" + ulid.Make().String()
	now := time.Now().UTC()
	q := `INSERT INTO webhook_secrets (id, api_key_id, signing_key, created_at, status) VALUES (` +
		ph(s.postgres, 1) + `,` + ph(s.postgres, 2) + `,` + ph(s.postgres, 3) + `,` + ph(s.postgres, 4) + `,'active')`
	_, err = s.db.ExecContext(ctx, q, id, apiKeyID, signingKeyPlain, formatTime(s.postgres, now))
	return id, err
}

func formatTime(pg bool, t time.Time) any {
	if pg {
		return t
	}
	return t.UTC().Format(time.RFC3339Nano)
}

type WebhookSecretListRow struct {
	ID        string
	Status    string
	CreatedAt time.Time
	RotatedAt sql.NullTime
}

func (s *Store) ListWebhookSecrets(ctx context.Context, apiKeyID string) ([]WebhookSecretListRow, error) {
	var q string
	args := []any{}
	if apiKeyID != "" {
		q = `SELECT id, status, created_at, rotated_at FROM webhook_secrets WHERE api_key_id = ` + ph(s.postgres, 1) + ` ORDER BY created_at DESC`
		args = append(args, apiKeyID)
	} else {
		q = `SELECT id, status, created_at, rotated_at FROM webhook_secrets ORDER BY created_at DESC`
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WebhookSecretListRow
	for rows.Next() {
		var r WebhookSecretListRow
		var cr any
		var rot sql.NullString
		var rotT sql.NullTime
		if s.postgres {
			if err := rows.Scan(&r.ID, &r.Status, &cr, &rotT); err != nil {
				return nil, err
			}
			r.RotatedAt = rotT
		} else {
			if err := rows.Scan(&r.ID, &r.Status, &cr, &rot); err != nil {
				return nil, err
			}
			if rot.Valid && rot.String != "" {
				t, e := parseTimeAny(rot.String)
				if e == nil {
					r.RotatedAt = sql.NullTime{Time: t, Valid: true}
				}
			}
		}
		ct, err := parseTimeAny(cr)
		if err != nil {
			return nil, err
		}
		r.CreatedAt = ct
		out = append(out, r)
	}
	return out, rows.Err()
}

func parseTimeAny(v any) (time.Time, error) {
	switch t := v.(type) {
	case time.Time:
		return t.UTC(), nil
	case string:
		if t == "" {
			return time.Time{}, fmt.Errorf("empty time")
		}
		return time.Parse(time.RFC3339Nano, t)
	default:
		return time.Time{}, fmt.Errorf("time type %T", v)
	}
}

// WebhookSigningPlaintext returns signing key material if secret belongs to apiKeyID and is active,
// or was rotated within rotationOverlapGrace (so old secret still verifies during overlap).
func (s *Store) WebhookSigningPlaintext(ctx context.Context, apiKeyID, secretID string, rotationOverlapGrace time.Duration) (string, error) {
	cutoff := time.Now().UTC().Add(-rotationOverlapGrace)
	q := `SELECT signing_key FROM webhook_secrets WHERE id = ` + ph(s.postgres, 1) +
		` AND api_key_id = ` + ph(s.postgres, 2) +
		` AND (status = 'active' OR (status = 'rotated' AND rotated_at IS NOT NULL AND rotated_at > ` + ph(s.postgres, 3) + `))`
	var plain string
	err := s.db.QueryRowContext(ctx, q, secretID, apiKeyID, formatTime(s.postgres, cutoff)).Scan(&plain)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	return plain, nil
}

func (s *Store) RotateWebhookSecret(ctx context.Context, apiKeyID, oldID string) error {
	now := time.Now().UTC()
	q := `UPDATE webhook_secrets SET status = 'rotated', rotated_at = ` + ph(s.postgres, 1) +
		` WHERE id = ` + ph(s.postgres, 2) + ` AND api_key_id = ` + ph(s.postgres, 3) + ` AND status = 'active'`
	res, err := s.db.ExecContext(ctx, q, formatTime(s.postgres, now), oldID, apiKeyID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) RevokeWebhookSecret(ctx context.Context, apiKeyID, secretID string) error {
	q := `UPDATE webhook_secrets SET status = 'revoked' WHERE id = ` + ph(s.postgres, 1) +
		` AND api_key_id = ` + ph(s.postgres, 2)
	res, err := s.db.ExecContext(ctx, q, secretID, apiKeyID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// --- Jobs ---

func (s *Store) InsertJob(ctx context.Context, j JobRow) error {
	meta := nullableJSON(j.MetadataJSON)
	var idem, idemHash any
	if j.IdempotencyKey.Valid {
		idem = j.IdempotencyKey.String
	} else {
		idem = nil
	}
	if j.IdempotencyBodyHash.Valid {
		idemHash = j.IdempotencyBodyHash.String
	} else {
		idemHash = nil
	}
	now := time.Now().UTC()
	ret := now.Add(7 * 24 * time.Hour)
	var cbURL, cbIP, cbHost, signID any
	if j.CallbackURL.Valid {
		cbURL = j.CallbackURL.String
	}
	if j.CallbackResolvedIP.Valid {
		cbIP = j.CallbackResolvedIP.String
	}
	if j.CallbackHostHeader.Valid {
		cbHost = j.CallbackHostHeader.String
	}
	if j.SigningSecretID.Valid {
		signID = j.SigningSecretID.String
	}
	delStatus := j.DeliveryStatus
	if delStatus == "" {
		if j.CallbackURL.Valid {
			delStatus = DeliveryPending
		} else {
			delStatus = DeliveryNA
		}
	}
	q := `INSERT INTO jobs (
		id, api_key_id, status, input, options, metadata,
		callback_url, callback_resolved_ip, callback_host_header, signing_secret_id,
		submitted_at, retention_expires_at, queue_available_at, idempotency_key, idempotency_body_hash, delivery_status, attempts
	) VALUES (` + phList(s.postgres, 17) + `)`

	args := []any{
		j.ID, j.APIKeyID, j.Status, j.InputJSON, j.OptionsJSON, meta,
		cbURL, cbIP, cbHost, signID,
		formatTime(s.postgres, now), formatTime(s.postgres, ret), formatTime(s.postgres, now), idem, idemHash, delStatus, 0,
	}
	_, err := s.db.ExecContext(ctx, q, args...)
	return err
}

func phList(pg bool, n int) string {
	parts := make([]string, n)
	for i := 0; i < n; i++ {
		parts[i] = ph(pg, i+1)
	}
	return strings.Join(parts, ",")
}

func nullableJSON(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

func (s *Store) FindJobByIdempotency(ctx context.Context, apiKeyID, idem string) (jobID string, submittedAt time.Time, err error) {
	q := `SELECT id, submitted_at FROM jobs WHERE api_key_id = ` + ph(s.postgres, 1) +
		` AND idempotency_key = ` + ph(s.postgres, 2)
	var sub any
	err = s.db.QueryRowContext(ctx, q, apiKeyID, idem).Scan(&jobID, &sub)
	if err != nil {
		return "", time.Time{}, err
	}
	t, err := parseTimeAny(sub)
	return jobID, t, err
}

func (s *Store) TryLeaseNextJob(ctx context.Context, workerID string, lease time.Duration, now time.Time) (*JobRow, error) {
	if s.postgres {
		return s.tryLeasePostgres(ctx, workerID, lease, now)
	}
	return s.tryLeaseSQLite(ctx, workerID, lease, now)
}

func (s *Store) tryLeasePostgres(ctx context.Context, workerID string, lease time.Duration, now time.Time) (*JobRow, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	qSel := `SELECT id FROM jobs WHERE status = 'queued' AND queue_available_at <= ` + ph(true, 1) +
		` ORDER BY queue_available_at, submitted_at LIMIT 1 FOR UPDATE SKIP LOCKED`
	var id string
	err = tx.QueryRowContext(ctx, qSel, now).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	exp := now.Add(lease)
	qUp := `UPDATE jobs SET status = 'running', lease_owner = ` + ph(true, 1) +
		`, lease_expires_at = ` + ph(true, 2) +
		`, started_at = COALESCE(started_at, ` + ph(true, 3) + `)` +
		`, attempts = attempts + 1 WHERE id = ` + ph(true, 4)
	_, err = tx.ExecContext(ctx, qUp, workerID, exp, now, id)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetJob(ctx, id)
}

func (s *Store) tryLeaseSQLite(ctx context.Context, workerID string, lease time.Duration, now time.Time) (*JobRow, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	qSel := `SELECT id FROM jobs WHERE status = 'queued' AND queue_available_at <= ` + ph(false, 1) +
		` ORDER BY queue_available_at, submitted_at LIMIT 1`
	var id string
	err = tx.QueryRowContext(ctx, qSel, formatTime(false, now)).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	exp := now.Add(lease)
	qUp := `UPDATE jobs SET status = 'running', lease_owner = ` + ph(false, 1) +
		`, lease_expires_at = ` + ph(false, 2) +
		`, started_at = COALESCE(started_at, ` + ph(false, 3) + `)` +
		`, attempts = attempts + 1 WHERE id = ` + ph(false, 4) + ` AND status = 'queued'`
	res, err := tx.ExecContext(ctx, qUp, workerID, formatTime(false, exp), formatTime(false, now), id)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		_ = tx.Rollback()
		return nil, nil
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetJob(ctx, id)
}

func (s *Store) SweepExpiredLeases(ctx context.Context, now time.Time) (int64, error) {
	q := `UPDATE jobs SET status = 'queued', lease_owner = NULL, lease_expires_at = NULL
		WHERE status = 'running' AND lease_expires_at IS NOT NULL AND lease_expires_at < ` + ph(s.postgres, 1)
	res, err := s.db.ExecContext(ctx, q, formatTime(s.postgres, now))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) RequeueRetryable(ctx context.Context, jobID string, backoff time.Duration, errJSON []byte, now time.Time) error {
	next := now.Add(backoff)
	q := `UPDATE jobs SET status = 'queued', lease_owner = NULL, lease_expires_at = NULL,
		queue_available_at = ` + ph(s.postgres, 1) + `, error = ` + ph(s.postgres, 2) + ` WHERE id = ` + ph(s.postgres, 3)
	_, e := s.db.ExecContext(ctx, q, formatTime(s.postgres, next), nullableJSON(errJSON), jobID)
	return e
}

func (s *Store) MarkJobFailedTerminal(ctx context.Context, jobID string, errJSON []byte, resultJSON []byte, now time.Time) error {
	nextDel := formatTime(s.postgres, now)
	var q string
	var args []any
	if len(resultJSON) > 0 {
		q = `UPDATE jobs SET status = 'failed', completed_at = ` + ph(s.postgres, 1) +
			`, error = ` + ph(s.postgres, 2) + `, result = ` + ph(s.postgres, 3) +
			`, lease_owner = NULL, lease_expires_at = NULL,
			delivery_next_attempt_at = CASE WHEN (callback_url IS NOT NULL AND TRIM(callback_url) != '') AND NOT cancelled_not_deliverable
				THEN ` + ph(s.postgres, 4) + ` ELSE NULL END
			WHERE id = ` + ph(s.postgres, 5)
		args = []any{formatTime(s.postgres, now), nullableJSON(errJSON), nullableJSON(resultJSON), nextDel, jobID}
	} else {
		q = `UPDATE jobs SET status = 'failed', completed_at = ` + ph(s.postgres, 1) +
			`, error = ` + ph(s.postgres, 2) + `,
			lease_owner = NULL, lease_expires_at = NULL,
			delivery_next_attempt_at = CASE WHEN (callback_url IS NOT NULL AND TRIM(callback_url) != '') AND NOT cancelled_not_deliverable
				THEN ` + ph(s.postgres, 3) + ` ELSE NULL END
			WHERE id = ` + ph(s.postgres, 4)
		args = []any{formatTime(s.postgres, now), nullableJSON(errJSON), nextDel, jobID}
	}
	_, err := s.db.ExecContext(ctx, q, args...)
	return err
}

func (s *Store) MarkJobSucceeded(ctx context.Context, jobID string, resultJSON []byte, now time.Time) error {
	q := `UPDATE jobs SET status = 'succeeded', completed_at = ` + ph(s.postgres, 1) +
		`, result = ` + ph(s.postgres, 2) + `,
		lease_owner = NULL, lease_expires_at = NULL,
		delivery_next_attempt_at = CASE WHEN (callback_url IS NOT NULL AND TRIM(callback_url) != '') AND NOT cancelled_not_deliverable
			THEN ` + ph(s.postgres, 3) + ` ELSE NULL END,
		error = NULL
		WHERE id = ` + ph(s.postgres, 4)
	_, err := s.db.ExecContext(ctx, q, formatTime(s.postgres, now), nullableJSON(resultJSON), formatTime(s.postgres, now), jobID)
	return err
}

func (s *Store) MarkCancelledQueued(ctx context.Context, jobID string, now time.Time) error {
	q := `UPDATE jobs SET status = 'cancelled', completed_at = ` + ph(s.postgres, 1) +
		`, delivery_status = 'n/a', lease_owner = NULL, lease_expires_at = NULL WHERE id = ` + ph(s.postgres, 2) +
		` AND status = 'queued'`
	res, err := s.db.ExecContext(ctx, q, formatTime(s.postgres, now), jobID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) MarkCancelRunningUndeliverable(ctx context.Context, jobID string) error {
	q := `UPDATE jobs SET cancelled_not_deliverable = true WHERE id = ` + ph(s.postgres, 1) + ` AND status = 'running'`
	_, err := s.db.ExecContext(ctx, q, jobID)
	return err
}

func (s *Store) JobIsTerminal(ctx context.Context, jobID string) (bool, string, error) {
	var st string
	err := s.db.QueryRowContext(ctx, `SELECT status FROM jobs WHERE id = `+ph(s.postgres, 1), jobID).Scan(&st)
	if err != nil {
		return false, "", err
	}
	switch st {
	case StatusSucceeded, StatusFailed, StatusDeadLettered, StatusCancelled:
		return true, st, nil
	default:
		return false, st, nil
	}
}

func (s *Store) PickDueDeliveries(ctx context.Context, now time.Time, limit int) ([]string, error) {
	if limit < 1 {
		limit = 1
	}
	q := `SELECT id FROM jobs WHERE delivery_status = 'pending'
		AND status IN ('succeeded', 'failed')
		AND (callback_url IS NOT NULL AND TRIM(callback_url) != '')
		AND NOT cancelled_not_deliverable
		AND delivery_next_attempt_at IS NOT NULL AND delivery_next_attempt_at <= ` + ph(s.postgres, 1) +
		` ORDER BY delivery_next_attempt_at LIMIT ` + ph(s.postgres, 2)
	rows, err := s.db.QueryContext(ctx, q, formatTime(s.postgres, now), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) BumpDeliveryAttempt(ctx context.Context, jobID string, attempt int, httpCode int, errMsg string, nextAttempt sql.NullTime, now time.Time) error {
	var next any
	if nextAttempt.Valid {
		next = formatTime(s.postgres, nextAttempt.Time)
	}
	q := `UPDATE jobs SET
		delivery_attempts = ` + ph(s.postgres, 1) + `,
		delivery_last_attempt_at = ` + ph(s.postgres, 2) + `,
		delivery_last_response_code = ` + ph(s.postgres, 3) + `,
		delivery_last_error = ` + ph(s.postgres, 4) + `,
		delivery_next_attempt_at = ` + ph(s.postgres, 5) + `
		WHERE id = ` + ph(s.postgres, 6)
	_, err := s.db.ExecContext(ctx, q, attempt, formatTime(s.postgres, now), httpCode, errMsg, next, jobID)
	return err
}

func (s *Store) MarkWebhookDelivered(ctx context.Context, jobID string, now time.Time) error {
	q := `UPDATE jobs SET delivery_status = 'delivered', delivery_next_attempt_at = NULL WHERE id = ` + ph(s.postgres, 1)
	_, err := s.db.ExecContext(ctx, q, jobID)
	return err
}

func (s *Store) MarkWebhookExhausted(ctx context.Context, jobID string, now time.Time) error {
	q := `UPDATE jobs SET delivery_status = 'exhausted', delivery_next_attempt_at = NULL,
		status = CASE WHEN callback_url IS NOT NULL AND TRIM(callback_url) != '' THEN 'dead_lettered' ELSE status END
		WHERE id = ` + ph(s.postgres, 1)
	_, err := s.db.ExecContext(ctx, q, jobID)
	return err
}

func (s *Store) DeleteExpiredJobs(ctx context.Context, now time.Time) (int64, error) {
	q := `DELETE FROM jobs WHERE retention_expires_at < ` + ph(s.postgres, 1)
	res, err := s.db.ExecContext(ctx, q, formatTime(s.postgres, now))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) CountQueued(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM jobs WHERE status = 'queued'`).Scan(&n)
	return n, err
}

func (s *Store) GetJob(ctx context.Context, id string) (*JobRow, error) {
	q := `SELECT id, api_key_id, status, input, options, metadata, result, error,
		callback_url, callback_resolved_ip, callback_host_header, signing_secret_id,
		attempts, lease_owner, lease_expires_at, submitted_at, started_at, completed_at,
		delivery_status, delivery_attempts, delivery_next_attempt_at, delivery_last_attempt_at,
		delivery_last_response_code, delivery_last_error, retention_expires_at, queue_available_at,
		idempotency_key, idempotency_body_hash, cancelled_not_deliverable
		FROM jobs WHERE id = ` + ph(s.postgres, 1)
	return scanJobRow(s.db.QueryRowContext(ctx, q, id), s.postgres)
}

// GetJobWithinRetention returns ErrNotFound when the row is missing or past retention.
func (s *Store) GetJobWithinRetention(ctx context.Context, id string, now time.Time) (*JobRow, error) {
	j, err := s.GetJob(ctx, id)
	if err != nil {
		return nil, err
	}
	if now.After(j.RetentionExpiresAt) {
		return nil, ErrNotFound
	}
	return j, nil
}

func scanJobRow(row *sql.Row, pg bool) (*JobRow, error) {
	var j JobRow
	var meta, res, errj, cb, cbip, cbh, sign, leaseO, idem, idemHash sql.NullString
	var leaseE, start, comp, delNext, delLast sql.NullTime
	var delCode sql.NullInt32
	var sub, ret, qavail any
	if pg {
		err := row.Scan(
			&j.ID, &j.APIKeyID, &j.Status, &j.InputJSON, &j.OptionsJSON, &meta, &res, &errj,
			&cb, &cbip, &cbh, &sign,
			&j.Attempts, &leaseO, &leaseE, &sub, &start, &comp,
			&j.DeliveryStatus, &j.DeliveryAttempts, &delNext, &delLast,
			&delCode, &j.DeliveryLastError, &ret, &qavail,
			&idem, &idemHash, &j.CancelledNotDeliverable,
		)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrNotFound
			}
			return nil, err
		}
	} else {
		var leaseES, startS, compS, delNextS, delLastS sql.NullString
		var ndel int64
		err := row.Scan(
			&j.ID, &j.APIKeyID, &j.Status, &j.InputJSON, &j.OptionsJSON, &meta, &res, &errj,
			&cb, &cbip, &cbh, &sign,
			&j.Attempts, &leaseO, &leaseES, &sub, &startS, &compS,
			&j.DeliveryStatus, &j.DeliveryAttempts, &delNextS, &delLastS,
			&delCode, &j.DeliveryLastError, &ret, &qavail,
			&idem, &idemHash, &ndel,
		)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrNotFound
			}
			return nil, err
		}
		j.CancelledNotDeliverable = ndel != 0
		parseSQLiteNullTime(leaseES, &leaseE)
		parseSQLiteNullTime(startS, &start)
		parseSQLiteNullTime(compS, &comp)
		parseSQLiteNullTime(delNextS, &delNext)
		parseSQLiteNullTime(delLastS, &delLast)
	}
	j.MetadataJSON = []byte(nullStr(meta))
	j.ResultJSON = []byte(nullStr(res))
	j.ErrorJSON = []byte(nullStr(errj))
	j.CallbackURL = cb
	j.CallbackResolvedIP = cbip
	j.CallbackHostHeader = cbh
	j.SigningSecretID = sign
	j.LeaseOwner = leaseO
	j.LeaseExpiresAt = leaseE
	j.StartedAt = start
	j.CompletedAt = comp
	j.DeliveryNextAttemptAt = delNext
	j.DeliveryLastAttemptAt = delLast
	if delCode.Valid {
		j.DeliveryLastCode = delCode
	}
	t, err := parseTimeAny(sub)
	if err != nil {
		return nil, err
	}
	j.SubmittedAt = t
	rt, err := parseTimeAny(ret)
	if err != nil {
		return nil, err
	}
	j.RetentionExpiresAt = rt
	qat, err := parseTimeAny(qavail)
	if err != nil {
		return nil, err
	}
	j.QueueAvailableAt = qat
	j.IdempotencyKey = idem
	j.IdempotencyBodyHash = idemHash
	return &j, nil
}

func nullStr(ns sql.NullString) string {
	if !ns.Valid {
		return ""
	}
	return ns.String
}

func parseSQLiteNullTime(s sql.NullString, out *sql.NullTime) {
	if !s.Valid || s.String == "" {
		return
	}
	t, err := time.Parse(time.RFC3339Nano, s.String)
	if err != nil {
		t, err = time.Parse(time.RFC3339, s.String)
	}
	if err != nil {
		return
	}
	*out = sql.NullTime{Time: t.UTC(), Valid: true}
}

func (s *Store) ListDeadLetteredAdmin(ctx context.Context, apiKeyID string, limit int) ([]JobRow, error) {
	if limit < 1 {
		limit = 50
	}
	q := `SELECT id, api_key_id, status, input, options, metadata, result, error,
		callback_url, callback_resolved_ip, callback_host_header, signing_secret_id,
		attempts, lease_owner, lease_expires_at, submitted_at, started_at, completed_at,
		delivery_status, delivery_attempts, delivery_next_attempt_at, delivery_last_attempt_at,
		delivery_last_response_code, delivery_last_error, retention_expires_at, queue_available_at,
		idempotency_key, idempotency_body_hash, cancelled_not_deliverable
		FROM jobs WHERE status = 'dead_lettered'`
	args := []any{}
	n := 1
	if apiKeyID != "" {
		q += ` AND api_key_id = ` + ph(s.postgres, n)
		args = append(args, apiKeyID)
		n++
	}
	q += ` ORDER BY completed_at DESC LIMIT ` + ph(s.postgres, n)
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []JobRow
	for rows.Next() {
		j, err := scanJobFromRows(rows, s.postgres)
		if err != nil {
			return nil, err
		}
		out = append(out, *j)
	}
	return out, rows.Err()
}

func scanJobFromRows(rows *sql.Rows, pg bool) (*JobRow, error) {
	var j JobRow
	var meta, res, errj, cb, cbip, cbh, sign, leaseO, idem, idemHash sql.NullString
	var leaseE, start, comp, delNext, delLast sql.NullTime
	var sub, ret, qavail any
	var delCode sql.NullInt32
	if pg {
		err := rows.Scan(
			&j.ID, &j.APIKeyID, &j.Status, &j.InputJSON, &j.OptionsJSON, &meta, &res, &errj,
			&cb, &cbip, &cbh, &sign,
			&j.Attempts, &leaseO, &leaseE, &sub, &start, &comp,
			&j.DeliveryStatus, &j.DeliveryAttempts, &delNext, &delLast,
			&delCode, &j.DeliveryLastError, &ret, &qavail,
			&idem, &idemHash, &j.CancelledNotDeliverable,
		)
		if err != nil {
			return nil, err
		}
	} else {
		var leaseES, startS, compS, delNextS, delLastS sql.NullString
		var ndel int64
		err := rows.Scan(
			&j.ID, &j.APIKeyID, &j.Status, &j.InputJSON, &j.OptionsJSON, &meta, &res, &errj,
			&cb, &cbip, &cbh, &sign,
			&j.Attempts, &leaseO, &leaseES, &sub, &startS, &compS,
			&j.DeliveryStatus, &j.DeliveryAttempts, &delNextS, &delLastS,
			&delCode, &j.DeliveryLastError, &ret, &qavail,
			&idem, &idemHash, &ndel,
		)
		if err != nil {
			return nil, err
		}
		j.CancelledNotDeliverable = ndel != 0
		parseSQLiteNullTime(leaseES, &leaseE)
		parseSQLiteNullTime(startS, &start)
		parseSQLiteNullTime(compS, &comp)
		parseSQLiteNullTime(delNextS, &delNext)
		parseSQLiteNullTime(delLastS, &delLast)
	}
	j.MetadataJSON = []byte(nullStr(meta))
	j.ResultJSON = []byte(nullStr(res))
	j.ErrorJSON = []byte(nullStr(errj))
	j.CallbackURL = cb
	j.CallbackResolvedIP = cbip
	j.CallbackHostHeader = cbh
	j.SigningSecretID = sign
	j.LeaseOwner = leaseO
	j.LeaseExpiresAt = leaseE
	j.StartedAt = start
	j.CompletedAt = comp
	j.DeliveryNextAttemptAt = delNext
	j.DeliveryLastAttemptAt = delLast
	if delCode.Valid {
		j.DeliveryLastCode = delCode
	}
	t, err := parseTimeAny(sub)
	if err != nil {
		return nil, err
	}
	j.SubmittedAt = t
	rt, err := parseTimeAny(ret)
	if err != nil {
		return nil, err
	}
	j.RetentionExpiresAt = rt
	qat, err := parseTimeAny(qavail)
	if err != nil {
		return nil, err
	}
	j.QueueAvailableAt = qat
	j.IdempotencyKey = idem
	j.IdempotencyBodyHash = idemHash
	return &j, nil
}

// MarshalJobInputOptions splits PRD combined body into stored columns.
func MarshalJobInputOptions(urlStr string, opt json.RawMessage) (input, options []byte, err error) {
	in := map[string]string{"url": urlStr}
	input, err = json.Marshal(in)
	if err != nil {
		return nil, nil, err
	}
	if len(opt) == 0 {
		opt = []byte("{}")
	}
	return input, opt, nil
}
