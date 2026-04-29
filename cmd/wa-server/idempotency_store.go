package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	idemLockTTLSeconds   = 60
	idemEntryTTLSeconds  = 86400   // 24h from first write, not refreshed on replay
	idemMaxCachedBody    = 1 << 20 // 1 MiB response body cap for cache
	idemBodyHashPrefix   = "sha256:"
	idempotencyKeyMaxLen = 255
)

type idemEntryState string

const (
	idemStateInProgress idemEntryState = "in_progress"
	idemStateCompleted  idemEntryState = "completed"
)

type idemRedisEntry struct {
	State       string             `json:"state"`
	BodyHash    string             `json:"body_hash"`
	Response    *idemRedisResponse `json:"response,omitempty"`
	FirstSeenAt string             `json:"first_seen_at"`
	CompletedAt string             `json:"completed_at,omitempty"`
	RequestID   string             `json:"request_id"`
	DurationMS  int64              `json:"duration_ms,omitempty"`
}

type idemRedisResponse struct {
	Status  int                 `json:"status"`
	Headers map[string][]string `json:"headers"`
	BodyB64 string              `json:"body_b64"`
}

func idemRedisKey(keyID, idemKey string) string {
	return fmt.Sprintf("idem:%s:%s", keyID, idemKey)
}

type idempotencyStore struct {
	client *redis.Client
}

func newIdempotencyStore(c *redis.Client) *idempotencyStore {
	if c == nil {
		return nil
	}
	return &idempotencyStore{client: c}
}

func (s *idempotencyStore) ping(ctx context.Context) error {
	if s == nil || s.client == nil {
		return redis.Nil
	}
	return s.client.Ping(ctx).Err()
}

func idemCompletedTTLSeconds(firstSeenRFC string) int {
	firstSeen, err := time.Parse(time.RFC3339Nano, firstSeenRFC)
	if err != nil {
		firstSeen, err = time.Parse(time.RFC3339, firstSeenRFC)
		if err != nil {
			return idemEntryTTLSeconds
		}
	}
	ttl := idemEntryTTLSeconds - int(time.Since(firstSeen).Seconds())
	if ttl < 1 {
		return 1
	}
	if ttl > idemEntryTTLSeconds {
		return idemEntryTTLSeconds
	}
	return ttl
}

// tryAcquire sets in_progress if missing. Returns true if this request owns the lock.
func (s *idempotencyStore) tryAcquire(ctx context.Context, redisKey, bodyHash, reqID string) (bool, idemRedisEntry, error) {
	if s == nil || s.client == nil {
		return true, idemRedisEntry{}, nil // fail-open: behave as first request
	}
	const maxRoundTrips = 5
	for attempt := 0; attempt < maxRoundTrips; attempt++ {
		now := time.Now().UTC()
		entry := idemRedisEntry{
			State:       string(idemStateInProgress),
			BodyHash:    bodyHash,
			FirstSeenAt: now.Format(time.RFC3339Nano),
			RequestID:   reqID,
		}
		b, err := json.Marshal(entry)
		if err != nil {
			return false, idemRedisEntry{}, err
		}
		ok, err := s.client.SetNX(ctx, redisKey, b, idemLockTTLSeconds*time.Second).Result()
		if err != nil {
			return false, idemRedisEntry{}, err
		}
		if ok {
			return true, entry, nil
		}
		raw, err := s.client.Get(ctx, redisKey).Bytes()
		if err == redis.Nil {
			continue // expired between NX and GET — retry
		}
		if err != nil {
			return false, idemRedisEntry{}, err
		}
		var existing idemRedisEntry
		if err := json.Unmarshal(raw, &existing); err != nil {
			return false, idemRedisEntry{}, err
		}
		return false, existing, nil
	}
	return false, idemRedisEntry{}, fmt.Errorf("idem acquire: exhausted retries")
}

func (s *idempotencyStore) getEntry(ctx context.Context, redisKey string) (idemRedisEntry, error) {
	if s == nil || s.client == nil {
		return idemRedisEntry{}, redis.Nil
	}
	raw, err := s.client.Get(ctx, redisKey).Bytes()
	if err != nil {
		return idemRedisEntry{}, err
	}
	var e idemRedisEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		return idemRedisEntry{}, err
	}
	return e, nil
}

// completeIfOwner replaces in_progress with completed when request_id matches (transactional).
func (s *idempotencyStore) completeIfOwner(ctx context.Context, redisKey, reqID string, done idemRedisEntry) error {
	if s == nil || s.client == nil {
		return nil
	}
	ttl := idemCompletedTTLSeconds(done.FirstSeenAt)
	payload, err := json.Marshal(done)
	if err != nil {
		return err
	}
	return s.client.Watch(ctx, func(tx *redis.Tx) error {
		raw, err := tx.Get(ctx, redisKey).Bytes()
		if err == redis.Nil {
			waIdempotencyLockExpired.Inc()
			return nil
		}
		if err != nil {
			return err
		}
		var cur idemRedisEntry
		if err := json.Unmarshal(raw, &cur); err != nil {
			return err
		}
		if cur.RequestID != reqID || cur.State != string(idemStateInProgress) {
			return nil
		}
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.Set(ctx, redisKey, payload, time.Duration(ttl)*time.Second)
			return nil
		})
		return err
	}, redisKey)
}

// abandonIfOwner deletes the key if still in_progress for this request_id.
func (s *idempotencyStore) abandonIfOwner(ctx context.Context, redisKey, reqID string) error {
	if s == nil || s.client == nil {
		return nil
	}
	return s.client.Watch(ctx, func(tx *redis.Tx) error {
		raw, err := tx.Get(ctx, redisKey).Bytes()
		if err == redis.Nil {
			return nil
		}
		if err != nil {
			return err
		}
		var cur idemRedisEntry
		if err := json.Unmarshal(raw, &cur); err != nil {
			return err
		}
		if cur.RequestID != reqID || cur.State != string(idemStateInProgress) {
			return nil
		}
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.Del(ctx, redisKey)
			return nil
		})
		return err
	}, redisKey)
}

func idemResponseFromHTTP(status int, hdr http.Header, body []byte) idemRedisResponse {
	hcopy := make(map[string][]string)
	for k, vv := range hdr {
		k = http.CanonicalHeaderKey(k)
		if isHopByHopHeader(k) {
			continue
		}
		if strings.EqualFold(k, "Idempotency-Key") {
			continue
		}
		if strings.HasPrefix(strings.ToLower(k), "x-idempotency") {
			continue
		}
		cp := make([]string, len(vv))
		copy(cp, vv)
		hcopy[k] = cp
	}
	return idemRedisResponse{
		Status:  status,
		Headers: hcopy,
		BodyB64: base64.StdEncoding.EncodeToString(body),
	}
}

func writeCachedResponse(w http.ResponseWriter, c idemRedisResponse) error {
	for k, vv := range c.Headers {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(c.Status)
	if c.BodyB64 == "" {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(c.BodyB64)
	if err != nil {
		return err
	}
	_, err = w.Write(raw)
	return err
}

func isHopByHopHeader(k string) bool {
	switch http.CanonicalHeaderKey(k) {
	case "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade":
		return true
	default:
		return false
	}
}

func parseErrorCodeFromBody(body []byte) string {
	var env struct {
		Error *struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil || env.Error == nil {
		return ""
	}
	return env.Error.Code
}

// idempotencyResponseCacheable returns whether we may store this response for replay.
func idempotencyResponseCacheable(status int, body []byte) bool {
	if status >= 200 && status < 300 {
		return len(body) <= idemMaxCachedBody
	}
	if status < 400 || status >= 500 {
		return false
	}
	code := parseErrorCodeFromBody(body)
	switch code {
	case CodeInvalidURL, CodeInvalidPayload, CodeBatchEmpty, CodeBatchTooLarge:
		return len(body) <= idemMaxCachedBody
	default:
		return false
	}
}

func validateIdempotencyKeyHeader(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("empty")
	}
	if len(s) > idempotencyKeyMaxLen {
		return "", errors.New("too long")
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 0x20 || b == 0x7f || b == ' ' || b == '\t' || b == '\n' || b == '\r' || b > 0x7e {
			return "", errors.New("invalid char")
		}
	}
	return s, nil
}
