package apikeys

import (
	"context"
	"errors"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2/simplelru"
)

// KeyContext is attached to authenticated requests.
type KeyContext struct {
	KeyID       string
	Owner       string
	Prefix      string
	RPSLimit    int
	DailyQuota  int
	FullKeyHash string // argon2 hash from DB (for quota/rps keys if needed)
}

const (
	cacheEntries     = 1024
	cacheNegativeTTL = 60 * time.Second
)

type verifiedEntry struct {
	val   KeyContext
	until time.Time
}

// Verifier resolves bearer tokens with LRU + TTL cache (per process).
type Verifier struct {
	store *Store

	mu  sync.Mutex
	pos *lru.LRU[[32]byte, verifiedEntry]
	neg *lru.LRU[[32]byte, time.Time]
}

// NewVerifier constructs a Verifier.
func NewVerifier(st *Store) (*Verifier, error) {
	pos, err := lru.NewLRU[[32]byte, verifiedEntry](cacheEntries, nil)
	if err != nil {
		return nil, err
	}
	neg, err := lru.NewLRU[[32]byte, time.Time](cacheEntries, nil)
	if err != nil {
		return nil, err
	}
	return &Verifier{store: st, pos: pos, neg: neg}, nil
}

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrMalformed    = errors.New("malformed key")
)

// Verify authenticates the raw bearer token string (without "Bearer " prefix).
func (v *Verifier) Verify(ctx context.Context, rawToken string) (KeyContext, error) {
	rawToken = NormalizeKey(rawToken)
	if err := ValidateFormat(rawToken); err != nil {
		return KeyContext{}, ErrMalformed
	}
	fp := Sha256Finger(rawToken)
	v.mu.Lock()
	if exp, ok := v.neg.Get(fp); ok {
		if time.Now().Before(exp) {
			v.mu.Unlock()
			return KeyContext{}, ErrUnauthorized
		}
		v.neg.Remove(fp)
	}
	if ent, ok := v.pos.Get(fp); ok {
		if time.Now().Before(ent.until) {
			v.mu.Unlock()
			return ent.val, nil
		}
		v.pos.Remove(fp)
	}
	v.mu.Unlock()

	pref := Prefix12(rawToken)
	row, err := v.store.LookupActiveByPrefix(ctx, pref)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			v.noteNegative(fp)
			return KeyContext{}, ErrUnauthorized
		}
		return KeyContext{}, err
	}
	ok, err := VerifySecret(rawToken, row.Hash)
	if err != nil {
		return KeyContext{}, err
	}
	if !ok {
		v.noteNegative(fp)
		return KeyContext{}, ErrUnauthorized
	}
	kc := KeyContext{
		KeyID:       row.ID,
		Owner:       row.Owner,
		Prefix:      pref,
		RPSLimit:    row.RPSLimit,
		DailyQuota:  row.DailyQuota,
		FullKeyHash: row.Hash,
	}
	v.mu.Lock()
	v.pos.Add(fp, verifiedEntry{val: kc, until: time.Now().Add(cacheNegativeTTL)})
	v.mu.Unlock()
	return kc, nil
}

func (v *Verifier) noteNegative(fp [32]byte) {
	v.mu.Lock()
	v.neg.Add(fp, time.Now().Add(cacheNegativeTTL))
	v.mu.Unlock()
}

// PurgeKey removes cache entries for this key's hash fingerprint (call on rotate from same process only; other pods use TTL).
func (v *Verifier) PurgeKey(_ [32]byte) {
	// optional: not implemented; rely on TTL
}
