package dnswhois

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const ianaRDAPBootstrapURL = "https://data.iana.org/rdap/dns.json"

type rdapBootstrapStore struct {
	tldToURLs map[string][]string
	fetchedAt time.Time
	ttl       time.Duration
	mu        sync.RWMutex
}

// RDAP performs HTTPS RDAP per IANA bootstrap.
type RDAP struct {
	HTTP      *http.Client
	bootstrap rdapBootstrapStore
}

func NewRDAP(timeout time.Duration) *RDAP {
	return &RDAP{
		HTTP: &http.Client{Timeout: timeout},
		bootstrap: rdapBootstrapStore{
			tldToURLs: make(map[string][]string),
			ttl:       24 * time.Hour,
		},
	}
}

func (r *RDAP) fetchBootstrap(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ianaRDAPBootstrapURL, nil)
	if err != nil {
		return err
	}
	resp, err := r.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	var f struct {
		Services [][]json.RawMessage `json:"services"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	m := make(map[string][]string)
	for _, svc := range f.Services {
		if len(svc) < 2 {
			continue
		}
		var tlds []string
		if err := json.Unmarshal(svc[0], &tlds); err != nil {
			continue
		}
		var urls []string
		if err := json.Unmarshal(svc[1], &urls); err != nil {
			continue
		}
		for _, t := range tlds {
			m[strings.ToLower(strings.TrimSpace(t))] = urls
		}
	}
	r.bootstrap.mu.Lock()
	r.bootstrap.tldToURLs = m
	r.bootstrap.fetchedAt = time.Now()
	r.bootstrap.mu.Unlock()
	return nil
}

func (r *RDAP) urlsForTLD(ctx context.Context, tld string) ([]string, error) {
	r.bootstrap.mu.RLock()
	stale := time.Since(r.bootstrap.fetchedAt) > r.bootstrap.ttl || len(r.bootstrap.tldToURLs) == 0
	r.bootstrap.mu.RUnlock()
	if stale {
		_ = r.fetchBootstrap(ctx)
	}
	r.bootstrap.mu.RLock()
	defer r.bootstrap.mu.RUnlock()
	u := r.bootstrap.tldToURLs[strings.ToLower(tld)]
	if len(u) == 0 {
		return nil, ErrRDAPNotAvailableErr
	}
	return u, nil
}

// LookupDomain queries RDAP /domain/{apex}.
func (r *RDAP) LookupDomain(ctx context.Context, apex string) (*WHOISBlock, error) {
	apex = strings.TrimSpace(strings.ToLower(apex))
	parts := strings.Split(apex, ".")
	if len(parts) < 2 {
		return nil, errors.New("invalid apex")
	}
	tld := parts[len(parts)-1]
	urls, err := r.urlsForTLD(ctx, tld)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, base := range urls {
		base = strings.TrimRight(strings.TrimSpace(base), "/")
		u := base + "/domain/" + url.PathEscape(apex)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Accept", "application/rdap+json, application/json")
		resp, err := r.HTTP.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			return nil, errRDAP429
		}
		if resp.StatusCode == http.StatusNotFound {
			lastErr = ErrRDAPNotAvailableErr
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("rdap http %d", resp.StatusCode)
			continue
		}
		block, err := parseRDAPDomainJSON(body)
		if err != nil {
			lastErr = err
			continue
		}
		block.Source = "rdap"
		now := time.Now().UTC()
		block.QueriedAt = now.Truncate(time.Millisecond)
		if block.CreatedAt != nil && *block.CreatedAt != "" {
			if days := ageDays(*block.CreatedAt, now); days >= 0 {
				block.DomainAgeDays = ptrInt(days)
			}
		}
		return block, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrRDAPNotAvailableErr
}

var errRDAP429 = errors.New("rdap 429")

func parseRDAPDomainJSON(raw []byte) (*WHOISBlock, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, err
	}
	b := &WHOISBlock{
		Status:      []string{},
		Nameservers: []string{},
		Errors:      []TypedSideError{},
		Privacy:     true,
	}
	if v, ok := root["status"]; ok {
		var st []string
		_ = json.Unmarshal(v, &st)
		b.Status = st
	}
	if v, ok := root["entities"]; ok {
		var ents []map[string]json.RawMessage
		_ = json.Unmarshal(v, &ents)
		for _, e := range ents {
			for _, role := range extractRoles(e) {
				if role == "registrar" {
					fn, id := extractVCardFN(e)
					if fn != "" {
						b.Registrar = ptrStr(fn)
						if id > 0 {
							b.RegistrarIANAID = ptrInt(id)
						}
					}
				}
			}
		}
	}
	if v, ok := root["events"]; ok {
		parseRDAPEvents(v, b)
	}
	if v, ok := root["nameservers"]; ok {
		var nss []struct {
			LdhName string `json:"ldhName"`
		}
		_ = json.Unmarshal(v, &nss)
		for _, ns := range nss {
			if ns.LdhName != "" {
				b.Nameservers = append(b.Nameservers, strings.ToLower(ns.LdhName))
			}
		}
	}
	return b, nil
}

func extractRoles(e map[string]json.RawMessage) []string {
	v, ok := e["roles"]
	if !ok {
		return nil
	}
	var roles []string
	_ = json.Unmarshal(v, &roles)
	return roles
}

func extractVCardFN(ent map[string]json.RawMessage) (string, int) {
	v, ok := ent["vcardArray"]
	if !ok {
		return "", 0
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(v, &arr); err != nil || len(arr) < 2 {
		return "", 0
	}
	var cards [][]json.RawMessage
	if err := json.Unmarshal(arr[1], &cards); err != nil {
		return "", 0
	}
	var fn string
	var ianaID int
	for _, row := range cards {
		if len(row) < 4 {
			continue
		}
		var kind string
		_ = json.Unmarshal(row[0], &kind)
		lk := strings.ToLower(kind)
		if lk == "fn" {
			var label string
			_ = json.Unmarshal(row[3], &label)
			if label != "" {
				fn = label
			}
		}
		if strings.Contains(lk, "iana") && strings.Contains(lk, "registrar") && strings.Contains(lk, "id") {
			var idStr string
			_ = json.Unmarshal(row[3], &idStr)
			if n, err := strconv.Atoi(strings.TrimSpace(idStr)); err == nil {
				ianaID = n
			}
		}
	}
	return fn, ianaID
}

func parseRDAPEvents(raw json.RawMessage, b *WHOISBlock) {
	var evts []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	}
	if err := json.Unmarshal(raw, &evts); err != nil {
		return
	}
	for _, e := range evts {
		d := normalizeRDAPDate(e.Date)
		switch strings.ToLower(e.Action) {
		case "registration":
			b.CreatedAt = ptrStr(d)
		case "last changed":
			b.UpdatedAt = ptrStr(d)
		case "expiration", "expiry":
			b.ExpiresAt = ptrStr(d)
		}
	}
}

func normalizeRDAPDate(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC().Format("2006-01-02")
	}
	if idx := strings.IndexByte(s, 'T'); idx > 0 {
		return s[:idx]
	}
	return s
}

func ageDays(createdISO string, now time.Time) int {
	t, err := time.Parse("2006-01-02", createdISO)
	if err != nil {
		return -1
	}
	return int(now.Sub(t.UTC()).Hours() / 24)
}

func ptrStr(s string) *string { return &s }

func ptrInt(n int) *int { return &n }
