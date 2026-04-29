package dnswhois

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Known WHOIS servers for port 43 fallback when RDAP misses (.com/.net/.org etc.).
var defaultWhoisServers = map[string]string{
	"com": "whois.verisign-grs.com",
	"net": "whois.verisign-grs.com",
	"org": "whois.publicinterestregistry.net",
	"io":  "whois.nic.io",
}

// GatherWHOIS tries RDAP then port 43; caches JSON in Redis when configured.
func GatherWHOIS(ctx context.Context, apex string, rdap *RDAP, timeout time.Duration, redisClient *redis.Client, cacheTTL time.Duration, fresh bool) (*WHOISBlock, time.Duration, bool) {
	t0 := time.Now()
	if apex == "" {
		return nil, 0, false
	}
	cacheKey := "wa:whois:" + strings.ToLower(strings.TrimSpace(apex))
	if redisClient != nil && !fresh {
		s, err := redisClient.Get(ctx, cacheKey).Result()
		if err == nil && s != "" {
			var cached WHOISBlock
			if json.Unmarshal([]byte(s), &cached) == nil {
				cached.Cached = true
				cached.DurationMS = time.Since(t0).Milliseconds()
				cached.QueriedAt = time.Now().UTC().Truncate(time.Millisecond)
				return &cached, time.Since(t0), true
			}
		}
	}

	if rdap == nil {
		rdap = NewRDAP(timeout)
	}
	wCtx, cancel := context.WithTimeout(ctx, timeout+2*time.Second)
	defer cancel()

	block, rdapErr := rdap.LookupDomain(wCtx, apex)
	if rdapErr != nil && errors.Is(rdapErr, errRDAP429) {
		return &WHOISBlock{
			Source:     "rdap",
			Errors:     []TypedSideError{{Code: ErrRDAPRateLimited, Message: "registry returned 429"}},
			Status:     []string{},
			Privacy:    true,
			QueriedAt:  time.Now().UTC().Truncate(time.Millisecond),
			DurationMS: time.Since(t0).Milliseconds(),
		}, time.Since(t0), false
	}

	fallback := rdapErr != nil || block == nil
	if fallback {
		parts := strings.Split(strings.TrimSpace(strings.ToLower(apex)), ".")
		tld := parts[len(parts)-1]
		srv := defaultWhoisServers[tld]
		if srv != "" {
			if fb, ferr := whoisDial(wCtx, srv, apex, timeout); ferr == nil && fb != nil {
				block = fb
			} else if block == nil {
				msg := "whois fallback failed"
				if ferr != nil {
					msg = ferr.Error()
				}
				block = &WHOISBlock{
					Source:      "port43",
					Status:      []string{},
					Nameservers: []string{},
					Errors:      []TypedSideError{{Code: ErrRDAPNotAvailable, Message: msg}},
					Privacy:     true,
					QueriedAt:   time.Now().UTC().Truncate(time.Millisecond),
				}
			}
		} else if block == nil {
			block = &WHOISBlock{
				Status:      []string{},
				Nameservers: []string{},
				Errors:      []TypedSideError{{Code: ErrRDAPNotAvailable, Message: "no bootstrap"}},
				Privacy:     true,
				QueriedAt:   time.Now().UTC().Truncate(time.Millisecond),
			}
		}
	}

	if block != nil {
		block.DurationMS = time.Since(t0).Milliseconds()
		if redisClient != nil && cacheTTL > 0 && !fresh {
			raw, _ := json.Marshal(block)
			_ = redisClient.Set(ctx, cacheKey, raw, cacheTTL).Err()
		}
	}
	return block, time.Since(t0), false
}

func whoisDial(ctx context.Context, server, apex string, timeout time.Duration) (*WHOISBlock, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(server, "43"))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(apex + "\r\n")); err != nil {
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	raw, err := io.ReadAll(io.LimitReader(conn, 512*1024))
	if err != nil {
		return nil, err
	}
	return parseWhoisText(string(raw))
}

func parseWhoisText(text string) (*WHOISBlock, error) {
	block := &WHOISBlock{
		Source:      "port43",
		Status:      []string{},
		Nameservers: []string{},
		Privacy:     true,
		QueriedAt:   time.Now().UTC().Truncate(time.Millisecond),
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") {
			continue
		}
		low := strings.ToLower(line)
		if strings.Contains(low, "registrar:") && block.Registrar == nil {
			idx := strings.Index(line, ":")
			if idx >= 0 {
				v := strings.TrimSpace(line[idx+1:])
				if v != "" {
					block.Registrar = ptrStr(v)
				}
			}
		}
		if (strings.Contains(low, "creation date") || strings.Contains(low, "created:")) && block.CreatedAt == nil {
			idx := strings.Index(line, ":")
			if idx >= 0 {
				v := strings.TrimSpace(line[idx+1:])
				fs := strings.Fields(strings.Trim(v, ","))
				if len(fs) > 0 {
					block.CreatedAt = ptrStr(normalizeWhoisDate(fs[0]))
				}
			}
		}
		if strings.Contains(low, "expiration") || strings.Contains(low, "registry expiry") {
			idx := strings.Index(line, ":")
			if idx >= 0 {
				v := strings.TrimSpace(line[idx+1:])
				fs := strings.Fields(strings.Trim(v, ","))
				if len(fs) > 0 {
					block.ExpiresAt = ptrStr(normalizeWhoisDate(fs[0]))
				}
			}
		}
		if strings.HasPrefix(low, "name server:") || strings.HasPrefix(low, "nserver:") {
			idx := strings.Index(line, ":")
			if idx >= 0 {
				v := strings.Fields(strings.TrimSpace(line[idx+1:]))
				if len(v) > 0 {
					block.Nameservers = append(block.Nameservers, strings.ToLower(strings.TrimSuffix(v[0], ".")))
				}
			}
		}
	}
	if block.CreatedAt != nil && *block.CreatedAt != "" {
		if days := ageDays(*block.CreatedAt, time.Now().UTC()); days >= 0 {
			block.DomainAgeDays = ptrInt(days)
		}
	}
	if block.Registrar == nil && block.CreatedAt == nil {
		return nil, errors.New("parse failed")
	}
	return block, nil
}

func normalizeWhoisDate(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 10 && s[4] == '-' {
		if _, err := strconv.Atoi(s[:4]); err == nil {
			return s[:10]
		}
	}
	if t, err := time.Parse("2006-01-02T15:04:05Z", s); err == nil {
		return t.UTC().Format("2006-01-02")
	}
	if t, err := time.Parse("02-Jan-2006", s); err == nil {
		return t.UTC().Format("2006-01-02")
	}
	return s
}
