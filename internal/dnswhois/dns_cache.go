package dnswhois

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

type cachedMsg struct {
	msg *dns.Msg
	exp time.Time
}

type ttlDNSCache struct {
	maxTTL time.Duration
	mu     sync.RWMutex
	m      map[string]cachedMsg
}

func newTTLDNSCache(maxTTL time.Duration) *ttlDNSCache {
	if maxTTL < time.Second {
		maxTTL = 5 * time.Minute
	}
	return &ttlDNSCache{maxTTL: maxTTL, m: make(map[string]cachedMsg)}
}

func (c *ttlDNSCache) get(key string) (*dns.Msg, time.Duration, bool) {
	c.mu.RLock()
	ent, ok := c.m[key]
	c.mu.RUnlock()
	if !ok || time.Now().After(ent.exp) {
		return nil, 0, false
	}
	ttl := time.Until(ent.exp)
	return ent.msg.Copy(), ttl, true
}

func (c *ttlDNSCache) set(key string, msg *dns.Msg, recordTTL time.Duration) {
	if msg == nil {
		return
	}
	ttl := recordTTL
	if ttl <= 0 || ttl > c.maxTTL {
		ttl = c.maxTTL
	}
	c.mu.Lock()
	c.m[key] = cachedMsg{msg: msg.Copy(), exp: time.Now().Add(ttl)}
	c.mu.Unlock()
}
