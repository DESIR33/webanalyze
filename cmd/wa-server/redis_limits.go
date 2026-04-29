package main

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

type redisLimiter struct {
	client *redis.Client
}

func newRedisLimiter(addr string) (*redisLimiter, error) {
	if addr == "" {
		return nil, nil
	}
	opt, err := redis.ParseURL(addr)
	if err != nil {
		opt = &redis.Options{Addr: addr}
	}
	c := redis.NewClient(opt)
	if err := c.Ping(context.Background()).Err(); err != nil {
		_ = c.Close()
		return nil, err
	}
	return &redisLimiter{client: c}, nil
}

func (rl *redisLimiter) Close() error {
	if rl == nil || rl.client == nil {
		return nil
	}
	return rl.client.Close()
}

// CheckRPS token bucket refill at rate/sec, capacity burst; consume one token if available.
func (rl *redisLimiter) CheckRPS(ctx context.Context, keyID string, rate, burst int, nowUnix int64) (allowed bool, remaining float64, retryAfter int64) {
	if rl == nil {
		return true, float64(rate), 0
	}
	if rate < 1 {
		rate = 1
	}
	res, err := luaRPS.Run(ctx, rl.client, []string{rpsRedisKey(keyID)}, rate, burst, nowUnix).Result()
	if err != nil {
		return true, float64(rate), 0 // fail-open
	}
	arr, ok := res.([]any)
	if !ok || len(arr) < 3 {
		return true, float64(rate), 0
	}
	okFlag := argvFloat(arr[0])
	rem := argvFloat(arr[1])
	wait := argvFloat(arr[2])
	if okFlag >= 1 {
		return true, rem, 0
	}
	return false, rem, int64(wait)
}

// DailyShouldReject rejects when current count is already at or beyond quota for this UTC day (PRD compares before granting request).
func (rl *redisLimiter) DailyShouldReject(ctx context.Context, keyID string, quota int) (bool, float64, error) {
	if rl == nil || quota < 1 {
		return false, float64(quota), nil
	}
	n, err := rl.dailyGet(ctx, keyID)
	if err != nil {
		return false, float64(quota), err
	}
	rem := float64(quota) - float64(n)
	if rem <= 0 {
		return true, 0, nil
	}
	return false, rem, nil
}

func (rl *redisLimiter) dailyGet(ctx context.Context, keyID string) (int64, error) {
	if rl == nil {
		return 0, nil
	}
	k := dailyRedisKey(keyID)
	s, err := rl.client.Get(ctx, k).Result()
	if err == redis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(s, 10, 64)
}

// IncrementDailyCounted adds counted usage for quota (2xx/5xx per PRD, called after handler).
func (rl *redisLimiter) IncrementDailyCounted(ctx context.Context, keyID string, delta int64) error {
	if rl == nil || delta == 0 {
		return nil
	}
	k := dailyRedisKey(keyID)
	cur, err := rl.client.IncrBy(ctx, k, delta).Result()
	if err != nil {
		return err
	}
	if cur == delta {
		_ = rl.client.Expire(ctx, k, 36*time.Hour).Err()
	}
	return nil
}

func dailyRedisKey(keyID string) string {
	return fmt.Sprintf("wa:quota:daily:%s:%s", keyID, time.Now().UTC().Format("20060102"))
}

func rpsRedisKey(keyID string) string {
	return fmt.Sprintf("wa:rps:%s", keyID)
}

func utcNextMidnightUnix() int64 {
	now := time.Now().UTC()
	next := now.AddDate(0, 0, 1)
	next = time.Date(next.Year(), next.Month(), next.Day(), 0, 0, 0, 0, time.UTC)
	return next.Unix()
}

func argvFloat(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int64:
		return float64(x)
	default:
		return 0
	}
}

// luaRPS keys[1]=state hash tokens+ts args rate burst now_sec
var luaRPS = redis.NewScript(`
local rate = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
if rate < 1 then rate = 1 end

local tokens = tonumber(redis.call('HGET', KEYS[1], 'tokens'))
local ts = tonumber(redis.call('HGET', KEYS[1], 'ts'))
if tokens == nil then tokens = tonumber(burst) end
if ts == nil then ts = tonumber(now) end

local elapsed = tonumber(now) - tonumber(ts)
if elapsed < 0 then elapsed = 0 end
tokens = math.min(tonumber(burst), tokens + elapsed * tonumber(rate))

if tokens < 1 then
  local shortage = 1 - tokens
  local wait_sec = math.ceil(shortage / tonumber(rate))
  if wait_sec < 1 then wait_sec = 1 end
  redis.call('HSET', KEYS[1], 'ts', now)
  redis.call('HSET', KEYS[1], 'tokens', tokens)
  redis.call('EXPIRE', KEYS[1], 86400)
  return {0, tokens, wait_sec}
end

tokens = tokens - 1
redis.call('HSET', KEYS[1], 'ts', now)
redis.call('HSET', KEYS[1], 'tokens', tokens)
redis.call('EXPIRE', KEYS[1], 86400)
return {1, tokens, 0}
`)
