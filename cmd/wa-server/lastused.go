package main

import (
	"context"
	"sync"
	"time"

	"github.com/rverton/webanalyze/internal/apikeys"
)

type lastUsedFlusher struct {
	store   *apikeys.Store
	mu      sync.Mutex
	pending map[string]struct{}
	tick    *time.Ticker
	done    chan struct{}
}

func startLastUsedFlusher(st *apikeys.Store) *lastUsedFlusher {
	if st == nil {
		return nil
	}
	f := &lastUsedFlusher{
		store:   st,
		pending: make(map[string]struct{}),
		tick:    time.NewTicker(5 * time.Second),
		done:    make(chan struct{}),
	}
	go f.loop()
	return f
}

func (f *lastUsedFlusher) Enqueue(id string) {
	if f == nil || id == "" {
		return
	}
	f.mu.Lock()
	f.pending[id] = struct{}{}
	f.mu.Unlock()
}

func (f *lastUsedFlusher) loop() {
	for {
		select {
		case <-f.done:
			return
		case <-f.tick.C:
			f.flush()
		}
	}
}

func (f *lastUsedFlusher) flush() {
	f.mu.Lock()
	ids := make([]string, 0, len(f.pending))
	for id := range f.pending {
		ids = append(ids, id)
	}
	f.pending = make(map[string]struct{})
	f.mu.Unlock()
	if len(ids) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = f.store.BatchTouchLastUsed(ctx, ids, time.Now().UTC())
}

func (f *lastUsedFlusher) Close() {
	if f == nil {
		return
	}
	close(f.done)
	f.tick.Stop()
	f.flush()
}
