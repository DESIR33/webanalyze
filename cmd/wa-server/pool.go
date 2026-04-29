package main

import (
	"context"
	"sync"
)

// scanPool limits concurrent in-flight analyze operations (WA_WORKERS).
type scanPool struct {
	sem   chan struct{}
	semMu sync.Mutex
	empty bool
}

func newScanPool(n int) *scanPool {
	if n < 1 {
		n = 1
	}
	return &scanPool{sem: make(chan struct{}, n)}
}

func (p *scanPool) close() {
	p.semMu.Lock()
	p.empty = true
	p.semMu.Unlock()
}

func (p *scanPool) acquire(ctx context.Context) error {
	p.semMu.Lock()
	empty := p.empty
	p.semMu.Unlock()
	if empty {
		return context.Canceled
	}
	select {
	case p.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *scanPool) release() {
	<-p.sem
}
