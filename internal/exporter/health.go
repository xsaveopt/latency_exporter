package exporter

import (
	"sync"
	"time"
)

const stallMultiple = 3

type healthTarget struct {
	interval time.Duration
	started  time.Time
	lastAt   time.Time
	lastErr  bool
}

type Health struct {
	mu      sync.Mutex
	targets map[string]healthTarget
}

func NewHealth() *Health {
	return &Health{targets: make(map[string]healthTarget)}
}

func (h *Health) register(name string, interval time.Duration, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.targets[name] = healthTarget{interval: interval, started: now}
}

func (h *Health) report(name string, err error, at time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.targets[name]
	if !ok {
		return
	}
	s.lastAt = at
	s.lastErr = err != nil
	h.targets[name] = s
}

func (h *Health) Degraded(now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.targets) == 0 {
		return false
	}
	for _, s := range h.targets {
		if s.lastAt.IsZero() {
			if now.Sub(s.started) <= stallMultiple*s.interval {
				return false
			}
			continue
		}
		if !s.lastErr && now.Sub(s.lastAt) <= stallMultiple*s.interval {
			return false
		}
	}
	return true
}
