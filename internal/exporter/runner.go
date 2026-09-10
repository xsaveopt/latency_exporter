package exporter

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/xsaveopt/latency_exporter/internal/probe"
)

type Target struct {
	Name     string
	Type     string
	Interval time.Duration
	Timeout  time.Duration
	Prober   probe.Prober
}

func Run(ctx context.Context, logger *slog.Logger, m *Metrics, targets []Target) {
	var wg sync.WaitGroup
	for _, t := range targets {
		m.register(t.Name, t.Type)
		wg.Go(func() { loop(ctx, logger.With("target", t.Name, "type", t.Type), m, t) })
	}
	wg.Wait()
}

func loop(ctx context.Context, logger *slog.Logger, m *Metrics, t Target) {
	jitter := time.NewTimer(rand.N(t.Interval))
	select {
	case <-ctx.Done():
		jitter.Stop()
		return
	case <-jitter.C:
	}

	ticker := time.NewTicker(t.Interval)
	defer ticker.Stop()
	healthy := true
	for {
		pctx, cancel := context.WithTimeout(ctx, t.Timeout)
		r := t.Prober.Probe(pctx)
		cancel()
		if ctx.Err() != nil {
			return
		}
		m.observe(t.Name, t.Type, r, time.Now())

		switch {
		case r.Err != nil && healthy:
			logger.Warn("probe failing", "reason", probe.Reason(r.Err), "err", r.Err)
			healthy = false
		case r.Err != nil:
			logger.Debug("probe failed", "reason", probe.Reason(r.Err), "err", r.Err)
		case !healthy:
			logger.Info("probe recovered", "duration", r.Duration)
			healthy = true
		default:
			logger.Debug("probe ok", "duration", r.Duration)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
