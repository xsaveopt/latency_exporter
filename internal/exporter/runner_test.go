package exporter

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/xsaveopt/latency_exporter/internal/probe"
)

type logEntry struct {
	level  slog.Level
	msg    string
	target string
}

type logStore struct {
	mu      sync.Mutex
	entries []logEntry
}

type recordingHandler struct {
	store  *logStore
	target string
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.store.mu.Lock()
	defer h.store.mu.Unlock()
	h.store.entries = append(h.store.entries, logEntry{level: r.Level, msg: r.Message, target: h.target})
	return nil
}

func (h *recordingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := &recordingHandler{store: h.store, target: h.target}
	for _, a := range attrs {
		if a.Key == "target" {
			next.target = a.Value.String()
		}
	}
	return next
}

func (h *recordingHandler) WithGroup(string) slog.Handler { return h }

func (s *logStore) messages(target string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, e := range s.entries {
		if e.target == target {
			out = append(out, e.level.String()+" "+e.msg)
		}
	}
	return out
}

type scriptedProber struct {
	mu        sync.Mutex
	results   []probe.Result
	calls     int
	deadlines []time.Duration
	exhausted chan struct{}
}

func newScripted(results ...probe.Result) *scriptedProber {
	return &scriptedProber{results: results, exhausted: make(chan struct{})}
}

func (p *scriptedProber) Probe(ctx context.Context) probe.Result {
	p.mu.Lock()
	if deadline, ok := ctx.Deadline(); ok {
		p.deadlines = append(p.deadlines, time.Until(deadline))
	} else {
		p.deadlines = append(p.deadlines, -1)
	}
	i := p.calls
	p.calls++
	p.mu.Unlock()
	if i < len(p.results) {
		return p.results[i]
	}
	if i == len(p.results) {
		close(p.exhausted)
	}
	<-ctx.Done()
	return probe.Result{Err: ctx.Err()}
}

func (p *scriptedProber) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

func lastRun(m *Metrics, name, typ string) time.Time {
	return time.Unix(0, int64(testutil.ToFloat64(m.lastRun.WithLabelValues(name, typ))*1e9))
}

func runUntilExhausted(t *testing.T, logger *slog.Logger, m *Metrics, h *Health, targets []Target, probers ...*scriptedProber) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		Run(ctx, logger, m, h, targets)
		close(done)
	}()
	for _, p := range probers {
		select {
		case <-p.exhausted:
		case <-time.After(10 * time.Second):
			cancel()
			<-done
			t.Fatalf("prober ran %d times, want its whole script", p.callCount())
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}
}

func TestRunObservesEveryProbeAndLogsTransitions(t *testing.T) {
	boom := &probe.Error{Reason: probe.ReasonRefused, Err: errors.New("connection refused")}
	p := newScripted(
		probe.Result{Duration: 2 * time.Millisecond},
		probe.Result{Err: boom},
		probe.Result{Err: boom},
		probe.Result{Duration: 3 * time.Millisecond},
	)
	store := &logStore{}
	logger := slog.New(&recordingHandler{store: store})
	reg := prometheus.NewPedanticRegistry()
	m := NewMetrics(reg)
	h := NewHealth()

	runUntilExhausted(t, logger, m, h, []Target{{Name: "nas", Type: "tcp", Interval: time.Millisecond, Timeout: time.Minute, Prober: p}}, p)

	if got := testutil.ToFloat64(m.probes.WithLabelValues("nas", "tcp")); got != 4 {
		t.Errorf("probes_total = %v, want 4 (the blocked probe cut short by shutdown is not counted)", got)
	}
	if got := testutil.ToFloat64(m.failures.WithLabelValues("nas", "tcp", probe.ReasonRefused)); got != 2 {
		t.Errorf("probe_failures_total{reason=refused} = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.success.WithLabelValues("nas", "tcp")); got != 1 {
		t.Errorf("probe_success = %v, want 1 after the last probe succeeded", got)
	}
	if got := testutil.ToFloat64(m.lastDuration.WithLabelValues("nas", "tcp")); got != 0.003 {
		t.Errorf("probe_last_duration_seconds = %v, want 0.003", got)
	}
	if h.Degraded(lastRun(m, "nas", "tcp")) {
		t.Error("Degraded() = true after the last probe succeeded")
	}

	want := []string{
		"DEBUG probe ok",
		"WARN probe failing",
		"DEBUG probe failed",
		"INFO probe recovered",
	}
	if got := store.messages("nas"); !slices.Equal(got, want) {
		t.Errorf("logs = %q, want %q", got, want)
	}
}

func TestRunAppliesTimeoutToEachProbe(t *testing.T) {
	p := newScripted(probe.Result{Duration: time.Millisecond}, probe.Result{Duration: time.Millisecond})
	m := NewMetrics(prometheus.NewPedanticRegistry())
	logger := slog.New(&recordingHandler{store: &logStore{}})

	runUntilExhausted(t, logger, m, NewHealth(), []Target{{Name: "api", Type: "http", Interval: time.Millisecond, Timeout: time.Minute, Prober: p}}, p)

	p.mu.Lock()
	defer p.mu.Unlock()
	for i, d := range p.deadlines {
		if d <= 0 || d > time.Minute {
			t.Errorf("probe %d: remaining deadline = %s, want within the 1m timeout", i, d)
		}
	}
}

func TestRunDrivesTargetsIndependently(t *testing.T) {
	failing := &probe.Error{Reason: probe.ReasonTimeout, Err: context.DeadlineExceeded}
	a := newScripted(probe.Result{Duration: time.Millisecond}, probe.Result{Duration: time.Millisecond}, probe.Result{Duration: time.Millisecond})
	b := newScripted(probe.Result{Err: failing})
	store := &logStore{}
	logger := slog.New(&recordingHandler{store: store})
	m := NewMetrics(prometheus.NewPedanticRegistry())
	h := NewHealth()

	runUntilExhausted(t, logger, m, h, []Target{
		{Name: "a", Type: "icmp", Interval: time.Millisecond, Timeout: time.Minute, Prober: a},
		{Name: "b", Type: "dns", Interval: 2 * time.Millisecond, Timeout: time.Minute, Prober: b},
	}, a, b)

	if got := testutil.ToFloat64(m.probes.WithLabelValues("a", "icmp")); got != 3 {
		t.Errorf("probes_total{target=a} = %v, want 3", got)
	}
	if got := testutil.ToFloat64(m.probes.WithLabelValues("b", "dns")); got != 1 {
		t.Errorf("probes_total{target=b} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.failures.WithLabelValues("b", "dns", probe.ReasonTimeout)); got != 1 {
		t.Errorf("probe_failures_total{target=b,reason=timeout} = %v, want 1", got)
	}
	if got := store.messages("b"); !slices.Equal(got, []string{"WARN probe failing"}) {
		t.Errorf("logs for b = %q", got)
	}
	if h.Degraded(lastRun(m, "a", "icmp")) {
		t.Error("Degraded() = true while target a is healthy")
	}
}

func TestRunStopsBeforeFirstProbeOnCancel(t *testing.T) {
	p := newScripted()
	reg := prometheus.NewPedanticRegistry()
	m := NewMetrics(reg)
	h := NewHealth()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		Run(ctx, slog.New(&recordingHandler{store: &logStore{}}), m, h, []Target{{Name: "slow", Type: "tcp", Interval: time.Hour, Timeout: time.Second, Prober: p}})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return on a cancelled context")
	}

	if got := p.callCount(); got != 0 {
		t.Errorf("prober called %d times, want 0", got)
	}
	if got := testutil.ToFloat64(m.probes.WithLabelValues("slow", "tcp")); got != 0 {
		t.Errorf("probes_total = %v, want 0", got)
	}
	if got := testutil.CollectAndCount(m.probes, "latency_probes_total"); got != 1 {
		t.Errorf("probes_total series = %d, want 1 seeded at registration", got)
	}
	if h.Degraded(time.Now()) {
		t.Error("Degraded() = true inside the startup grace")
	}
}

func TestRunWithNoTargetsReturns(t *testing.T) {
	done := make(chan struct{})
	go func() {
		Run(context.Background(), slog.New(&recordingHandler{store: &logStore{}}), NewMetrics(prometheus.NewPedanticRegistry()), NewHealth(), nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run with no targets did not return")
	}
}
