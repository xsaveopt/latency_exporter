package exporter

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/xsaveopt/latency_exporter/internal/probe"
)

func TestHistogramOpts(t *testing.T) {
	opts := histogramOpts("probe_duration_seconds", "Latency of successful probes.")
	if opts.Namespace != namespace {
		t.Errorf("Namespace = %q, want %q", opts.Namespace, namespace)
	}
	if opts.Name != "probe_duration_seconds" {
		t.Errorf("Name = %q", opts.Name)
	}
	if opts.Help != "Latency of successful probes." {
		t.Errorf("Help = %q", opts.Help)
	}
	if !slices.Equal(opts.Buckets, buckets) {
		t.Errorf("Buckets = %v, want %v", opts.Buckets, buckets)
	}
	if opts.NativeHistogramBucketFactor != 1.1 {
		t.Errorf("NativeHistogramBucketFactor = %v, want 1.1", opts.NativeHistogramBucketFactor)
	}
	if opts.NativeHistogramMaxBucketNumber != 160 {
		t.Errorf("NativeHistogramMaxBucketNumber = %d, want 160", opts.NativeHistogramMaxBucketNumber)
	}
	if opts.NativeHistogramMinResetDuration != time.Hour {
		t.Errorf("NativeHistogramMinResetDuration = %s, want 1h", opts.NativeHistogramMinResetDuration)
	}
	if !slices.IsSorted(buckets) {
		t.Errorf("buckets are not sorted: %v", buckets)
	}
}

func TestNewMetricsRegisters(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	NewMetrics(reg)

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	if len(families) != 0 {
		t.Errorf("a freshly registered exporter exposed %d families, want none until a probe runs", len(families))
	}

	defer func() {
		if recover() == nil {
			t.Error("NewMetrics on an already populated registry should panic")
		}
	}()
	NewMetrics(reg)
}

func TestRegisterSeedsSeries(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	m := NewMetrics(reg)
	m.register("gateway", "icmp")

	want := `
# HELP latency_probes_total Probes attempted.
# TYPE latency_probes_total counter
latency_probes_total{target="gateway",type="icmp"} 0
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "latency_probes_total"); err != nil {
		t.Error(err)
	}
	if got := testutil.CollectAndCount(m.duration, "latency_probe_duration_seconds"); got != 1 {
		t.Errorf("duration series = %d, want 1 seeded by register", got)
	}
	if got := testutil.CollectAndCount(m.success, "latency_probe_success"); got != 0 {
		t.Errorf("success series = %d, want none before the first probe", got)
	}
}

func TestObserveSuccess(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	m := NewMetrics(reg)
	finished := time.Unix(1700000000, 0)

	m.observe("site", "http", probe.Result{
		Duration:   250 * time.Millisecond,
		StatusCode: 200,
		Phases: []probe.Phase{
			{Name: "connect", Duration: 10 * time.Millisecond},
			{Name: "tls", Duration: 40 * time.Millisecond},
		},
	}, finished)

	if got := testutil.ToFloat64(m.probes.WithLabelValues("site", "http")); got != 1 {
		t.Errorf("probes_total = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.success.WithLabelValues("site", "http")); got != 1 {
		t.Errorf("probe_success = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.lastDuration.WithLabelValues("site", "http")); got != 0.25 {
		t.Errorf("probe_last_duration_seconds = %v, want 0.25", got)
	}
	if got := testutil.ToFloat64(m.lastRun.WithLabelValues("site", "http")); got != float64(finished.UnixNano())/1e9 {
		t.Errorf("probe_last_run_timestamp_seconds = %v", got)
	}
	if got := testutil.ToFloat64(m.httpStatus.WithLabelValues("site")); got != 200 {
		t.Errorf("http_status_code = %v, want 200", got)
	}
	if got := testutil.CollectAndCount(m.failures, "latency_probe_failures_total"); got != 0 {
		t.Errorf("failures series = %d, want none", got)
	}
	if got := testutil.CollectAndCount(m.phase, "latency_probe_phase_duration_seconds"); got != 2 {
		t.Errorf("phase series = %d, want one per phase", got)
	}

	want := `
# HELP latency_probe_phase_duration_seconds Duration of individual phases of successful HTTP and TCP probes.
# TYPE latency_probe_phase_duration_seconds histogram
latency_probe_phase_duration_seconds_bucket{phase="connect",target="site",type="http",le="0.0005"} 0
latency_probe_phase_duration_seconds_bucket{phase="connect",target="site",type="http",le="0.001"} 0
latency_probe_phase_duration_seconds_bucket{phase="connect",target="site",type="http",le="0.0025"} 0
latency_probe_phase_duration_seconds_bucket{phase="connect",target="site",type="http",le="0.005"} 0
latency_probe_phase_duration_seconds_bucket{phase="connect",target="site",type="http",le="0.01"} 1
latency_probe_phase_duration_seconds_bucket{phase="connect",target="site",type="http",le="0.025"} 1
latency_probe_phase_duration_seconds_bucket{phase="connect",target="site",type="http",le="0.05"} 1
latency_probe_phase_duration_seconds_bucket{phase="connect",target="site",type="http",le="0.1"} 1
latency_probe_phase_duration_seconds_bucket{phase="connect",target="site",type="http",le="0.25"} 1
latency_probe_phase_duration_seconds_bucket{phase="connect",target="site",type="http",le="0.5"} 1
latency_probe_phase_duration_seconds_bucket{phase="connect",target="site",type="http",le="1"} 1
latency_probe_phase_duration_seconds_bucket{phase="connect",target="site",type="http",le="2.5"} 1
latency_probe_phase_duration_seconds_bucket{phase="connect",target="site",type="http",le="5"} 1
latency_probe_phase_duration_seconds_bucket{phase="connect",target="site",type="http",le="10"} 1
latency_probe_phase_duration_seconds_bucket{phase="connect",target="site",type="http",le="+Inf"} 1
latency_probe_phase_duration_seconds_sum{phase="connect",target="site",type="http"} 0.01
latency_probe_phase_duration_seconds_count{phase="connect",target="site",type="http"} 1
latency_probe_phase_duration_seconds_bucket{phase="tls",target="site",type="http",le="0.0005"} 0
latency_probe_phase_duration_seconds_bucket{phase="tls",target="site",type="http",le="0.001"} 0
latency_probe_phase_duration_seconds_bucket{phase="tls",target="site",type="http",le="0.0025"} 0
latency_probe_phase_duration_seconds_bucket{phase="tls",target="site",type="http",le="0.005"} 0
latency_probe_phase_duration_seconds_bucket{phase="tls",target="site",type="http",le="0.01"} 0
latency_probe_phase_duration_seconds_bucket{phase="tls",target="site",type="http",le="0.025"} 0
latency_probe_phase_duration_seconds_bucket{phase="tls",target="site",type="http",le="0.05"} 1
latency_probe_phase_duration_seconds_bucket{phase="tls",target="site",type="http",le="0.1"} 1
latency_probe_phase_duration_seconds_bucket{phase="tls",target="site",type="http",le="0.25"} 1
latency_probe_phase_duration_seconds_bucket{phase="tls",target="site",type="http",le="0.5"} 1
latency_probe_phase_duration_seconds_bucket{phase="tls",target="site",type="http",le="1"} 1
latency_probe_phase_duration_seconds_bucket{phase="tls",target="site",type="http",le="2.5"} 1
latency_probe_phase_duration_seconds_bucket{phase="tls",target="site",type="http",le="5"} 1
latency_probe_phase_duration_seconds_bucket{phase="tls",target="site",type="http",le="10"} 1
latency_probe_phase_duration_seconds_bucket{phase="tls",target="site",type="http",le="+Inf"} 1
latency_probe_phase_duration_seconds_sum{phase="tls",target="site",type="http"} 0.04
latency_probe_phase_duration_seconds_count{phase="tls",target="site",type="http"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "latency_probe_phase_duration_seconds"); err != nil {
		t.Error(err)
	}
}

func TestObserveFailure(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	m := NewMetrics(reg)

	m.observe("broker", "tcp", probe.Result{
		Duration: 5 * time.Second,
		Phases:   []probe.Phase{{Name: "connect", Duration: time.Second}},
		Err:      &probe.Error{Reason: probe.ReasonRefused, Err: errors.New("connection refused")},
	}, time.Unix(1700000000, 0))

	if got := testutil.ToFloat64(m.probes.WithLabelValues("broker", "tcp")); got != 1 {
		t.Errorf("probes_total = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.success.WithLabelValues("broker", "tcp")); got != 0 {
		t.Errorf("probe_success = %v, want 0", got)
	}
	if got := testutil.ToFloat64(m.failures.WithLabelValues("broker", "tcp", probe.ReasonRefused)); got != 1 {
		t.Errorf("probe_failures_total = %v, want 1", got)
	}
	if got := testutil.CollectAndCount(m.lastDuration, "latency_probe_last_duration_seconds"); got != 0 {
		t.Errorf("last duration series = %d, want none for a failed probe", got)
	}
	if got := testutil.CollectAndCount(m.phase, "latency_probe_phase_duration_seconds"); got != 0 {
		t.Errorf("phase series = %d, want none for a failed probe", got)
	}
	if got := testutil.CollectAndCount(m.httpStatus, "latency_http_status_code"); got != 0 {
		t.Errorf("http_status_code series = %d, want none without a status", got)
	}

	want := `
# HELP latency_probe_success Whether the most recent probe succeeded (1) or failed (0).
# TYPE latency_probe_success gauge
latency_probe_success{target="broker",type="tcp"} 0
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "latency_probe_success"); err != nil {
		t.Error(err)
	}
}

func TestObserveRecovery(t *testing.T) {
	m := NewMetrics(prometheus.NewPedanticRegistry())
	finished := time.Unix(1700000000, 0)

	m.observe("site", "http", probe.Result{StatusCode: 500, Err: &probe.Error{Reason: probe.ReasonStatus, Err: errors.New("unexpected status 500")}}, finished)
	m.observe("site", "http", probe.Result{StatusCode: 200, Duration: time.Second}, finished.Add(time.Second))

	if got := testutil.ToFloat64(m.probes.WithLabelValues("site", "http")); got != 2 {
		t.Errorf("probes_total = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.success.WithLabelValues("site", "http")); got != 1 {
		t.Errorf("probe_success = %v, want 1 after recovery", got)
	}
	if got := testutil.ToFloat64(m.failures.WithLabelValues("site", "http", probe.ReasonStatus)); got != 1 {
		t.Errorf("probe_failures_total = %v, want the earlier failure kept", got)
	}
	if got := testutil.ToFloat64(m.httpStatus.WithLabelValues("site")); got != 200 {
		t.Errorf("http_status_code = %v, want the latest status", got)
	}
	if got := testutil.ToFloat64(m.lastRun.WithLabelValues("site", "http")); got != float64(finished.Add(time.Second).UnixNano())/1e9 {
		t.Errorf("probe_last_run_timestamp_seconds = %v, want the latest run", got)
	}
}
