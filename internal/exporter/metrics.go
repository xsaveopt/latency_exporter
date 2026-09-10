package exporter

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/xsaveopt/latency_exporter/internal/probe"
)

const namespace = "latency"

var buckets = []float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

type Metrics struct {
	duration     *prometheus.HistogramVec
	phase        *prometheus.HistogramVec
	probes       *prometheus.CounterVec
	failures     *prometheus.CounterVec
	success      *prometheus.GaugeVec
	lastDuration *prometheus.GaugeVec
	lastRun      *prometheus.GaugeVec
	httpStatus   *prometheus.GaugeVec
}

func histogramOpts(name, help string) prometheus.HistogramOpts {
	return prometheus.HistogramOpts{
		Namespace:                       namespace,
		Name:                            name,
		Help:                            help,
		Buckets:                         buckets,
		NativeHistogramBucketFactor:     1.1,
		NativeHistogramMaxBucketNumber:  160,
		NativeHistogramMinResetDuration: time.Hour,
	}
}

func NewMetrics(reg prometheus.Registerer) *Metrics {
	target := []string{"target", "type"}
	m := &Metrics{
		duration: prometheus.NewHistogramVec(
			histogramOpts("probe_duration_seconds", "Latency of successful probes: ICMP round trip, DNS query round trip, TCP connect plus TLS handshake, or the full HTTP request."),
			target),
		phase: prometheus.NewHistogramVec(
			histogramOpts("probe_phase_duration_seconds", "Duration of individual phases of successful HTTP and TCP probes."),
			[]string{"target", "type", "phase"}),
		probes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "probes_total", Help: "Probes attempted.",
		}, target),
		failures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "probe_failures_total", Help: "Probes that failed, by reason.",
		}, []string{"target", "type", "reason"}),
		success: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Name: "probe_success", Help: "Whether the most recent probe succeeded (1) or failed (0).",
		}, target),
		lastDuration: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Name: "probe_last_duration_seconds", Help: "Latency of the most recent successful probe.",
		}, target),
		lastRun: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Name: "probe_last_run_timestamp_seconds", Help: "Unix time the most recent probe finished.",
		}, target),
		httpStatus: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Name: "http_status_code", Help: "Status code of the most recent HTTP response.",
		}, []string{"target"}),
	}
	reg.MustRegister(m.duration, m.phase, m.probes, m.failures, m.success, m.lastDuration, m.lastRun, m.httpStatus)
	return m
}

func (m *Metrics) register(name, typ string) {
	m.probes.WithLabelValues(name, typ)
	m.duration.WithLabelValues(name, typ)
}

func (m *Metrics) observe(name, typ string, r probe.Result, finished time.Time) {
	m.probes.WithLabelValues(name, typ).Inc()
	m.lastRun.WithLabelValues(name, typ).Set(float64(finished.UnixNano()) / 1e9)
	if r.StatusCode != 0 {
		m.httpStatus.WithLabelValues(name).Set(float64(r.StatusCode))
	}
	if r.Err != nil {
		m.failures.WithLabelValues(name, typ, probe.Reason(r.Err)).Inc()
		m.success.WithLabelValues(name, typ).Set(0)
		return
	}
	m.success.WithLabelValues(name, typ).Set(1)
	m.lastDuration.WithLabelValues(name, typ).Set(r.Duration.Seconds())
	m.duration.WithLabelValues(name, typ).Observe(r.Duration.Seconds())
	for _, p := range r.Phases {
		m.phase.WithLabelValues(name, typ, p.Name).Observe(p.Duration.Seconds())
	}
}
