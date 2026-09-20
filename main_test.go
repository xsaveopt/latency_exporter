package main

import (
	"testing"

	"github.com/xsaveopt/latency_exporter/internal/config"
	"github.com/xsaveopt/latency_exporter/internal/exporter"
)

func TestSummarize(t *testing.T) {
	for _, tc := range []struct {
		name    string
		targets []exporter.Target
		want    string
	}{
		{name: "none", want: ""},
		{
			name:    "one of each in a fixed order",
			targets: []exporter.Target{{Type: config.TypeTCP}, {Type: config.TypeDNS}, {Type: config.TypeHTTP}, {Type: config.TypeICMP}},
			want:    "icmp=1 http=1 dns=1 tcp=1",
		},
		{
			name:    "counts add up",
			targets: []exporter.Target{{Type: config.TypeHTTP}, {Type: config.TypeHTTP}, {Type: config.TypeHTTP}},
			want:    "http=3",
		},
		{
			name:    "gaps are skipped",
			targets: []exporter.Target{{Type: config.TypeICMP}, {Type: config.TypeTCP}, {Type: config.TypeTCP}},
			want:    "icmp=1 tcp=2",
		},
		{
			name:    "unknown types are ignored",
			targets: []exporter.Target{{Type: "gopher"}, {Type: config.TypeDNS}},
			want:    "dns=1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := summarize(tc.targets); got != tc.want {
				t.Errorf("summarize() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEnv(t *testing.T) {
	const key = "LATENCY_EXPORTER_TEST_KEY"

	if got := env(key, "fallback"); got != "fallback" {
		t.Errorf("env() with the variable unset = %q, want %q", got, "fallback")
	}

	t.Setenv(key, "")
	if got := env(key, "fallback"); got != "fallback" {
		t.Errorf("env() with an empty variable = %q, want %q", got, "fallback")
	}

	t.Setenv(key, "/var/lib/latency.yml")
	if got := env(key, "fallback"); got != "/var/lib/latency.yml" {
		t.Errorf("env() = %q, want the variable", got)
	}
}
