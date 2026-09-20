package config

import (
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func load(t *testing.T, name string) *Config {
	t.Helper()
	cfg, err := Load(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("Load(%s): %v", name, err)
	}
	return cfg
}

func TestLoadValid(t *testing.T) {
	cfg := load(t, "valid.yml")

	if cfg.Defaults.Interval != 30*time.Second || cfg.Defaults.Timeout != 3*time.Second {
		t.Fatalf("defaults = %+v", cfg.Defaults)
	}
	if len(cfg.Targets) != 4 {
		t.Fatalf("got %d targets, want 4", len(cfg.Targets))
	}

	gateway := cfg.Targets[0]
	if gateway.Name != "gateway" {
		t.Errorf("name = %q, want trimmed %q", gateway.Name, "gateway")
	}
	if gateway.Type != TypeICMP {
		t.Errorf("type = %q, want %q", gateway.Type, TypeICMP)
	}
	if gateway.PayloadSize != 64 {
		t.Errorf("payload_size = %d, want 64", gateway.PayloadSize)
	}
	if gateway.Interval != 30*time.Second || gateway.Timeout != 3*time.Second {
		t.Errorf("gateway interval/timeout = %s/%s, want 30s/3s", gateway.Interval, gateway.Timeout)
	}

	site := cfg.Targets[1]
	if site.URL != "https://example.invalid/" || site.Method != "post" || site.Body != `{"ping":true}` {
		t.Errorf("http fields = %+v", site)
	}
	if got := site.Headers["Content-Type"]; got != "application/json" {
		t.Errorf("headers[Content-Type] = %q", got)
	}
	if !slices.Equal(site.ValidStatusCodes, []int{200, 204}) {
		t.Errorf("valid_status_codes = %v", site.ValidStatusCodes)
	}
	if !site.FollowRedirects {
		t.Error("follow_redirects = false, want true")
	}

	resolver := cfg.Targets[2]
	if resolver.Server != "192.0.2.53" || resolver.Query != "example.invalid" {
		t.Errorf("dns fields = %+v", resolver)
	}
	if resolver.RecordType != "AAAA" || resolver.Transport != "tcp" {
		t.Errorf("record_type/transport = %q/%q", resolver.RecordType, resolver.Transport)
	}
	if !slices.Equal(resolver.ValidRcodes, []string{"NOERROR", "NXDOMAIN"}) {
		t.Errorf("valid_rcodes = %v", resolver.ValidRcodes)
	}
	if resolver.Recursion == nil || *resolver.Recursion {
		t.Errorf("recursion = %v, want pointer to false", resolver.Recursion)
	}
	if resolver.Interval != time.Minute || resolver.Timeout != 3*time.Second {
		t.Errorf("resolver interval/timeout = %s/%s, want 1m0s/3s", resolver.Interval, resolver.Timeout)
	}

	broker := cfg.Targets[3]
	if broker.Address != "192.0.2.10:8883" || !broker.TLS || !broker.TLSSkipVerify {
		t.Errorf("tcp fields = %+v", broker)
	}
	if broker.TLSServerName != "broker.example.invalid" {
		t.Errorf("tls_server_name = %q", broker.TLSServerName)
	}
	if broker.IPVersion != 6 {
		t.Errorf("ip_version = %d, want 6", broker.IPVersion)
	}
	if broker.Interval != 30*time.Second || broker.Timeout != time.Second {
		t.Errorf("broker interval/timeout = %s/%s, want 30s/1s", broker.Interval, broker.Timeout)
	}
}

func TestLoadAppliesBuiltinDefaults(t *testing.T) {
	cfg := load(t, "defaults-omitted.yml")
	if cfg.Defaults.Interval != defaultInterval {
		t.Errorf("defaults.interval = %s, want %s", cfg.Defaults.Interval, defaultInterval)
	}
	got := cfg.Targets[0]
	if got.Interval != defaultInterval {
		t.Errorf("interval = %s, want %s", got.Interval, defaultInterval)
	}
	if got.Timeout != defaultTimeout {
		t.Errorf("timeout = %s, want %s", got.Timeout, defaultTimeout)
	}
}

func TestLoadClampsTimeoutToInterval(t *testing.T) {
	cfg := load(t, "timeout-clamped.yml")
	if got := cfg.Targets[0].Timeout; got != 2*time.Second {
		t.Errorf("timeout = %s, want 2s (clamped to interval)", got)
	}
}

func TestLoadExample(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "config.example.yml"))
	if err != nil {
		t.Fatalf("config.example.yml: %v", err)
	}
	if len(cfg.Targets) == 0 {
		t.Fatal("config.example.yml has no targets")
	}
	for _, target := range cfg.Targets {
		if target.Interval <= 0 || target.Timeout <= 0 || target.Timeout > target.Interval {
			t.Errorf("target %s: interval %s timeout %s", target.Name, target.Interval, target.Timeout)
		}
	}
}

func TestLoadErrors(t *testing.T) {
	for _, tc := range []struct {
		file string
		want string
	}{
		{"missing.yml", "no such file"},
		{"malformed.yml", "parse "},
		{"unknown-field.yml", "field payload_sizes not found"},
		{"no-targets.yml", "no targets configured"},
		{"unknown-type.yml", `unknown type "gopher"`},
		{"wrong-field.yml", "field url does not apply to type icmp"},
		{"duplicate-name.yml", "duplicate name"},
		{"missing-name.yml", "target #1: name is required"},
		{"bad-ip-version.yml", "ip_version must be 4 or 6, got 5"},
		{"timeout-over-interval.yml", "timeout 5s is longer than interval 1s"},
		{"negative-defaults.yml", "defaults: interval and timeout must be positive"},
		{"negative-target.yml", "interval and timeout must be positive"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			_, err := Load(filepath.Join("testdata", tc.file))
			if err == nil {
				t.Fatal("got nil error, want failure")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestNormalizeReportsEveryBadTarget(t *testing.T) {
	cfg := &Config{Targets: []Target{
		{Name: "a", Type: "nope"},
		{Name: "b", Type: TypeICMP, Host: "192.0.2.1", IPVersion: 9},
	}}
	err := cfg.normalize()
	if err == nil {
		t.Fatal("got nil error, want failure")
	}
	for _, want := range []string{"target a:", "target b:"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to contain %q", err, want)
		}
	}
}

func TestNormalizeTargetLowercasesType(t *testing.T) {
	cfg := &Config{Defaults: Defaults{Interval: time.Second, Timeout: time.Second}}
	target := &Target{Name: "x", Type: "  HTTP  ", URL: "https://example.invalid/"}
	if err := cfg.normalizeTarget(target); err != nil {
		t.Fatalf("normalizeTarget: %v", err)
	}
	if target.Type != TypeHTTP {
		t.Errorf("type = %q, want %q", target.Type, TypeHTTP)
	}
}

func TestSetFields(t *testing.T) {
	recursion := false
	for _, tc := range []struct {
		name   string
		target Target
		want   []string
	}{
		{"empty", Target{Name: "x", Type: TypeICMP}, nil},
		{"icmp", Target{Host: "h", PayloadSize: 64}, []string{"host", "payload_size"}},
		{
			"http",
			Target{URL: "u", Method: "GET", Headers: map[string]string{"A": "b"}, Body: "x", ValidStatusCodes: []int{200}, FollowRedirects: true, TLSSkipVerify: true},
			[]string{"url", "method", "headers", "body", "valid_status_codes", "follow_redirects", "tls_skip_verify"},
		},
		{
			"dns",
			Target{Server: "s", Query: "q", RecordType: "A", Transport: "udp", ValidRcodes: []string{"NOERROR"}, Recursion: &recursion},
			[]string{"server", "query", "record_type", "transport", "valid_rcodes", "recursion"},
		},
		{"tcp", Target{Address: "a:1", TLS: true, TLSServerName: "n"}, []string{"address", "tls", "tls_server_name"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.target.setFields(); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("setFields() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSetFieldsCoversEveryTypeField(t *testing.T) {
	full := Target{
		Host: "h", PayloadSize: 1,
		URL: "u", Method: "GET", Headers: map[string]string{"A": "b"}, Body: "x",
		ValidStatusCodes: []int{200}, FollowRedirects: true,
		Server: "s", Query: "q", RecordType: "A", Transport: "udp",
		ValidRcodes: []string{"NOERROR"}, Recursion: new(bool),
		Address: "a:1", TLS: true, TLSServerName: "n", TLSSkipVerify: true,
	}
	set := full.setFields()
	for typ, fields := range typeFields {
		for _, f := range fields {
			if !slices.Contains(set, f) {
				t.Errorf("type %s field %s is never reported by setFields", typ, f)
			}
		}
	}
}
