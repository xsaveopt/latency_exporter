package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	TypeICMP = "icmp"
	TypeHTTP = "http"
	TypeDNS  = "dns"
	TypeTCP  = "tcp"

	defaultInterval = 10 * time.Second
	defaultTimeout  = 5 * time.Second
)

type Config struct {
	Defaults Defaults `yaml:"defaults"`
	Targets  []Target `yaml:"targets"`
}

type Defaults struct {
	Interval time.Duration `yaml:"interval"`
	Timeout  time.Duration `yaml:"timeout"`
}

type Target struct {
	Name      string        `yaml:"name"`
	Type      string        `yaml:"type"`
	Interval  time.Duration `yaml:"interval"`
	Timeout   time.Duration `yaml:"timeout"`
	IPVersion int           `yaml:"ip_version"`

	Host        string `yaml:"host"`
	PayloadSize int    `yaml:"payload_size"`

	URL              string            `yaml:"url"`
	Method           string            `yaml:"method"`
	Headers          map[string]string `yaml:"headers"`
	Body             string            `yaml:"body"`
	ValidStatusCodes []int             `yaml:"valid_status_codes"`
	FollowRedirects  bool              `yaml:"follow_redirects"`

	Server      string   `yaml:"server"`
	Query       string   `yaml:"query"`
	RecordType  string   `yaml:"record_type"`
	Transport   string   `yaml:"transport"`
	ValidRcodes []string `yaml:"valid_rcodes"`
	Recursion   *bool    `yaml:"recursion"`

	Address       string `yaml:"address"`
	TLS           bool   `yaml:"tls"`
	TLSServerName string `yaml:"tls_server_name"`

	TLSSkipVerify bool `yaml:"tls_skip_verify"`
}

var typeFields = map[string][]string{
	TypeICMP: {"host", "payload_size"},
	TypeHTTP: {"url", "method", "headers", "body", "valid_status_codes", "follow_redirects", "tls_skip_verify"},
	TypeDNS:  {"server", "query", "record_type", "transport", "valid_rcodes", "recursion"},
	TypeTCP:  {"address", "tls", "tls_server_name", "tls_skip_verify"},
}

func (t *Target) setFields() []string {
	set := []struct {
		name string
		on   bool
	}{
		{"host", t.Host != ""},
		{"payload_size", t.PayloadSize != 0},
		{"url", t.URL != ""},
		{"method", t.Method != ""},
		{"headers", len(t.Headers) > 0},
		{"body", t.Body != ""},
		{"valid_status_codes", len(t.ValidStatusCodes) > 0},
		{"follow_redirects", t.FollowRedirects},
		{"server", t.Server != ""},
		{"query", t.Query != ""},
		{"record_type", t.RecordType != ""},
		{"transport", t.Transport != ""},
		{"valid_rcodes", len(t.ValidRcodes) > 0},
		{"recursion", t.Recursion != nil},
		{"address", t.Address != ""},
		{"tls", t.TLS},
		{"tls_server_name", t.TLSServerName != ""},
		{"tls_skip_verify", t.TLSSkipVerify},
	}
	var out []string
	for _, f := range set {
		if f.on {
			out = append(out, f.name)
		}
	}
	return out
}

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := cfg.normalize(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &cfg, nil
}

func (c *Config) normalize() error {
	if c.Defaults.Interval < 0 || c.Defaults.Timeout < 0 {
		return errors.New("defaults: interval and timeout must be positive")
	}
	if c.Defaults.Interval == 0 {
		c.Defaults.Interval = defaultInterval
	}
	if len(c.Targets) == 0 {
		return errors.New("no targets configured")
	}

	var errs []error
	seen := map[string]bool{}
	for i := range c.Targets {
		t := &c.Targets[i]
		if err := c.normalizeTarget(t); err != nil {
			label := t.Name
			if label == "" {
				label = fmt.Sprintf("#%d", i+1)
			}
			errs = append(errs, fmt.Errorf("target %s: %w", label, err))
			continue
		}
		if seen[t.Name] {
			errs = append(errs, fmt.Errorf("target %s: duplicate name", t.Name))
		}
		seen[t.Name] = true
	}
	return errors.Join(errs...)
}

func (c *Config) normalizeTarget(t *Target) error {
	t.Name = strings.TrimSpace(t.Name)
	if t.Name == "" {
		return errors.New("name is required")
	}
	t.Type = strings.ToLower(strings.TrimSpace(t.Type))
	allowed, ok := typeFields[t.Type]
	if !ok {
		return fmt.Errorf("unknown type %q (want icmp, http, dns or tcp)", t.Type)
	}
	for _, f := range t.setFields() {
		if !slices.Contains(allowed, f) {
			return fmt.Errorf("field %s does not apply to type %s", f, t.Type)
		}
	}

	if t.Interval < 0 || t.Timeout < 0 {
		return errors.New("interval and timeout must be positive")
	}
	if t.Interval == 0 {
		t.Interval = c.Defaults.Interval
	}
	if t.Timeout == 0 {
		t.Timeout = c.Defaults.Timeout
		if t.Timeout == 0 {
			t.Timeout = defaultTimeout
		}
		t.Timeout = min(t.Timeout, t.Interval)
	}
	if t.Timeout > t.Interval {
		return fmt.Errorf("timeout %s is longer than interval %s", t.Timeout, t.Interval)
	}

	switch t.IPVersion {
	case 0, 4, 6:
	default:
		return fmt.Errorf("ip_version must be 4 or 6, got %d", t.IPVersion)
	}
	return nil
}
