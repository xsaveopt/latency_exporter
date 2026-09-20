package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/xsaveopt/latency_exporter/internal/config"
)

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestNew(t *testing.T) {
	for _, tc := range []struct {
		name    string
		target  config.Target
		want    any
		wantErr string
	}{
		{name: "icmp", target: config.Target{Type: config.TypeICMP, Host: "192.0.2.1"}, want: &icmpProber{}},
		{name: "http", target: config.Target{Type: config.TypeHTTP, URL: "https://example.invalid/"}, want: &httpProber{}},
		{name: "dns", target: config.Target{Type: config.TypeDNS, Server: "192.0.2.53", Query: "example.invalid"}, want: &dnsProber{}},
		{name: "tcp", target: config.Target{Type: config.TypeTCP, Address: "192.0.2.1:22"}, want: &tcpProber{}},
		{name: "icmp without host", target: config.Target{Type: config.TypeICMP}, wantErr: "host is required"},
		{name: "http without url", target: config.Target{Type: config.TypeHTTP}, wantErr: "url is required"},
		{name: "dns without query", target: config.Target{Type: config.TypeDNS, Server: "192.0.2.53"}, wantErr: "query is required"},
		{name: "tcp without address", target: config.Target{Type: config.TypeTCP}, wantErr: "address is required"},
		{name: "unknown", target: config.Target{Type: "gopher"}, wantErr: `unknown probe type "gopher"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := New(&tc.target)
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("New() error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if fmt.Sprintf("%T", got) != fmt.Sprintf("%T", tc.want) {
				t.Errorf("New() = %T, want %T", got, tc.want)
			}
		})
	}
}

func TestReason(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"probe error wins", &Error{Reason: ReasonStatus, Err: errors.New("unexpected status 500")}, ReasonStatus},
		{"wrapped probe error", fmt.Errorf("read body: %w", &Error{Reason: ReasonRcode, Err: errors.New("x")}), ReasonRcode},
		{"dns error", &net.DNSError{Err: "no such host", Name: "example.invalid"}, ReasonResolve},
		{"deadline exceeded", context.DeadlineExceeded, ReasonTimeout},
		{"wrapped deadline", fmt.Errorf("dial: %w", context.DeadlineExceeded), ReasonTimeout},
		{"net timeout", timeoutError{}, ReasonTimeout},
		{"connection refused", syscall.ECONNREFUSED, ReasonRefused},
		{"connection reset", syscall.ECONNRESET, ReasonReset},
		{"broken pipe", syscall.EPIPE, ReasonReset},
		{"host unreachable", syscall.EHOSTUNREACH, ReasonUnreachable},
		{"network unreachable", syscall.ENETUNREACH, ReasonUnreachable},
		{"host down", syscall.EHOSTDOWN, ReasonUnreachable},
		{"permission denied", syscall.EACCES, ReasonPermission},
		{"operation not permitted", syscall.EPERM, ReasonPermission},
		{"unknown authority", x509.UnknownAuthorityError{}, ReasonTLS},
		{"wrapped unknown authority", fmt.Errorf("handshake: %w", x509.UnknownAuthorityError{}), ReasonTLS},
		{"anything else", errors.New("boom"), ReasonError},
		{"nil", nil, ReasonError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Reason(tc.err); got != tc.want {
				t.Errorf("Reason() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestReasonUsesSyscallInsideOpError(t *testing.T) {
	err := &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}}
	if got := Reason(err); got != ReasonRefused {
		t.Errorf("Reason() = %q, want %q", got, ReasonRefused)
	}
}

func TestIsTLSError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"record header", tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}, true},
		{"alert", tls.AlertError(80), true},
		{"certificate verification", &tls.CertificateVerificationError{}, true},
		{"unknown authority", x509.UnknownAuthorityError{}, true},
		{"hostname mismatch", x509.HostnameError{Host: "example.invalid"}, true},
		{"certificate invalid", x509.CertificateInvalidError{Reason: x509.Expired}, true},
		{"wrapped", fmt.Errorf("tcp: %w", tls.AlertError(42)), true},
		{"plain error", errors.New("boom"), false},
		{"refused", syscall.ECONNREFUSED, false},
		{"nil", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTLSError(tc.err); got != tc.want {
				t.Errorf("isTLSError() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLookupNetwork(t *testing.T) {
	for _, tc := range []struct {
		ipVersion int
		want      string
	}{
		{0, "ip"},
		{4, "ip4"},
		{6, "ip6"},
		{9, "ip"},
	} {
		if got := lookupNetwork(tc.ipVersion); got != tc.want {
			t.Errorf("lookupNetwork(%d) = %q, want %q", tc.ipVersion, got, tc.want)
		}
	}
}

func TestDialNetwork(t *testing.T) {
	for _, tc := range []struct {
		base      string
		ipVersion int
		want      string
	}{
		{"tcp", 0, "tcp"},
		{"tcp", 4, "tcp4"},
		{"tcp", 6, "tcp6"},
		{"udp", 4, "udp4"},
		{"udp", 9, "udp"},
	} {
		if got := dialNetwork(tc.base, tc.ipVersion); got != tc.want {
			t.Errorf("dialNetwork(%q, %d) = %q, want %q", tc.base, tc.ipVersion, got, tc.want)
		}
	}
}

func TestTLSConfig(t *testing.T) {
	cfg := tlsConfig("example.invalid", false)
	if cfg.ServerName != "example.invalid" {
		t.Errorf("ServerName = %q", cfg.ServerName)
	}
	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = true, want false")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %#x, want %#x", cfg.MinVersion, tls.VersionTLS12)
	}

	skip := tlsConfig("", true)
	if skip.ServerName != "" || !skip.InsecureSkipVerify {
		t.Errorf("tlsConfig(\"\", true) = %+v", skip)
	}
}

func TestCtxErr(t *testing.T) {
	inner := errors.New("read: connection reset")

	if got := ctxErr(context.Background(), inner); !errors.Is(got, inner) || Reason(got) != ReasonError {
		t.Errorf("ctxErr on live context = %v, reason %q", got, Reason(got))
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := ctxErr(ctx, inner)
	if Reason(got) != ReasonTimeout {
		t.Errorf("ctxErr on cancelled context reason = %q, want %q", Reason(got), ReasonTimeout)
	}
	if !errors.Is(got, inner) || !errors.Is(got, context.Canceled) {
		t.Errorf("ctxErr should wrap both the context error and %v, got %v", inner, got)
	}
}
