package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xsaveopt/latency_exporter/internal/config"
)

func newTCPProber(t *testing.T, target config.Target) *tcpProber {
	t.Helper()
	target.Type = config.TypeTCP
	p, err := newTCP(&target)
	if err != nil {
		t.Fatalf("newTCP: %v", err)
	}
	return p
}

func TestNewTCPErrors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		target  config.Target
		wantErr string
	}{
		{"no address", config.Target{}, "address is required"},
		{"no port", config.Target{Address: "192.0.2.1"}, "address must be host:port"},
		{"empty host", config.Target{Address: ":22"}, "address must be host:port"},
		{"empty port", config.Target{Address: "192.0.2.1:"}, "address must be host:port"},
		{"server name without tls", config.Target{Address: "192.0.2.1:22", TLSServerName: "x"}, "need tls: true"},
		{"skip verify without tls", config.Target{Address: "192.0.2.1:22", TLSSkipVerify: true}, "need tls: true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newTCP(&tc.target)
			if err == nil {
				t.Fatal("got nil error, want failure")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestNewTCPTLSServerName(t *testing.T) {
	plain := newTCPProber(t, config.Target{Address: "mail.example.invalid:993"})
	if plain.tls != nil {
		t.Error("tls config should be nil when tls is off")
	}
	if plain.host != "mail.example.invalid" || plain.port != "993" {
		t.Errorf("host/port = %q/%q", plain.host, plain.port)
	}

	byName := newTCPProber(t, config.Target{Address: "mail.example.invalid:993", TLS: true})
	if byName.tls == nil || byName.tls.ServerName != "mail.example.invalid" {
		t.Errorf("ServerName = %+v, want it taken from the host", byName.tls)
	}

	byIP := newTCPProber(t, config.Target{Address: "192.0.2.1:993", TLS: true})
	if byIP.tls == nil || byIP.tls.ServerName != "" {
		t.Errorf("ServerName = %+v, want it left empty for a literal address", byIP.tls)
	}

	override := newTCPProber(t, config.Target{Address: "192.0.2.1:993", TLS: true, TLSServerName: "mail.example.invalid", TLSSkipVerify: true})
	if override.tls.ServerName != "mail.example.invalid" || !override.tls.InsecureSkipVerify {
		t.Errorf("tls config = %+v", override.tls)
	}
}

func TestTCPProbe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	res := newTCPProber(t, config.Target{Address: net.JoinHostPort(host, port)}).Probe(context.Background())
	if res.Err != nil {
		t.Fatalf("Probe() error = %v", res.Err)
	}
	if res.Duration <= 0 {
		t.Error("Duration should be positive")
	}
	if names := phaseNames(res.Phases); len(names) != 2 || names[0] != "resolve" || names[1] != "connect" {
		t.Errorf("phases = %v, want resolve then connect", names)
	}
	if res.StatusCode != 0 {
		t.Errorf("StatusCode = %d, want 0 for a tcp probe", res.StatusCode)
	}
}

func TestTCPProbeRefused(t *testing.T) {
	res := newTCPProber(t, config.Target{Address: closedAddr(t)}).Probe(context.Background())
	if Reason(res.Err) != ReasonRefused {
		t.Errorf("reason = %q, want %q", Reason(res.Err), ReasonRefused)
	}
}

func TestTCPProbeResolveFailure(t *testing.T) {
	res := newTCPProber(t, config.Target{Address: "192.0.2.1:22", IPVersion: 6}).Probe(context.Background())
	if Reason(res.Err) != ReasonResolve {
		t.Errorf("reason = %q, want %q", Reason(res.Err), ReasonResolve)
	}
}

func TestTCPProbeTLS(t *testing.T) {
	srv := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	addr := strings.TrimPrefix(srv.URL, "https://")

	res := newTCPProber(t, config.Target{Address: addr, TLS: true, TLSSkipVerify: true}).Probe(context.Background())
	if res.Err != nil {
		t.Fatalf("Probe() error = %v", res.Err)
	}
	if !hasPhase(res.Phases, "tls") {
		t.Errorf("phases = %v, want a tls phase", phaseNames(res.Phases))
	}

	strict := newTCPProber(t, config.Target{Address: addr, TLS: true})
	if got := strict.Probe(context.Background()); Reason(got.Err) != ReasonTLS {
		t.Errorf("reason = %q, want %q", Reason(got.Err), ReasonTLS)
	}
}

func TestTCPProbeTLSAgainstPlainListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte("220 plain service ready\r\n"))
		time.Sleep(50 * time.Millisecond)
		_ = conn.Close()
	}()

	res := newTCPProber(t, config.Target{Address: ln.Addr().String(), TLS: true, TLSSkipVerify: true}).Probe(context.Background())
	if Reason(res.Err) != ReasonTLS {
		t.Errorf("reason = %q, want %q", Reason(res.Err), ReasonTLS)
	}
	var recordErr tls.RecordHeaderError
	if !errors.As(res.Err, &recordErr) {
		t.Errorf("error = %v, want a tls.RecordHeaderError", res.Err)
	}
}

func TestTCPProbeCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := newTCPProber(t, config.Target{Address: closedAddr(t)}).Probe(ctx)
	if Reason(res.Err) != ReasonTimeout {
		t.Errorf("reason = %q, want %q", Reason(res.Err), ReasonTimeout)
	}
}

func TestTCPProbeResolveTimeout(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	res := newTCPProber(t, config.Target{Address: "latency-exporter.invalid:22"}).Probe(ctx)
	if got := Reason(res.Err); got != ReasonTimeout {
		t.Errorf("reason = %q (%v), want %q when the deadline passes while resolving", got, res.Err, ReasonTimeout)
	}
}

func TestTCPProbeTLSHandshakeHangTimesOut(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		<-release
		_ = conn.Close()
	}()
	t.Cleanup(func() {
		close(release)
		_ = ln.Close()
		<-done
	})

	res := probeWithin(newTCPProber(t, config.Target{Address: ln.Addr().String(), TLS: true, TLSSkipVerify: true}), 100*time.Millisecond)
	if got := Reason(res.Err); got != ReasonTimeout {
		t.Errorf("reason = %q (%v), want %q for a server that never answers the handshake", got, res.Err, ReasonTimeout)
	}
	if res.Duration != 0 {
		t.Errorf("Duration = %s, want 0 when the handshake never finished", res.Duration)
	}
}

func sniTestServer(t *testing.T) (string, <-chan string) {
	t.Helper()
	names := make(chan string, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			select {
			case names <- hello.ServerName:
			default:
			}
			return nil, nil
		},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String(), names
}

func TestTCPProbeTLSSendsServerName(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target func(port string) config.Target
		want   string
	}{
		{
			name: "explicit tls_server_name",
			target: func(port string) config.Target {
				return config.Target{Address: net.JoinHostPort("127.0.0.1", port), TLS: true, TLSSkipVerify: true, TLSServerName: "probe.example.invalid"}
			},
			want: "probe.example.invalid",
		},
		{
			name: "hostname from the address",
			target: func(port string) config.Target {
				return config.Target{Address: net.JoinHostPort("localhost", port), TLS: true, TLSSkipVerify: true, IPVersion: 4}
			},
			want: "localhost",
		},
		{
			name: "no sni for an ip literal",
			target: func(port string) config.Target {
				return config.Target{Address: net.JoinHostPort("127.0.0.1", port), TLS: true, TLSSkipVerify: true}
			},
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, names := sniTestServer(t)
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				t.Fatal(err)
			}
			res := probeWithin(newTCPProber(t, tc.target(port)), 5*time.Second)
			if res.Err != nil {
				t.Fatalf("Probe() error = %v", res.Err)
			}
			select {
			case got := <-names:
				if got != tc.want {
					t.Errorf("server saw SNI %q, want %q", got, tc.want)
				}
			default:
				t.Fatal("server never saw a ClientHello")
			}
		})
	}
}
