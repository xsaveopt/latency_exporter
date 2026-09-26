package probe

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/xsaveopt/latency_exporter/internal/config"
)

func TestNewICMP(t *testing.T) {
	p, err := newICMP(&config.Target{Host: "192.0.2.1", IPVersion: 4})
	if err != nil {
		t.Fatalf("newICMP: %v", err)
	}
	if p.host != "192.0.2.1" || p.ipVersion != 4 {
		t.Errorf("host/ipVersion = %q/%d", p.host, p.ipVersion)
	}
	if p.payloadSize != defaultPayloadSize {
		t.Errorf("payloadSize = %d, want the default %d", p.payloadSize, defaultPayloadSize)
	}
	if p.id != os.Getpid()&0xffff {
		t.Errorf("id = %d, want the pid masked to 16 bits", p.id)
	}
	if p.seq != 0 {
		t.Errorf("seq = %d, want 0 before the first probe", p.seq)
	}
}

func TestNewICMPPayloadSize(t *testing.T) {
	for _, tc := range []struct {
		name    string
		size    int
		want    int
		wantErr bool
	}{
		{name: "zero uses the default", size: 0, want: defaultPayloadSize},
		{name: "smallest that fits the token", size: tokenSize, want: tokenSize},
		{name: "largest allowed", size: maxPayloadSize, want: maxPayloadSize},
		{name: "custom", size: 1024, want: 1024},
		{name: "too small for the token", size: tokenSize - 1, wantErr: true},
		{name: "negative", size: -1, wantErr: true},
		{name: "too large", size: maxPayloadSize + 1, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := newICMP(&config.Target{Host: "192.0.2.1", PayloadSize: tc.size})
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "payload_size must be between 16 and 65000") {
					t.Fatalf("newICMP() error = %v, want a payload_size range error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("newICMP: %v", err)
			}
			if p.payloadSize != tc.want {
				t.Errorf("payloadSize = %d, want %d", p.payloadSize, tc.want)
			}
		})
	}
}

func TestNewICMPRequiresHost(t *testing.T) {
	if _, err := newICMP(&config.Target{PayloadSize: 64}); err == nil || err.Error() != "host is required" {
		t.Errorf("newICMP() error = %v, want %q", err, "host is required")
	}
}

func TestICMPProbeAddressFamilyMismatch(t *testing.T) {
	for _, tc := range []struct {
		name      string
		host      string
		ipVersion int
	}{
		{"ipv4 literal pinned to v6", "192.0.2.1", 6},
		{"ipv6 literal pinned to v4", "2001:db8::1", 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := newICMP(&config.Target{Host: tc.host, IPVersion: tc.ipVersion})
			if err != nil {
				t.Fatalf("newICMP: %v", err)
			}
			r := p.Probe(context.Background())
			if r.Err == nil {
				t.Fatal("Probe() succeeded, want a resolve failure")
			}
			if got := Reason(r.Err); got != ReasonResolve {
				t.Errorf("Reason() = %q, want %q", got, ReasonResolve)
			}
			if r.Duration != 0 {
				t.Errorf("Duration = %s, want 0 on failure", r.Duration)
			}
			if p.seq != 0 {
				t.Errorf("seq = %d, want 0 when nothing was sent", p.seq)
			}
		})
	}
}

func TestICMPProbeResolveCancelled(t *testing.T) {
	p, err := newICMP(&config.Target{Host: "latency-exporter.invalid"})
	if err != nil {
		t.Fatalf("newICMP: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := p.Probe(ctx)
	if r.Err == nil {
		t.Fatal("Probe() with a cancelled context succeeded")
	}
	if p.seq != 0 {
		t.Errorf("seq = %d, want 0 when resolving failed", p.seq)
	}
}

func requirePingSocket(t *testing.T) {
	t.Helper()
	conn, err := icmp.ListenPacket("udp4", "127.0.0.1")
	if err != nil {
		t.Skipf("unprivileged ICMP sockets are not available here: %v", err)
	}
	_ = conn.Close()
}

func TestICMPProbeLoopback(t *testing.T) {
	requirePingSocket(t)
	p, err := newICMP(&config.Target{Host: "127.0.0.1", PayloadSize: 64})
	if err != nil {
		t.Fatalf("newICMP: %v", err)
	}
	for i := 1; i <= 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		r := p.Probe(ctx)
		cancel()
		if r.Err != nil {
			t.Fatalf("probe %d: %v", i, r.Err)
		}
		if r.Duration <= 0 {
			t.Errorf("probe %d: Duration = %s, want a positive round trip", i, r.Duration)
		}
		if int(p.seq) != i {
			t.Errorf("probe %d: seq = %d, want %d", i, p.seq, i)
		}
	}
}

func TestICMPProbeLoopbackIPv6(t *testing.T) {
	conn, err := icmp.ListenPacket("udp6", "::1")
	if err != nil {
		t.Skipf("unprivileged ICMPv6 sockets are not available here: %v", err)
	}
	_ = conn.Close()

	p, err := newICMP(&config.Target{Host: "::1"})
	if err != nil {
		t.Fatalf("newICMP: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r := p.Probe(ctx)
	if r.Err != nil {
		t.Fatalf("Probe(::1): %v", r.Err)
	}
	if r.Duration <= 0 {
		t.Errorf("Duration = %s, want a positive round trip", r.Duration)
	}
}

func TestICMPProbePermissionHint(t *testing.T) {
	if conn, err := icmp.ListenPacket("udp4", "0.0.0.0"); err == nil {
		_ = conn.Close()
		t.Skip("unprivileged ICMP sockets are allowed here, run with a gid outside net.ipv4.ping_group_range to cover this")
	}
	p, err := newICMP(&config.Target{Host: "127.0.0.1"})
	if err != nil {
		t.Fatalf("newICMP: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r := p.Probe(ctx)
	if got := Reason(r.Err); got != ReasonPermission {
		t.Fatalf("Reason() = %q (%v), want %q", got, r.Err, ReasonPermission)
	}
	if !strings.Contains(r.Err.Error(), "net.ipv4.ping_group_range") {
		t.Errorf("error = %q, want the ping_group_range hint", r.Err)
	}
	if !errors.Is(r.Err, syscall.EACCES) && !errors.Is(r.Err, syscall.EPERM) {
		t.Errorf("error = %v, want the underlying permission error kept", r.Err)
	}
	if p.seq != 0 {
		t.Errorf("seq = %d, want 0 when no socket could be opened", p.seq)
	}
}

func rawEchoListener(t *testing.T) *icmp.PacketConn {
	t.Helper()
	b, err := os.ReadFile("/proc/sys/net/ipv4/icmp_echo_ignore_all")
	if err != nil || strings.TrimSpace(string(b)) != "1" {
		t.Skip("needs net.ipv4.icmp_echo_ignore_all=1 so the kernel does not answer loopback pings itself")
	}
	requirePingSocket(t)
	raw, err := icmp.ListenPacket("ip4:icmp", "127.0.0.1")
	if err != nil {
		t.Skipf("raw ICMP sockets are not available here: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	return raw
}

func readEchoRequest(t *testing.T, raw *icmp.PacketConn) *icmp.Echo {
	t.Helper()
	buf := make([]byte, 1500)
	_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		n, _, err := raw.ReadFrom(buf)
		if err != nil {
			t.Fatalf("waiting for the echo request: %v", err)
		}
		m, err := icmp.ParseMessage(1, buf[:n])
		if err != nil || m.Type != ipv4.ICMPTypeEcho {
			continue
		}
		if echo, ok := m.Body.(*icmp.Echo); ok {
			return echo
		}
	}
}

func sendEchoReply(t *testing.T, raw *icmp.PacketConn, id, seq int, data []byte) {
	t.Helper()
	wire, err := (&icmp.Message{Type: ipv4.ICMPTypeEchoReply, Body: &icmp.Echo{ID: id, Seq: seq, Data: data}}).Marshal(nil)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := raw.WriteTo(wire, &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}); err != nil {
		t.Fatalf("send reply: %v", err)
	}
}

func TestICMPProbeIgnoresUnmatchedReplies(t *testing.T) {
	raw := rawEchoListener(t)
	p, err := newICMP(&config.Target{Host: "127.0.0.1"})
	if err != nil {
		t.Fatalf("newICMP: %v", err)
	}

	result := make(chan Result, 1)
	go func() { result <- probeWithin(p, 10*time.Second) }()

	req := readEchoRequest(t, raw)
	wrongToken := append([]byte(nil), req.Data...)
	wrongToken[0] ^= 0xff

	sendEchoReply(t, raw, req.ID, req.Seq+1, req.Data)
	sendEchoReply(t, raw, req.ID, req.Seq, wrongToken)
	sendEchoReply(t, raw, req.ID, req.Seq, req.Data[:tokenSize-1])

	select {
	case r := <-result:
		t.Fatalf("Probe() returned %+v on a reply that does not match the request", r)
	case <-time.After(200 * time.Millisecond):
	}

	sendEchoReply(t, raw, req.ID, req.Seq, req.Data)
	select {
	case r := <-result:
		if r.Err != nil {
			t.Fatalf("Probe() error = %v, want the matching reply accepted", r.Err)
		}
		if r.Duration <= 0 {
			t.Errorf("Duration = %s, want a positive round trip", r.Duration)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Probe() did not accept the matching reply")
	}
}
