package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/xsaveopt/latency_exporter/internal/config"
)

func TestWithDefaultPort(t *testing.T) {
	for _, tc := range []struct {
		name    string
		server  string
		want    string
		wantErr bool
	}{
		{name: "bare ipv4", server: "9.9.9.9", want: "9.9.9.9:53"},
		{name: "ipv4 with port", server: "9.9.9.9:5353", want: "9.9.9.9:5353"},
		{name: "hostname", server: "ns1.example.invalid", want: "ns1.example.invalid:53"},
		{name: "bare ipv6", server: "2620:fe::fe", want: "[2620:fe::fe]:53"},
		{name: "bracketed ipv6", server: "[2620:fe::fe]", want: "[2620:fe::fe]:53"},
		{name: "bracketed ipv6 with port", server: "[2620:fe::fe]:5353", want: "[2620:fe::fe]:5353"},
		{name: "empty", server: "", wantErr: true},
		{name: "stray brackets", server: "[a]b]", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := withDefaultPort(tc.server, "53")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("withDefaultPort(%q) = %q, want an error", tc.server, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("withDefaultPort(%q): %v", tc.server, err)
			}
			if got != tc.want {
				t.Errorf("withDefaultPort(%q) = %q, want %q", tc.server, got, tc.want)
			}
		})
	}
}

func dnsResponse(t *testing.T, id uint16, response bool, rcode dnsmessage.RCode) []byte {
	t.Helper()
	name, err := dnsmessage.NewName("example.invalid.")
	if err != nil {
		t.Fatalf("NewName: %v", err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, Response: response, RCode: rcode})
	if err := b.StartQuestions(); err != nil {
		t.Fatalf("StartQuestions: %v", err)
	}
	q := dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	if err := b.Question(q); err != nil {
		t.Fatalf("Question: %v", err)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	return msg
}

func TestMatchResponse(t *testing.T) {
	t.Run("match", func(t *testing.T) {
		h, ok := matchResponse(dnsResponse(t, 4242, true, dnsmessage.RCodeNameError), 4242)
		if !ok {
			t.Fatal("matchResponse() = false, want a match")
		}
		if h.ID != 4242 || !h.Response {
			t.Errorf("header = %+v", h)
		}
		if h.RCode != dnsmessage.RCodeNameError {
			t.Errorf("RCode = %v, want NXDOMAIN", h.RCode)
		}
	})

	t.Run("wrong id", func(t *testing.T) {
		if _, ok := matchResponse(dnsResponse(t, 1, true, dnsmessage.RCodeSuccess), 2); ok {
			t.Error("matchResponse() = true for a mismatched id")
		}
	})

	t.Run("not a response", func(t *testing.T) {
		if _, ok := matchResponse(dnsResponse(t, 7, false, dnsmessage.RCodeSuccess), 7); ok {
			t.Error("matchResponse() = true for a query")
		}
	})

	t.Run("garbage", func(t *testing.T) {
		if _, ok := matchResponse([]byte{0x01, 0x02}, 7); ok {
			t.Error("matchResponse() = true for an unparsable message")
		}
	})

	t.Run("empty", func(t *testing.T) {
		if _, ok := matchResponse(nil, 0); ok {
			t.Error("matchResponse() = true for an empty message")
		}
	})
}

func TestRcodeName(t *testing.T) {
	for _, tc := range []struct {
		rcode dnsmessage.RCode
		want  string
	}{
		{dnsmessage.RCodeSuccess, "NOERROR"},
		{dnsmessage.RCodeFormatError, "FORMERR"},
		{dnsmessage.RCodeServerFailure, "SERVFAIL"},
		{dnsmessage.RCodeNameError, "NXDOMAIN"},
		{dnsmessage.RCodeNotImplemented, "NOTIMP"},
		{dnsmessage.RCodeRefused, "REFUSED"},
		{dnsmessage.RCode(9), "RCODE9"},
	} {
		if got := rcodeName(tc.rcode); got != tc.want {
			t.Errorf("rcodeName(%d) = %q, want %q", int(tc.rcode), got, tc.want)
		}
	}
}

func TestNewDNSDefaults(t *testing.T) {
	p, err := newDNS(&config.Target{Type: config.TypeDNS, Server: "9.9.9.9", Query: "example.invalid"})
	if err != nil {
		t.Fatalf("newDNS: %v", err)
	}
	if p.server != "9.9.9.9:53" {
		t.Errorf("server = %q, want the default port appended", p.server)
	}
	if p.network != "udp" || p.tcp {
		t.Errorf("network = %q, tcp = %v, want udp", p.network, p.tcp)
	}
	if got := p.question.Name.String(); got != "example.invalid." {
		t.Errorf("question name = %q, want the query made absolute", got)
	}
	if p.question.Type != dnsmessage.TypeA || p.question.Class != dnsmessage.ClassINET {
		t.Errorf("question = %+v, want an IN A query", p.question)
	}
	if !p.recursion {
		t.Error("recursion = false, want it on by default")
	}
	if len(p.validRcodes) != 1 || p.validRcodes[0] != dnsmessage.RCodeSuccess {
		t.Errorf("validRcodes = %v, want just NOERROR", p.validRcodes)
	}
}

func TestNewDNSExplicit(t *testing.T) {
	recursion := false
	p, err := newDNS(&config.Target{
		Type:        config.TypeDNS,
		Server:      "[2620:fe::fe]:5353",
		Query:       "example.invalid.",
		RecordType:  "aaaa",
		Transport:   "TCP",
		ValidRcodes: []string{"nxdomain", "SERVFAIL"},
		Recursion:   &recursion,
		IPVersion:   6,
	})
	if err != nil {
		t.Fatalf("newDNS: %v", err)
	}
	if p.server != "[2620:fe::fe]:5353" {
		t.Errorf("server = %q", p.server)
	}
	if p.network != "tcp6" || !p.tcp {
		t.Errorf("network = %q, tcp = %v, want tcp6", p.network, p.tcp)
	}
	if p.question.Type != dnsmessage.TypeAAAA {
		t.Errorf("question type = %v, want AAAA", p.question.Type)
	}
	if p.recursion {
		t.Error("recursion = true, want it off")
	}
	want := []dnsmessage.RCode{dnsmessage.RCodeNameError, dnsmessage.RCodeServerFailure}
	if len(p.validRcodes) != len(want) || p.validRcodes[0] != want[0] || p.validRcodes[1] != want[1] {
		t.Errorf("validRcodes = %v, want %v", p.validRcodes, want)
	}
}

func TestNewDNSErrors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		target  config.Target
		wantErr string
	}{
		{"no query", config.Target{Server: "9.9.9.9"}, "query is required"},
		{"unparsable query", config.Target{Server: "9.9.9.9", Query: strings.Repeat("a", 300)}, "query: "},
		{"unknown record type", config.Target{Server: "9.9.9.9", Query: "example.invalid", RecordType: "HINFO"}, `record_type "HINFO" is not supported`},
		{"bad transport", config.Target{Server: "9.9.9.9", Query: "example.invalid", Transport: "quic"}, `transport must be udp or tcp, got "quic"`},
		{"unknown rcode", config.Target{Server: "9.9.9.9", Query: "example.invalid", ValidRcodes: []string{"YXDOMAIN"}}, `unknown rcode "YXDOMAIN"`},
		{"bad server", config.Target{Server: "[a]b]", Query: "example.invalid"}, "server: "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newDNS(&tc.target)
			if err == nil {
				t.Fatal("got nil error, want failure")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestDNSQueryEncodesHeader(t *testing.T) {
	p, err := newDNS(&config.Target{Type: config.TypeDNS, Server: "9.9.9.9", Query: "example.invalid"})
	if err != nil {
		t.Fatalf("newDNS: %v", err)
	}
	id, msg, err := p.query()
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(msg) < 3 {
		t.Fatalf("message is %d bytes", len(msg))
	}
	if got := int(msg[0])<<8 | int(msg[1]); got != len(msg)-2 {
		t.Errorf("tcp length prefix = %d, want %d", got, len(msg)-2)
	}

	var parser dnsmessage.Parser
	h, err := parser.Start(msg[2:])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if h.ID != id {
		t.Errorf("header id = %d, want %d", h.ID, id)
	}
	if !h.RecursionDesired {
		t.Error("RecursionDesired = false, want true")
	}
	q, err := parser.Question()
	if err != nil {
		t.Fatalf("question: %v", err)
	}
	if q.Name.String() != "example.invalid." || q.Type != dnsmessage.TypeA {
		t.Errorf("question = %+v", q)
	}
}

type seenQuery struct {
	header   dnsmessage.Header
	question dnsmessage.Question
}

func parseQuery(b []byte) (seenQuery, error) {
	var parser dnsmessage.Parser
	h, err := parser.Start(b)
	if err != nil {
		return seenQuery{}, err
	}
	q, err := parser.Question()
	if err != nil {
		return seenQuery{}, err
	}
	return seenQuery{header: h, question: q}, nil
}

func withID(msg []byte, id uint16) []byte {
	out := append([]byte(nil), msg...)
	binary.BigEndian.PutUint16(out, id)
	return out
}

func dnsReplies(query seenQuery, answer []byte) [][]byte {
	id := query.header.ID
	return [][]byte{
		{0xde, 0xad},
		withID(answer, id^0xffff),
		withID(answer, id)[:3],
		withID(answer, id),
	}
}

func serveUDPDNS(t *testing.T, answer []byte) (string, <-chan seenQuery) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	seen := make(chan seenQuery, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		q, err := parseQuery(buf[:n])
		if err != nil {
			t.Errorf("server could not parse the query: %v", err)
			return
		}
		seen <- q
		if answer == nil {
			return
		}
		notResponse := withID(answer, q.header.ID)
		notResponse[2] &^= 0x80
		_, _ = conn.WriteTo(notResponse, from)
		for _, reply := range dnsReplies(q, answer) {
			_, _ = conn.WriteTo(reply, from)
		}
	}()
	t.Cleanup(func() {
		_ = conn.Close()
		<-done
	})
	return conn.LocalAddr().String(), seen
}

func writeFramed(w io.Writer, msg []byte) {
	var lenb [2]byte
	binary.BigEndian.PutUint16(lenb[:], uint16(len(msg)))
	_, _ = w.Write(append(lenb[:], msg...))
}

func serveTCPDNS(t *testing.T, respond func(net.Conn, seenQuery)) (string, <-chan seenQuery) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	seen := make(chan seenQuery, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		var lenb [2]byte
		if _, err := io.ReadFull(conn, lenb[:]); err != nil {
			t.Errorf("server read length: %v", err)
			return
		}
		buf := make([]byte, binary.BigEndian.Uint16(lenb[:]))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Errorf("server read query: %v", err)
			return
		}
		q, err := parseQuery(buf)
		if err != nil {
			t.Errorf("server could not parse the query: %v", err)
			return
		}
		seen <- q
		respond(conn, q)
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})
	return ln.Addr().String(), seen
}

func newDNSProber(t *testing.T, target config.Target) *dnsProber {
	t.Helper()
	target.Type = config.TypeDNS
	if target.Query == "" {
		target.Query = "example.invalid"
	}
	p, err := newDNS(&target)
	if err != nil {
		t.Fatalf("newDNS: %v", err)
	}
	return p
}

func probeWithin(p Prober, d time.Duration) Result {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return p.Probe(ctx)
}

func TestDNSProbeUDP(t *testing.T) {
	for _, tc := range []struct {
		name       string
		rcode      dnsmessage.RCode
		validCodes []string
		wantErr    string
	}{
		{name: "noerror", rcode: dnsmessage.RCodeSuccess},
		{name: "nxdomain is a failure by default", rcode: dnsmessage.RCodeNameError, wantErr: "unexpected rcode NXDOMAIN"},
		{name: "nxdomain accepted when listed", rcode: dnsmessage.RCodeNameError, validCodes: []string{"NXDOMAIN"}},
		{name: "noerror rejected when not listed", rcode: dnsmessage.RCodeSuccess, validCodes: []string{"SERVFAIL"}, wantErr: "unexpected rcode NOERROR"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, seen := serveUDPDNS(t, dnsResponse(t, 0, true, tc.rcode))
			res := probeWithin(newDNSProber(t, config.Target{Server: addr, RecordType: "MX", ValidRcodes: tc.validCodes}), 5*time.Second)

			q := <-seen
			if q.question.Name.String() != "example.invalid." || q.question.Type != dnsmessage.TypeMX {
				t.Errorf("server saw question %+v", q.question)
			}
			if !q.header.RecursionDesired {
				t.Error("server saw RecursionDesired = false, want true by default")
			}

			if tc.wantErr == "" {
				if res.Err != nil {
					t.Fatalf("Probe() error = %v", res.Err)
				}
			} else {
				if Reason(res.Err) != ReasonRcode || !strings.Contains(res.Err.Error(), tc.wantErr) {
					t.Fatalf("Probe() error = %v (reason %q), want %q with reason %q", res.Err, Reason(res.Err), tc.wantErr, ReasonRcode)
				}
			}
			if res.Duration <= 0 {
				t.Errorf("Duration = %s, want the round trip even when the rcode is rejected", res.Duration)
			}
		})
	}
}

func TestDNSProbeRecursionOff(t *testing.T) {
	addr, seen := serveUDPDNS(t, dnsResponse(t, 0, true, dnsmessage.RCodeSuccess))
	recursion := false
	if res := probeWithin(newDNSProber(t, config.Target{Server: addr, Recursion: &recursion}), 5*time.Second); res.Err != nil {
		t.Fatalf("Probe() error = %v", res.Err)
	}
	if q := <-seen; q.header.RecursionDesired {
		t.Error("server saw RecursionDesired = true, want it off")
	}
}

func TestDNSProbeUDPNoAnswerTimesOut(t *testing.T) {
	addr, seen := serveUDPDNS(t, nil)
	res := probeWithin(newDNSProber(t, config.Target{Server: addr}), 100*time.Millisecond)
	<-seen
	if Reason(res.Err) != ReasonTimeout {
		t.Errorf("reason = %q (%v), want %q", Reason(res.Err), res.Err, ReasonTimeout)
	}
	if res.Duration != 0 {
		t.Errorf("Duration = %s, want 0 without an answer", res.Duration)
	}
}

func TestDNSProbeTCP(t *testing.T) {
	answer := dnsResponse(t, 0, true, dnsmessage.RCodeServerFailure)
	addr, seen := serveTCPDNS(t, func(conn net.Conn, q seenQuery) {
		for _, reply := range dnsReplies(q, answer) {
			writeFramed(conn, reply)
		}
	})
	res := probeWithin(newDNSProber(t, config.Target{Server: addr, Transport: "tcp", RecordType: "TXT"}), 5*time.Second)

	if q := <-seen; q.question.Type != dnsmessage.TypeTXT {
		t.Errorf("server saw question %+v", q.question)
	}
	if Reason(res.Err) != ReasonRcode || !strings.Contains(res.Err.Error(), "unexpected rcode SERVFAIL") {
		t.Errorf("Probe() error = %v, want the SERVFAIL answer after the stray frames", res.Err)
	}
	if res.Duration <= 0 {
		t.Errorf("Duration = %s, want a positive round trip", res.Duration)
	}
}

func TestDNSProbeTCPTruncatedAnswer(t *testing.T) {
	for _, tc := range []struct {
		name  string
		frame []byte
	}{
		{"cut inside the length prefix", []byte{0x00}},
		{"cut inside the message", []byte{0x00, 0x40, 0x12, 0x34}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, seen := serveTCPDNS(t, func(conn net.Conn, _ seenQuery) {
				_, _ = conn.Write(tc.frame)
			})
			res := probeWithin(newDNSProber(t, config.Target{Server: addr, Transport: "tcp"}), 5*time.Second)
			<-seen
			if !errors.Is(res.Err, io.ErrUnexpectedEOF) && !errors.Is(res.Err, io.EOF) {
				t.Errorf("Probe() error = %v, want an EOF from the short frame", res.Err)
			}
			if Reason(res.Err) != ReasonError {
				t.Errorf("reason = %q, want %q", Reason(res.Err), ReasonError)
			}
		})
	}
}

func TestDNSProbeTCPRefused(t *testing.T) {
	res := probeWithin(newDNSProber(t, config.Target{Server: closedAddr(t), Transport: "tcp"}), 5*time.Second)
	if Reason(res.Err) != ReasonRefused {
		t.Errorf("reason = %q (%v), want %q", Reason(res.Err), res.Err, ReasonRefused)
	}
}

func TestDNSProbeCancelledContext(t *testing.T) {
	addr, _ := serveTCPDNS(t, func(net.Conn, seenQuery) {})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := newDNSProber(t, config.Target{Server: addr, Transport: "tcp"}).Probe(ctx)
	if Reason(res.Err) != ReasonTimeout || !errors.Is(res.Err, context.Canceled) {
		t.Errorf("Probe() error = %v (reason %q), want a cancelled timeout", res.Err, Reason(res.Err))
	}
}

func TestNewDNSUsesSystemNameserver(t *testing.T) {
	var want string
	if b, err := os.ReadFile(resolvConf); err == nil {
		for line := range strings.Lines(string(b)) {
			if f := strings.Fields(line); len(f) >= 2 && f[0] == "nameserver" {
				want = f[1]
				break
			}
		}
	}

	p, err := newDNS(&config.Target{Type: config.TypeDNS, Query: "example.invalid"})
	if want == "" {
		if err == nil || !strings.Contains(err.Error(), "server not set and no nameserver found in "+resolvConf) {
			t.Fatalf("newDNS() error = %v, want the missing nameserver error", err)
		}
		return
	}
	if err != nil {
		t.Fatalf("newDNS: %v", err)
	}
	if wantAddr := net.JoinHostPort(strings.Trim(want, "[]"), "53"); p.server != wantAddr {
		t.Errorf("server = %q, want %q from %s", p.server, wantAddr, resolvConf)
	}
}

func TestDNSProbeCancelledWhileWaiting(t *testing.T) {
	addr, seen := serveUDPDNS(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-seen
		cancel()
	}()
	res := newDNSProber(t, config.Target{Server: addr}).Probe(ctx)
	if Reason(res.Err) != ReasonTimeout || !errors.Is(res.Err, context.Canceled) {
		t.Errorf("Probe() error = %v (reason %q), want the in-flight query aborted by the cancel", res.Err, Reason(res.Err))
	}
}

func TestDNSProbeUDPIPVersion(t *testing.T) {
	t.Run("pinned to v4", func(t *testing.T) {
		addr, seen := serveUDPDNS(t, dnsResponse(t, 0, true, dnsmessage.RCodeSuccess))
		p := newDNSProber(t, config.Target{Server: addr, IPVersion: 4})
		if p.network != "udp4" {
			t.Errorf("network = %q, want udp4", p.network)
		}
		if res := probeWithin(p, 5*time.Second); res.Err != nil {
			t.Fatalf("Probe() error = %v", res.Err)
		}
		<-seen
	})

	t.Run("pinned to v6 against a v4 server", func(t *testing.T) {
		addr, seen := serveUDPDNS(t, dnsResponse(t, 0, true, dnsmessage.RCodeSuccess))
		p := newDNSProber(t, config.Target{Server: addr, IPVersion: 6})
		if p.network != "udp6" {
			t.Errorf("network = %q, want udp6", p.network)
		}
		res := probeWithin(p, 500*time.Millisecond)
		if res.Err == nil {
			t.Fatal("Probe() succeeded, want the v4 server rejected when pinned to v6")
		}
		if res.Duration != 0 {
			t.Errorf("Duration = %s, want 0 on failure", res.Duration)
		}
		select {
		case q := <-seen:
			t.Errorf("server saw %+v, want no query sent over the wrong family", q.question)
		default:
		}
	})
}

func TestDNSProbeHostnameServer(t *testing.T) {
	for _, transport := range []string{"udp", "tcp"} {
		t.Run(transport, func(t *testing.T) {
			var addr string
			var seen <-chan seenQuery
			if transport == "udp" {
				addr, seen = serveUDPDNS(t, dnsResponse(t, 0, true, dnsmessage.RCodeSuccess))
			} else {
				answer := dnsResponse(t, 0, true, dnsmessage.RCodeSuccess)
				addr, seen = serveTCPDNS(t, func(conn net.Conn, q seenQuery) {
					writeFramed(conn, withID(answer, q.header.ID))
				})
			}
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				t.Fatal(err)
			}
			p := newDNSProber(t, config.Target{Server: net.JoinHostPort("localhost", port), Transport: transport, IPVersion: 4})
			if p.server != "localhost:"+port {
				t.Errorf("server = %q, want the hostname kept for the dialer", p.server)
			}
			if res := probeWithin(p, 5*time.Second); res.Err != nil {
				t.Fatalf("Probe() error = %v", res.Err)
			}
			<-seen
		})
	}

	p := newDNSProber(t, config.Target{Server: "localhost"})
	if p.server != "localhost:53" {
		t.Errorf("server = %q, want the default port added to a bare hostname", p.server)
	}
}
