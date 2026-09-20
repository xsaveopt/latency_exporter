package probe

import (
	"strings"
	"testing"

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
