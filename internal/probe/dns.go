package probe

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/xsaveopt/latency_exporter/internal/config"
)

const resolvConf = "/etc/resolv.conf"

var recordTypes = map[string]dnsmessage.Type{
	"A":     dnsmessage.TypeA,
	"AAAA":  dnsmessage.TypeAAAA,
	"CNAME": dnsmessage.TypeCNAME,
	"MX":    dnsmessage.TypeMX,
	"NS":    dnsmessage.TypeNS,
	"PTR":   dnsmessage.TypePTR,
	"SOA":   dnsmessage.TypeSOA,
	"SRV":   dnsmessage.TypeSRV,
	"TXT":   dnsmessage.TypeTXT,
}

var rcodes = map[string]dnsmessage.RCode{
	"NOERROR":  dnsmessage.RCodeSuccess,
	"FORMERR":  dnsmessage.RCodeFormatError,
	"SERVFAIL": dnsmessage.RCodeServerFailure,
	"NXDOMAIN": dnsmessage.RCodeNameError,
	"NOTIMP":   dnsmessage.RCodeNotImplemented,
	"REFUSED":  dnsmessage.RCodeRefused,
}

type dnsProber struct {
	server      string
	network     string
	tcp         bool
	question    dnsmessage.Question
	recursion   bool
	validRcodes []dnsmessage.RCode
}

func newDNS(t *config.Target) (*dnsProber, error) {
	if t.Query == "" {
		return nil, errors.New("query is required")
	}
	fqdn := t.Query
	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}
	name, err := dnsmessage.NewName(fqdn)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}

	rtype := strings.ToUpper(t.RecordType)
	if rtype == "" {
		rtype = "A"
	}
	qtype, ok := recordTypes[rtype]
	if !ok {
		return nil, fmt.Errorf("record_type %q is not supported", t.RecordType)
	}

	transport := strings.ToLower(t.Transport)
	switch transport {
	case "":
		transport = "udp"
	case "udp", "tcp":
	default:
		return nil, fmt.Errorf("transport must be udp or tcp, got %q", t.Transport)
	}

	valid := []dnsmessage.RCode{dnsmessage.RCodeSuccess}
	if len(t.ValidRcodes) > 0 {
		valid = valid[:0]
		for _, s := range t.ValidRcodes {
			rc, ok := rcodes[strings.ToUpper(s)]
			if !ok {
				return nil, fmt.Errorf("valid_rcodes: unknown rcode %q", s)
			}
			valid = append(valid, rc)
		}
	}

	server := t.Server
	if server == "" {
		server, err = systemNameserver()
		if err != nil {
			return nil, fmt.Errorf("server not set and no nameserver found in %s: %w", resolvConf, err)
		}
	}
	server, err = withDefaultPort(server, "53")
	if err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}

	return &dnsProber{
		server:      server,
		network:     dialNetwork(transport, t.IPVersion),
		tcp:         transport == "tcp",
		question:    dnsmessage.Question{Name: name, Type: qtype, Class: dnsmessage.ClassINET},
		recursion:   t.Recursion == nil || *t.Recursion,
		validRcodes: valid,
	}, nil
}

func withDefaultPort(server, port string) (string, error) {
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server, nil
	}
	host := strings.TrimSuffix(strings.TrimPrefix(server, "["), "]")
	if host == "" || strings.ContainsAny(host, "[]") {
		return "", fmt.Errorf("invalid address %q", server)
	}
	return net.JoinHostPort(host, port), nil
}

func systemNameserver() (string, error) {
	f, err := os.Open(resolvConf)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			return fields[1], nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", errors.New("no nameserver line")
}

func (p *dnsProber) query() (uint16, []byte, error) {
	var idb [2]byte
	_, _ = rand.Read(idb[:])
	id := binary.BigEndian.Uint16(idb[:])

	b := dnsmessage.NewBuilder(make([]byte, 2, 512), dnsmessage.Header{ID: id, RecursionDesired: p.recursion})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return 0, nil, err
	}
	if err := b.Question(p.question); err != nil {
		return 0, nil, err
	}
	if err := b.StartAdditionals(); err != nil {
		return 0, nil, err
	}
	var opt dnsmessage.ResourceHeader
	if err := opt.SetEDNS0(1232, dnsmessage.RCodeSuccess, false); err != nil {
		return 0, nil, err
	}
	if err := b.OPTResource(opt, dnsmessage.OPTResource{}); err != nil {
		return 0, nil, err
	}
	msg, err := b.Finish()
	if err != nil {
		return 0, nil, err
	}
	binary.BigEndian.PutUint16(msg[:2], uint16(len(msg)-2))
	return id, msg, nil
}

func (p *dnsProber) Probe(ctx context.Context) Result {
	id, msg, err := p.query()
	if err != nil {
		return fail(ReasonError, err)
	}
	if !p.tcp {
		msg = msg[2:]
	}

	start := time.Now()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, p.network, p.server)
	if err != nil {
		return Result{Err: ctxErr(ctx, err)}
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	if _, err := conn.Write(msg); err != nil {
		return Result{Err: ctxErr(ctx, err)}
	}

	var header dnsmessage.Header
	if p.tcp {
		header, err = readTCPResponse(conn, id)
	} else {
		header, err = readUDPResponse(conn, id)
	}
	if err != nil {
		return Result{Err: ctxErr(ctx, err)}
	}
	res := Result{Duration: time.Since(start)}
	if !slices.Contains(p.validRcodes, header.RCode) {
		res.Err = &Error{Reason: ReasonRcode, Err: fmt.Errorf("unexpected rcode %s", rcodeName(header.RCode))}
	}
	return res
}

func readUDPResponse(conn net.Conn, id uint16) (dnsmessage.Header, error) {
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return dnsmessage.Header{}, err
		}
		if h, ok := matchResponse(buf[:n], id); ok {
			return h, nil
		}
	}
}

func readTCPResponse(conn net.Conn, id uint16) (dnsmessage.Header, error) {
	for {
		var lenb [2]byte
		if _, err := io.ReadFull(conn, lenb[:]); err != nil {
			return dnsmessage.Header{}, err
		}
		buf := make([]byte, binary.BigEndian.Uint16(lenb[:]))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return dnsmessage.Header{}, err
		}
		if h, ok := matchResponse(buf, id); ok {
			return h, nil
		}
	}
}

func matchResponse(b []byte, id uint16) (dnsmessage.Header, bool) {
	var parser dnsmessage.Parser
	h, err := parser.Start(b)
	if err != nil || !h.Response || h.ID != id {
		return dnsmessage.Header{}, false
	}
	return h, true
}

func rcodeName(rc dnsmessage.RCode) string {
	for name, code := range rcodes {
		if code == rc {
			return name
		}
	}
	return fmt.Sprintf("RCODE%d", int(rc))
}
