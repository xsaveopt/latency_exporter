package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/xsaveopt/latency_exporter/internal/config"
)

type tcpProber struct {
	host      string
	port      string
	ipVersion int
	tls       *tls.Config
}

func newTCP(t *config.Target) (*tcpProber, error) {
	if t.Address == "" {
		return nil, errors.New("address is required")
	}
	host, port, err := net.SplitHostPort(t.Address)
	if err != nil {
		return nil, fmt.Errorf("address must be host:port: %w", err)
	}
	if host == "" || port == "" {
		return nil, errors.New("address must be host:port")
	}
	if (t.TLSServerName != "" || t.TLSSkipVerify) && !t.TLS {
		return nil, errors.New("tls_server_name and tls_skip_verify need tls: true")
	}

	p := &tcpProber{host: host, port: port, ipVersion: t.IPVersion}
	if t.TLS {
		name := t.TLSServerName
		if name == "" {
			if _, err := netip.ParseAddr(host); err != nil {
				name = host
			}
		}
		p.tls = tlsConfig(name, t.TLSSkipVerify)
	}
	return p, nil
}

func (p *tcpProber) Probe(ctx context.Context) Result {
	start := time.Now()
	addr, err := resolve(ctx, p.host, p.ipVersion)
	if err != nil {
		return Result{Err: err}
	}
	resolved := time.Now()

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(addr.String(), p.port))
	if err != nil {
		return Result{Err: ctxErr(ctx, err)}
	}
	defer func() { _ = conn.Close() }()
	connected := time.Now()

	phases := []Phase{
		{Name: "resolve", Duration: resolved.Sub(start)},
		{Name: "connect", Duration: connected.Sub(resolved)},
	}
	if p.tls == nil {
		return Result{Duration: connected.Sub(resolved), Phases: phases}
	}

	tc := tls.Client(conn, p.tls)
	if err := tc.HandshakeContext(ctx); err != nil {
		err = ctxErr(ctx, err)
		if Reason(err) == ReasonError {
			err = &Error{Reason: ReasonTLS, Err: err}
		}
		return Result{Err: err}
	}
	done := time.Now()
	phases = append(phases, Phase{Name: "tls", Duration: done.Sub(connected)})
	return Result{Duration: done.Sub(resolved), Phases: phases}
}
