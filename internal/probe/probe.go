package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/xsaveopt/latency_exporter/internal/config"
)

const (
	ReasonTimeout     = "timeout"
	ReasonResolve     = "resolve"
	ReasonRefused     = "refused"
	ReasonReset       = "reset"
	ReasonUnreachable = "unreachable"
	ReasonPermission  = "permission"
	ReasonTLS         = "tls"
	ReasonStatus      = "status"
	ReasonRcode       = "rcode"
	ReasonError       = "error"
)

type Phase struct {
	Name     string
	Duration time.Duration
}

type Result struct {
	Duration   time.Duration
	Phases     []Phase
	StatusCode int
	Err        error
}

type Prober interface {
	Probe(ctx context.Context) Result
}

type Error struct {
	Reason string
	Err    error
}

func (e *Error) Error() string { return e.Err.Error() }

func (e *Error) Unwrap() error { return e.Err }

func fail(reason string, err error) Result {
	return Result{Err: &Error{Reason: reason, Err: err}}
}

func New(t *config.Target) (Prober, error) {
	switch t.Type {
	case config.TypeICMP:
		return newICMP(t)
	case config.TypeHTTP:
		return newHTTP(t)
	case config.TypeDNS:
		return newDNS(t)
	case config.TypeTCP:
		return newTCP(t)
	}
	return nil, fmt.Errorf("unknown probe type %q", t.Type)
}

func Reason(err error) string {
	var pe *Error
	if errors.As(err, &pe) {
		return pe.Reason
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return ReasonResolve
	}
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return ReasonTimeout
	}
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return ReasonRefused
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		return ReasonReset
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTDOWN):
		return ReasonUnreachable
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return ReasonPermission
	}
	if isTLSError(err) {
		return ReasonTLS
	}
	return ReasonError
}

func isTLSError(err error) bool {
	var (
		recordErr   tls.RecordHeaderError
		alertErr    tls.AlertError
		verifyErr   *tls.CertificateVerificationError
		authorityEr x509.UnknownAuthorityError
		hostnameErr x509.HostnameError
		invalidErr  x509.CertificateInvalidError
	)
	return errors.As(err, &recordErr) || errors.As(err, &alertErr) || errors.As(err, &verifyErr) ||
		errors.As(err, &authorityEr) || errors.As(err, &hostnameErr) || errors.As(err, &invalidErr)
}

func lookupNetwork(ipVersion int) string {
	switch ipVersion {
	case 4:
		return "ip4"
	case 6:
		return "ip6"
	}
	return "ip"
}

func dialNetwork(base string, ipVersion int) string {
	switch ipVersion {
	case 4:
		return base + "4"
	case 6:
		return base + "6"
	}
	return base
}

func resolve(ctx context.Context, host string, ipVersion int) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		if (ipVersion == 4 && !addr.Is4()) || (ipVersion == 6 && !addr.Is6()) {
			return netip.Addr{}, &Error{Reason: ReasonResolve, Err: fmt.Errorf("%s is not an IPv%d address", host, ipVersion)}
		}
		return addr, nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, lookupNetwork(ipVersion), host)
	if err != nil {
		if ctx.Err() != nil {
			return netip.Addr{}, err
		}
		return netip.Addr{}, &Error{Reason: ReasonResolve, Err: err}
	}
	if len(addrs) == 0 {
		return netip.Addr{}, &Error{Reason: ReasonResolve, Err: fmt.Errorf("no addresses for %s", host)}
	}
	return addrs[0].Unmap(), nil
}

func tlsConfig(serverName string, skipVerify bool) *tls.Config {
	return &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: skipVerify,
		MinVersion:         tls.VersionTLS12,
	}
}
