package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/xsaveopt/latency_exporter/internal/config"
)

type httpProber struct {
	client      *http.Client
	method      string
	url         string
	host        string
	headers     http.Header
	body        string
	validStatus []int
}

func newHTTP(t *config.Target) (*httpProber, error) {
	if t.URL == "" {
		return nil, errors.New("url is required")
	}
	u, err := url.Parse(t.URL)
	if err != nil {
		return nil, fmt.Errorf("url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("url scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("url has no host")
	}
	for _, code := range t.ValidStatusCodes {
		if code < 100 || code > 599 {
			return nil, fmt.Errorf("valid_status_codes: %d is not an HTTP status code", code)
		}
	}

	method := strings.ToUpper(t.Method)
	if method == "" {
		method = http.MethodGet
	}

	headers := http.Header{}
	var host string
	for k, v := range t.Headers {
		if strings.EqualFold(k, "Host") {
			host = v
			continue
		}
		headers.Set(k, v)
	}
	if headers.Get("User-Agent") == "" {
		headers.Set("User-Agent", "latency_exporter")
	}

	dialer := &net.Dialer{}
	network := dialNetwork("tcp", t.IPVersion)
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:    tlsConfig("", t.TLSSkipVerify),
		DisableKeepAlives:  true,
		DisableCompression: true,
		ForceAttemptHTTP2:  true,
	}
	client := &http.Client{Transport: transport}
	if !t.FollowRedirects {
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}

	return &httpProber{
		client:      client,
		method:      method,
		url:         t.URL,
		host:        host,
		headers:     headers,
		body:        t.Body,
		validStatus: t.ValidStatusCodes,
	}, nil
}

type httpTimes struct {
	mu                        sync.Mutex
	dnsStart, dnsDone         time.Time
	connectStart, connectDone time.Time
	tlsStart, tlsDone         time.Time
	wroteRequest, firstByte   time.Time
}

func (h *httpTimes) mark(t *time.Time) {
	h.mu.Lock()
	if t.IsZero() {
		*t = time.Now()
	}
	h.mu.Unlock()
}

func (h *httpTimes) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		DNSStart:     func(httptrace.DNSStartInfo) { h.mark(&h.dnsStart) },
		DNSDone:      func(httptrace.DNSDoneInfo) { h.mark(&h.dnsDone) },
		ConnectStart: func(string, string) { h.mark(&h.connectStart) },
		ConnectDone: func(_, _ string, err error) {
			if err == nil {
				h.mark(&h.connectDone)
			}
		},
		TLSHandshakeStart: func() { h.mark(&h.tlsStart) },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err == nil {
				h.mark(&h.tlsDone)
			}
		},
		WroteRequest:         func(httptrace.WroteRequestInfo) { h.mark(&h.wroteRequest) },
		GotFirstResponseByte: func() { h.mark(&h.firstByte) },
	}
}

func span(name string, from, to time.Time) (Phase, bool) {
	if from.IsZero() || to.IsZero() || to.Before(from) {
		return Phase{}, false
	}
	return Phase{Name: name, Duration: to.Sub(from)}, true
}

func (h *httpTimes) phases(end time.Time) []Phase {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []Phase
	for _, c := range []struct {
		name     string
		from, to time.Time
	}{
		{"resolve", h.dnsStart, h.dnsDone},
		{"connect", h.connectStart, h.connectDone},
		{"tls", h.tlsStart, h.tlsDone},
		{"processing", h.wroteRequest, h.firstByte},
		{"transfer", h.firstByte, end},
	} {
		if p, ok := span(c.name, c.from, c.to); ok {
			out = append(out, p)
		}
	}
	return out
}

func (p *httpProber) Probe(ctx context.Context) Result {
	times := &httpTimes{}
	var body io.Reader
	if p.body != "" {
		body = strings.NewReader(p.body)
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, times.trace()), p.method, p.url, body)
	if err != nil {
		return fail(ReasonError, err)
	}
	req.Header = p.headers.Clone()
	if p.host != "" {
		req.Host = p.host
	}

	start := time.Now()
	resp, err := p.client.Do(req)
	if err != nil {
		return Result{Err: ctxErr(ctx, err)}
	}
	_, copyErr := io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	end := time.Now()

	res := Result{
		Duration:   end.Sub(start),
		Phases:     times.phases(end),
		StatusCode: resp.StatusCode,
	}
	switch {
	case copyErr != nil:
		res.Err = ctxErr(ctx, fmt.Errorf("read body: %w", copyErr))
	case !p.statusOK(resp.StatusCode):
		res.Err = &Error{Reason: ReasonStatus, Err: fmt.Errorf("unexpected status %d", resp.StatusCode)}
	}
	return res
}

func (p *httpProber) statusOK(code int) bool {
	if len(p.validStatus) == 0 {
		return code >= 200 && code < 400
	}
	return slices.Contains(p.validStatus, code)
}
