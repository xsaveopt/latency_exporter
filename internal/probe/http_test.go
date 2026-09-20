package probe

import (
	"context"
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

func newHTTPProber(t *testing.T, target config.Target) *httpProber {
	t.Helper()
	target.Type = config.TypeHTTP
	p, err := newHTTP(&target)
	if err != nil {
		t.Fatalf("newHTTP: %v", err)
	}
	return p
}

func tlsTestServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func phaseNames(phases []Phase) []string {
	out := make([]string, 0, len(phases))
	for _, p := range phases {
		out = append(out, p.Name)
	}
	return out
}

func hasPhase(phases []Phase, name string) bool {
	for _, p := range phases {
		if p.Name == name {
			return true
		}
	}
	return false
}

func TestNewHTTPErrors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		target  config.Target
		wantErr string
	}{
		{"no url", config.Target{}, "url is required"},
		{"unparsable url", config.Target{URL: "http://exa mple.invalid/"}, "url: "},
		{"wrong scheme", config.Target{URL: "ftp://example.invalid/"}, `url scheme must be http or https, got "ftp"`},
		{"no host", config.Target{URL: "http:///metrics"}, "url has no host"},
		{"status code too low", config.Target{URL: "http://example.invalid/", ValidStatusCodes: []int{99}}, "99 is not an HTTP status code"},
		{"status code too high", config.Target{URL: "http://example.invalid/", ValidStatusCodes: []int{600}}, "600 is not an HTTP status code"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newHTTP(&tc.target)
			if err == nil {
				t.Fatal("got nil error, want failure")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestNewHTTPDefaults(t *testing.T) {
	p := newHTTPProber(t, config.Target{URL: "http://example.invalid/"})
	if p.method != http.MethodGet {
		t.Errorf("method = %q, want GET", p.method)
	}
	if got := p.headers.Get("User-Agent"); got != "latency_exporter" {
		t.Errorf("User-Agent = %q", got)
	}
	if p.client.CheckRedirect == nil {
		t.Error("CheckRedirect is nil, want redirects disabled by default")
	}

	custom := newHTTPProber(t, config.Target{
		URL:             "http://example.invalid/",
		Method:          "post",
		FollowRedirects: true,
		Headers:         map[string]string{"host": "virtual.invalid", "User-Agent": "custom"},
	})
	if custom.method != http.MethodPost {
		t.Errorf("method = %q, want POST", custom.method)
	}
	if custom.host != "virtual.invalid" {
		t.Errorf("host = %q, want the Host header lifted out", custom.host)
	}
	if custom.headers.Get("Host") != "" {
		t.Error("Host should not stay in the header map")
	}
	if got := custom.headers.Get("User-Agent"); got != "custom" {
		t.Errorf("User-Agent = %q, want the configured one", got)
	}
	if custom.client.CheckRedirect != nil {
		t.Error("CheckRedirect should be nil when follow_redirects is true")
	}
}

func TestStatusOK(t *testing.T) {
	for _, tc := range []struct {
		name  string
		valid []int
		code  int
		want  bool
	}{
		{"default lower bound", nil, 200, true},
		{"default below range", nil, 199, false},
		{"default redirect", nil, 302, true},
		{"default upper bound", nil, 399, true},
		{"default above range", nil, 400, false},
		{"default server error", nil, 500, false},
		{"explicit match", []int{500, 503}, 503, true},
		{"explicit miss", []int{500, 503}, 200, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &httpProber{validStatus: tc.valid}
			if got := p.statusOK(tc.code); got != tc.want {
				t.Errorf("statusOK(%d) = %v, want %v", tc.code, got, tc.want)
			}
		})
	}
}

func TestSpan(t *testing.T) {
	start := time.Now()
	if p, ok := span("connect", start, start.Add(time.Millisecond)); !ok || p.Duration != time.Millisecond || p.Name != "connect" {
		t.Errorf("span() = %+v, %v", p, ok)
	}
	if _, ok := span("connect", time.Time{}, start); ok {
		t.Error("span with zero start should be dropped")
	}
	if _, ok := span("connect", start, time.Time{}); ok {
		t.Error("span with zero end should be dropped")
	}
	if _, ok := span("connect", start, start.Add(-time.Millisecond)); ok {
		t.Error("span running backwards should be dropped")
	}
}

func TestHTTPTimesMarkKeepsFirst(t *testing.T) {
	times := &httpTimes{}
	times.mark(&times.connectStart)
	first := times.connectStart
	times.mark(&times.connectStart)
	if times.connectStart != first {
		t.Error("mark overwrote an already recorded timestamp")
	}
}

func TestHTTPProbe(t *testing.T) {
	var gotMethod, gotHost, gotAgent, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotHost, gotAgent = r.Method, r.Host, r.Header.Get("User-Agent")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "hello")
	}))
	defer srv.Close()

	p := newHTTPProber(t, config.Target{
		URL:              srv.URL,
		Method:           "POST",
		Body:             "ping",
		Headers:          map[string]string{"Host": "virtual.invalid"},
		ValidStatusCodes: []int{http.StatusCreated},
	})
	res := p.Probe(context.Background())

	if res.Err != nil {
		t.Fatalf("Probe() error = %v", res.Err)
	}
	if res.StatusCode != http.StatusCreated {
		t.Errorf("StatusCode = %d, want 201", res.StatusCode)
	}
	if res.Duration <= 0 {
		t.Error("Duration should be positive")
	}
	if gotMethod != http.MethodPost || gotBody != "ping" {
		t.Errorf("server saw %s with body %q", gotMethod, gotBody)
	}
	if gotHost != "virtual.invalid" {
		t.Errorf("server saw Host %q", gotHost)
	}
	if gotAgent != "latency_exporter" {
		t.Errorf("server saw User-Agent %q", gotAgent)
	}
	for _, want := range []string{"connect", "processing", "transfer"} {
		if !hasPhase(res.Phases, want) {
			t.Errorf("phases %v are missing %q", phaseNames(res.Phases), want)
		}
	}
	if hasPhase(res.Phases, "tls") {
		t.Errorf("phases %v should have no tls phase over plain http", phaseNames(res.Phases))
	}
	var sum time.Duration
	for _, phase := range res.Phases {
		if phase.Duration < 0 {
			t.Errorf("phase %s has negative duration %s", phase.Name, phase.Duration)
		}
		sum += phase.Duration
	}
	if sum > res.Duration*10 {
		t.Errorf("phases sum to %s, far beyond the total %s", sum, res.Duration)
	}
}

func TestHTTPProbeTLS(t *testing.T) {
	srv := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "secure")
	}))

	p := newHTTPProber(t, config.Target{URL: srv.URL, TLSSkipVerify: true})
	res := p.Probe(context.Background())
	if res.Err != nil {
		t.Fatalf("Probe() error = %v", res.Err)
	}
	if !hasPhase(res.Phases, "tls") {
		t.Errorf("phases %v are missing the tls phase", phaseNames(res.Phases))
	}

	strict := newHTTPProber(t, config.Target{URL: srv.URL})
	if got := strict.Probe(context.Background()); Reason(got.Err) != ReasonTLS {
		t.Errorf("Probe() against an untrusted certificate: reason = %q, want %q", Reason(got.Err), ReasonTLS)
	}
}

func TestHTTPProbeUnexpectedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	res := newHTTPProber(t, config.Target{URL: srv.URL}).Probe(context.Background())
	if Reason(res.Err) != ReasonStatus {
		t.Errorf("reason = %q, want %q", Reason(res.Err), ReasonStatus)
	}
	if res.StatusCode != http.StatusInternalServerError {
		t.Errorf("StatusCode = %d, want 500", res.StatusCode)
	}
	if res.Duration <= 0 {
		t.Error("a failing status should still carry a duration")
	}

	accepted := newHTTPProber(t, config.Target{URL: srv.URL, ValidStatusCodes: []int{http.StatusInternalServerError}})
	if res := accepted.Probe(context.Background()); res.Err != nil {
		t.Errorf("500 listed in valid_status_codes still failed: %v", res.Err)
	}
}

func TestHTTPProbeRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "final")
	}))
	defer srv.Close()

	stop := newHTTPProber(t, config.Target{URL: srv.URL})
	if res := stop.Probe(context.Background()); res.StatusCode != http.StatusFound {
		t.Errorf("StatusCode = %d, want the 302 itself", res.StatusCode)
	}

	follow := newHTTPProber(t, config.Target{URL: srv.URL, FollowRedirects: true})
	if res := follow.Probe(context.Background()); res.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200 after following", res.StatusCode)
	}
}

func TestHTTPProbeConnectionRefused(t *testing.T) {
	p := newHTTPProber(t, config.Target{URL: "http://" + closedAddr(t) + "/"})
	res := p.Probe(context.Background())
	if Reason(res.Err) != ReasonRefused {
		t.Errorf("reason = %q, want %q", Reason(res.Err), ReasonRefused)
	}
}

func TestHTTPProbeCancelledContext(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-block
	}))
	defer func() {
		close(block)
		srv.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	res := newHTTPProber(t, config.Target{URL: srv.URL}).Probe(ctx)
	if Reason(res.Err) != ReasonTimeout {
		t.Errorf("reason = %q, want %q", Reason(res.Err), ReasonTimeout)
	}
}

func closedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return addr
}
