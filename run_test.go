package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func withArgs(t *testing.T, args ...string) {
	t.Helper()
	for _, key := range []string{"LATENCY_EXPORTER_CONFIG", "LATENCY_EXPORTER_ADDR", "LATENCY_EXPORTER_PATH", "LATENCY_EXPORTER_LOG_LEVEL"} {
		t.Setenv(key, "")
	}
	oldArgs, oldFlags := os.Args, flag.CommandLine
	os.Args = append([]string{"latency_exporter"}, args...)
	flag.CommandLine = flag.NewFlagSet("latency_exporter", flag.ContinueOnError)
	t.Cleanup(func() {
		os.Args, flag.CommandLine = oldArgs, oldFlags
	})
}

func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	out := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		out <- string(b)
	}()
	runErr := fn()
	os.Stdout = old
	_ = w.Close()
	s := <-out
	_ = r.Close()
	return s, runErr
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const validConfig = `targets:
  - name: gateway
    type: icmp
    host: 192.0.2.1
    interval: 1h
  - name: site
    type: http
    url: http://192.0.2.1/
    interval: 1h
`

func TestRunVersion(t *testing.T) {
	withArgs(t, "-version")
	out, err := captureStdout(t, run)
	if err != nil {
		t.Fatalf("run() = %v", err)
	}
	if out != "latency_exporter dev\n" {
		t.Errorf("stdout = %q", out)
	}
}

func TestRunConfigCheck(t *testing.T) {
	path := writeConfig(t, validConfig)
	withArgs(t, "-config.check", "-config.file", path)
	out, err := captureStdout(t, run)
	if err != nil {
		t.Fatalf("run() = %v", err)
	}
	if want := path + ": 2 targets OK\n"; out != want {
		t.Errorf("stdout = %q, want %q", out, want)
	}
}

func TestRunConfigFromEnv(t *testing.T) {
	path := writeConfig(t, validConfig)
	withArgs(t, "-config.check")
	t.Setenv("LATENCY_EXPORTER_CONFIG", path)
	out, err := captureStdout(t, run)
	if err != nil {
		t.Fatalf("run() = %v", err)
	}
	if !strings.HasPrefix(out, path+":") {
		t.Errorf("stdout = %q, want the config path from the environment", out)
	}
}

func TestRunErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.yml")
	badTargets := writeConfig(t, `targets:
  - name: tiny
    type: icmp
    host: 192.0.2.1
    payload_size: 8
  - name: nohost
    type: tcp
    address: 192.0.2.1
`)
	invalid := writeConfig(t, "targets: []\n")

	for _, tc := range []struct {
		name string
		args []string
		want []string
	}{
		{"bad log level", []string{"-log.level", "loud", "-config.file", missing}, []string{"log.level"}},
		{"missing config", []string{"-config.file", missing}, []string{"missing.yml"}},
		{"invalid config", []string{"-config.file", invalid}, []string{"no targets configured"}},
		{"probe construction fails", []string{"-config.check", "-config.file", badTargets}, []string{
			badTargets + ":",
			"target tiny: payload_size must be between",
			"target nohost: address must be host:port",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withArgs(t, tc.args...)
			out, err := captureStdout(t, run)
			if err == nil {
				t.Fatal("run() succeeded, want an error")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error = %q, want it to contain %q", err, w)
				}
			}
			if out != "" {
				t.Errorf("stdout = %q, want nothing on failure", out)
			}
		})
	}
}

func TestRunListenFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	withArgs(t, "-config.file", writeConfig(t, validConfig), "-web.listen-address", ln.Addr().String(), "-log.level", "error")
	if err := run(); err == nil || !strings.HasPrefix(err.Error(), "listen:") {
		t.Errorf("run() = %v, want a listen error", err)
	}
}

var listenLine = regexp.MustCompile(`msg="starting latency_exporter".* listen=(\S+)`)

func startRun(t *testing.T, args ...string) (string, <-chan error) {
	t.Helper()
	withArgs(t, args...)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w

	result := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		err := run()
		_ = w.Close()
		result <- err
		close(finished)
	}()
	t.Cleanup(func() {
		select {
		case <-finished:
		case <-time.After(10 * time.Second):
			t.Error("run() still running at cleanup")
		}
		os.Stderr = old
		_ = r.Close()
	})

	addr := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(r)
		sent := false
		for sc.Scan() {
			if m := listenLine.FindStringSubmatch(sc.Text()); m != nil && !sent {
				addr <- m[1]
				sent = true
			}
		}
		if !sent {
			close(addr)
		}
	}()

	select {
	case a, ok := <-addr:
		if !ok {
			t.Fatalf("run() exited before listening: %v", <-result)
		}
		return a, result
	case <-time.After(10 * time.Second):
		t.Fatal("run() did not log its listen address")
	}
	return "", nil
}

func get(t *testing.T, url string) (int, string, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	return resp.StatusCode, resp.Header.Get("Content-Type"), string(b)
}

func stopRun(t *testing.T, result <-chan error) {
	t.Helper()
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Errorf("run() after SIGTERM = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run() did not shut down after SIGTERM")
	}
}

func TestRunServesAndShutsDown(t *testing.T) {
	addr, result := startRun(t,
		"-config.file", writeConfig(t, validConfig),
		"-web.listen-address", "127.0.0.1:0",
		"-web.telemetry-path", "/probe-metrics",
		"-log.level", "debug",
	)
	base := "http://" + addr

	var code int
	var ctype, body string
	for deadline := time.Now().Add(10 * time.Second); ; {
		code, ctype, body = get(t, base+"/probe-metrics")
		if strings.Contains(body, `latency_probes_total{target="site"`) || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if code != http.StatusOK {
		t.Errorf("metrics status = %d", code)
	}
	for _, want := range []string{
		`latency_exporter_build_info{goversion="`,
		`version="dev"`,
		`latency_probes_total{target="gateway",type="icmp"} 0`,
		`latency_probes_total{target="site",type="http"} 0`,
		"go_goroutines",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics body is missing %q", want)
		}
	}
	if !strings.HasPrefix(ctype, "text/plain") {
		t.Errorf("metrics Content-Type = %q", ctype)
	}

	code, ctype, body = get(t, base+"/health")
	if code != http.StatusOK || body != "up" || ctype != "text/plain; charset=utf-8" {
		t.Errorf("health = %d %q %q, want 200 up inside the startup grace", code, ctype, body)
	}

	code, ctype, body = get(t, base+"/")
	if code != http.StatusOK || ctype != "text/html; charset=utf-8" || !strings.Contains(body, `<a href="/probe-metrics">/probe-metrics</a>`) {
		t.Errorf("index = %d %q %q", code, ctype, body)
	}

	if code, _, _ := get(t, base+"/nope"); code != http.StatusNotFound {
		t.Errorf("unknown path status = %d, want 404", code)
	}

	stopRun(t, result)

	if resp, err := http.Get(base + "/health"); err == nil {
		_ = resp.Body.Close()
		t.Error("server still answering after shutdown")
	}
}

func TestRunMetricsAtRoot(t *testing.T) {
	addr, result := startRun(t,
		"-config.file", writeConfig(t, validConfig),
		"-web.listen-address", "127.0.0.1:0",
		"-web.telemetry-path", "/",
	)

	code, _, body := get(t, fmt.Sprintf("http://%s/", addr))
	if code != http.StatusOK || !strings.Contains(body, "latency_exporter_build_info") {
		t.Errorf("GET / = %d, want the metrics page when the telemetry path is /", code)
	}

	stopRun(t, result)
}

func TestRunHealthDegradedWhenEveryTargetFails(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	_ = ln.Close()

	addr, result := startRun(t,
		"-config.file", writeConfig(t, fmt.Sprintf("targets:\n  - name: down\n    type: tcp\n    address: %s\n    interval: 50ms\n", closed)),
		"-web.listen-address", "127.0.0.1:0",
	)

	var code int
	var ctype, body string
	for deadline := time.Now().Add(10 * time.Second); ; {
		code, ctype, body = get(t, "http://"+addr+"/health")
		if code == http.StatusServiceUnavailable || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if code != http.StatusServiceUnavailable || body != "degraded" || ctype != "text/plain; charset=utf-8" {
		t.Errorf("health = %d %q %q, want 503 degraded once the only target fails", code, ctype, body)
	}

	stopRun(t, result)
}

func TestRunIndexEscapesTelemetryPath(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		want string
	}{
		{"html special characters", `/a"b<c>&d`, `<a href="/a&#34;b&lt;c&gt;&amp;d">/a&#34;b&lt;c&gt;&amp;d</a>`},
		{"backslash kept as is", `/a\b`, `<a href="/a\b">/a\b</a>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, result := startRun(t,
				"-config.file", writeConfig(t, validConfig),
				"-web.listen-address", "127.0.0.1:0",
				"-web.telemetry-path", tc.path,
			)
			code, _, body := get(t, "http://"+addr+"/")
			stopRun(t, result)
			if code != http.StatusOK {
				t.Fatalf("index status = %d", code)
			}
			if !strings.Contains(body, tc.want) {
				t.Errorf("index body = %q, want it to contain %q", body, tc.want)
			}
		})
	}
}

func shutdownListener(t *testing.T, addr string) error {
	t.Helper()
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	for fd := 3; fd < 4096; fd++ {
		sa, err := syscall.Getsockname(fd)
		if err != nil {
			continue
		}
		in4, ok := sa.(*syscall.SockaddrInet4)
		if !ok || in4.Port != port {
			continue
		}
		if listening, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ACCEPTCONN); err != nil || listening != 1 {
			continue
		}
		return syscall.Shutdown(fd, syscall.SHUT_RDWR)
	}
	return fmt.Errorf("no listening socket found for %s", addr)
}

func TestRunServerFailure(t *testing.T) {
	addr, result := startRun(t,
		"-config.file", writeConfig(t, validConfig),
		"-web.listen-address", "127.0.0.1:0",
	)
	if code, _, _ := get(t, "http://"+addr+"/health"); code != http.StatusOK {
		t.Fatalf("health status = %d before the failure", code)
	}

	if err := shutdownListener(t, addr); err != nil {
		stopRun(t, result)
		t.Skipf("this platform cannot shut down a listening socket: %v", err)
	}

	select {
	case err := <-result:
		if err == nil || !strings.HasPrefix(err.Error(), "http server: ") {
			t.Errorf("run() = %v, want an http server error", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run() kept running after its listener failed")
	}
}
