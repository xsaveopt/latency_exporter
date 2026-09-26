package main

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xsaveopt/latency_exporter/internal/config"
	"github.com/xsaveopt/latency_exporter/internal/exporter"
)

func TestSummarize(t *testing.T) {
	for _, tc := range []struct {
		name    string
		targets []exporter.Target
		want    string
	}{
		{name: "none", want: ""},
		{
			name:    "one of each in a fixed order",
			targets: []exporter.Target{{Type: config.TypeTCP}, {Type: config.TypeDNS}, {Type: config.TypeHTTP}, {Type: config.TypeICMP}},
			want:    "icmp=1 http=1 dns=1 tcp=1",
		},
		{
			name:    "counts add up",
			targets: []exporter.Target{{Type: config.TypeHTTP}, {Type: config.TypeHTTP}, {Type: config.TypeHTTP}},
			want:    "http=3",
		},
		{
			name:    "gaps are skipped",
			targets: []exporter.Target{{Type: config.TypeICMP}, {Type: config.TypeTCP}, {Type: config.TypeTCP}},
			want:    "icmp=1 tcp=2",
		},
		{
			name:    "unknown types are ignored",
			targets: []exporter.Target{{Type: "gopher"}, {Type: config.TypeDNS}},
			want:    "dns=1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := summarize(tc.targets); got != tc.want {
				t.Errorf("summarize() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEnv(t *testing.T) {
	const key = "LATENCY_EXPORTER_TEST_KEY"

	if got := env(key, "fallback"); got != "fallback" {
		t.Errorf("env() with the variable unset = %q, want %q", got, "fallback")
	}

	t.Setenv(key, "")
	if got := env(key, "fallback"); got != "fallback" {
		t.Errorf("env() with an empty variable = %q, want %q", got, "fallback")
	}

	t.Setenv(key, "/var/lib/latency.yml")
	if got := env(key, "fallback"); got != "/var/lib/latency.yml" {
		t.Errorf("env() = %q, want the variable", got)
	}
}

const helperArgsEnv = "LATENCY_EXPORTER_TEST_MAIN_ARGS"

func TestMain(m *testing.M) {
	if args, ok := os.LookupEnv(helperArgsEnv); ok {
		os.Args = append([]string{"latency_exporter"}, strings.Fields(args)...)
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func runMain(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(),
		helperArgsEnv+"="+strings.Join(args, " "),
		"LATENCY_EXPORTER_CONFIG=",
		"LATENCY_EXPORTER_ADDR=",
		"LATENCY_EXPORTER_PATH=",
		"LATENCY_EXPORTER_LOG_LEVEL=",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return 0, stdout.String(), stderr.String()
	case errors.As(err, &exitErr):
		return exitErr.ExitCode(), stdout.String(), stderr.String()
	}
	t.Fatalf("running %v: %v", args, err)
	return 0, "", ""
}

func TestMainExitCodes(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.yml")
	for _, tc := range []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr []string
	}{
		{name: "version", args: []string{"-version"}, wantStdout: "latency_exporter dev\n"},
		{name: "fatal error", args: []string{"-config.file", missing}, wantCode: 1, wantStderr: []string{"level=ERROR", "msg=fatal", "missing.yml"}},
		{name: "bad log level", args: []string{"-log.level", "loud"}, wantCode: 1, wantStderr: []string{"msg=fatal", "log.level"}},
		{name: "unknown flag", args: []string{"-no-such-flag"}, wantCode: 2, wantStderr: []string{"flag provided but not defined: -no-such-flag", "-config.file"}},
		{name: "help", args: []string{"-h"}, wantStderr: []string{"Usage of latency_exporter", "-web.listen-address"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runMain(t, tc.args...)
			if code != tc.wantCode {
				t.Errorf("exit code = %d, want %d (stderr %q)", code, tc.wantCode, stderr)
			}
			if stdout != tc.wantStdout {
				t.Errorf("stdout = %q, want %q", stdout, tc.wantStdout)
			}
			for _, w := range tc.wantStderr {
				if !strings.Contains(stderr, w) {
					t.Errorf("stderr = %q, want it to contain %q", stderr, w)
				}
			}
			if len(tc.wantStderr) == 0 && stderr != "" {
				t.Errorf("stderr = %q, want nothing", stderr)
			}
		})
	}
}
