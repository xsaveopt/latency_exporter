package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"html"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/xsaveopt/latency_exporter/internal/config"
	"github.com/xsaveopt/latency_exporter/internal/exporter"
	"github.com/xsaveopt/latency_exporter/internal/probe"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		slog.New(slog.NewTextHandler(os.Stderr, nil)).Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configFile  = flag.String("config.file", env("LATENCY_EXPORTER_CONFIG", "config.yml"), "Path to the YAML target configuration.")
		listenAddr  = flag.String("web.listen-address", env("LATENCY_EXPORTER_ADDR", ":9428"), "Address to expose metrics on.")
		metricsPath = flag.String("web.telemetry-path", env("LATENCY_EXPORTER_PATH", "/metrics"), "Path under which to expose metrics.")
		logLevel    = flag.String("log.level", env("LATENCY_EXPORTER_LOG_LEVEL", "info"), "Log level: debug, info, warn or error.")
		checkConfig = flag.Bool("config.check", false, "Validate the configuration and exit.")
		showVersion = flag.Bool("version", false, "Print version and exit.")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("latency_exporter %s\n", version)
		return nil
	}

	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		return fmt.Errorf("log.level: %w", err)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	cfg, err := config.Load(*configFile)
	if err != nil {
		return err
	}
	targets := make([]exporter.Target, 0, len(cfg.Targets))
	var errs []error
	for i := range cfg.Targets {
		t := &cfg.Targets[i]
		p, err := probe.New(t)
		if err != nil {
			errs = append(errs, fmt.Errorf("target %s: %w", t.Name, err))
			continue
		}
		targets = append(targets, exporter.Target{Name: t.Name, Type: t.Type, Interval: t.Interval, Timeout: t.Timeout, Prober: p})
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("%s: %w", *configFile, err)
	}
	if *checkConfig {
		fmt.Printf("%s: %d targets OK\n", *configFile, len(targets))
		return nil
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "latency_exporter_build_info",
		Help: "Build information for latency_exporter.",
	}, []string{"version", "goversion"})
	buildInfo.WithLabelValues(version, runtime.Version()).Set(1)
	reg.MustRegister(buildInfo)
	metrics := exporter.NewMetrics(reg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	mux := http.NewServeMux()
	mux.Handle(*metricsPath, promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}))
	if *metricsPath != "/" {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			path := html.EscapeString(*metricsPath)
			_, _ = fmt.Fprintf(w, "<html><head><title>latency_exporter</title></head><body><h1>latency_exporter</h1><p><a href=%q>%s</a></p></body></html>\n", path, path)
		})
	}
	srv := &http.Server{
		Addr:              *listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	logger.Info("starting latency_exporter", "version", version, "listen", ln.Addr().String(), "targets", len(targets), "types", summarize(targets))

	done := make(chan struct{})
	go func() {
		exporter.Run(ctx, logger, metrics, targets)
		close(done)
	}()

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	select {
	case err := <-serveErr:
		stop()
		<-done
		return fmt.Errorf("http server: %w", err)
	case <-ctx.Done():
	}

	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("http shutdown", "err", err)
	}
	<-done
	return nil
}

func summarize(targets []exporter.Target) string {
	counts := map[string]int{}
	for _, t := range targets {
		counts[t.Type]++
	}
	var parts []string
	for _, typ := range []string{config.TypeICMP, config.TypeHTTP, config.TypeDNS, config.TypeTCP} {
		if counts[typ] > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", typ, counts[typ]))
		}
	}
	return strings.Join(parts, " ")
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}
