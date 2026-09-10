# latency_exporter

A Prometheus exporter that continuously measures ICMP, HTTP, DNS and TCP/TLS latency.

Each target in the config file is probed on its own interval, independently of Prometheus scrapes, and /metrics returns the latency histograms and failure counters built up so far.
All series start with latency\_ and carry a target and type label, with failures counted per reason such as timeout, refused, tls, status or rcode.

## Configuration

Copy config.example.yml to config.yml and edit the targets.

## Environment variables

| Variable                     | Default              | Meaning                                        |
| ---------------------------- | -------------------- | ---------------------------------------------- |
| `LATENCY_EXPORTER_CONFIG`    | `/config/config.yml` | Path to the target config file.                |
| `LATENCY_EXPORTER_ADDR`      | `:9428`              | Address the metrics server listens on.         |
| `LATENCY_EXPORTER_PATH`      | `/metrics`           | Path the metrics are served under.             |
| `LATENCY_EXPORTER_LOG_LEVEL` | `info`               | Log level: `debug`, `info`, `warn` or `error`. |
