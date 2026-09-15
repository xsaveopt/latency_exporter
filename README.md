# latency_exporter

A Prometheus exporter that continuously measures ICMP, HTTP and DNS latency, along with TCP connect time and an optional TLS handshake.
Each target in the config file is probed on its own interval, separate from Prometheus scrapes, so /metrics returns the latency histograms and failure counters built up since the exporter started.
The probe series all start with latency\_ and are labelled by target, and failures are counted per reason such as timeout, refused, tls, status or rcode.

## Running

Images are published to ghcr.io/xsaveopt/latency_exporter, tagged latest and by version for each release, with dev tracking the main branch.
Copy config.example.yml to config.yml and edit the targets, then start the container with the docker-compose.yml in this repo, which mounts that file at /config/config.yml and serves metrics on port 9428.

## Environment variables

| Variable                     | Default      | Meaning                                                                   |
| ---------------------------- | ------------ | ------------------------------------------------------------------------- |
| `LATENCY_EXPORTER_CONFIG`    | `config.yml` | Path to the target config file, set to `/config/config.yml` in the image. |
| `LATENCY_EXPORTER_ADDR`      | `:9428`      | Address the metrics server listens on.                                    |
| `LATENCY_EXPORTER_PATH`      | `/metrics`   | Path the metrics are served under.                                        |
| `LATENCY_EXPORTER_LOG_LEVEL` | `info`       | Log level, one of `debug`, `info`, `warn` or `error`.                     |

## License

Licensed under the GPL-2.0, with the full text in LICENSE.
