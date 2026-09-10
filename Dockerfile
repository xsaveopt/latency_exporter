FROM golang:1.27-alpine3.24 AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/latency_exporter .

FROM alpine:3.24
RUN apk add --no-cache bash tzdata \
 && addgroup -S -g 10001 latency \
 && adduser -S -D -H -u 10001 -G latency -s /sbin/nologin latency
COPY --from=build /out/latency_exporter /usr/local/bin/latency_exporter
COPY --chmod=0755 docker/entrypoint.sh /usr/local/bin/entrypoint.sh
ENV LATENCY_EXPORTER_CONFIG=/config/config.yml
EXPOSE 9428
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
