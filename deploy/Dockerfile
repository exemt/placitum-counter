FROM golang:1.25-alpine AS build

WORKDIR /src

ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ENV CGO_ENABLED=0

ARG VERSION=dev
ARG REVISION=unknown
RUN go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/counter ./cmd/inspector && \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/counter-probe ./cmd/probe

FROM alpine:3.22

ARG VERSION=dev
ARG REVISION=unknown

LABEL org.opencontainers.image.title="placitum/counter" \
      org.opencontainers.image.description="Placitum counter inspector: behavioural score of what the client received" \
      org.opencontainers.image.source="https://github.com/exemt/placitum-counter" \
      org.opencontainers.image.licenses="LicenseRef-Placitum" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

WORKDIR /app

COPY --from=build /out/counter /out/counter-probe /usr/local/bin/
COPY profiles ./profiles
COPY inspector.conf ./inspector.conf

RUN adduser -D -H -u 10001 counter && \
    mkdir -p /var/lib/waf/counter && \
    chown -R counter:counter /var/lib/waf
USER counter

ENV NATS_URL=nats://nats:4222 \
    WAF_COUNTER_SUBJECT=waf.req.counter \
    WAF_COUNTER_NAME=counter \
    WAF_COUNTER_PROFILES=/app/profiles \
    WAF_COUNTER_DATA=/var/lib/waf/counter \
    WAF_COUNTER_LOG=info

HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=3 \
    CMD ["counter-probe", "--quiet", "--timeout", "1s", "--uri", "/healthcheck"]

CMD ["counter"]
