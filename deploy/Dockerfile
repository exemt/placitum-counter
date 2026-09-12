# Контекст сборки -- корень инспектора (inspectors/counter), не корень
# репозитория: модуль Go самостоятелен и ничего оттуда не берёт.
#
#     docker build -f deploy/Dockerfile -t placitum/counter .
#     docker buildx build -f deploy/Dockerfile -t placitum/counter \
#         "https://github.com/exemt/placitum-counter.git#develop"

FROM golang:1.25-alpine AS build

WORKDIR /src

# Прокси модулей -- аргументом: в изолированном контуре подставляют своё зеркало.
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}

# Зависимости отдельным слоем: они меняются на порядок реже кода.
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

# CGO не нужен: NATS, Redis и разбор YAML -- чистый Go. Отсюда и статический
# бинарник, и возможность собрать образ без libc.
ENV CGO_ENABLED=0

# Профили из образа обязаны подниматься: опечатка в counters.yaml иначе
# ловится только стартом контейнера.
COPY profiles ./profiles

RUN go test ./...

# Сборка в бинарь: версия и ревизия видны в журнале старта и в кадре
# присутствия, а не только в метках образа.
ARG VERSION=dev
ARG REVISION=unknown
RUN go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/counter ./cmd/inspector && \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/counter-probe ./cmd/probe

FROM alpine:3.22

# Версия и ревизия приходят снаружи: .git в контекст сборки не попадает.
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

# Проба идёт тем же путём, что и реальная инспекция: вердикт в ответе означает,
# что живы соединение с шиной, подписка, профили и пул воркеров. TCP-пинг до
# NATS не сказал бы ни про одно из этого.
#
# Профиль _probe держит правило с порогом 0: deny приходит с пустой корзины,
# без Redis и без трафика.
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=3 \
    CMD ["counter-probe", "--quiet", "--timeout", "1s", "--uri", "/healthcheck"]

CMD ["counter"]
