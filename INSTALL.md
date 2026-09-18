# Installation

English · [Русский](INSTALL.ru.md)

The inspector does not listen on the network: it is a queue subscriber on the bus. It needs no
address and no service, and adding a copy touches neither the protection node nor the
configuration. Usually `placitum-core` installs it.

## What it needs

| Component | Required | Why |
| --- | --- | --- |
| NATS | yes | the `waf.req.counter` queue, audit, log, profile generations |
| Internal Redis | yes | `cnt:bkt:*` buckets; without it evaluation answers `verdict: error` |
| Buffer Redis | for the `sess` and `user` axes and body rules | request and response snapshot by locator |
| `geo` | for the `asn_net` and `asn_router` axes and `net`/`asn` writes | announcements and AS number by address |
| Controller | yes | sends profiles and the shared counter section as generations |

## Settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `NATS_URL` | `nats://127.0.0.1:4222` | bus |
| `REDIS_URL` | from `inspector.conf` | buffer: request and response snapshot |
| `REDIS_INTERNAL_URL` | from `inspector.conf` | internal Redis: buckets |
| `WAF_COUNTER_SUBJECT` | `waf.req.counter` | subscription; one for all phases, branched by `phase` in the message |
| `WAF_COUNTER_NAME` | `counter` | name in the inspector registry and the presence frame |
| `WAF_COUNTER_PROFILES` | `./profiles`; `/app/profiles` in the image | profile directory |
| `WAF_COUNTER_DATA` | `<profiles>.applied`; `/var/lib/waf/counter` in the image | where rollout puts the applied generation |
| `WAF_COUNTER_GEO_ADDR` | empty | network directory (`host:port`); empty keeps the `asn_net` and `asn_router` axes silent, the others work |
| `WAF_COUNTER_GEO_TIMEOUT` | `500ms` | network directory wait within the message budget |
| `WAF_COUNTER_GEO_NEG_MAX` | `0` | negative cache limit of the network directory client; `0` means the default |
| `WAF_COUNTER_LOG` | `info` | starting log level; the panel changes it live |
| `WAF_COUNTER_VERSIONS` | `2` | accepted message schema versions |
| `WAF_COUNTER_WORKERS` | number of CPUs | pool workers |
| `WAF_COUNTER_QUEUE_DEPTH`, `WAF_COUNTER_QUEUE_FULL`, `WAF_COUNTER_QUEUE_EXPAND` | `256`, `drop`, `off` | queue; the same through `inspector.conf` |
| `WAF_COUNTER_RESERVE_MS`, `WAF_COUNTER_MIN_BUDGET_MS` | `2`, `2` | budget reserve for the answer and the minimum budget below which a message is not taken |
| `WAF_COUNTER_RELOAD_EVERY` | `1s` | how often to check the profile directory |
| `WAF_COUNTER_CONF` | `inspector.conf` in the working directory, then `/app/inspector.conf` | queue and Redis settings |

`inspector.conf` in the image names both Redis instances by their compose service names; the
environment overrides it.

## Docker Compose

```yaml
services:
  inspector-counter:
    image: placitum/counter
    scale: 2
    environment:
      NATS_URL: nats://nats:4222
      REDIS_URL: redis://redis:6379
      REDIS_INTERNAL_URL: redis://redis-internal:6379
      WAF_COUNTER_GEO_ADDR: geo:50051
      WAF_COUNTER_LOG: info
    depends_on: [nats, redis, redis-internal]
```

## Route

Put the counter **before** the receivers of its actions, such as captcha and modsec: neighbours on
the same wave do not see actions. The response phase is enabled separately and needs a snapshot of
the response headers:

```nginx
waf_inspector counter subject=waf.req.counter;

location /api/ {
    waf_inspect ip       wave=0 timeout=5ms;
    waf_inspect counter  wave=1 timeout=10ms;            # evaluates and sends actions
    waf_inspect captcha  wave=2 timeout=10ms;
    waf_inspect response counter wave=0 timeout=10ms;    # measures
    waf_capture response headers;
}
```

The `sess` and `user` axes need the route to capture request headers; counting matches in the body
needs a preview of the response body. Size in kilobytes works without the body.

## Checking

```sh
docker exec <container> counter-probe --quiet --timeout 1s --uri /healthcheck
```

The probe takes the same path as a real inspection and gets `deny` from an empty bucket, without
Redis and without traffic. A healthy start logs the bus connection, the loaded profiles and the
worker count, then a presence frame every four seconds.

## Pitfalls

- **Requests denied earlier do not charge buckets.** Only what the client actually received reaches
  the response phase, so a counter behind a denying route shows less than the logs.
- **Blind spot of the response phase.** Routes where the module passes the response through (`sse`,
  `upgrade`, a body that is too large) are not measured at all.
- **The `_probe` profile ships in the image, not in generations.** A generation does not carry it;
  the process adds it from the image directory, and if that breaks the container turns `unhealthy`
  while the inspector is fully alive.
