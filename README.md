# Placitum counter

English · [Русский](README.ru.md)

Placitum behavioural inspector. Request-phase inspectors evaluate intent: what the client sent. The
counter evaluates the result: what the client took away. A scraper walking through a catalog with
legitimate requests looks like a shopper to signatures, and only the total tells them apart.

One subject, three phases:

```
response  ──►  measure: the response becomes bucket charges (how many objects, how many kilobytes)
request   ──►  judge:   bucket levels against thresholds → score | deny | actions for neighbours
frames    ──►  both on every WebSocket frame; the conn axis lives until the connection ends
```

Buckets live in the internal Redis (GCRA, the same arithmetic as captcha). Counters are declared
per inspector, not per profile, in the shared section `profiles/_shared/counters.yaml`; profile
thresholds are percentages of fill.

When there is nothing to measure (a broken message, an unsupported version, an unknown profile, a
silent bucket Redis), the answer is `verdict: error`, and the route chooses between pass and deny.

## Axes

| Axis | Subject |
| --- | --- |
| `ip` | client address |
| `asn_net`, `asn_router` | the announcement and the autonomous system of the address (needs `geo`) |
| `sess` | a session key, by default the captcha clearance id cookie `waf_cid` |
| `user` | a client key from a cookie or header, or the identity from the login gate (`session:user`, `session:sid`) |
| `conn` | a WebSocket connection, until it closes |

## Build

```sh
docker build -f deploy/Dockerfile -t placitum/counter .
```

The image carries a probe: its `HEALTHCHECK` sends an ordinary bus message with the `_probe`
profile and expects `deny`, checking the bus, the subscription, the profiles and the workers at
once.

What it needs and all settings are in [INSTALL.md](INSTALL.md).

## Layout

```
cmd/inspector/     bus, waf.req.counter, all phases; axis keys
cmd/probe/         health check: profile _probe with threshold 0
internal/buckets/  GCRA buckets
internal/measure/  response phase rules: predicate → source → charge
internal/decide/   evaluation by levels and neighbour signals, pure functions
internal/config/   environment, counters.yaml, profiles and hot reload
internal/desired/  generation from KV (policy/counter)
profiles/          _shared/counters.yaml, default, _probe
```

Shared process code (presence frame, machine snapshot, flow counters, log levels, network directory
client) comes from [`placitum-shared`](https://github.com/exemt/placitum-shared).

## License

[Placitum License Agreement](LICENSE.md). A Russian translation is in [LICENSE.ru.md](LICENSE.ru.md);
the English text is the legally binding one.
