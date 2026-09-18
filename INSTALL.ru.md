# Установка

[English](INSTALL.md) · Русский

Инспектор не слушает сеть: он подписчик очереди на шине. Ни адреса, ни сервиса ему не нужно, и
добавление копии не трогает ни узел защиты, ни конфигурацию. Обычно его ставит `placitum-core`.

## Что нужно рядом

| Компонент | Обязателен | Зачем |
| --- | --- | --- |
| NATS | да | очередь `waf.req.counter`, аудит, журнал, поколение профилей |
| Redis: внутренний | да | бакеты `cnt:bkt:*`; без него оценка отвечает `verdict: error` |
| Redis: буфер | для осей `sess`, `user` и правил по телу | копия запроса и ответа по локатору |
| `geo` | для осей `asn_net`, `asn_router` и записи `net`/`asn` | анонсы и номер системы по адресу |
| Контроллер | да | шлёт профили и общую секцию счётчиков поколением |

## Настройки

| Переменная | По умолчанию | Что задаёт |
| --- | --- | --- |
| `NATS_URL` | `nats://127.0.0.1:4222` | шина |
| `REDIS_URL` | из `inspector.conf` | буфер: копия запроса и ответа |
| `REDIS_INTERNAL_URL` | из `inspector.conf` | внутренний Redis: бакеты |
| `WAF_COUNTER_SUBJECT` | `waf.req.counter` | подписка; одна на все фазы, ветка по `phase` в сообщении |
| `WAF_COUNTER_NAME` | `counter` | имя в реестре инспекторов и в кадре присутствия |
| `WAF_COUNTER_PROFILES` | `./profiles`; в образе `/app/profiles` | каталог профилей |
| `WAF_COUNTER_DATA` | `<профили>.applied`; в образе `/var/lib/waf/counter` | куда сохраняется применённое поколение |
| `WAF_COUNTER_GEO_ADDR` | пусто | справочник сетей (`host:port`); пусто — оси `asn_net` и `asn_router` молчат, остальные работают |
| `WAF_COUNTER_GEO_TIMEOUT` | `500ms` | ожидание справочника сетей в бюджете сообщения |
| `WAF_COUNTER_GEO_NEG_MAX` | `0` | предел отрицательного кэша клиента справочника сетей; `0` — умолчание |
| `WAF_COUNTER_LOG` | `info` | стартовый уровень журнала; живьём его переставляет панель |
| `WAF_COUNTER_VERSIONS` | `2` | версии схемы сообщения, которые процесс принимает |
| `WAF_COUNTER_WORKERS` | число ядер | воркеры пула |
| `WAF_COUNTER_QUEUE_DEPTH`, `WAF_COUNTER_QUEUE_FULL`, `WAF_COUNTER_QUEUE_EXPAND` | `256`, `drop`, `off` | очередь; то же через `inspector.conf` |
| `WAF_COUNTER_RESERVE_MS`, `WAF_COUNTER_MIN_BUDGET_MS` | `2`, `2` | запас бюджета на ответ и минимальный бюджет, ниже которого сообщение не берётся |
| `WAF_COUNTER_RELOAD_EVERY` | `1s` | как часто проверять каталог профилей |
| `WAF_COUNTER_CONF` | `inspector.conf` в рабочем каталоге, затем `/app/inspector.conf` | очередь и адреса Redis |

`inspector.conf` в образе называет оба Redis по именам сервисов compose; окружение его перекрывает.

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

## Маршрут

Счётчик ставят **раньше** получателей своих действий — капчи, modsec: действия соседям по своей
волне не видны. Фазу ответа включают отдельно, и для неё нужна копия заголовков ответа:

```nginx
waf_inspector counter subject=waf.req.counter;

location /api/ {
    waf_inspect ip       wave=0 timeout=5ms;
    waf_inspect counter  wave=1 timeout=10ms;            # оценивает и шлёт действия
    waf_inspect captcha  wave=2 timeout=10ms;
    waf_inspect response counter wave=0 timeout=10ms;    # меряет
    waf_capture response headers;
}
```

Для осей `sess` и `user` маршрут должен копировать заголовки запроса; для счёта совпадений в теле —
превью тела ответа. Размер в килобайтах работает и без тела.

## Проверка

```sh
docker exec <контейнер> counter-probe --quiet --timeout 1s --uri /healthcheck
```

Проба идёт тем же путём, что настоящая проверка, и получает `deny` с пустого бакета — без Redis и без
трафика. В журнале при здоровом старте: подключение к шине, загруженные профили, число воркеров;
дальше кадр присутствия каждые четыре секунды.

## Типичные ошибки

- **Заблокированные раньше запросы бакеты не наполняют.** До фазы ответа доходит только то, что клиент
  действительно получил, — поэтому счётчик за блокирующим маршрутом покажет меньше, чем логи.
- **Слепое пятно фазы ответа.** Маршруты, где модуль отдаёт ответ в обход (`sse`, `upgrade`,
  слишком большое тело), не меряются вовсе.
- **Профиль `_probe` уходит в образе, а не поколением.** Поколение его не передаёт; процесс подмешивает
  его из каталога образа сам, и если это сломать — контейнер станет `unhealthy` при полностью живом
  инспекторе.
