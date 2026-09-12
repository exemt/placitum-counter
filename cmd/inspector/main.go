/*
 * Точка входа инспектора счётчика.
 *
 * Здесь только инициализация и подписка: решения принимают пакеты internal/...,
 * а этот файл собирает их в конвейер и следит, чтобы ответ уходил на каждом
 * пути без исключения.
 *
 * Порядок инициализации важен: профили и объявления счётчиков разбираются до
 * подписки. Опечатка в counters.yaml обязана обнаруживаться при старте, а не
 * на первом сообщении -- инспектор, который из-за неё молча не считает, хуже
 * отказавшего.
 */

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-counter/internal/audit"
	"github.com/exemt/placitum-counter/internal/body"
	"github.com/exemt/placitum-counter/internal/buckets"
	"github.com/exemt/placitum-counter/internal/config"
	"github.com/exemt/placitum-counter/internal/desired"
	"github.com/exemt/placitum-counter/internal/queue"
	"github.com/exemt/placitum-shared/dataset"
	"github.com/exemt/placitum-shared/flow"
	"github.com/exemt/placitum-shared/logkit"
	"github.com/exemt/placitum-shared/netinfo"
	"github.com/exemt/placitum-shared/pulse"
)

func main() {
	if err := run(); err != nil {
		slog.Error("startup failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	/*
	 * Журнал процесса уезжает в waf.log той же пачкой, что и строки nginx:
	 * контур один, и искать причину отказа по трём десяткам docker-логов
	 * незачем. Приёмник поднимается раньше шины -- строки о том, как читался
	 * конфиг, копятся и уезжают первой же пачкой. Копия, не перенос: stdout
	 * остаётся на месте.
	 */
	var (
		logs  *logkit.Sink
		logIO *flow.Counter
	)

	if config.LogShip() {
		logIO = flow.New()
		logs = logkit.NewSink(config.LogWriter(cfg.Name), cfg.Name, logIO)

		defer logs.Close()
	}

	/*
	 * Порог журнала живой: поколение из KV переставляет его без рестарта
	 * (internal/loglevel). Переменная окружения задаёт стартовое значение.
	 */
	level := new(slog.LevelVar)
	level.Set(cfg.LogLevel)

	log := slog.New(slog.NewJSONHandler(logs.Tee(os.Stdout),
		&slog.HandlerOptions{Level: level}))
	slog.SetDefault(log)

	store, err := config.LoadProfiles(cfg.ProfilesDir, log)
	if err != nil {
		return err
	}

	snap := store.Current()

	for _, p := range snap.All() {
		log.Info("profile loaded",
			"profile", p.Name,
			"mode", p.Mode,
			"judge", len(p.Request.Judge),
			"measure", len(p.Response.Measure),
			"request", p.Request.Enabled,
			"response", p.Response.Enabled,
		)
	}

	log.Info("counters declared", "counters", len(snap.Counters().Counters))

	/*
	 * Применённое поколение поднимается до подписки: рестарт до того, как watch
	 * догнал KV, не должен откатывать процесс на файлы из образа.
	 */
	if desired.Bootstrap(store, cfg.DataDir, log) {
		snap = store.Current()
	}

	loader, closeStore, err := bodyLoader(cfg, log)
	if err != nil {
		return err
	}

	defer closeStore()

	nc, err := nats.Connect(strings.Join(cfg.Servers, ","),
		nats.Name("waf-inspector-"+cfg.Name),
		// Инспектор переживает перезапуск шины, а не умирает вместе с ней.
		nats.MaxReconnects(-1),
		nats.ReconnectWait(500*time.Millisecond),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			log.Warn("bus disconnected", "error", errText(err))
		}),
		nats.ReconnectHandler(func(c *nats.Conn) {
			log.Info("bus reconnected", "server", c.ConnectedUrl())
		}),
	)
	if err != nil {
		return err
	}

	defer nc.Close()

	if err := audit.Ensure(nc); err != nil {
		log.Warn("audit stream", "error", err.Error())
	}

	/*
	 * Поток журнала заводит тот писатель, который пришёл первым: на контуре,
	 * где ни одна нода ещё не поднялась, им оказывается инспектор. Публикация
	 * в несуществующий поток -- тишина, а не ошибка.
	 */
	if logs != nil {
		if err := logkit.Ensure(nc); err != nil {
			log.Warn("log stream", "error", err.Error())
		}

		logs.Attach(nc)
		log.Info("log stream", "stream", logkit.Stream,
			"subject", logkit.Subject(logs.Writer()))
	}

	/*
	 * Публикатор наборов создаётся всегда, когда есть шина: профиль с
	 * инициатором «на отказе -- в набор» может приехать из KV после старта, и
	 * решать это на старте значило бы требовать перезапуска на правку профиля.
	 */
	/*
	 * Резолвер подсети и системы: нужен только строкам инициаторов с
	 * write: net|asn. Без адреса сервиса гео он nil -- такие строки молчат,
	 * остальное работает.
	 */
	var resolver *netinfo.Resolver

	if cfg.GeoAddr != "" {
		var rerr error

		resolver, rerr = netinfo.New(cfg.GeoAddr, cfg.GeoTimeout, cfg.GeoNegMax, log)
		if rerr != nil {
			return fmt.Errorf("geo resolver: %w", rerr)
		}

		defer resolver.Close()
	}

	/*
	 * Корзины. Без адреса Redis экземпляр считает в своей памяти -- каждая
	 * реплика видит свою долю трафика, и это ровно та слепота, от которой
	 * общий счёт заводился, -- поэтому предупреждение обязано быть громким.
	 */
	config.LogInternalRedis(log, cfg.BucketsURL, cfg.BucketsFrom)
	bkt := buckets.New(nil, config.BucketsTimeout)

	if cfg.BucketsURL != "" {
		bkt, err = buckets.Dial(cfg.BucketsURL, config.BucketsTimeout)
		if err != nil {
			return err
		}

		log.Info("buckets store connected", "driver", "redis")
	} else {
		log.Warn("buckets store is not configured",
			"detail", "no internal redis and no REDIS_URL: every instance counts alone, in memory")
	}

	/*
	 * События аудита уезжают пачками, а не по одной на инспекцию: при четырёх
	 * инспекторах в наборе это впятеро больше сообщений, чем запросов, и
	 * партия из одного сообщения кладёт вставку у потребителя.
	 *
	 * Закрывается после пула: в очереди события уже отвеченных запросов.
	 */
	auditSink := audit.NewSink(nc, log)

	h := &handler{cfg: cfg, log: log, nc: nc,
		audit: auditSink, store: store, loader: loader, bkt: bkt,
		lists: dataset.NewBackground(nc, cfg.Name, log), resolver: resolver}

	pool := queue.New(cfg.Workers, cfg.QueueDepth, cfg.ReserveMS, cfg.MinBudgetMS,
		cfg.QueueFull, h.evaluate)
	h.pool = pool

	// Queue group: горизонтальное масштабирование без координации. Ответ уходит
	// в инбокс того воркера nginx, который спрашивал, потому что его имя
	// приехало в reply-to.
	sub, err := nc.QueueSubscribe(cfg.Subject, cfg.Queue, h.receive)
	if err != nil {
		return err
	}

	// Забираем с шины сразу. pending -- запас на полёт в колбэк, не очередь:
	// прокисшие выкидываем из pool, слот занимает свежий запрос.
	if err := sub.SetPendingLimits(cfg.QueueDepth+cfg.Workers+2, 8*1024*1024); err != nil {
		return err
	}

	log.Info("connected",
		"server", nc.ConnectedUrl(),
		"subject", cfg.Subject,
		"queue", cfg.Queue,
		"inspector", cfg.Name,
		"profiles", snap.Names(),
		"workers", cfg.Workers,
		"queue_max", cfg.QueueDepth,
		"queue_full", cfg.QueueFull,
		"conf", cfg.ConfPath,
	)

	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	// Опрос отпечатка каталога: профили правят руками там, где контроллера нет.
	go store.Watch(ctx, cfg.ReloadEvery)

	var applied *desired.Applied

	applied, err = desired.Watch(ctx, nc, store, cfg.DataDir, level, log)
	if err != nil {
		log.Warn("desired watch failed", "error", err.Error())
	} else {
		log.Info("desired watch on",
			"bucket", desired.Bucket,
			"key", desired.Key,
			"data", cfg.DataDir,
		)
	}

	inspectorID := pulse.NewID()
	stopBeat := startHeartbeat(nc, cfg, inspectorID, pool, applied, store, logIO, log)

	defer stopBeat()

	waitForSignal(log)
	stop()

	/*
	 * Дренаж: сначала снимается подписка, потом воркеры дожидаются принятых
	 * сообщений. Без него reload инспектора выглядит на стороне модуля как
	 * всплеск срабатываний политики waf_deadline на его subject.
	 */
	if err := sub.Drain(); err != nil {
		log.Warn("drain failed", "error", err.Error())
	}

	pool.Close()
	auditSink.Close()

	log.Info("drained",
		"accepted", pool.Accepted.Load(),
		"shed", pool.Shed.Load(),
		"expired", pool.Expired.Load(),
	)

	return nil
}

func bodyLoader(cfg *config.Config, log *slog.Logger) (*body.Loader, func(), error) {
	if cfg.RedisURL == "" {
		/*
		 * Без обменника инспектор бесполезен: тело едет локатором, и проверять
		 * ему нечего. Ошибкой старта это всё же не делается -- контур может
		 * подниматься по частям, -- но предупреждение обязано быть громким.
		 */
		log.Warn("body store is not configured",
			"detail", "REDIS_URL is empty: every body will be reported as unavailable")

		return body.NewLoader(nil, nil), func() {}, nil
	}

	store, err := body.NewRedisStore(cfg.RedisURL, config.RedisTimeout)
	if err != nil {
		return nil, nil, err
	}

	// Недостижимое хранилище -- ошибка старта, а не сюрприз на первом теле.
	if err := store.Ping(context.Background()); err != nil {
		return nil, nil, err
	}

	log.Info("body store connected", "driver", "redis")

	return body.NewLoader(store, nil), func() { _ = store.Close() }, nil
}

func startHeartbeat(
	nc *nats.Conn,
	cfg *config.Config,
	id string,
	pool *queue.Pool,
	applied *desired.Applied,
	store *config.Store,
	logIO *flow.Counter,
	log *slog.Logger,
) func() {
	subject := pulse.Subject(cfg.Name, id)
	log.Info("heartbeat on", "subject", subject, "id", id, "every", cfg.HeartbeatEvery.String())

	beat := func() {
		work := &pulse.Work{
			Workers:    cfg.Workers,
			QueueDepth: cfg.QueueDepth,
			Queued:     pool.Queued(),
			Accepted:   pool.Accepted.Load(),
			Shed:       pool.Shed.Load(),
			Expired:    pool.Expired.Load(),
		}

		io := map[string]flow.Flow{"inspect": pool.IO()}

		// Канал журнала -- там же, где темп инспекции: потерянная строка
		// видна ошибкой канала, и это единственное место, где её видно.
		// Сам приёмник о своих потерях молчит по построению.
		if logIO != nil {
			io["log"] = logIO.Snapshot()
		}
		msg := pulse.Build(id, cfg.Name, cfg.Subject, cfg.Queue, work, io)

		if hash, rev, apply, names := applied.Snapshot(); apply != "" {
			msg.ConfigHash = hash
			msg.Rev = rev
			msg.Apply = apply
			msg.Profiles = names
		} else {
			msg.Profiles = store.Current().Names()
		}

		if err := pulse.Publish(nc, msg); err != nil {
			log.Warn("heartbeat failed", "error", err.Error())
		}
	}

	beat()

	tick := time.NewTicker(cfg.HeartbeatEvery)
	done := make(chan struct{})

	go func() {
		for {
			select {
			case <-done:
				return
			case <-tick.C:
				beat()
			}
		}
	}()

	return func() {
		tick.Stop()
		close(done)
	}
}

func waitForSignal(log *slog.Logger) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)

	sig := <-ch
	log.Info("draining", "signal", sig.String())
}

func errText(err error) string {
	if err == nil {
		return ""
	}

	return err.Error()
}
