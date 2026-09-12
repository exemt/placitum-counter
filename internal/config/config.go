/*
 * Конфигурация из переменных окружения.
 *
 * Всё, что можно проверить до первого сообщения, проверяется здесь: инспектор,
 * который тихо пропускает трафик из-за опечатки в пути к профилям, хуже не
 * запустившегося. Поэтому Load() возвращает ошибку, а не значение по умолчанию,
 * на каждом нераспознанном значении.
 */

package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/exemt/placitum-shared/loglevel"
)

type Config struct {
	Servers []string
	Subject string
	Name    string
	Queue   string

	ProfilesDir string
	DataDir     string

	// ReloadEvery -- период опроса отпечатка каталога профилей. Ноль
	// выключает опрос: поколение приезжает из KV, и на ноде без контроллера
	// профили правят вручную с рестартом.
	ReloadEvery time.Duration

	// Пул воркеров и очередь перед ним -- это и есть admission control:
	// отменить идущий разбор нельзя, поэтому единственная возможная проверка
	// бюджета -- на входе.
	Workers     int
	QueueDepth  int
	QueueFull   string
	QueueExpand string
	ConfPath    string

	ReserveMS   int
	MinBudgetMS int

	RedisURL string

	// BucketsURL -- Redis корзин: внутренний Redis контура, рядом с корзинами
	// капчи и роастером, отдельно от обменника объектов. Источник -- в
	// BucketsFrom: REDIS_INTERNAL_URL, путь
	// inspector.conf с internal блока redis или REDIS_URL, когда адреса нет.
	BucketsURL  string
	BucketsFrom string

	/*
	 * GeoAddr -- gRPC-адрес кодера гео внутри контура (host:port): из него
	 * резолвятся анонсированная подсеть и номер автономной системы -- оси
	 * asn_net и asn_router плюс инициаторы с write: net|asn. Пусто -- эти оси
	 * и записи молчат, остальное работает как обычно.
	 * GeoTimeout -- сколько ждать кодер на промахе; ожидание синхронное и
	 * в бюджете сообщения.
	 */
	GeoAddr    string
	GeoTimeout time.Duration
	/*
	 * GeoNegMax -- потолок отрицательного кэша резолвера: сколько адресов,
	 * о которых кодер ничего не знает, помнить, чтобы не спрашивать снова.
	 * На потолке кэш вытесняется, а не сбрасывается целиком. 0 -- умолчание
	 * резолвера.
	 */
	GeoNegMax int

	Versions []int
	LogLevel slog.Level

	// Пульс присутствия на WAF_STATUS. Тот же период, что у агента.
	HeartbeatEvery time.Duration
}

// RedisTimeout ограничивает чтение объекта обменника по локатору. Значение
// заведомо меньше типичного дедлайна: тело, приехавшее после того, как модуль
// перестал ждать, не нужно никому.
const RedisTimeout = 20 * time.Millisecond

// BucketsTimeout ограничивает поход корзин: не успели -- счёт уходит в
// локальную книгу, а не двигает дедлайн волны.
const BucketsTimeout = 15 * time.Millisecond

func Load() (*Config, error) {
	c := &Config{
		Servers:     splitList(env("NATS_URL", "nats://127.0.0.1:4222")),
		Subject:     env("WAF_COUNTER_SUBJECT", "waf.req.counter"),
		Name:        env("WAF_COUNTER_NAME", "counter"),
		ProfilesDir: env("WAF_COUNTER_PROFILES", "./profiles"),
		DataDir:     env("WAF_COUNTER_DATA", ""),
		GeoAddr:     env("WAF_COUNTER_GEO_ADDR", ""),
	}

	c.Queue = env("WAF_COUNTER_QUEUE", c.Name)

	var err error

	if c.Workers, err = envInt("WAF_COUNTER_WORKERS", runtime.GOMAXPROCS(0)); err != nil {
		return nil, err
	}

	/*
	 * Глубина очереди -- произведение числа воркеров на запас в четыре
	 * сообщения. Очередь длиннее этого не ускоряет никого: сообщение,
	 * дождавшееся своей очереди, к тому времени уже потеряет бюджет и будет
	 * отброшено вторым порогом. inspector.conf и WAF_COUNTER_QUEUE_DEPTH
	 * перекрывают расчёт.
	 */
	q := queueSettings{
		/*
		 * 256, а не производная от числа воркеров: это число задаёт не только
		 * свою очередь, но и буфер подписки клиента NATS (queue_max + workers
		 * + 2), а буфер меряется темпом прихода на паузу, которую горутина
		 * доставки может пропустить, -- не тем, сколько воркеров за ней стоит.
		 * Прежние workers*8 давали 16 сообщений, это ~2 мс терпения на 10 000
		 * сообщений в секунду, и сообщения терялись молча на обычном дрожании.
		 */
		Max:    256,
		Full:   QueueFullDrop,
		Expand: QueueExpandOff,
	}

	var file queueFile

	c.ConfPath = confPath("WAF_COUNTER_CONF")
	if c.ConfPath != "" {
		var ferr error
		if file, ferr = loadQueueFile(c.ConfPath); ferr != nil {
			return nil, ferr
		}

		applyQueueFile(&q, file)
	}

	// Адреса -- блок redis в inspector.conf, env перекрывает: общий обменник
	// (url, REDIS_URL) для снимка запроса, внутренний (internal,
	// REDIS_INTERNAL_URL) для корзин; без internal -- обменник с
	// предупреждением при старте.
	c.RedisURL = exchangeRedis(file)
	c.BucketsURL, c.BucketsFrom = internalRedis(c.ConfPath, file, c.RedisURL)

	if q.Max, err = envIntIfSet("WAF_COUNTER_QUEUE_DEPTH", q.Max); err != nil {
		return nil, err
	}

	c.QueueDepth = q.Max
	c.QueueFull = envOverride("WAF_COUNTER_QUEUE_FULL", q.Full)
	c.QueueExpand = envOverride("WAF_COUNTER_QUEUE_EXPAND", q.Expand)

	if c.ReserveMS, err = envInt("WAF_COUNTER_RESERVE_MS", 2); err != nil {
		return nil, err
	}

	if c.MinBudgetMS, err = envInt("WAF_COUNTER_MIN_BUDGET_MS", 2); err != nil {
		return nil, err
	}

	if c.Versions, err = envIntList("WAF_COUNTER_VERSIONS", []int{2}); err != nil {
		return nil, err
	}

	if c.LogLevel, err = parseLevel(env("WAF_COUNTER_LOG", "info")); err != nil {
		return nil, err
	}

	if c.GeoTimeout, err = envDuration("WAF_COUNTER_GEO_TIMEOUT", 500*time.Millisecond); err != nil {
		return nil, err
	}

	if c.GeoNegMax, err = envInt("WAF_COUNTER_GEO_NEG_MAX", 0); err != nil {
		return nil, err
	}

	if c.HeartbeatEvery, err = envDuration("WAF_HEARTBEAT_EVERY", 4*time.Second); err != nil {
		return nil, err
	}

	if c.ReloadEvery, err = envDurationOrZero("WAF_COUNTER_RELOAD_EVERY", time.Second); err != nil {
		return nil, err
	}

	return c, c.validate()
}

func (c *Config) validate() error {
	if len(c.Servers) == 0 {
		return fmt.Errorf("NATS_URL is empty")
	}

	if c.Subject == "" || c.Name == "" || c.Queue == "" {
		return fmt.Errorf("subject, name and queue must not be empty")
	}

	if c.Workers < 1 {
		return fmt.Errorf("WAF_COUNTER_WORKERS must be positive, got %d", c.Workers)
	}

	if c.QueueDepth < 1 {
		return fmt.Errorf("queue_max must be positive, got %d", c.QueueDepth)
	}

	switch c.QueueFull {
	case QueueFullDrop, QueueFullWait:
	default:
		return fmt.Errorf("queue_full must be drop or wait, got %q", c.QueueFull)
	}

	switch c.QueueExpand {
	case QueueExpandOff, QueueExpandAsk:
	default:
		return fmt.Errorf("queue_expand must be off or ask, got %q", c.QueueExpand)
	}

	if c.ReserveMS < 0 || c.MinBudgetMS < 0 {
		return fmt.Errorf("WAF_COUNTER_RESERVE_MS and WAF_COUNTER_MIN_BUDGET_MS must not be negative")
	}

	if len(c.Versions) == 0 {
		return fmt.Errorf("WAF_COUNTER_VERSIONS is empty")
	}

	abs, err := filepath.Abs(c.ProfilesDir)
	if err != nil {
		return fmt.Errorf("WAF_COUNTER_PROFILES: %w", err)
	}

	c.ProfilesDir = abs

	if c.DataDir == "" {
		c.DataDir = abs + ".applied"
	}

	data, err := filepath.Abs(c.DataDir)
	if err != nil {
		return fmt.Errorf("WAF_COUNTER_DATA: %w", err)
	}

	c.DataDir = data

	return nil
}

// Supports сообщает, берётся ли инспектор обрабатывать эту версию схемы.
// Незнакомая версия -- это ответ с причиной, а не молчание: молчание для модуля
// неотличимо от перегрузки и стоит ему полного дедлайна.
func (c *Config) Supports(v int) bool {
	for _, known := range c.Versions {
		if known == v {
			return true
		}
	}

	return false
}

func env(name, def string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}

	return def
}

func envInt(name string, def int) (int, error) {
	return envIntIfSet(name, def)
}

func envIntIfSet(name string, def int) (int, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return def, nil
	}

	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}

	return v, nil
}

func envIntList(name string, def []int) ([]int, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return def, nil
	}

	var out []int

	for _, part := range splitList(raw) {
		v, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}

		out = append(out, v)
	}

	return out, nil
}

func envDuration(name string, def time.Duration) (time.Duration, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return def, nil
	}

	d, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}

	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive", name)
	}

	return d, nil
}

// envDurationOrZero отличается от envDuration ровно нулём: "0" здесь --
// осмысленное значение «не опрашивать», а не ошибка.
func envDurationOrZero(name string, def time.Duration) (time.Duration, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return def, nil
	}

	d, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}

	if d < 0 {
		return 0, fmt.Errorf("%s must not be negative", name)
	}

	return d, nil
}

func splitList(s string) []string {
	var out []string

	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}

	return out
}

/*
 * Стартовый порог журнала: словарь error_log nginx без emerg
 * (internal/loglevel). Поколение из KV переставляет порог живьём, переменная
 * действует до первого поколения с блоком settings.
 */
func parseLevel(s string) (slog.Level, error) {
	level, err := loglevel.Parse(s)
	if err != nil {
		return 0, fmt.Errorf("WAF_COUNTER_LOG: %w", err)
	}

	return level, nil
}
