package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseQueueFile(t *testing.T) {
	got, err := parseQueueFile("t.conf", `
# comment
queue_max     16;
queue_full    drop;
queue_expand  off;
`)
	if err != nil {
		t.Fatal(err)
	}

	if got.Max == nil || *got.Max != 16 {
		t.Fatalf("max = %v", got.Max)
	}

	if got.Full != QueueFullDrop || got.Expand != QueueExpandOff {
		t.Fatalf("full=%q expand=%q", got.Full, got.Expand)
	}
}

func TestParseQueueFileWaitAsk(t *testing.T) {
	got, err := parseQueueFile("t.conf", "queue_full wait;\nqueue_expand ask;\n")
	if err != nil {
		t.Fatal(err)
	}

	if got.Full != QueueFullWait || got.Expand != QueueExpandAsk {
		t.Fatalf("full=%q expand=%q", got.Full, got.Expand)
	}
}

func TestParseQueueFileErrors(t *testing.T) {
	cases := []string{
		"queue_max 16",
		"queue_max 0;",
		"queue_full bounce;",
		"queue_expand yes;",
		"workers 4;",
		"queue_max 8;\nqueue_max 16;",
		// Плоской директивы больше нет: адреса только блоком redis.
		"redis_internal redis://redis-internal:6379;",
		"redis {\n    url redis://a:6379;\n",
		"}",
		"cache {\n}",
		"redis {\n}\nredis {\n}",
		"redis {\n    url http://a:6379;\n}",
		"redis {\n    url redis://;\n}",
		"redis {\n    url redis://a:6379\n}",
		"redis {\n    nodes a:6379;\n}",
		"redis {\n    url redis://a:6379;\n    url redis://b:6379;\n}",
		"redis {\n    internal redis://a:6379 redis://b:6379;\n}",
	}

	for _, src := range cases {
		if _, err := parseQueueFile("t.conf", src); err == nil {
			t.Fatalf("expected error for %q", src)
		}
	}
}

func TestLoadQueueFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inspector.conf")

	if err := os.WriteFile(path, []byte("queue_max 4;\nqueue_full wait;\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := loadQueueFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if got.Max == nil || *got.Max != 4 || got.Full != QueueFullWait {
		t.Fatalf("%+v", got)
	}
}

func TestParseRedisBlock(t *testing.T) {
	// CRLF: файлы стенда правят и на Windows, перевод строки не часть адреса.
	src := "queue_max 8;\r\n" +
		"redis {\r\n" +
		"    url       redis://redis:6379;            # общий обменник\r\n" +
		"    internal  rediss://u:p@redis-internal:6380/2;\r\n" +
		"}\r\n" +
		"queue_full wait;\r\n"

	got, err := parseQueueFile("t.conf", src)
	if err != nil {
		t.Fatal(err)
	}

	if got.RedisURL != "redis://redis:6379" || got.RedisInternal != "rediss://u:p@redis-internal:6380/2" {
		t.Fatalf("redis = %q / %q", got.RedisURL, got.RedisInternal)
	}

	if got.Max == nil || *got.Max != 8 || got.Full != QueueFullWait {
		t.Fatalf("queue after the block: %+v", got)
	}
}

func TestExchangeRedis(t *testing.T) {
	file := queueFile{RedisURL: "redis://from-file:6379"}

	t.Setenv("REDIS_URL", "redis://from-env:6379")
	if got := exchangeRedis(file); got != "redis://from-env:6379" {
		t.Fatalf("env: %q", got)
	}

	t.Setenv("REDIS_URL", "")
	if got := exchangeRedis(file); got != "redis://from-file:6379" {
		t.Fatalf("file: %q", got)
	}
}

func TestInternalRedisOrder(t *testing.T) {
	file := queueFile{RedisInternal: "redis://from-file:6379"}

	t.Setenv("REDIS_INTERNAL_URL", "redis://from-env:6379")
	if addr, from := internalRedis("/app/inspector.conf", file, "redis://exchange:6379"); addr != "redis://from-env:6379" || from != "REDIS_INTERNAL_URL" {
		t.Fatalf("env: %q from %q", addr, from)
	}

	t.Setenv("REDIS_INTERNAL_URL", "")
	if addr, from := internalRedis("/app/inspector.conf", file, "redis://exchange:6379"); addr != "redis://from-file:6379" || from != "/app/inspector.conf" {
		t.Fatalf("file: %q from %q", addr, from)
	}

	if addr, from := internalRedis("", queueFile{}, "redis://exchange:6379"); addr != "redis://exchange:6379" || from != InternalFromExchange {
		t.Fatalf("fallback: %q from %q", addr, from)
	}

	if addr, from := internalRedis("", queueFile{}, ""); addr != "" || from != "" {
		t.Fatalf("none: %q from %q", addr, from)
	}
}

func TestRedisKeyGuards(t *testing.T) {
	if err := noInternalRedis("t.conf", queueFile{RedisURL: "redis://x:6379"}); err != nil {
		t.Fatal(err)
	}

	if err := noInternalRedis("t.conf", queueFile{RedisInternal: "redis://x:6379"}); err == nil {
		t.Fatal("internal: expected error")
	}

	if err := noExchangeRedis("t.conf", queueFile{RedisInternal: "redis://x:6379"}); err != nil {
		t.Fatal(err)
	}

	if err := noExchangeRedis("t.conf", queueFile{RedisURL: "redis://x:6379"}); err == nil {
		t.Fatal("url: expected error")
	}
}

func TestRedactURL(t *testing.T) {
	if got := redactURL("redis://user:secret@redis-internal:6379/0"); strings.Contains(got, "secret") {
		t.Fatalf("password leaked: %q", got)
	}
}
