package main

import (
	"testing"

	"github.com/exemt/placitum-counter/internal/protocol"
)

/*
 * Ключ оси user из секции sessions: только проверенные записи, и выбор один и
 * тот же на каждом запросе -- иначе корзина человека прыгала бы между ключами
 * от волны к волне.
 */
func TestSessionValue(t *testing.T) {
	sessions := []protocol.Session{
		{Inspector: "gate", Source: "totp", User: "bob", ID: "sid-bob", Verified: true},
		{Inspector: "auth", Source: "corp", User: "alice", ID: "sid-alice", Verified: true},
		{Inspector: "auth", Source: "app", User: "root", ID: "sid-root", Verified: false},
	}

	if got := sessionValue(sessions, "user"); got != "alice" {
		t.Fatalf("user = %q, want the smallest (inspector, source) pair", got)
	}

	if got := sessionValue(sessions, "sid"); got != "sid-alice" {
		t.Fatalf("sid = %q, want the same session as the login", got)
	}

	// Порядок в массиве ничего не решает: ключ обязан быть тот же.
	shuffled := []protocol.Session{sessions[2], sessions[1], sessions[0]}

	if got := sessionValue(shuffled, "user"); got != "alice" {
		t.Fatalf("user = %q after reordering, want alice", got)
	}
}

// Непроверенная сессия -- это то, что клиент прислал сам: ключом счёта она не
// становится, и ось молчит, как при отсутствующей куке.
func TestSessionValueSkipsUnverified(t *testing.T) {
	sessions := []protocol.Session{
		{Inspector: "auth", Source: "corp", User: "admin", ID: "sid", Verified: false},
	}

	if got := sessionValue(sessions, "user"); got != "" {
		t.Fatalf("user = %q, want no subject at all", got)
	}

	if got := sessionValue(nil, "user"); got != "" {
		t.Fatalf("user = %q without any sessions, want empty", got)
	}
}

// Анонимная запись (калитка видела куку, но логина в ней нет) оси не даёт, а
// соседняя с логином -- даёт: пустое поле пропускается, а не побеждает.
func TestSessionValueSkipsEmptyField(t *testing.T) {
	sessions := []protocol.Session{
		{Inspector: "auth", Source: "app", ID: "sid-app", Verified: true},
		{Inspector: "auth", Source: "corp", User: "alice", ID: "sid-alice", Verified: true},
	}

	if got := sessionValue(sessions, "user"); got != "alice" {
		t.Fatalf("user = %q, want the record that has one", got)
	}

	if got := sessionValue(sessions, "sid"); got != "sid-app" {
		t.Fatalf("sid = %q, want the smallest pair, which has an id", got)
	}
}
