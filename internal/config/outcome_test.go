package config

import (
	"strings"
	"testing"
)

// profileWith -- минимальный профиль с секцией инициаторов у фазы запроса.
func profileWith(t *testing.T, outcomes string) (*Profile, error) {
	t.Helper()

	src := "mode: enforce\nrequest:\n  enabled: true\n" +
		"  outcomes:\n" + outcomes

	p, err := ParseProfile("x", []byte(src))
	if err != nil {
		return nil, err
	}

	return p, p.Validate()
}

func TestOutcomeAccepts(t *testing.T) {
	cases := map[string]string{
		"ask on score": "    - {on: score, at: 40, to: captcha, do: challenge}\n",
		"ask below":    "    - {on: score, at: 10, below: true, to: modsec, do: skip}\n",
		"ask on allow": "    - {on: allow, to: vlai, do: threshold, delta: -50}\n",
		"note with axis": "    - {on: score, at: 60, to: captcha, do: note, apply: ip, " +
			"value: 25}\n",
		"note with counter": "    - {on: score, at: 60, to: counter, do: note, apply: ip, " +
			"value: 25, counter: abuse}\n",
		"ask on exact score": "    - {on: score, at: 40, eq: true, to: captcha, do: challenge}\n",
		"level above": "    - {on: level, if: {counter: abuse, axis: ip}, at: 40, " +
			"list: hot, ttl: 1h}\n",
		"level below": "    - {on: level, below: true, if: {counter: abuse, axis: sess}, " +
			"at: 10, list: cool, ttl: 15m}\n",
		"level asks a neighbour": "    - {on: level, if: {counter: abuse, axis: ip}, at: 60, " +
			"to: captcha, do: challenge}\n",
		"list on deny":  "    - {on: deny, list: api_abusers, ttl: 1h}\n",
		"list on score": "    - {on: score, at: 80, list: api_abusers, ttl: 15m, code: COUNTER_HOT}\n",
		// Фаза вызова адресата: режим одному из вызовов имени; пусто -- всем.
		"off on the response call": "    - {on: score, at: 80, to: json, do: off, apply: request, " +
			"phase: response}\n",
		"passive on every call": "    - {on: score, at: 80, to: json, do: passive, apply: request}\n",
	}

	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := profileWith(t, src); err != nil {
				t.Fatalf("rejected: %v", err)
			}
		})
	}
}

func TestOutcomeRejects(t *testing.T) {
	cases := map[string]string{
		// Триггер и его порог.
		"unknown on":            "    - {on: sneeze, list: x, ttl: 1h}\n",
		"score without at":      "    - {on: score, list: x, ttl: 1h}\n",
		"at without score":      "    - {on: allow, at: 40, list: x, ttl: 1h}\n",
		"at out of range":       "    - {on: score, at: 900, list: x, ttl: 1h}\n",
		"below on allow":        "    - {on: allow, below: true, list: x, ttl: 1h}\n",
		"eq on allow":           "    - {on: allow, eq: true, list: x, ttl: 1h}\n",
		"below with eq":         "    - {on: score, at: 40, below: true, eq: true, list: x, ttl: 1h}\n",
		"level without if":      "    - {on: level, at: 40, list: x, ttl: 1h}\n",
		"level without counter": "    - {on: level, if: {axis: ip}, at: 40, list: x, ttl: 1h}\n",
		"level bad axis": "    - {on: level, if: {counter: abuse, axis: moon}, at: 40, " +
			"list: x, ttl: 1h}\n",
		"level without at": "    - {on: level, if: {counter: abuse, axis: ip}, " +
			"list: x, ttl: 1h}\n",
		"level at over": "    - {on: level, if: {counter: abuse, axis: ip}, at: 150, " +
			"list: x, ttl: 1h}\n",
		// Уровень непрерывен: «ровно 40%» не случается, строка молчала бы всегда.
		"level with eq": "    - {on: level, eq: true, if: {counter: abuse, axis: ip}, at: 40, " +
			"list: x, ttl: 1h}\n",
		"if without level": "    - {on: allow, if: {counter: abuse, axis: ip}, " +
			"list: x, ttl: 1h}\n",

		// Действие: ровно одно, и оно осмысленное.
		"neither do nor list": "    - {on: allow}\n",
		"both do and list": "    - {on: allow, to: captcha, do: challenge, list: x, " +
			"ttl: 1h}\n",
		"list without ttl":        "    - {on: allow, list: x}\n",
		"unknown verb":            "    - {on: allow, to: captcha, do: nuke}\n",
		"bad axis":                "    - {on: allow, to: captcha, do: challenge, apply: asn}\n",
		"note without axis":       "    - {on: allow, to: captcha, do: note, value: 10}\n",
		"threshold without delta": "    - {on: allow, to: modsec, do: threshold}\n",
		"threshold zero delta": "    - {on: allow, to: modsec, do: threshold, " +
			"delta: 0}\n",
		"delta out of range": "    - {on: allow, to: modsec, do: threshold, delta: 1000}\n",
		"note zero value": "    - {on: allow, to: captcha, do: note, apply: ip, " +
			"value: 0}\n",
		"counter not on note": "    - {on: allow, to: modsec, do: skip, counter: abuse}\n",
		"bad counter name": "    - {on: allow, to: counter, do: note, apply: ip, " +
			"value: 10, counter: \"п лохо\"}\n",
		"bad code": "    - {on: allow, list: x, ttl: 1h, code: \"плохой повод\"}\n",

		// Просьба на отказе: deny обрывает фазу, доехать ей некуда.
		"ask on deny": "    - {on: deny, to: captcha, do: challenge}\n",

		// Глаголы записи: адресата нет, сторона обязательна, срок и предел --
		// только у archive с set on.
		"audit with addressee":        "    - {on: allow, to: modsec, do: audit, set: on}\n",
		"audit without set":           "    - {on: allow, do: audit}\n",
		"archive off with ttl":        "    - {on: allow, do: archive, apply: request, set: off, ttl: 30d}\n",
		"archive bad object set":      "    - {on: allow, do: archive, apply: request, set: on, body: {set: maybe}}\n",
		"objects on skip":             "    - {on: allow, to: modsec, do: skip, body: {limit: 10}}\n",
		"audit with ttl again":        "    - {on: allow, do: audit, apply: request, set: on, body: {limit: 10}, ttl: 1h}\n",
		"audit with ttl":              "    - {on: allow, do: audit, apply: request, set: on, ttl: 30d}\n",
		"bad source":                  "    - {on: allow, do: archive, apply: request, set: on, body: {source: elsewhere}}\n",
		"object on set off":           "    - {on: allow, do: archive, apply: request, set: off, body: {source: original}}\n",
		"args on the response record": "    - {on: allow, do: audit, apply: response, set: on, args: {limit: 10}}\n",

		// Исход просьбы: два слова, каждое не дважды, только у archive с set on.
		"archive bad when":      "    - {on: allow, do: archive, apply: request, set: on, when: [redirect]}\n",
		"archive when twice":    "    - {on: allow, do: archive, apply: request, set: on, when: [deny, deny]}\n",
		"audit with when":       "    - {on: allow, do: audit, apply: request, set: on, when: [deny]}\n",
		"archive off with when": "    - {on: allow, do: archive, apply: request, set: off, when: [deny]}\n",
		"when on skip":          "    - {on: allow, to: modsec, do: skip, when: [deny]}\n",

		// Фаза вызова -- только у управляющих, слова три.
		"phase on skip":  "    - {on: allow, to: modsec, do: skip, phase: response}\n",
		"phase on audit": "    - {on: allow, do: audit, apply: request, set: on, phase: request}\n",
		"unknown phase":  "    - {on: allow, to: json, do: off, apply: request, phase: later}\n",
	}

	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := profileWith(t, src); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// Ось досочиняется там, где выбора нет, и уезжает на провод явной: модуль
// пишет её всегда, и пустая означала бы сообщение старого образца.
// Глаголы записи грузятся без адресата; срок, предел и объекты -- у archive.
func TestOutcomeAuditVerbs(t *testing.T) {
	p, err := profileWith(t,
		"    - {on: allow, do: audit, set: on, code: COUNTER_WATCH}\n"+
			"    - {on: allow, do: archive, apply: request, set: on, headers: {source: original}, body: {limit: 65536, source: original}, ttl: 30d, when: [deny]}\n"+
			"    - {on: allow, do: archive, apply: response, set: on, body: {source: store}, ttl: 1h}\n")
	if err != nil {
		t.Fatal(err)
	}

	got := p.Request.Outcomes

	// Без apply глагол записи -- про запись запроса; response -- про запись ответа.
	if len(got) != 3 || got[0].To != "" || got[0].Set != "on" || got[0].Axis() != "request" ||
		got[2].Axis() != "response" || got[2].Body == nil || got[2].TTL.Seconds() != 3600 {
		t.Fatalf("audit: %+v", got)
	}

	if got[1].TTL.Seconds() != 30*24*3600 || got[1].Body == nil || got[1].Body.Limit != 65536 ||
		got[1].Body.Source != "original" || got[1].Headers == nil || got[1].Args != nil ||
		// Исход уезжает в каноническом порядке; не названный -- пустой.
		len(got[1].When) != 1 || got[1].When[0] != "deny" || len(got[2].When) != 0 {
		t.Fatalf("archive: %+v", got[1])
	}
}

func TestOutcomeAxisFilledIn(t *testing.T) {
	p, err := profileWith(t, "    - {on: allow, to: captcha, do: challenge}\n")
	if err != nil {
		t.Fatal(err)
	}

	if got := p.Request.Outcomes[0].Axis(); got != "request" {
		t.Fatalf("axis = %q, want request", got)
	}
}

func TestOutcomeMatches(t *testing.T) {
	at := 40
	score := Outcome{On: OnScore, At: &at}
	below := Outcome{On: OnScore, At: &at, Below: true}
	exact := Outcome{On: OnScore, At: &at, Eq: true}

	cases := []struct {
		name    string
		outcome Outcome
		verdict string
		score   int
		want    bool
	}{
		{"score at the threshold", score, "score", 40, true},
		{"score above", score, "score", 70, true},
		{"score below the threshold", score, "score", 39, false},
		{"below matches under", below, "score", 39, true},
		{"below ignores over", below, "score", 40, false},
		{"eq matches exactly", exact, "score", 40, true},
		{"eq ignores above", exact, "score", 41, false},
		{"eq ignores below", exact, "score", 39, false},
		{"score rule ignores allow", score, "allow", 90, false},
		{"deny matches deny", Outcome{On: OnDeny}, "deny", 0, true},
		{"deny ignores allow", Outcome{On: OnDeny}, "allow", 0, false},
		{"allow matches allow", Outcome{On: OnAllow}, "allow", 0, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.outcome.Matches(tc.verdict, tc.score); got != tc.want {
				t.Fatalf("matches = %v, want %v", got, tc.want)
			}
		})
	}
}

// Срок читается человеческой записью: секунды в файле, который правят руками,
// читаются хуже, чем ошибаются.
func TestParseDuration(t *testing.T) {
	cases := map[string]int{
		"":     0,
		"30s":  30,
		"15m":  900,
		"1h":   3600,
		"7d":   604800,
		"3600": 3600,
	}

	for src, want := range cases {
		got, err := ParseDuration(src)
		if err != nil {
			t.Fatalf("%q: %v", src, err)
		}

		if got != want {
			t.Fatalf("%q = %d, want %d", src, got, want)
		}
	}

	for _, bad := range []string{"-1h", "abc", "1w"} {
		if _, err := ParseDuration(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

// Ошибка называет место: строка профиля, которую правил оператор.
func TestOutcomeErrorNamesTheRow(t *testing.T) {
	_, err := profileWith(t, "    - {on: allow, list: x}\n")
	if err == nil {
		t.Fatal("accepted")
	}

	if !strings.Contains(err.Error(), "request.outcomes[0]") {
		t.Fatalf("error does not name the row: %v", err)
	}
}
