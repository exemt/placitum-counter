package decide

import (
	"testing"

	"github.com/exemt/placitum-counter/internal/config"
	"github.com/exemt/placitum-counter/internal/protocol"
)

func at(n int) *int { return &n }

// rules -- инициаторы без обвязки: наблюдение включает Decision.WouldVerdict,
// а не режим -- Fire видит решение, уже прошедшее через observe.
func rules(outcomes ...config.Outcome) []config.Outcome { return outcomes }

// clientIP -- адрес запроса: подсеть и систему по нему разворачивает
// обработчик у кодера, Fire называет только охват.
const clientIP = "203.0.113.7"

// Просьба уезжает ответом этого же запроса, и ось у неё явная: модуль пишет её
// всегда, а пустая означала бы сообщение старого образца.
func TestFireAsk(t *testing.T) {
	ph := rules(config.Outcome{
		On: config.OnScore, At: at(40), To: "captcha", Do: protocol.DoChallenge,
	})

	fired := Fire(ph, Decision{Verdict: protocol.VerdictScore, Score: 40, Code: "COUNTER_INVALID"}, clientIP, nil)

	if len(fired.Actions) != 1 || len(fired.Bans) != 0 {
		t.Fatalf("fired = %+v", fired)
	}

	got := fired.Actions[0]

	if got.To != "captcha" || got.Do != protocol.DoChallenge || got.Apply != protocol.ApplyRequest {
		t.Fatalf("action = %+v", got)
	}

	// Повод свой не назван -- едет код решения: иначе по записи не понять, на
	// чём инициатор сработал.
	if got.Code != "COUNTER_INVALID" {
		t.Fatalf("code = %q", got.Code)
	}

	if len(fired.Names) != 1 || fired.Names[0] != protocol.DoChallenge {
		t.Fatalf("names = %v", fired.Names)
	}
}

func TestFireOwnCodeWins(t *testing.T) {
	ph := rules(config.Outcome{
		On: config.OnAllow, To: "modsec", Do: protocol.DoThreshold,
		Delta: at(50), Code: "COUNTER_API_HOT",
	})

	fired := Fire(ph, Decision{Verdict: protocol.VerdictAllow}, clientIP, nil)

	if len(fired.Actions) != 1 {
		t.Fatalf("fired = %+v", fired)
	}

	if fired.Actions[0].Code != "COUNTER_API_HOT" || fired.Actions[0].Delta != 50 {
		t.Fatalf("action = %+v", fired.Actions[0])
	}
}

func TestFireList(t *testing.T) {
	ph := rules(config.Outcome{
		On: config.OnDeny, List: "api_abusers", TTL: config.Duration(3600),
	})

	fired := Fire(ph, Decision{Verdict: protocol.VerdictDeny, Code: "COUNTER_INVALID"}, clientIP, nil)

	if len(fired.Bans) != 1 || len(fired.Actions) != 0 {
		t.Fatalf("fired = %+v", fired)
	}

	ban := fired.Bans[0]

	if ban.Dataset != "api_abusers" || ban.Addr != clientIP || ban.Write != config.WriteAddr ||
		ban.TTL != 3600 {
		t.Fatalf("ban = %+v", ban)
	}

	if ban.Reason != "COUNTER_INVALID" {
		t.Fatalf("reason = %q", ban.Reason)
	}
}

// Сообщение без адреса приходит только от пробы: писать в набор нечего.
func TestFireListWithoutAddress(t *testing.T) {
	ph := rules(config.Outcome{
		On: config.OnDeny, List: "api_abusers", TTL: config.Duration(3600),
	})

	fired := Fire(ph, Decision{Verdict: protocol.VerdictDeny}, "", nil)

	if len(fired.Bans) != 0 {
		t.Fatalf("bans = %+v", fired.Bans)
	}
}

func TestFireThreshold(t *testing.T) {
	ph := rules(
		config.Outcome{On: config.OnScore, At: at(40), List: "hot", TTL: config.Duration(60)},
		config.Outcome{On: config.OnScore, At: at(10), Below: true, List: "cold",
			TTL: config.Duration(60)},
	)

	cases := []struct {
		name  string
		score int
		want  []string
	}{
		{"over the threshold", 70, []string{"hot"}},
		{"between", 20, nil},
		{"under the low one", 5, []string{"cold"}},
		{"exactly at", 40, []string{"hot"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fired := Fire(ph, Decision{Verdict: protocol.VerdictScore, Score: tc.score}, clientIP, nil)

			if len(fired.Names) != len(tc.want) {
				t.Fatalf("names = %v, want %v", fired.Names, tc.want)
			}

			for i, want := range tc.want {
				if fired.Names[i] != want {
					t.Fatalf("names = %v, want %v", fired.Names, tc.want)
				}
			}
		})
	}
}

/*
 * Наблюдение глушит только ответ модулю: инициаторы судят по решению enforce
 * и стреляют как в бою -- просьба уезжает соседу под поводом решения, а не
 * под кодом наблюдения.
 */
func TestFireObserveFiresOutward(t *testing.T) {
	ph := rules(
		config.Outcome{On: config.OnScore, At: at(40), To: "captcha", Do: protocol.DoChallenge},
		config.Outcome{On: config.OnDeny, List: "api_abusers", TTL: config.Duration(60)},
	)

	d := Decision{
		Verdict:      protocol.VerdictAllow,
		Code:         CodeObserve,
		WouldVerdict: protocol.VerdictScore,
		WouldScore:   70,
		WouldCode:    "CNT_HOT",
	}

	fired := Fire(ph, d, clientIP, nil)

	if len(fired.Actions) != 1 || fired.Actions[0].Do != protocol.DoChallenge {
		t.Fatalf("actions = %+v, want the challenge ask", fired.Actions)
	}

	if fired.Actions[0].Code != "CNT_HOT" {
		t.Fatalf("code = %q, want the enforce reason, not the observe one", fired.Actions[0].Code)
	}

	if len(fired.Bans) != 0 || len(fired.Names) != 1 || fired.Names[0] != protocol.DoChallenge {
		t.Fatalf("fired = %+v", fired)
	}
}

// Наблюдение судит would-вердикт: allow, которым оно отвечает модулю, не его
// собственное решение и инициатор «на пропуске» дёргать не должен.
func TestFireObserveJudgesWouldVerdict(t *testing.T) {
	ph := rules(
		config.Outcome{On: config.OnAllow, List: "seen", TTL: config.Duration(60)},
	)

	d := Decision{
		Verdict:      protocol.VerdictAllow,
		Code:         CodeObserve,
		WouldVerdict: protocol.VerdictDeny,
	}

	if fired := Fire(ph, d, clientIP, nil); len(fired.Bans) != 0 || len(fired.Names) != 0 {
		t.Fatalf("fired = %+v: наблюдение судит решение enforce, а не свой allow", fired)
	}
}

func TestFireWithoutOutcomes(t *testing.T) {
	fired := Fire(nil, Decision{Verdict: protocol.VerdictAllow}, clientIP, nil)

	if len(fired.Actions) != 0 || len(fired.Bans) != 0 {
		t.Fatalf("fired = %+v", fired)
	}
}

// Кого писать в набор -- решает строка: адрес меняется дешевле всего, анонс
// уже нет, а система целиком -- решение другого масштаба. Разворачивает их
// обработчик у кодера; Fire называет охват и адрес.
func TestFireWritesSubject(t *testing.T) {
	cases := map[string]string{
		config.WriteAddr:   config.WriteAddr,
		config.WriteNet:    config.WriteNet,
		config.WriteNetAll: config.WriteNetAll,
		config.WriteASN:    config.WriteASN,
		"":                 config.WriteAddr,
	}

	for write, want := range cases {
		t.Run("write "+write, func(t *testing.T) {
			ph := rules(config.Outcome{
				On: config.OnDeny, List: "hot", Write: write,
				TTL: config.Duration(60),
			})

			fired := Fire(ph, Decision{Verdict: protocol.VerdictDeny}, clientIP, nil)

			if len(fired.Bans) != 1 || fired.Bans[0].Write != want || fired.Bans[0].Addr != clientIP {
				t.Fatalf("bans = %+v, want write %q for %s", fired.Bans, want, clientIP)
			}
		})
	}
}

/*
 * Инициатор по уровню корзины: условие -- не вердикт, а названная корзина.
 * Ради этого он и заведён -- вердикт у фазы один, а корзин у счётчика много,
 * и по вердикту не отличить, какая из них перелилась.
 */
func TestFireOnBucketLevel(t *testing.T) {
	at := 40

	ph := rules(config.Outcome{
		On: config.OnLevel,
		If: &config.OutcomeIf{Counter: "abuse", Axis: "ip"},
		At: &at, List: "hot", Write: config.WriteAddr, TTL: config.Duration(60),
	})

	level := func(percent float64, ok bool) LevelLookup {
		return func(counter, axis string) (float64, string, bool) {
			if counter != "abuse" || axis != "ip" {
				return 0, "", false
			}

			return percent, clientIP + "/32", ok
		}
	}

	// Вердикт фазы -- allow: строке по уровню он безразличен.
	hot := Fire(ph, Decision{Verdict: protocol.VerdictAllow}, clientIP, level(55, true))

	if len(hot.Bans) != 1 || hot.Bans[0].Dataset != "hot" {
		t.Fatalf("bans = %+v: уровень за порогом обязан записать", hot.Bans)
	}

	if len(hot.Levels) != 1 || !hot.Levels[0].Fired || hot.Levels[0].Percent != 55 {
		t.Fatalf("levels = %+v", hot.Levels)
	}

	cold := Fire(ph, Decision{Verdict: protocol.VerdictDeny}, clientIP, level(39, true))

	if len(cold.Bans) != 0 {
		t.Fatalf("bans = %+v: ниже порога записи быть не должно", cold.Bans)
	}

	// Несработавшее сравнение тоже уезжает в аудит: по нему разбирают тишину.
	if len(cold.Levels) != 1 || cold.Levels[0].Fired {
		t.Fatalf("levels = %+v", cold.Levels)
	}

	// Субъекта нет -- строка молчит, как правило judge в том же случае.
	none := Fire(ph, Decision{Verdict: protocol.VerdictAllow}, clientIP, level(90, false))

	if len(none.Bans) != 0 || !none.Levels[0].NoSubject {
		t.Fatalf("no-subject case leaked: %+v", none)
	}
}

// Сравнение вниз: «корзина остыла» -- законный повод, например снять субъекта
// с наблюдения.
func TestFireOnBucketBelow(t *testing.T) {
	at := 40
	ph := rules(config.Outcome{
		On: config.OnLevel, Below: true,
		If: &config.OutcomeIf{Counter: "abuse", Axis: "ip"},
		At: &at, List: "cool", Write: config.WriteAddr, TTL: config.Duration(60),
	})

	lookup := func(percent float64) LevelLookup {
		return func(string, string) (float64, string, bool) {
			return percent, clientIP + "/32", true
		}
	}

	if fired := Fire(ph, Decision{Verdict: protocol.VerdictAllow},
		clientIP, lookup(10)); len(fired.Bans) != 1 {

		t.Fatal("below: 10% ниже порога 40 -- строка обязана сработать")
	}

	if fired := Fire(ph, Decision{Verdict: protocol.VerdictAllow},
		clientIP, lookup(70)); len(fired.Bans) != 0 {

		t.Fatal("below: 70% выше порога 40 -- строка обязана молчать")
	}
}
