package config

import (
	"strings"
	"testing"
)

const goodCounters = `
counters:
  objects:
    unit: obj
    axes:
      ip:      { max: 1000, loss: 2 }
      asn_net: { max: 5000, loss: 2 }
      sess:    { max: 800,  loss: 2 }
  volume:
    axes:
      user: { max: 100, loss: 5 }
  abuse:
    fill: note
    axes:
      ip:         { max: 100, loss: 1 }
      asn_router: { max: 500, loss: 1 }
subjects:
  sess: { cookie: waf_cid }
  user: { from: "header:x-api-key" }
`

func TestCountersParse(t *testing.T) {
	c, err := ParseCounters([]byte(goodCounters))
	if err != nil {
		t.Fatal(err)
	}

	tiers := c.Tiers()

	if len(tiers) != 6 {
		t.Fatalf("tiers = %d, want 6 buckets", len(tiers))
	}

	tier, ok := tiers[Kind("objects", AxisIP)]
	if !ok || tier.Max != 1000 || tier.Loss != 2 {
		t.Fatalf("tier = %+v", tier)
	}

	if !c.HasAxis("objects", AxisSess) || c.HasAxis("objects", AxisUser) {
		t.Fatal("axis lookup is wrong")
	}

	// Оси счётчика -- в устойчивом порядке словаря осей.
	axes := c.AxesOf("objects")
	if len(axes) != 3 || axes[0] != AxisIP || axes[1] != AxisNet || axes[2] != AxisSess {
		t.Fatalf("axes = %v", axes)
	}

	// Владение: пустой fill -- measure, объявленный note читается как есть.
	if c.Fill("objects") != FillMeasure || c.Fill("abuse") != FillNote {
		t.Fatal("fill lookup is wrong")
	}

	// Ось провода разворачивается в объявленные: asn -- только объявленная
	// asn_router, session у abuse не объявлена вовсе.
	if got := c.NoteAxes("abuse", "asn"); len(got) != 1 || got[0] != AxisRouter {
		t.Fatalf("note axes for asn = %v", got)
	}

	if got := c.NoteAxes("abuse", "session"); len(got) != 0 {
		t.Fatalf("note axes for session = %v", got)
	}

	if c.UserFrom("volume") != "header:x-api-key" {
		t.Fatalf("user source = %q", c.UserFrom("volume"))
	}
}

/*
 * Свои источники ключей в объявлении счётчика: «на эту куку заведён счётчик»
 * -- прямо в декларации, а общая секция subjects остаётся умолчанием. Так
 * счётчик на куке сессии калитки живёт рядом со счётчиком на куке капчи.
 */
func TestCounterOwnSubjects(t *testing.T) {
	c, err := ParseCounters([]byte(`
counters:
  sessions:
    axes:
      sess: { max: 100, loss: 1 }
    subjects:
      sess: { cookie: waf_sid_default }
  api_calls:
    axes:
      user: { max: 100, loss: 1 }
    subjects:
      user: { from: "header:x-api-key" }
  clearance:
    axes:
      sess: { max: 100, loss: 1 }
`))
	if err != nil {
		t.Fatal(err)
	}

	if c.SessCookie("sessions") != "waf_sid_default" {
		t.Fatalf("own sess cookie = %q", c.SessCookie("sessions"))
	}

	// Без своего источника счётчик читает общий: умолчание -- кука клиренса.
	if c.SessCookie("clearance") != DefaultSessCookie {
		t.Fatalf("shared sess cookie = %q", c.SessCookie("clearance"))
	}

	// Ось user жива от собственного источника даже при пустом общем.
	if c.UserFrom("api_calls") != "header:x-api-key" {
		t.Fatalf("own user source = %q", c.UserFrom("api_calls"))
	}

	// Битый свой источник -- ошибка загрузки, как и битый общий.
	_, err = ParseCounters([]byte(`
counters:
  x:
    axes:
      ip: { max: 1, loss: 1 }
    subjects:
      user: { from: "jwt:sub" }
`))
	if err == nil {
		t.Fatal("bad per-counter source accepted")
	}
}

// Кука клиренса капчи -- умолчание оси sess: контур один, и второй раз её
// имя не называют.
func TestCountersSessCookieDefault(t *testing.T) {
	c, err := ParseCounters([]byte("counters:\n  x:\n    axes:\n      ip: {max: 1, loss: 1}\n"))
	if err != nil {
		t.Fatal(err)
	}

	if c.Subjects.Sess.Cookie != DefaultSessCookie {
		t.Fatalf("cookie = %q", c.Subjects.Sess.Cookie)
	}
}

func TestCountersRejects(t *testing.T) {
	cases := map[string]string{
		"empty":               "",
		"no axes":             "counters:\n  x: {axes: {}}\n",
		"bad axis":            "counters:\n  x:\n    axes:\n      moon: {max: 1, loss: 1}\n",
		"zero max":            "counters:\n  x:\n    axes:\n      ip: {max: 0, loss: 1}\n",
		"zero loss":           "counters:\n  x:\n    axes:\n      ip: {max: 1, loss: 0}\n",
		"loss over":           "counters:\n  x:\n    axes:\n      ip: {max: 1, loss: 200}\n",
		"bad name":            "counters:\n  \"плохое имя\":\n    axes:\n      ip: {max: 1, loss: 1}\n",
		"bad fill":            "counters:\n  x:\n    fill: wind\n    axes:\n      ip: {max: 1, loss: 1}\n",
		"user without source": "counters:\n  x:\n    axes:\n      user: {max: 1, loss: 1}\n",
		"bad user source": "counters:\n  x:\n    axes:\n      ip: {max: 1, loss: 1}\n" +
			"subjects:\n  user: {from: \"jwt:sub\"}\n",
		"bad session field": "counters:\n  x:\n    axes:\n      ip: {max: 1, loss: 1}\n" +
			"subjects:\n  user: {from: \"session:groups\"}\n",
		"session without field": "counters:\n  x:\n    axes:\n      ip: {max: 1, loss: 1}\n" +
			"subjects:\n  user: {from: \"session:\"}\n",
	}

	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCounters([]byte(src)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// Ссылка на необъявленное отвергает профиль: связность проверяется там, где
// прочитаны обе стороны.
func TestProfileAgainstCounters(t *testing.T) {
	c, err := ParseCounters([]byte(goodCounters))
	if err != nil {
		t.Fatal(err)
	}

	parse := func(t *testing.T, src string) *Profile {
		t.Helper()

		p, err := ParseProfile("x", []byte(src))
		if err != nil {
			t.Fatal(err)
		}

		if err := p.Validate(); err != nil {
			t.Fatal(err)
		}

		return p
	}

	good := parse(t, `
mode: enforce
request:
  enabled: true
  judge:
    - {counter: objects, axis: ip, at: 60, action: score, score: 40}
response:
  enabled: true
  measure:
    - {source: const, counter: volume, axes: [user]}
`)
	if err := good.ValidateAgainst(c); err != nil {
		t.Fatal(err)
	}

	unknownCounter := parse(t, `
mode: enforce
request:
  enabled: true
  judge:
    - {counter: ghosts, axis: ip, at: 60, action: score, score: 40}
`)
	if err := unknownCounter.ValidateAgainst(c); err == nil ||
		!strings.Contains(err.Error(), "ghosts") {
		t.Fatalf("err = %v", err)
	}

	unknownAxis := parse(t, `
mode: enforce
response:
  enabled: true
  measure:
    - {source: const, counter: objects, axes: [user]}
`)
	if err := unknownAxis.ValidateAgainst(c); err == nil {
		t.Fatal("accepted a measure axis the counter does not declare")
	}

	// Владение: один вход на шкалу. Судить сигнальную корзину можно, мерить --
	// нельзя; note целит только в fill: note.
	noteJudged := parse(t, `
mode: enforce
trigger:
  prior:
    - {from: modsec, accept: [note], counter: abuse}
request:
  enabled: true
  judge:
    - {counter: abuse, axis: ip, at: 90, action: score, score: 40}
`)
	if err := noteJudged.ValidateAgainst(c); err != nil {
		t.Fatal(err)
	}

	measureIntoNote := parse(t, `
mode: enforce
response:
  enabled: true
  measure:
    - {source: const, counter: abuse}
`)
	if err := measureIntoNote.ValidateAgainst(c); err == nil {
		t.Fatal("accepted a measure rule into a fill: note counter")
	}

	noteIntoMeasure := parse(t, `
mode: enforce
trigger:
  prior:
    - {from: modsec, accept: [note], counter: objects}
`)
	if err := noteIntoMeasure.ValidateAgainst(c); err == nil {
		t.Fatal("accepted a note rule into a fill: measure counter")
	}

	noteUndeclared := parse(t, `
mode: enforce
trigger:
  prior:
    - {from: modsec, accept: [note], counter: ghosts}
`)
	if err := noteUndeclared.ValidateAgainst(c); err == nil ||
		!strings.Contains(err.Error(), "ghosts") {
		t.Fatalf("err = %v", err)
	}

	// Корзина из одной оси user словам соседей недоступна: канал такой оси
	// не знает, и правило не сработало бы никогда.
	userOnly, err := ParseCounters([]byte(`
counters:
  hidden:
    fill: note
    axes:
      user: { max: 100, loss: 1 }
subjects:
  user: { from: "header:x-api-key" }
`))
	if err != nil {
		t.Fatal(err)
	}

	unreachable := parse(t, `
mode: enforce
trigger:
  prior:
    - {from: modsec, accept: [note], counter: hidden}
`)
	if err := unreachable.ValidateAgainst(userOnly); err == nil {
		t.Fatal("accepted a note rule the channel cannot reach")
	}

	// Выключенный профиль связность не проверяет: запретить выключение
	// сломанной ссылки было бы хуже самой ссылки.
	off := parse(t, "mode: off\n")
	if err := off.ValidateAgainst(c); err != nil {
		t.Fatal(err)
	}
}

func TestJudgeRejects(t *testing.T) {
	cases := map[string]string{
		"no counter":    "    - {axis: ip, at: 10, action: deny}\n",
		"bad axis":      "    - {counter: x, axis: moon, at: 10, action: deny}\n",
		"at over":       "    - {counter: x, axis: ip, at: 150, action: deny}\n",
		"bad action":    "    - {counter: x, axis: ip, at: 10, action: shrug}\n",
		"score on deny": "    - {counter: x, axis: ip, at: 10, action: deny, score: 50}\n",
		"score missing": "    - {counter: x, axis: ip, at: 10, action: score}\n",
		"score over":    "    - {counter: x, axis: ip, at: 10, action: score, score: 200}\n",
		"bad code":      "    - {counter: x, axis: ip, at: 10, action: deny, code: \"о ужас\"}\n",
	}

	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			p, err := ParseProfile("x", []byte(
				"mode: enforce\nrequest:\n  enabled: true\n  judge:\n"+src))
			if err == nil {
				err = p.Validate()
			}

			if err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestMeasureRejects(t *testing.T) {
	cases := map[string]string{
		"no counter":     "    - {source: const}\n",
		"bad source":     "    - {source: entropy, counter: x}\n",
		"regex missing":  "    - {source: regex_count, counter: x}\n",
		"regex broken":   "    - {source: regex_count, regex: '[', counter: x}\n",
		"regex on const": "    - {source: const, regex: 'x', counter: x}\n",
		"zero per":       "    - {source: const, per: 0, counter: x}\n",
		"bad axis":       "    - {source: const, counter: x, axes: [moon]}\n",
		// Пути в предикате больше нет: поведение по путям -- разные профили
		// на разных маршрутах. Строгий разбор отвергает поле как чужое.
		"path removed": "    - {if: {path: /api}, source: const, counter: x}\n",
		"bad method":   "    - {if: {methods: [get]}, source: const, counter: x}\n",
		"bad status":   "    - {if: {status: [42]}, source: const, counter: x}\n",
	}

	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			p, err := ParseProfile("x", []byte(
				"mode: enforce\nresponse:\n  enabled: true\n  measure:\n"+src))
			if err == nil {
				err = p.Validate()
			}

			if err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// Отказное правило без записи каталога не грузится: код и страницу отдаёт
// nginx по символьному имени, и имя обязано быть названо.
func TestDenyNeedsResponse(t *testing.T) {
	p, err := ParseProfile("x", []byte(`
mode: enforce
request:
  enabled: true
  deny_response: ""
  judge:
    - {counter: x, axis: ip, at: 10, action: deny}
`))
	if err != nil {
		t.Fatal(err)
	}

	if err := p.Validate(); err == nil {
		t.Fatal("accepted a deny without deny_response")
	}
}

/*
 * Личность как источник оси user: счётчик заведён не на то, что прислал
 * клиент, а на то, что о нём сказала калитка. Заголовки такому источнику не
 * нужны -- личность приезжает в самом сообщении.
 */
func TestCountersSessionSubject(t *testing.T) {
	const src = `
counters:
  people:
    axes:
      user: { max: 100, loss: 1 }
  logins:
    axes:
      user: { max: 50, loss: 1 }
    subjects:
      user: { from: "session:sid" }
subjects:
  user: { from: "session:user" }
`

	c, err := ParseCounters([]byte(src))
	if err != nil {
		t.Fatal(err)
	}

	if got := c.UserFrom("people"); got != "session:user" {
		t.Fatalf("people user source = %q, want the shared one", got)
	}

	if got := c.UserFrom("logins"); got != "session:sid" {
		t.Fatalf("logins user source = %q, want its own", got)
	}

	if WantsHeaders("session:user") || WantsHeaders("session:sid") {
		t.Fatal("the session source asked for request headers")
	}

	if !WantsHeaders("cookie:waf_sid_default") || !WantsHeaders("header:x-api-key") {
		t.Fatal("a cookie or header source must ask for request headers")
	}
}

func TestSplitFrom(t *testing.T) {
	cases := []struct {
		from string
		kind string
		name string
		ok   bool
	}{
		{"cookie:waf_sid_default", FromCookie, "waf_sid_default", true},
		{"header:x-api-key", FromHeader, "x-api-key", true},
		{"session:user", FromSession, SubjectUser, true},
		{"session:sid", FromSession, SubjectSID, true},
		{"session:login", "", "", false},
		{"cookie:", "", "", false},
		{"waf_cid", "", "", false},
		{"", "", "", false},
	}

	for _, c := range cases {
		kind, name, ok := SplitFrom(c.from)

		if ok != c.ok || kind != c.kind || name != c.name {
			t.Errorf("SplitFrom(%q) = %q, %q, %v; want %q, %q, %v",
				c.from, kind, name, ok, c.kind, c.name, c.ok)
		}
	}
}
