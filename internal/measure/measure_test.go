package measure

import (
	"testing"

	"github.com/exemt/placitum-counter/internal/config"
)

func counters(t *testing.T) *config.Counters {
	t.Helper()

	c, err := config.ParseCounters([]byte(`
counters:
  objects:
    axes:
      ip:   { max: 100, loss: 1 }
      sess: { max: 100, loss: 1 }
  kb:
    axes:
      ip:   { max: 1000, loss: 1 }
`))
	if err != nil {
		t.Fatal(err)
	}

	return c
}

func rule(t *testing.T, src string) []config.MeasureRule {
	t.Helper()

	p, err := config.ParseProfile("x", []byte(
		"mode: enforce\nrequest: {enabled: false}\nresponse:\n  enabled: true\n  measure:\n"+src))
	if err != nil {
		t.Fatal(err)
	}

	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}

	return p.Response.Measure
}

func TestRegexCount(t *testing.T) {
	rules := rule(t, `    - {source: regex_count, regex: '"id":', counter: objects}`+"\n")

	in := Input{
		Method: "GET", Status: 200,
		Body: []byte(`[{"id":1},{"id":2},{"id":3}]`),
	}

	values, fired := Run(rules, counters(t), in)

	if len(values) != 1 || values[0].Add != 3 {
		t.Fatalf("values = %+v, want one charge of 3", values)
	}

	// Оси не названы -- заряжаются все объявленные у счётчика.
	if len(values[0].Axes) != 2 {
		t.Fatalf("axes = %v, want both declared", values[0].Axes)
	}

	if len(fired) != 1 || fired[0].Truncated {
		t.Fatalf("fired = %+v", fired)
	}
}

// Усечённое тело -- осознанный недосчёт, и он обязан быть виден в аудите.
func TestRegexCountTruncated(t *testing.T) {
	rules := rule(t, `    - {source: regex_count, regex: 'x', counter: objects}`+"\n")

	_, fired := Run(rules, counters(t), Input{Body: []byte("xx"), BodyTruncated: true})

	if len(fired) != 1 || !fired[0].Truncated {
		t.Fatalf("fired = %+v, want truncated", fired)
	}
}

// size_kb берётся из локатора, а не из тела: размер полный даже при превью.
func TestSizeKB(t *testing.T) {
	rules := rule(t, "    - {source: size_kb, counter: kb}\n")

	values, _ := Run(rules, counters(t), Input{BodySize: 2048, Body: []byte("tiny")})

	if len(values) != 1 || values[0].Add != 2 {
		t.Fatalf("values = %+v, want 2 kb", values)
	}
}

func TestConstAndPer(t *testing.T) {
	rules := rule(t, "    - {source: const, per: 5, counter: objects, axes: [ip]}\n")

	values, _ := Run(rules, counters(t), Input{Method: "GET"})

	if len(values) != 1 || values[0].Add != 5 {
		t.Fatalf("values = %+v, want 5", values)
	}

	if len(values[0].Axes) != 1 || values[0].Axes[0] != "ip" {
		t.Fatalf("axes = %v, want [ip]", values[0].Axes)
	}
}

// Отрицательный per снимает: «хороший ответ возвращает кредит».
func TestNegativePer(t *testing.T) {
	rules := rule(t, "    - {source: const, per: -2, counter: objects}\n")

	values, _ := Run(rules, counters(t), Input{})

	if len(values) != 1 || values[0].Add != -2 {
		t.Fatalf("values = %+v, want -2", values)
	}
}

func TestPredicates(t *testing.T) {
	rules := rule(t, `    - if: {status: [200], content_type: ["application/json", "+json"], methods: [GET]}
      source: const
      counter: objects
`)

	cases := []struct {
		name string
		in   Input
		want int
	}{
		{"matches", Input{Method: "GET", Status: 200,
			ContentType: "application/json; charset=utf-8"}, 1},
		{"suffix type", Input{Method: "GET", Status: 200,
			ContentType: "application/problem+json"}, 1},
		{"wrong status", Input{Method: "GET", Status: 404,
			ContentType: "application/json"}, 0},
		{"wrong method", Input{Method: "POST", Status: 200,
			ContentType: "application/json"}, 0},
		{"wrong type", Input{Method: "GET", Status: 200,
			ContentType: "text/html"}, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			values, _ := Run(rules, counters(t), tc.in)

			if len(values) != tc.want {
				t.Fatalf("values = %+v, want %d", values, tc.want)
			}
		})
	}
}

// Правила накопительные: срабатывают все совпавшие, каждое со своим значением.
func TestRulesAccumulate(t *testing.T) {
	rules := rule(t, `    - {source: const, counter: objects, axes: [ip]}
    - {source: size_kb, counter: kb}
`)

	values, _ := Run(rules, counters(t), Input{BodySize: 1024})

	if len(values) != 2 {
		t.Fatalf("values = %+v, want two", values)
	}
}

// Нулевое значение источника не заряжает и не пишется: нечего.
func TestZeroValueSkipped(t *testing.T) {
	rules := rule(t, `    - {source: regex_count, regex: 'zzz', counter: objects}
    - {source: size_kb, counter: kb}
`)

	values, fired := Run(rules, counters(t), Input{Body: []byte("nothing here")})

	if len(values) != 0 || len(fired) != 0 {
		t.Fatalf("values = %+v fired = %+v, want none", values, fired)
	}
}
