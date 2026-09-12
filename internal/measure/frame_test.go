package measure

import (
	"testing"

	"github.com/exemt/placitum-counter/internal/config"
)

func frameRules(t *testing.T, src string) []config.MeasureRule {
	t.Helper()

	p, err := config.ParseProfile("x", []byte(
		"mode: enforce\nrequest: {enabled: false}\nresponse: {enabled: false}\n"+
			"frame:\n  enabled: true\n  measure:\n"+src))
	if err != nil {
		t.Fatal(err)
	}

	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}

	return p.Frame.Measure
}

func TestFrameDirectionAndBytes(t *testing.T) {
	rules := frameRules(t, `
    - { if: { direction: [c2s] }, source: const, counter: objects, axes: [ip] }
    - { if: { direction: [s2c] }, source: bytes, counter: kb, axes: [ip] }
`)

	values, fired := Run(rules, counters(t), Input{
		Frame: true, Direction: "s2c", Opcode: "text", BodySize: 1500,
	})

	if len(values) != 1 || values[0].Counter != "kb" || values[0].Add != 1500 {
		t.Fatalf("s2c bytes: %+v", values)
	}

	if len(fired) != 1 || fired[0].Source != config.SourceBytes {
		t.Fatalf("fired: %+v", fired)
	}

	values, _ = Run(rules, counters(t), Input{
		Frame: true, Direction: "c2s", Opcode: "text", BodySize: 10,
	})

	if len(values) != 1 || values[0].Counter != "objects" || values[0].Add != 1 {
		t.Fatalf("c2s const: %+v", values)
	}
}

func TestFrameRegexOnPayload(t *testing.T) {
	rules := frameRules(t, `
    - { if: { opcode: [text] }, source: regex_count, regex: '"id"', counter: objects, axes: [ip] }
`)

	values, _ := Run(rules, counters(t), Input{
		Frame: true, Direction: "s2c", Opcode: "text",
		Body: []byte(`[{"id":1},{"id":2},{"id":3}]`),
	})

	if len(values) != 1 || values[0].Add != 3 {
		t.Fatalf("regex on payload: %+v", values)
	}

	// Двоичный кадр текстовым правилом не считается.
	values, _ = Run(rules, counters(t), Input{
		Frame: true, Direction: "s2c", Opcode: "binary", Body: []byte(`"id"`),
	})

	if len(values) != 0 {
		t.Fatalf("binary must not match a text rule: %+v", values)
	}
}
