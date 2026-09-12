package config

import (
	"strings"
	"testing"
)

func frameProfile(t *testing.T, yaml string) (*Profile, error) {
	t.Helper()

	p, err := ParseProfile("t", []byte(yaml))
	if err != nil {
		return nil, err
	}

	return p, p.Validate()
}

func TestFrameSectionDefaults(t *testing.T) {
	p, err := frameProfile(t, "mode: enforce\n")
	if err != nil {
		t.Fatal(err)
	}

	// Секция достраивается: профиль без неё на кадрах ничего не делает, но и
	// не отвергается -- маршрут с frame:c2s counter получит allow.
	if !p.Frame.Enabled || p.Frame.DenyResponse != DefaultFrameDenyResponse {
		t.Fatalf("frame defaults: %+v", p.Frame)
	}
}

func TestFrameSectionParses(t *testing.T) {
	p, err := frameProfile(t, `
mode: enforce
request: { enabled: false }
response: { enabled: false }
frame:
  enabled: true
  measure:
    - if: { direction: [c2s], opcode: [text] }
      source: const
      counter: ws_frames
    - if: { direction: [s2c] }
      source: bytes
      counter: ws_bytes
      axes: [conn]
  judge:
    - { counter: ws_frames, axis: conn, at: 90, action: deny, code: WS_FLOOD }
  deny_response: ws_policy
`)
	if err != nil {
		t.Fatal(err)
	}

	if len(p.Frame.Measure) != 2 || len(p.Frame.Judge) != 1 {
		t.Fatalf("rules: %+v", p.Frame)
	}

	if !p.Frame.Measure[0].If.MatchesFrame("c2s", "text") {
		t.Fatal("c2s/text must match the first rule")
	}

	if p.Frame.Measure[0].If.MatchesFrame("s2c", "text") {
		t.Fatal("s2c must not match a c2s rule")
	}

	if p.Frame.Measure[0].If.MatchesFrame("c2s", "binary") {
		t.Fatal("binary must not match a text rule")
	}

	if !p.Frame.Measure[1].If.MatchesFrame("s2c", "binary") {
		t.Fatal("an opcode-less rule matches any opcode")
	}
}

func TestFrameSelectorsRejectedOutsideFrames(t *testing.T) {
	cases := map[string]string{
		"direction on response": `
mode: enforce
response:
  enabled: true
  measure:
    - { if: { direction: [c2s] }, source: const, counter: x }
`,
		"conn axis on request": `
mode: enforce
request:
  enabled: true
  judge:
    - { counter: x, axis: conn, at: 50, action: score, score: 10 }
`,
		"status on frame": `
mode: enforce
frame:
  enabled: true
  measure:
    - { if: { status: [200] }, source: const, counter: x }
`,
		"bad direction": `
mode: enforce
frame:
  enabled: true
  measure:
    - { if: { direction: [up] }, source: const, counter: x }
`,
	}

	for name, yaml := range cases {
		if _, err := frameProfile(t, yaml); err == nil {
			t.Errorf("%s: must reject", name)
		}
	}
}

func TestFrameReferencesChecked(t *testing.T) {
	c, err := ParseCounters([]byte(`
counters:
  ws_frames:
    axes:
      conn: { max: 100, loss: 10 }
`))
	if err != nil {
		t.Fatal(err)
	}

	p, err := frameProfile(t, `
mode: enforce
frame:
  enabled: true
  judge:
    - { counter: ws_frames, axis: ip, at: 50, action: score, score: 10 }
`)
	if err != nil {
		t.Fatal(err)
	}

	err = p.ValidateAgainst(c)
	if err == nil || !strings.Contains(err.Error(), "frame.judge[0]") {
		t.Fatalf("undeclared axis must reject with the frame path: %v", err)
	}
}

func TestAllPhasesDisabledRejected(t *testing.T) {
	_, err := frameProfile(t, `
mode: enforce
request: { enabled: false }
response: { enabled: false }
frame: { enabled: false }
`)
	if err == nil || !strings.Contains(err.Error(), "all phases") {
		t.Fatalf("all disabled must reject: %v", err)
	}
}
