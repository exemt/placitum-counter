package decide

import (
	"testing"

	"github.com/exemt/placitum-counter/internal/config"
	"github.com/exemt/placitum-counter/internal/protocol"
)

func judgedFrame(t *testing.T, mode, src string, levels map[string]float64) (Decision, []RuleAudit) {
	t.Helper()

	p, err := config.ParseProfile("x", []byte(
		"mode: "+mode+"\nrequest: {enabled: false}\nresponse: {enabled: false}\n"+
			"frame:\n  enabled: true\n  deny_response: ws_policy\n  judge:\n"+src))
	if err != nil {
		t.Fatal(err)
	}

	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}

	return JudgeFrame(p, func(counter, axis string) (float64, string, bool) {
		percent, ok := levels[counter+":"+axis]
		if !ok {
			return 0, "", false
		}

		return percent, "key", true
	})
}

func TestJudgeFrameDenyClosesWithWebsocketEntry(t *testing.T) {
	d, rows := judgedFrame(t, "enforce", `
    - { counter: ws_frames, axis: conn, at: 90, action: deny, code: WS_FLOOD }
`, map[string]float64{"ws_frames:conn": 95})

	if d.Verdict != protocol.VerdictDeny || d.Code != "WS_FLOOD" {
		t.Fatalf("verdict: %+v", d)
	}

	// Отказ на кадре -- запись type=websocket секции frame, не запроса.
	if d.DenyResponse != "ws_policy" {
		t.Fatalf("deny_response: %q", d.DenyResponse)
	}

	if len(rows) != 1 || !rows[0].Fired {
		t.Fatalf("audit: %+v", rows)
	}
}

func TestJudgeFrameDefaultsToWsPolicy(t *testing.T) {
	p, err := config.ParseProfile("x", []byte("mode: enforce\nframe:\n  judge:\n"+
		"    - { counter: c, axis: conn, at: 0, action: deny }\n"))
	if err != nil {
		t.Fatal(err)
	}

	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}

	d, _ := JudgeFrame(p, func(string, string) (float64, string, bool) { return 0, "k", true })

	if d.DenyResponse != config.DefaultFrameDenyResponse {
		t.Fatalf("default deny_response: %q", d.DenyResponse)
	}
}

func TestJudgeFrameObserve(t *testing.T) {
	d, _ := judgedFrame(t, "observe", `
    - { counter: ws_frames, axis: conn, at: 50, action: deny }
`, map[string]float64{"ws_frames:conn": 60})

	if d.Verdict != protocol.VerdictAllow || d.WouldVerdict != protocol.VerdictDeny {
		t.Fatalf("observe: %+v", d)
	}
}
