package decide

import (
	"testing"

	"github.com/exemt/placitum-counter/internal/config"
	"github.com/exemt/placitum-counter/internal/protocol"
)

func judged(t *testing.T, mode, src string, levels map[string]float64) (Decision, []RuleAudit) {
	t.Helper()

	p, err := config.ParseProfile("x", []byte(
		"mode: "+mode+"\nrequest:\n  enabled: true\n  deny_response: counter_limit\n  judge:\n"+src))
	if err != nil {
		t.Fatal(err)
	}

	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}

	return Judge(p, func(counter, axis string) (float64, string, bool) {
		percent, ok := levels[counter+":"+axis]
		if !ok {
			return 0, "", false
		}

		return percent, "key", true
	})
}

func TestJudgeQuietUnderThreshold(t *testing.T) {
	d, rows := judged(t, "enforce",
		"    - {counter: obj, axis: ip, at: 60, action: score, score: 40}\n",
		map[string]float64{"obj:ip": 30})

	if d.Verdict != protocol.VerdictAllow || d.Code != "" {
		t.Fatalf("decision = %+v, want clean allow", d)
	}

	if len(rows) != 1 || rows[0].Fired || rows[0].Percent != 30 {
		t.Fatalf("rows = %+v", rows)
	}
}

func TestJudgeScoreAtThreshold(t *testing.T) {
	d, rows := judged(t, "enforce",
		"    - {counter: obj, axis: ip, at: 60, action: score, score: 40, code: CNT_HOT}\n",
		map[string]float64{"obj:ip": 60})

	if d.Verdict != protocol.VerdictScore || d.Score != 40 || d.Code != "CNT_HOT" {
		t.Fatalf("decision = %+v", d)
	}

	if !rows[0].Fired {
		t.Fatalf("rows = %+v", rows)
	}
}

// Побеждает самое строгое: deny поверх любого score, больший score поверх
// меньшего. Код едет с победившим правилом.
func TestJudgeStrongestWins(t *testing.T) {
	src := "    - {counter: obj, axis: ip, at: 40, action: score, score: 30, code: CNT_WARM}\n" +
		"    - {counter: obj, axis: ip, at: 60, action: score, score: 70, code: CNT_HOT}\n" +
		"    - {counter: obj, axis: sess, at: 90, action: deny, code: CNT_EXFIL}\n"

	d, _ := judged(t, "enforce", src, map[string]float64{"obj:ip": 65, "obj:sess": 10})

	if d.Verdict != protocol.VerdictScore || d.Score != 70 || d.Code != "CNT_HOT" {
		t.Fatalf("decision = %+v, want the hotter score", d)
	}

	d, _ = judged(t, "enforce", src, map[string]float64{"obj:ip": 65, "obj:sess": 95})

	if d.Verdict != protocol.VerdictDeny || d.Code != "CNT_EXFIL" {
		t.Fatalf("decision = %+v, want deny", d)
	}

	if d.DenyResponse != "counter_limit" {
		t.Fatalf("deny_response = %q", d.DenyResponse)
	}
}

// Порядок правил не важен: deny не затирается score, пришедшим позже.
func TestJudgeDenyNotOvershadowed(t *testing.T) {
	src := "    - {counter: obj, axis: ip, at: 50, action: deny, code: CNT_BAN}\n" +
		"    - {counter: obj, axis: ip, at: 40, action: score, score: 90}\n"

	d, _ := judged(t, "enforce", src, map[string]float64{"obj:ip": 60})

	if d.Verdict != protocol.VerdictDeny || d.Code != "CNT_BAN" {
		t.Fatalf("decision = %+v", d)
	}
}

// Субъекта нет -- правило молчит, и это видно в аудите отдельной пометкой.
func TestJudgeNoSubject(t *testing.T) {
	d, rows := judged(t, "enforce",
		"    - {counter: obj, axis: sess, at: 0, action: deny}\n", nil)

	if d.Verdict != protocol.VerdictAllow {
		t.Fatalf("decision = %+v, want allow", d)
	}

	if len(rows) != 1 || !rows[0].NoSubject || rows[0].Fired {
		t.Fatalf("rows = %+v", rows)
	}
}

// Правило без своего повода едет с общим кодом уровня.
func TestJudgeDefaultCode(t *testing.T) {
	d, _ := judged(t, "enforce",
		"    - {counter: obj, axis: ip, at: 10, action: score, score: 20}\n",
		map[string]float64{"obj:ip": 50})

	if d.Code != CodeLevel {
		t.Fatalf("code = %q, want %q", d.Code, CodeLevel)
	}
}

// Наблюдение: наружу allow, решение остаётся в записи.
func TestJudgeObserve(t *testing.T) {
	d, _ := judged(t, "observe",
		"    - {counter: obj, axis: ip, at: 10, action: deny, code: CNT_BAN}\n",
		map[string]float64{"obj:ip": 50})

	if d.Verdict != protocol.VerdictAllow || d.DenyResponse != "" {
		t.Fatalf("decision = %+v, want allow outward", d)
	}

	if d.WouldVerdict != protocol.VerdictDeny || d.WouldCode != "CNT_BAN" {
		t.Fatalf("decision = %+v, want the would-verdict kept", d)
	}

	if d.Code != CodeObserve {
		t.Fatalf("code = %q, want %q: наблюдение видно в записи модуля", d.Code, CodeObserve)
	}
}

// Порог 0 срабатывает на пустой корзине: этим живёт профиль пробы.
func TestJudgeZeroThreshold(t *testing.T) {
	d, _ := judged(t, "enforce",
		"    - {counter: obj, axis: ip, at: 0, action: deny}\n",
		map[string]float64{"obj:ip": 0})

	if d.Verdict != protocol.VerdictDeny {
		t.Fatalf("decision = %+v, want deny off an empty bucket", d)
	}
}
