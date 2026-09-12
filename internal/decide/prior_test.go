package decide

import (
	"testing"

	"github.com/exemt/placitum-counter/internal/config"
	"github.com/exemt/placitum-counter/internal/protocol"
)

func entry(from string, act protocol.Action) protocol.PriorVerdict {
	return protocol.PriorVerdict{
		Phase:     protocol.PhaseRequest,
		Inspector: from,
		Verdict:   "allow",
		Actions:   []protocol.Action{act},
	}
}

/*
 * profileOf -- профиль с этими правилами приёма и включёнными фазами: note
 * снимается на фазе своей записи, и фаза запроса включена у большинства
 * профилей.
 */
func profileOf(rules []config.PriorRule) *config.Profile {
	return &config.Profile{
		Mode:     config.ModeEnforce,
		Trigger:  config.Trigger{Prior: rules},
		Request:  config.RequestPhase{Enabled: true},
		Response: config.ResponsePhase{Enabled: true},
	}
}

// testCounters -- декларации для приёма note: сигнальная корзина с осями
// адреса и обеих ASN, без sess.
func testCounters() *config.Counters {
	return &config.Counters{Counters: map[string]config.Counter{
		"abuse": {Fill: config.FillNote, Axes: map[string]config.AxisTier{
			"ip":         {Max: 100, Loss: 1},
			"asn_net":    {Max: 500, Loss: 1},
			"asn_router": {Max: 1000, Loss: 1},
		}},
	}}
}

// Скидка и наценка берутся целиком -- потолков у правил нет, числа держит
// загрузчик отправителя, -- а сумма прижата к −100…+900: измерение не бывает
// меньше нуля.
func TestEvaluatePrior(t *testing.T) {
	rules := []config.PriorRule{
		{From: "ip", Accept: []string{"threshold"}},
		{From: "action", Accept: []string{"skip"}},
	}

	ask := EvaluatePrior([]protocol.PriorVerdict{
		entry("ip", protocol.Action{Do: "threshold", Apply: "request", Delta: -50}),
	}, profileOf(rules), testCounters(), protocol.PhaseRequest)

	if ask.Percent != -50 || ask.Skip {
		t.Fatalf("ask = %+v, want -50 taken whole without skip", ask)
	}

	if len(ask.Outcomes) != 1 || ask.Outcomes[0].Outcome != OutcomeApplied ||
		ask.Outcomes[0].Took != -50 {
		t.Fatalf("outcomes = %+v", ask.Outcomes)
	}

	floored := EvaluatePrior([]protocol.PriorVerdict{
		entry("ip", protocol.Action{Do: "threshold", Apply: "request", Delta: -500}),
	}, profileOf(rules), testCounters(), protocol.PhaseRequest)

	if floored.Percent != PercentMin || floored.Outcomes[0].Outcome != OutcomeApplied {
		t.Fatalf("ask = %+v, want the sum floored at %d", floored, PercentMin)
	}

	skip := EvaluatePrior([]protocol.PriorVerdict{
		entry("action", protocol.Action{Do: "skip", Apply: "request"}),
	}, profileOf(rules), testCounters(), protocol.PhaseRequest)

	if !skip.Skip {
		t.Fatalf("skip was not applied: %+v", skip)
	}

	// Просьба от отправителя без правила -- записанное молчание.
	silent := EvaluatePrior([]protocol.PriorVerdict{
		entry("modsec", protocol.Action{Do: "skip", Apply: "request"}),
	}, profileOf(rules), testCounters(), protocol.PhaseRequest)

	if silent.Skip || silent.Outcomes[0].Outcome != OutcomeNoRule {
		t.Fatalf("no-rule ask leaked into the decision: %+v", silent)
	}
}

/*
 * note: заряд снимается на фазе своей записи (запись фазы запроса -- на фазе
 * запроса), ось провода разворачивается декларациями (asn -- обе ASN-оси),
 * недостижимая ось даёт no_counter, повод фильтруется правилом. Проценты
 * уезжают как есть: в единицы их переводит вызывающий.
 */
func TestEvaluatePriorNote(t *testing.T) {
	rules := []config.PriorRule{
		{From: "modsec", Accept: []string{"note"}, Counter: "abuse",
			Codes: []string{"MODSEC_SQLI"}},
	}

	sqli := entry("modsec", protocol.Action{
		Do: "note", Apply: "asn", Value: 20, Code: "MODSEC_SQLI",
	})

	/*
	 * Запись сделана на фазе запроса -- там её и снимают: у заблокированного
	 * запроса фазы ответа не будет вовсе, а такие запросы и надо копить.
	 */
	rsp := EvaluatePrior([]protocol.PriorVerdict{sqli}, profileOf(rules),
		testCounters(), protocol.PhaseRequest)

	if len(rsp.Notes) != 2 {
		t.Fatalf("notes = %+v, want both ASN axes", rsp.Notes)
	}

	// На фазе ответа та же запись приезжает снова (prior сквозная) и
	// пропускается: она уже снята, второй заряд удвоил бы шкалу.
	again := EvaluatePrior([]protocol.PriorVerdict{sqli}, profileOf(rules),
		testCounters(), protocol.PhaseResponse)

	if len(again.Notes) != 0 || len(again.Outcomes) != 0 {
		t.Fatalf("the same record was charged twice: %+v", again)
	}

	/*
	 * Профиль без фазы запроса на ней не работал: запись фазы запроса он видит
	 * впервые уже на фазе ответа -- и снимает её там.
	 */
	late := *profileOf(rules)
	late.Request.Enabled = false

	if fired := EvaluatePrior([]protocol.PriorVerdict{sqli}, &late,
		testCounters(), protocol.PhaseResponse); len(fired.Notes) != 2 {

		t.Fatalf("response-only profile lost the request-phase note: %+v", fired)
	}

	for i, axis := range []string{"asn_net", "asn_router"} {
		n := rsp.Notes[i]

		if n.Counter != "abuse" || n.Axis != axis || n.Percent != 20 ||
			n.Code != "MODSEC_SQLI" || n.From != "modsec" {
			t.Fatalf("notes[%d] = %+v", i, n)
		}
	}

	if len(rsp.Outcomes) != 1 || rsp.Outcomes[0].Outcome != OutcomeApplied ||
		rsp.Outcomes[0].Took != 20 {
		t.Fatalf("outcomes = %+v", rsp.Outcomes)
	}

	// Ось, которой у корзины нет: правило подошло, класть некуда.
	sess := EvaluatePrior([]protocol.PriorVerdict{
		entry("modsec", protocol.Action{
			Do: "note", Apply: "session", Value: 20, Code: "MODSEC_SQLI",
		}),
	}, profileOf(rules), testCounters(), protocol.PhaseRequest)

	if len(sess.Notes) != 0 || sess.Outcomes[0].Outcome != OutcomeNoCounter {
		t.Fatalf("session note found a bucket it should not: %+v", sess)
	}

	// Чужой повод -- записанное молчание, как чужой отправитель.
	code := EvaluatePrior([]protocol.PriorVerdict{
		entry("modsec", protocol.Action{Do: "note", Apply: "ip", Value: 20,
			Code: "MODSEC_XSS"}),
	}, profileOf(rules), testCounters(), protocol.PhaseRequest)

	if len(code.Notes) != 0 || code.Outcomes[0].Outcome != OutcomeNoRule {
		t.Fatalf("a foreign code was accepted: %+v", code)
	}

	// Минус — снятие: знак едет как есть.
	minus := EvaluatePrior([]protocol.PriorVerdict{
		entry("modsec", protocol.Action{Do: "note", Apply: "ip", Value: -100,
			Code: "MODSEC_SQLI"}),
	}, profileOf(rules), testCounters(), protocol.PhaseRequest)

	if len(minus.Notes) != 1 || minus.Notes[0].Percent != -100 {
		t.Fatalf("minus note = %+v", minus.Notes)
	}

	/*
	 * Селектор корзины с провода: названная корзина проходит только через
	 * правило, которое её и выдаёт. Совпадение -- заряд, чужое имя -- no_rule:
	 * грант живёт у получателя, провод лишь выбирает среди выданного.
	 */
	picked := EvaluatePrior([]protocol.PriorVerdict{
		entry("modsec", protocol.Action{Do: "note", Apply: "ip", Value: 20,
			Code: "MODSEC_SQLI", Counter: "abuse"}),
	}, profileOf(rules), testCounters(), protocol.PhaseRequest)

	if len(picked.Notes) != 1 || picked.Notes[0].Counter != "abuse" ||
		picked.Outcomes[0].Outcome != OutcomeApplied ||
		picked.Outcomes[0].Counter != "abuse" {
		t.Fatalf("picked note = %+v", picked)
	}

	foreign := EvaluatePrior([]protocol.PriorVerdict{
		entry("modsec", protocol.Action{Do: "note", Apply: "ip", Value: 20,
			Code: "MODSEC_SQLI", Counter: "someone_elses"}),
	}, profileOf(rules), testCounters(), protocol.PhaseRequest)

	if len(foreign.Notes) != 0 || foreign.Outcomes[0].Outcome != OutcomeNoRule {
		t.Fatalf("a foreign counter passed the rules: %+v", foreign)
	}
}

func TestScaleScore(t *testing.T) {
	cases := []struct {
		score, percent, want int
	}{
		{50, 0, 50},
		{50, -50, 25},
		{40, 50, 60},
		{50, -100, 0},
		{20, 900, 100},
	}

	for _, c := range cases {
		if got := ScaleScore(c.score, c.percent); got != c.want {
			t.Errorf("ScaleScore(%d, %d) = %d, want %d",
				c.score, c.percent, got, c.want)
		}
	}
}

// Правила приёма: все три глагола умеют ослаблять, поэтому имя отправителя
// обязательно, а чужие глаголы не грузятся вовсе.
func TestPriorValidation(t *testing.T) {
	bad := []config.PriorRule{
		{From: "*", Accept: []string{"skip"}},
		{From: "*", Accept: []string{"note"}, Counter: "abuse"},
		{From: "ip", Accept: []string{"challenge"}},
		{From: "ip", Accept: []string{"reauth"}},
		{From: "ip", Accept: []string{"block"}},
		{From: "", Accept: []string{"skip"}},
		{From: "ip", Accept: []string{"skip"}, Apply: []string{"ip"}},
		// note без корзины, корзина не у note, битое имя, мёртвая пара с осью.
		{From: "modsec", Accept: []string{"note"}},
		{From: "ip", Accept: []string{"skip"}, Counter: "abuse"},
		{From: "modsec", Accept: []string{"note"}, Counter: "п лохо"},
		{From: "modsec", Accept: []string{"note"}, Counter: "abuse",
			Apply: []string{"request"}},
	}

	for i, r := range bad {
		p := config.Profile{Mode: config.ModeOff, Trigger: config.Trigger{
			Prior: []config.PriorRule{r},
		}}

		if err := p.Validate(); err == nil {
			t.Errorf("bad[%d] %+v was accepted", i, r)
		}
	}

	ok := config.Profile{Mode: config.ModeOff, Trigger: config.Trigger{
		Prior: []config.PriorRule{
			{From: "ip", Accept: []string{"threshold", "skip"},
				Codes: []string{"IP_ALLOWLIST"}},
			// Потолка нет: threshold с одним именем отправителя -- полное правило.
			{From: "action", Accept: []string{"threshold"}},
			{From: "modsec", Accept: []string{"note"}, Counter: "abuse",
				Apply: []string{"ip", "asn"}, Codes: []string{"MODSEC_SQLI"}},
		},
	}}

	if err := ok.Validate(); err != nil {
		t.Fatalf("a valid rule was rejected: %v", err)
	}
}

/*
 * Приём note больше не требует фазы ответа: запись фазы запроса снимается на
 * фазе запроса, и профиль с одной только фазой запроса законен -- именно он
 * и копит заблокированные запросы.
 */
func TestNotePhaseIndependent(t *testing.T) {
	p := config.Profile{
		Mode: config.ModeEnforce,
		Trigger: config.Trigger{Prior: []config.PriorRule{
			{From: "modsec", Accept: []string{"note"}, Counter: "abuse"},
		}},
		Request:  config.RequestPhase{Enabled: true},
		Response: config.ResponsePhase{Enabled: false},
	}

	if err := p.Validate(); err != nil {
		t.Fatalf("a request-only profile with a note rule was rejected: %v", err)
	}
}
