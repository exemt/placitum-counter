package decide

import (
	"math"

	"github.com/exemt/placitum-counter/internal/config"
	"github.com/exemt/placitum-counter/internal/protocol"
)

const (
	PercentMin = -100
	PercentMax = 900
)

const (
	OutcomeApplied   = "applied"
	OutcomeNoRule    = "no_rule"
	OutcomeNoCounter = "no_counter"
)

type Ask struct {
	Skip     bool
	Percent  int
	Notes    []NoteCharge
	Outcomes []ActionOutcome
}

type NoteCharge struct {
	Counter string
	Axis    string
	Percent int
	Code    string
	From    string
}

type ActionOutcome struct {
	From    string `json:"from"`
	Do      string `json:"do"`
	Apply   string `json:"apply"`
	Code    string `json:"code,omitempty"`
	Delta   int    `json:"delta,omitempty"`
	Value   int    `json:"value,omitempty"`
	Counter string `json:"counter,omitempty"`

	Took    int    `json:"took,omitempty"`
	Outcome string `json:"outcome"`
}

func EvaluatePrior(
	entries []protocol.PriorVerdict,
	p *config.Profile,
	counters *config.Counters,
	phase string,
) Ask {
	var a Ask

	if p == nil {
		return a
	}

	rules := p.Trigger.Prior

	for _, v := range entries {
		for _, act := range v.Actions {
			if act.Do == protocol.DoNote && !chargeHere(v.Phase, phase, p.Request.Enabled) {
				continue
			}

			a.deliver(v.Inspector, act, rules, counters)
		}
	}

	if a.Percent < PercentMin {
		a.Percent = PercentMin
	}

	if a.Percent > PercentMax {
		a.Percent = PercentMax
	}

	return a
}

func chargeHere(recorded, phase string, requestEnabled bool) bool {
	if recorded == "" {
		recorded = protocol.PhaseRequest
	}

	if recorded == phase {
		return true
	}

	return phase == protocol.PhaseResponse &&
		recorded == protocol.PhaseRequest &&
		!requestEnabled
}

func (a *Ask) deliver(
	from string,
	act protocol.Action,
	rules []config.PriorRule,
	counters *config.Counters,
) {
	out := ActionOutcome{
		From:    from,
		Do:      act.Do,
		Apply:   act.Scope(),
		Code:    act.Code,
		Delta:   act.Delta,
		Value:   act.Value,
		Counter: act.Counter,
		Outcome: OutcomeNoRule,
	}

	for _, r := range rules {
		if r.From != from {
			continue
		}

		if !r.Accepts(act.Do) || !r.WantsAxis(act.Scope()) || !r.WantsCode(act.Code) {
			continue
		}

		if act.Do == protocol.DoNote && act.Counter != "" && act.Counter != r.Counter {
			continue
		}

		switch act.Do {
		case protocol.DoSkip:
			a.Skip = true
			out.apply(0)

		case protocol.DoThreshold:
			a.Percent += act.Delta
			out.apply(act.Delta)

		case protocol.DoNote:
			a.note(r, act, from, counters, &out)
		}
	}

	a.Outcomes = append(a.Outcomes, out)
}

func (a *Ask) note(
	r config.PriorRule,
	act protocol.Action,
	from string,
	counters *config.Counters,
	out *ActionOutcome,
) {
	if act.Value == 0 {
		out.apply(0)

		return
	}

	axes := counters.NoteAxes(r.Counter, act.Scope())
	if len(axes) == 0 {
		out.noCounter()

		return
	}

	out.apply(act.Value)

	for _, axis := range axes {
		a.Notes = append(a.Notes, NoteCharge{
			Counter: r.Counter,
			Axis:    axis,
			Percent: act.Value,
			Code:    act.Code,
			From:    from,
		})
	}
}

func (o *ActionOutcome) apply(took int) {
	o.Outcome = OutcomeApplied
	o.Took += took
}

func (o *ActionOutcome) noCounter() {
	if o.Outcome == OutcomeNoRule {
		o.Outcome = OutcomeNoCounter
	}
}

func ScaleScore(score, percent int) int {
	if percent == 0 || score <= 0 {
		return max(score, 0)
	}

	scaled := int(math.Round(float64(score) * (1 + float64(percent)/100)))

	if scaled < 0 {
		scaled = 0
	}

	return min(scaled, 100)
}
