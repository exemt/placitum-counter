package measure

import (
	"github.com/exemt/placitum-counter/internal/config"
)

type Input struct {
	Method string
	Status int

	Frame       bool
	Direction   string
	Opcode      string
	ContentType string

	Body          []byte
	BodyTruncated bool
	BodySize      int64
}

type Value struct {
	Counter string
	Axes    []string
	Add     float64
}

type Fired struct {
	Counter   string   `json:"counter"`
	Source    string   `json:"source"`
	Value     float64  `json:"value"`
	Axes      []string `json:"axes"`
	Truncated bool     `json:"truncated,omitempty"`
}

func Run(rules []config.MeasureRule, counters *config.Counters, in Input) ([]Value, []Fired) {
	var (
		values []Value
		fired  []Fired
	)

	for i := range rules {
		r := &rules[i]

		if in.Frame {
			if !r.If.MatchesFrame(in.Direction, in.Opcode) {
				continue
			}

		} else if !r.If.Matches(in.Method, in.Status, in.ContentType) {
			continue
		}

		amount, truncated := extract(r, in)
		if amount == 0 {
			continue
		}

		amount *= r.Weight()

		axes := r.Axes
		if len(axes) == 0 {
			axes = counters.AxesOf(r.Counter)
		}

		values = append(values, Value{Counter: r.Counter, Axes: axes, Add: amount})
		fired = append(fired, Fired{
			Counter:   r.Counter,
			Source:    r.Source,
			Value:     amount,
			Axes:      axes,
			Truncated: truncated,
		})
	}

	return values, fired
}

func extract(r *config.MeasureRule, in Input) (float64, bool) {
	switch r.Source {
	case config.SourceConst:
		return 1, false

	case config.SourceSizeKB:
		if in.BodySize <= 0 {
			return 0, false
		}

		return float64(in.BodySize) / 1024, false

	case config.SourceBytes:
		if in.BodySize <= 0 {
			return 0, false
		}

		return float64(in.BodySize), false

	case config.SourceRegexCount:
		if len(in.Body) == 0 {
			return 0, false
		}

		n := len(r.Regexp().FindAllIndex(in.Body, -1))

		return float64(n), in.BodyTruncated
	}

	return 0, false
}
