package decide

import (
	"github.com/exemt/placitum-counter/internal/config"
	"github.com/exemt/placitum-counter/internal/overload"
	"github.com/exemt/placitum-counter/internal/protocol"
)

const (
	CodeLevel = "COUNTER_LEVEL"

	CodeObserve = "COUNTER_OBSERVE"

	CodeUnknownProfile     = "COUNTER_UNKNOWN_PROFILE"
	CodeSkipped            = "COUNTER_SKIPPED"
	CodePhaseNotSupported  = "COUNTER_PHASE_NOT_SUPPORTED"
	CodePhaseDisabled      = "COUNTER_PHASE_DISABLED"
	CodeProfileOff         = "COUNTER_PROFILE_OFF"
	CodeMeasured           = "COUNTER_MEASURED"
	CodeInternalError      = "COUNTER_INTERNAL_ERROR"
	CodeBucketsUnavailable = "COUNTER_BUCKETS_UNAVAILABLE"
	CodeStoreUnavailable   = "COUNTER_STORE_UNAVAILABLE"
	CodeGeoUnavailable     = "COUNTER_GEO_UNAVAILABLE"
	CodeMalformedRequest   = "COUNTER_MALFORMED_REQUEST"
	CodeUnsupportedVersion = "COUNTER_UNSUPPORTED_VERSION"
)

type Decision struct {
	Verdict      string
	Score        int
	Code         string
	DenyResponse string

	WouldVerdict string
	WouldScore   int
	WouldCode    string
}

type LevelLookup func(counter, axis string) (percent float64, key string, ok bool)

type RuleAudit struct {
	Counter   string  `json:"counter"`
	Axis      string  `json:"axis"`
	Key       string  `json:"key,omitempty"`
	Percent   float64 `json:"percent"`
	At        float64 `json:"at"`
	Fired     bool    `json:"fired"`
	Action    string  `json:"action,omitempty"`
	Code      string  `json:"code,omitempty"`
	NoSubject bool    `json:"no_subject,omitempty"`
}

func Judge(p *config.Profile, lookup LevelLookup) (Decision, []RuleAudit) {
	return judge(p.Request.Judge, denyResponseOf(p), p.Mode, lookup)
}

func JudgeFrame(p *config.Profile, lookup LevelLookup) (Decision, []RuleAudit) {
	return judge(p.Frame.Judge, frameDenyResponseOf(p), p.Mode, lookup)
}

func judge(
	rules []config.JudgeRule,
	denyResponse string,
	mode string,
	lookup LevelLookup,
) (Decision, []RuleAudit) {
	d := Decision{Verdict: protocol.VerdictAllow}

	if len(rules) == 0 {
		return d, nil
	}

	audit := make([]RuleAudit, 0, len(rules))

	for _, r := range rules {
		row := RuleAudit{
			Counter: r.Counter,
			Axis:    r.Axis,
			At:      r.At,
			Action:  r.Action,
			Code:    codeOf(r),
		}

		percent, key, ok := lookup(r.Counter, r.Axis)
		if !ok {
			row.NoSubject = true
			audit = append(audit, row)

			continue
		}

		row.Percent, row.Key = percent, key

		if percent < r.At {
			audit = append(audit, row)

			continue
		}

		row.Fired = true
		audit = append(audit, row)

		take(&d, r, denyResponse)
	}

	if mode == config.ModeObserve && d.Verdict != protocol.VerdictAllow {
		d.WouldVerdict = d.Verdict
		d.WouldScore = d.Score
		d.WouldCode = d.Code
		d.Verdict = protocol.VerdictAllow
		d.Score = 0
		d.Code = CodeObserve
		d.DenyResponse = ""
	}

	return d, audit
}

func codeOf(r config.JudgeRule) string {
	if r.Code == "" {
		return CodeLevel
	}

	return r.Code
}

func take(d *Decision, r config.JudgeRule, denyResponse string) {
	code := codeOf(r)

	if r.Action == config.ActionDeny {
		d.Verdict = protocol.VerdictDeny
		d.Score = 0
		d.Code = code
		d.DenyResponse = denyResponse

		return
	}

	if d.Verdict == protocol.VerdictDeny {
		return
	}

	if d.Verdict != protocol.VerdictScore || r.Score > d.Score {
		d.Verdict = protocol.VerdictScore
		d.Score = r.Score
		d.Code = code
	}
}

func denyResponseOf(p *config.Profile) string {
	if p.Request.DenyResponse != "" {
		return p.Request.DenyResponse
	}

	return config.DefaultDenyResponse
}

func frameDenyResponseOf(p *config.Profile) string {
	if p.Frame.DenyResponse != "" {
		return p.Frame.DenyResponse
	}

	return config.DefaultFrameDenyResponse
}

type Ban struct {
	Dataset string
	Write   string
	Addr    string
	TTL     int
	Reason  string
}

type Fired struct {
	Actions []protocol.Action
	Bans    []Ban
	Names   []string
	Levels  []LevelAudit
}

type LevelAudit struct {
	Counter   string  `json:"counter"`
	Axis      string  `json:"axis"`
	Key       string  `json:"key,omitempty"`
	Percent   float64 `json:"percent"`
	At        int     `json:"at"`
	Below     bool    `json:"below,omitempty"`
	Fired     bool    `json:"fired"`
	NoSubject bool    `json:"no_subject,omitempty"`
}

func Fire(
	outcomes []config.Outcome,
	d Decision,
	addr string,
	lookup LevelLookup,
) Fired {
	if len(outcomes) == 0 {
		return Fired{}
	}

	verdict, score, code := d.Verdict, d.Score, d.Code

	if d.WouldVerdict != "" {
		verdict, score, code = d.WouldVerdict, d.WouldScore, d.WouldCode
	}

	var out Fired

	for _, o := range outcomes {
		if o.OnBucket() {
			if !out.level(o, lookup) {
				continue
			}
		} else if !o.Matches(verdict, score) {
			continue
		}

		if o.Asks() {
			out.Actions = append(out.Actions, ask(o, code))
			out.Names = append(out.Names, outcomeName(o))

			continue
		}

		if addr == "" {
			continue
		}

		out.Bans = append(out.Bans, Ban{
			Dataset: o.List,
			Write:   o.Subject(),
			Addr:    addr,
			TTL:     o.TTL.Seconds(),
			Reason:  reason(o, code),
		})

		out.Names = append(out.Names, outcomeName(o))
	}

	return out
}

func (f *Fired) level(o config.Outcome, lookup LevelLookup) bool {
	row := LevelAudit{
		Counter: o.If.Counter,
		Axis:    o.If.Axis,
		Below:   o.Below,
	}

	if o.At != nil {
		row.At = *o.At
	}

	percent, key, ok := 0.0, "", false

	if lookup != nil {
		percent, key, ok = lookup(o.If.Counter, o.If.Axis)
	}

	if !ok {
		row.NoSubject = true
		f.Levels = append(f.Levels, row)

		return false
	}

	row.Percent, row.Key = percent, key
	row.Fired = o.MatchesLevel(percent, ok)
	f.Levels = append(f.Levels, row)

	return row.Fired
}

func ask(o config.Outcome, code string) protocol.Action {
	out := protocol.Action{
		To:      o.To,
		Do:      o.Do,
		Apply:   o.Axis(),
		Phase:   o.Phase,
		Code:    reason(o, code),
		Counter: o.Counter,
		Marker:  o.Marker,
		Group:   o.Group,
		Set:     o.Set,
		Headers: o.Headers,
		Args:    o.Args,
		Body:    o.Body,
	}

	if o.Do == protocol.DoArchive && o.Set == "on" && o.TTL.Seconds() > 0 {
		ttl := int64(o.TTL.Seconds())
		out.TTL = &ttl
	}

	if o.Do == protocol.DoArchive && o.Set == "on" && len(o.When) > 0 {
		when, _ := protocol.CheckArchiveWhen(o.When)
		out.When = when
	}

	if o.Delta != nil {
		out.Delta = *o.Delta
	}

	if o.Value != nil {
		out.Value = *o.Value
	}

	return out
}

func reason(o config.Outcome, code string) string {
	if o.Code != "" {
		return o.Code
	}

	return code
}

func outcomeName(o config.Outcome) string {
	if o.Asks() {
		return o.Do
	}

	return o.List
}

func FireOverload(outcomes []config.Outcome, fill int, shed bool, addr, code string) Fired {
	var out Fired

	for _, o := range outcomes {
		if o.On != config.OnOverload || !overload.Fires(overload.At(o.At), fill, shed) {
			continue
		}

		if o.Asks() {
			out.Actions = append(out.Actions, ask(o, code))
			out.Names = append(out.Names, outcomeName(o))

			continue
		}

		if addr == "" {
			continue
		}

		out.Bans = append(out.Bans, Ban{
			Dataset: o.List,
			Write:   o.Subject(),
			Addr:    addr,
			TTL:     o.TTL.Seconds(),
			Reason:  reason(o, code),
		})

		out.Names = append(out.Names, outcomeName(o))
	}

	return out
}
