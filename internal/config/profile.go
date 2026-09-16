package config

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/exemt/placitum-counter/internal/overload"
	"github.com/exemt/placitum-counter/internal/protocol"
)

const (
	ModeEnforce = "enforce"
	ModeObserve = "observe"
	ModeOff     = "off"

	ActionDeny  = "deny"
	ActionScore = "score"
	ActionAllow = "allow"

	SourceConst      = "const"
	SourceRegexCount = "regex_count"
	SourceSizeKB     = "size_kb"
	SourceBytes      = "bytes"

	DirectionC2S = "c2s"
	DirectionS2C = "s2c"

	OpcodeText         = "text"
	OpcodeBinary       = "binary"
	OpcodeContinuation = "continuation"

	OnDeny  = ActionDeny
	OnAllow = ActionAllow
	OnScore = ActionScore

	OnLevel = "level"

	OnOverload = overload.On

	WriteAddr   = "addr"
	WriteNet    = "net"
	WriteNetAll = "net_all"
	WriteASN    = "asn"
)

const DefaultName = "default"

const ProbeName = "_probe"

const DefaultDenyResponse = "counter_limit"

const DefaultFrameDenyResponse = "ws_policy"

var (
	nameRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	methodRe = regexp.MustCompile(`^[A-Z]+$`)
	codeRe   = regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`)
)

type Duration int

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var raw string
	if err := node.Decode(&raw); err != nil {
		return err
	}

	v, err := ParseDuration(raw)
	if err != nil {
		return err
	}

	*d = Duration(v)

	return nil
}

func (d Duration) Seconds() int { return int(d) }

func ParseDuration(raw string) (int, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return 0, nil
	}

	mult := 1

	switch {
	case strings.HasSuffix(raw, "s"):
		raw = strings.TrimSuffix(raw, "s")
	case strings.HasSuffix(raw, "m"):
		mult, raw = 60, strings.TrimSuffix(raw, "m")
	case strings.HasSuffix(raw, "h"):
		mult, raw = 3600, strings.TrimSuffix(raw, "h")
	case strings.HasSuffix(raw, "d"):
		mult, raw = 86400, strings.TrimSuffix(raw, "d")
	}

	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("duration %q: %w", raw, err)
	}

	if n < 0 {
		return 0, fmt.Errorf("duration must not be negative: %q", raw)
	}

	return n * mult, nil
}

type Profile struct {
	Name string `yaml:"-"`

	Mode        string `yaml:"mode"`
	Description string `yaml:"description"`

	Trigger  Trigger       `yaml:"trigger"`
	Request  RequestPhase  `yaml:"request"`
	Response ResponsePhase `yaml:"response"`
	Frame    FramePhase    `yaml:"frame"`
}

type FramePhase struct {
	Enabled      bool          `yaml:"enabled"`
	Measure      []MeasureRule `yaml:"measure"`
	Judge        []JudgeRule   `yaml:"judge"`
	DenyResponse string        `yaml:"deny_response"`
	Outcomes     []Outcome     `yaml:"outcomes"`
}

type RequestPhase struct {
	Enabled      bool        `yaml:"enabled"`
	Judge        []JudgeRule `yaml:"judge"`
	DenyResponse string      `yaml:"deny_response"`
	Outcomes     []Outcome   `yaml:"outcomes"`
}

type ResponsePhase struct {
	Enabled bool          `yaml:"enabled"`
	Measure []MeasureRule `yaml:"measure"`
}

type JudgeRule struct {
	Counter string  `yaml:"counter"`
	Axis    string  `yaml:"axis"`
	At      float64 `yaml:"at"`
	Action  string  `yaml:"action"`
	Score   int     `yaml:"score"`
	Code    string  `yaml:"code"`
}

type MeasureRule struct {
	If      Match    `yaml:"if"`
	Source  string   `yaml:"source"`
	Regex   string   `yaml:"regex"`
	Per     *float64 `yaml:"per"`
	Counter string   `yaml:"counter"`
	Axes    []string `yaml:"axes"`

	re *regexp.Regexp
}

func (m *MeasureRule) Weight() float64 {
	if m.Per == nil {
		return 1
	}

	return *m.Per
}

func (m *MeasureRule) Regexp() *regexp.Regexp { return m.re }

type Match struct {
	Status      []int    `yaml:"status"`
	ContentType []string `yaml:"content_type"`
	Methods     []string `yaml:"methods"`

	Direction []string `yaml:"direction"`
	Opcode    []string `yaml:"opcode"`
}

func (m *Match) MatchesFrame(direction, opcode string) bool {
	if len(m.Direction) > 0 && !hasFold(m.Direction, direction) {
		return false
	}

	return len(m.Opcode) == 0 || hasFold(m.Opcode, opcode)
}

func (m *Match) Matches(method string, status int, contentType string) bool {
	if len(m.Status) > 0 && !hasInt(m.Status, status) {
		return false
	}

	if len(m.Methods) > 0 && !hasFold(m.Methods, method) {
		return false
	}

	return typeAllowed(m.ContentType, contentType)
}

func typeAllowed(want []string, contentType string) bool {
	if len(want) == 0 {
		return true
	}

	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}

	for _, w := range want {
		w = strings.ToLower(strings.TrimSpace(w))

		if strings.HasPrefix(w, "+") {
			if strings.HasSuffix(ct, w) {
				return true
			}

			continue
		}

		if ct == w {
			return true
		}
	}

	return false
}

func defaults(name string) *Profile {
	return &Profile{
		Name: name,
		Mode: ModeEnforce,
		Request: RequestPhase{
			Enabled:      true,
			DenyResponse: DefaultDenyResponse,
		},
		Response: ResponsePhase{
			Enabled: true,
		},
		Frame: FramePhase{
			Enabled:      true,
			DenyResponse: DefaultFrameDenyResponse,
		},
	}
}

func ParseProfile(name string, raw []byte) (*Profile, error) {
	p := defaults(name)

	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)

	if err := dec.Decode(p); err != nil {
		return nil, fmt.Errorf("profile %s: %w", name, err)
	}

	p.Name = name

	return p, nil
}

var outcomeVerbs = map[string][]string{
	protocol.DoChallenge: {protocol.ApplyRequest},
	protocol.DoThreshold: {protocol.ApplyRequest},
	protocol.DoSkip:      {protocol.ApplyRequest},
	protocol.DoMutate:    {protocol.ApplyRequest},
	protocol.DoReauth:    {protocol.ApplySession},
	protocol.DoNote: {protocol.ApplyRequest, protocol.ApplyIP,
		protocol.ApplyASN, protocol.ApplySession},
	protocol.DoActive:  {protocol.ApplyRequest, protocol.ApplyConn},
	protocol.DoPassive: {protocol.ApplyRequest, protocol.ApplyConn},
	protocol.DoOff:     {protocol.ApplyRequest, protocol.ApplyConn},
	protocol.DoVote:    {protocol.ApplyRequest, protocol.ApplyConn},
	protocol.DoAudit:   {protocol.ApplyRequest, protocol.ApplyResponse},
	protocol.DoArchive: {protocol.ApplyRequest, protocol.ApplyResponse},
	protocol.DoMark:    {protocol.ApplyRequest},
	protocol.DoScore:   {protocol.ApplyRequest},
}

func auditVerb(do string) bool {
	return do == protocol.DoAudit || do == protocol.DoArchive
}

func recordVerb(do string) bool {
	return auditVerb(do) || do == protocol.DoMark || do == protocol.DoScore
}

func controlVerb(do string) bool {
	switch do {
	case protocol.DoActive, protocol.DoPassive, protocol.DoOff, protocol.DoVote:
		return true
	}

	return false
}

func checkPhaseAsk(do, phase, apply string) error {
	if phase == "" {
		return nil
	}

	if !controlVerb(do) {
		return fmt.Errorf("phase is only for active, passive, vote and off")
	}

	switch phase {
	case protocol.PhaseRequest, protocol.PhaseResponse, protocol.PhaseFrame:
	default:
		return fmt.Errorf("phase must be request, response or frame, got %q", phase)
	}

	if apply == protocol.ApplyConn && phase != protocol.PhaseFrame {
		return fmt.Errorf("apply conn needs phase frame")
	}

	return nil
}

type Outcome struct {
	On    string     `yaml:"on"`
	At    *int       `yaml:"at"`
	Below bool       `yaml:"below"`
	Eq    bool       `yaml:"eq"`
	If    *OutcomeIf `yaml:"if"`

	To      string               `yaml:"to"`
	Do      string               `yaml:"do"`
	Apply   string               `yaml:"apply"`
	Phase   string               `yaml:"phase"`
	Delta   *int                 `yaml:"delta"`
	Value   *int                 `yaml:"value"`
	Counter string               `yaml:"counter"`
	Group   string               `yaml:"group"`
	Set     string               `yaml:"set"`
	Headers *protocol.ObjectSpec `yaml:"headers"`
	Args    *protocol.ObjectSpec `yaml:"args"`
	Body    *protocol.ObjectSpec `yaml:"body"`
	When    []string             `yaml:"when"`

	Marker string `yaml:"marker"`

	List  string   `yaml:"list"`
	Write string   `yaml:"write"`
	TTL   Duration `yaml:"ttl"`

	Code string `yaml:"code"`
}

type OutcomeIf struct {
	Counter string `yaml:"counter"`
	Axis    string `yaml:"axis"`
}

func (o Outcome) Asks() bool { return o.Do != "" }

func (o Outcome) OnBucket() bool { return o.On == OnLevel && o.If != nil }

func (o Outcome) Subject() string {
	if o.Write == "" {
		return WriteAddr
	}

	return o.Write
}

func (o Outcome) MatchesLevel(percent float64, ok bool) bool {
	if !o.OnBucket() || !ok || o.At == nil {
		return false
	}

	if o.Below {
		return percent < float64(*o.At)
	}

	return percent >= float64(*o.At)
}

func (o Outcome) Matches(verdict string, score int) bool {
	switch o.On {
	case OnAllow:
		return verdict == protocol.VerdictAllow

	case OnDeny:
		return verdict == protocol.VerdictDeny

	case OnScore:
		if verdict != protocol.VerdictScore || o.At == nil {
			return false
		}

		if o.Eq {
			return score == *o.At
		}

		if o.Below {
			return score < *o.At
		}

		return score >= *o.At
	}

	return false
}

func validateOutcome(section string, i int, o Outcome) error {
	where := fmt.Sprintf("%s.outcomes[%d]", section, i)

	switch o.On {
	case OnDeny, OnAllow:
		if o.At != nil {
			return fmt.Errorf("%s: at is only for on: %s or %s", where, OnScore, OnLevel)
		}

		if o.Below || o.Eq {
			return fmt.Errorf("%s: below and eq are only for on: %s or %s",
				where, OnScore, OnLevel)
		}

	case OnScore:
		if o.At == nil {
			return fmt.Errorf("%s: on: score needs at", where)
		}

		if *o.At < 0 || *o.At > 100 {
			return fmt.Errorf("%s: at %d is out of 0..100", where, *o.At)
		}

		if o.Below && o.Eq {
			return fmt.Errorf("%s: below and eq are mutually exclusive", where)
		}

	case OnLevel:
		if o.If == nil || o.If.Counter == "" {
			return fmt.Errorf("%s: on: %s needs if.counter", where, OnLevel)
		}

		if !hasString(knownAxes, o.If.Axis) {
			return fmt.Errorf("%s: if.axis must be one of %s, got %q",
				where, strings.Join(knownAxes, ", "), o.If.Axis)
		}

		if o.At == nil {
			return fmt.Errorf("%s: on: %s needs at", where, OnLevel)
		}

		if *o.At < 0 || *o.At > 100 {
			return fmt.Errorf("%s: at %d is out of 0..100 percent", where, *o.At)
		}

		if o.Eq {
			return fmt.Errorf("%s: eq is only for on: %s: a bucket level is "+
				"continuous, use %q or below", where, OnScore, "at")
		}

	case OnOverload:
		if section != "request" {
			return fmt.Errorf("%s: on: %s is only for the request section", where, OnOverload)
		}

		if err := overload.Check(o.At); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}

		if o.Below || o.Eq {
			return fmt.Errorf("%s: below and eq are only for on: %s or %s", where, OnScore, OnLevel)
		}

	default:
		return fmt.Errorf("%s: unknown on %q", where, o.On)
	}

	if o.If != nil && o.On != OnLevel {
		return fmt.Errorf("%s: if is only for on: %s", where, OnLevel)
	}

	if err := checkCode(o.Code); err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}

	if o.Asks() && o.List != "" {
		return fmt.Errorf("%s: do and list are mutually exclusive", where)
	}

	if o.Asks() {
		if err := validateOutcomeAsk(where, o); err != nil {
			return err
		}

		if o.Apply == protocol.ApplyConn && section != "frame" {
			return fmt.Errorf("%s: apply conn is only for the frame section", where)
		}

		if o.Apply == protocol.ApplyResponse && section == "frame" {
			return fmt.Errorf("%s: apply response is not for the frame section: frames have no response record", where)
		}

		return nil
	}

	if o.List == "" {
		return fmt.Errorf("%s: neither do nor list", where)
	}

	if !nameRe.MatchString(o.List) {
		return fmt.Errorf("%s: bad dataset name %q", where, o.List)
	}

	switch o.Write {
	case "", WriteAddr, WriteNet, WriteNetAll, WriteASN:
	default:
		return fmt.Errorf("%s: write must be %s, %s, %s or %s, got %q",
			where, WriteAddr, WriteNet, WriteNetAll, WriteASN, o.Write)
	}

	if o.TTL.Seconds() <= 0 {
		return fmt.Errorf("%s: list needs ttl", where)
	}

	return nil
}

func validateOutcomeAsk(where string, o Outcome) error {
	if o.On == OnDeny && !recordVerb(o.Do) {
		return fmt.Errorf("%s: deny ends the phase, an ask has nowhere to go", where)
	}

	axes, ok := outcomeVerbs[o.Do]
	if !ok {
		return fmt.Errorf("%s: unknown verb %q", where, o.Do)
	}

	if o.Apply != "" && !hasString(axes, o.Apply) {
		return fmt.Errorf("%s: verb %q does not take apply %q", where, o.Do, o.Apply)
	}

	if o.Apply == "" && len(axes) != 1 && !auditVerb(o.Do) {
		return fmt.Errorf("%s: %s needs apply", where, o.Do)
	}

	if controlVerb(o.Do) && o.To == "" {
		return fmt.Errorf("%s: %s needs to", where, o.Do)
	}

	if err := checkPhaseAsk(o.Do, o.Phase, o.Axis()); err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}

	if o.Delta != nil && (*o.Delta < -100 || *o.Delta > 900) {
		return fmt.Errorf("%s: delta %d is out of -100..900 percent", where, *o.Delta)
	}

	if o.Value != nil && (*o.Value < -100 || *o.Value > 100) {
		return fmt.Errorf("%s: value %d is out of -100..100 percent", where, *o.Value)
	}

	if o.Do == protocol.DoThreshold && (o.Delta == nil || *o.Delta == 0) {
		return fmt.Errorf("%s: threshold needs a non-zero delta", where)
	}

	if o.Do == protocol.DoNote && (o.Value == nil || *o.Value == 0) {
		return fmt.Errorf("%s: note needs a non-zero value", where)
	}

	if o.Do == protocol.DoScore {
		if o.To != "" && o.To != "*" {
			return fmt.Errorf("%s: %s takes no to: the module adds to the route's own sum", where, o.Do)
		}

		if o.Value == nil || *o.Value == 0 {
			return fmt.Errorf("%s: score needs a non-zero value", where)
		}
	}

	if o.Counter != "" {
		if o.Do != protocol.DoNote {
			return fmt.Errorf("%s: counter is only for %q", where, protocol.DoNote)
		}

		if !nameRe.MatchString(o.Counter) {
			return fmt.Errorf("%s: bad counter name %q", where, o.Counter)
		}
	}

	if o.Do == protocol.DoMutate {
		if o.Group == "" {
			return fmt.Errorf("%s: mutate needs a group", where)
		}

		if !nameRe.MatchString(o.Group) {
			return fmt.Errorf("%s: bad group name %q", where, o.Group)
		}

		if o.Set != "on" && o.Set != "off" {
			return fmt.Errorf("%s: mutate needs set: on or off, got %q", where, o.Set)
		}
	} else if o.Group != "" || (o.Set != "" && !auditVerb(o.Do)) {
		return fmt.Errorf("%s: group and set are only for %q", where, protocol.DoMutate)
	}

	if o.Do == protocol.DoMark {
		if o.To != "" && o.To != "*" {
			return fmt.Errorf("%s: %s takes no to: the module marks the route's own record", where, o.Do)
		}

		if err := protocol.CheckMarker(o.Marker); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
	} else if o.Marker != "" {
		return fmt.Errorf("%s: marker is only for %q", where, protocol.DoMark)
	}

	if auditVerb(o.Do) {
		if o.To != "" && o.To != "*" {
			return fmt.Errorf("%s: %s takes no to: the module writes the route's own record", where, o.Do)
		}

		if o.Set != "on" && o.Set != "off" {
			return fmt.Errorf("%s: %s needs set: on or off, got %q", where, o.Do, o.Set)
		}

		if o.Set == "off" && (o.TTL.Seconds() != 0 || len(o.When) != 0 ||
			o.Headers != nil || o.Args != nil || o.Body != nil) {
			return fmt.Errorf("%s: ttl, when and objects are only for set on", where)
		}

		if o.Do == protocol.DoAudit && (o.TTL.Seconds() != 0 || len(o.When) != 0) {
			return fmt.Errorf("%s: ttl and when are only for archive", where)
		}

		if _, err := protocol.CheckArchiveWhen(o.When); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}

		if o.Apply == protocol.ApplyResponse && o.Args != nil {
			return fmt.Errorf("%s: args has no meaning for the response record", where)
		}

		for _, item := range []struct {
			name string
			spec *protocol.ObjectSpec
		}{{"headers", o.Headers}, {"args", o.Args}, {"body", o.Body}} {
			if err := protocol.CheckObjectSpec(item.name, item.spec, o.Do == protocol.DoAudit); err != nil {
				return fmt.Errorf("%s: %w", where, err)
			}
		}
	}

	if !auditVerb(o.Do) && (len(o.When) != 0 || o.Headers != nil || o.Args != nil || o.Body != nil) {
		return fmt.Errorf("%s: when, headers, args and body are only for audit and archive", where)
	}

	return nil
}

func (o Outcome) Axis() string {
	if o.Apply != "" {
		return o.Apply
	}

	if axes, ok := outcomeVerbs[o.Do]; ok && (len(axes) == 1 || auditVerb(o.Do)) {
		return axes[0]
	}

	return ""
}

func hasString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}

	return false
}

func hasFold(list []string, want string) bool {
	for _, v := range list {
		if strings.EqualFold(v, want) {
			return true
		}
	}

	return false
}

func hasInt(list []int, want int) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}

	return false
}

func checkCode(code string) error {
	if code == "" {
		return nil
	}

	if len(code) > 64 {
		return fmt.Errorf("code is longer than 64 bytes")
	}

	if !codeRe.MatchString(code) {
		return fmt.Errorf("bad code %q", code)
	}

	return nil
}

const AnyInspector = "*"

type Trigger struct {
	Prior []PriorRule `yaml:"prior"`
}

type PriorRule struct {
	From    string   `yaml:"from"`
	Accept  []string `yaml:"accept"`
	Apply   []string `yaml:"apply"`
	Codes   []string `yaml:"codes"`
	Counter string   `yaml:"counter"`
}

func (r PriorRule) Accepts(verb string) bool {
	for _, v := range r.Accept {
		if v == verb {
			return true
		}
	}

	return false
}

func (r PriorRule) WantsAxis(axis string) bool {
	if len(r.Apply) == 0 {
		return true
	}

	for _, a := range r.Apply {
		if a == axis {
			return true
		}
	}

	return false
}

func (r PriorRule) WantsCode(code string) bool {
	if len(r.Codes) == 0 {
		return true
	}

	for _, c := range r.Codes {
		if c == code {
			return true
		}
	}

	return false
}

func validatePrior(i int, r PriorRule) error {
	if r.From == "" {
		return fmt.Errorf("trigger.prior[%d]: from is empty", i)
	}

	if len(r.Accept) == 0 {
		return fmt.Errorf("trigger.prior[%d]: accept is required", i)
	}

	for _, verb := range r.Accept {
		switch verb {
		case "threshold", "skip", "note":

		case "challenge", "reauth":
			return fmt.Errorf("trigger.prior[%d]: %q is not ours to apply", i, verb)

		default:
			return fmt.Errorf("trigger.prior[%d]: unknown verb %q", i, verb)
		}
	}

	for _, axis := range r.Apply {
		switch axis {
		case "request":
			if !r.Accepts("threshold") && !r.Accepts("skip") {
				return fmt.Errorf("trigger.prior[%d]: axis %q never hits a bucket of %v",
					i, axis, r.Accept)
			}

		case "ip", "asn", "session":
			if !r.Accepts("note") {
				return fmt.Errorf("trigger.prior[%d]: axis %q never occurs with %v",
					i, axis, r.Accept)
			}

		default:
			return fmt.Errorf("trigger.prior[%d]: unknown axis %q", i, axis)
		}
	}

	if r.Accepts("note") {
		if r.Counter == "" {
			return fmt.Errorf("trigger.prior[%d]: counter is required for %q", i, "note")
		}

		if !nameRe.MatchString(r.Counter) {
			return fmt.Errorf("trigger.prior[%d]: bad counter name %q", i, r.Counter)
		}
	} else if r.Counter != "" {
		return fmt.Errorf("trigger.prior[%d]: counter is only for %q", i, "note")
	}

	if r.From == AnyInspector {
		return fmt.Errorf("trigger.prior[%d]: %v need a named sender: they can weaken",
			i, r.Accept)
	}

	return nil
}

func (p *Profile) Validate() error {
	switch p.Mode {
	case ModeEnforce, ModeObserve, ModeOff:
	default:
		return fmt.Errorf("mode must be enforce, observe or off, got %q", p.Mode)
	}

	for i, r := range p.Trigger.Prior {
		if err := validatePrior(i, r); err != nil {
			return err
		}
	}

	for i, o := range p.Request.Outcomes {
		if err := validateOutcome("request", i, o); err != nil {
			return err
		}
	}

	for i, o := range p.Frame.Outcomes {
		if err := validateOutcome("frame", i, o); err != nil {
			return err
		}
	}

	if p.Mode == ModeOff {
		return nil
	}

	if !p.Request.Enabled && !p.Response.Enabled && !p.Frame.Enabled {
		return fmt.Errorf("all phases are disabled: the profile would do nothing")
	}

	if err := validateJudges("request", p.Request.Judge, p.Request.DenyResponse, false); err != nil {
		return err
	}

	if err := validateJudges("frame", p.Frame.Judge, p.Frame.DenyResponse, true); err != nil {
		return err
	}

	for i := range p.Response.Measure {
		if err := validateMeasure("response", i, &p.Response.Measure[i], false); err != nil {
			return err
		}
	}

	for i := range p.Frame.Measure {
		if err := validateMeasure("frame", i, &p.Frame.Measure[i], true); err != nil {
			return err
		}
	}

	return nil
}

func validateJudges(section string, rules []JudgeRule, denyResponse string, frame bool) error {
	denies := false

	for i, r := range rules {
		if err := validateJudge(section, i, r, frame); err != nil {
			return err
		}

		if r.Action == ActionDeny {
			denies = true
		}
	}

	if denies && denyResponse == "" {
		return fmt.Errorf("%s.deny_response is required when a judge rule is %s",
			section, ActionDeny)
	}

	return nil
}

func validateJudge(section string, i int, r JudgeRule, frame bool) error {
	where := fmt.Sprintf("%s.judge[%d]", section, i)

	if r.Counter == "" {
		return fmt.Errorf("%s: counter is required", where)
	}

	if !hasString(knownAxes, r.Axis) {
		return fmt.Errorf("%s: axis must be one of %s, got %q",
			where, strings.Join(knownAxes, ", "), r.Axis)
	}

	if r.Axis == AxisConn && !frame {
		return fmt.Errorf("%s: axis %s is only for the frame phase", where, AxisConn)
	}

	if r.At < 0 || r.At > 100 {
		return fmt.Errorf("%s: at %v is out of 0..100 percent", where, r.At)
	}

	switch r.Action {
	case ActionDeny:
		if r.Score != 0 {
			return fmt.Errorf("%s: score is only for action: score", where)
		}

	case ActionScore:
		if r.Score < 1 || r.Score > 100 {
			return fmt.Errorf("%s: score must be within 1..100, got %d", where, r.Score)
		}

	default:
		return fmt.Errorf("%s: action must be %s or %s, got %q",
			where, ActionScore, ActionDeny, r.Action)
	}

	return checkCode(r.Code)
}

func validateMeasure(section string, i int, m *MeasureRule, frame bool) error {
	where := fmt.Sprintf("%s.measure[%d]", section, i)

	if m.Counter == "" {
		return fmt.Errorf("%s: counter is required", where)
	}

	switch m.Source {
	case SourceConst, SourceSizeKB, SourceBytes:
		if m.Regex != "" {
			return fmt.Errorf("%s: regex is only for source: %s", where, SourceRegexCount)
		}

	case SourceRegexCount:
		if m.Regex == "" {
			return fmt.Errorf("%s: source %s needs regex", where, SourceRegexCount)
		}

		re, err := regexp.Compile(m.Regex)
		if err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}

		m.re = re

	default:
		return fmt.Errorf("%s: source must be %s, %s, %s or %s, got %q",
			where, SourceConst, SourceRegexCount, SourceSizeKB, SourceBytes, m.Source)
	}

	if m.Weight() == 0 {
		return fmt.Errorf("%s: per must not be zero: a rule that adds nothing "+
			"is written by not writing it", where)
	}

	for _, axis := range m.Axes {
		if !hasString(knownAxes, axis) {
			return fmt.Errorf("%s: axis must be one of %s, got %q",
				where, strings.Join(knownAxes, ", "), axis)
		}

		if axis == AxisConn && !frame {
			return fmt.Errorf("%s: axis %s is only for the frame phase", where, AxisConn)
		}
	}

	if frame {
		if len(m.If.Status)+len(m.If.ContentType)+len(m.If.Methods) != 0 {
			return fmt.Errorf("%s: if.status, if.content_type and if.methods are "+
				"not frame selectors; use if.direction and if.opcode", where)
		}

		for _, d := range m.If.Direction {
			if d != DirectionC2S && d != DirectionS2C {
				return fmt.Errorf("%s: if.direction must be %s or %s, got %q",
					where, DirectionC2S, DirectionS2C, d)
			}
		}

		for _, op := range m.If.Opcode {
			if op != OpcodeText && op != OpcodeBinary && op != OpcodeContinuation {
				return fmt.Errorf("%s: if.opcode must be %s, %s or %s, got %q",
					where, OpcodeText, OpcodeBinary, OpcodeContinuation, op)
			}
		}

		return nil
	}

	if len(m.If.Direction)+len(m.If.Opcode) != 0 {
		return fmt.Errorf("%s: if.direction and if.opcode are frame selectors", where)
	}

	for _, meth := range m.If.Methods {
		if !methodRe.MatchString(meth) {
			return fmt.Errorf("%s: if.methods: %q is not an upper-case method", where, meth)
		}
	}

	for _, st := range m.If.Status {
		if st < 100 || st > 599 {
			return fmt.Errorf("%s: if.status %d is not an HTTP status", where, st)
		}
	}

	return nil
}

func (p *Profile) ValidateAgainst(c *Counters) error {
	if p.Mode == ModeOff {
		return nil
	}

	for i, r := range p.Request.Judge {
		if !c.HasAxis(r.Counter, r.Axis) {
			return fmt.Errorf("request.judge[%d]: counter %q has no axis %q declared "+
				"in %s/%s", i, r.Counter, r.Axis, SharedDir, CountersFile)
		}
	}

	for i, m := range p.Response.Measure {
		if _, ok := c.Counters[m.Counter]; !ok {
			return fmt.Errorf("response.measure[%d]: counter %q is not declared "+
				"in %s/%s", i, m.Counter, SharedDir, CountersFile)
		}

		if c.Fill(m.Counter) != FillMeasure {
			return fmt.Errorf("response.measure[%d]: counter %q is fill: %s: "+
				"neighbours fill it, measure would be a second owner",
				i, m.Counter, FillNote)
		}

		for _, axis := range m.Axes {
			if !c.HasAxis(m.Counter, axis) {
				return fmt.Errorf("response.measure[%d]: counter %q has no axis %q",
					i, m.Counter, axis)
			}
		}
	}

	for i, o := range p.Request.Outcomes {
		if !o.OnBucket() {
			continue
		}

		if !c.HasAxis(o.If.Counter, o.If.Axis) {
			return fmt.Errorf("request.outcomes[%d]: counter %q has no axis %q declared "+
				"in %s/%s", i, o.If.Counter, o.If.Axis, SharedDir, CountersFile)
		}
	}

	for i, r := range p.Frame.Judge {
		if !c.HasAxis(r.Counter, r.Axis) {
			return fmt.Errorf("frame.judge[%d]: counter %q has no axis %q declared "+
				"in %s/%s", i, r.Counter, r.Axis, SharedDir, CountersFile)
		}
	}

	for i, m := range p.Frame.Measure {
		if _, ok := c.Counters[m.Counter]; !ok {
			return fmt.Errorf("frame.measure[%d]: counter %q is not declared "+
				"in %s/%s", i, m.Counter, SharedDir, CountersFile)
		}

		if c.Fill(m.Counter) != FillMeasure {
			return fmt.Errorf("frame.measure[%d]: counter %q is fill: %s: "+
				"neighbours fill it, measure would be a second owner",
				i, m.Counter, FillNote)
		}

		for _, axis := range m.Axes {
			if !c.HasAxis(m.Counter, axis) {
				return fmt.Errorf("frame.measure[%d]: counter %q has no axis %q",
					i, m.Counter, axis)
			}
		}
	}

	for i, o := range p.Frame.Outcomes {
		if !o.OnBucket() {
			continue
		}

		if !c.HasAxis(o.If.Counter, o.If.Axis) {
			return fmt.Errorf("frame.outcomes[%d]: counter %q has no axis %q declared "+
				"in %s/%s", i, o.If.Counter, o.If.Axis, SharedDir, CountersFile)
		}
	}

	for i, r := range p.Trigger.Prior {
		if !r.Accepts("note") {
			continue
		}

		if _, ok := c.Counters[r.Counter]; !ok {
			return fmt.Errorf("trigger.prior[%d]: counter %q is not declared "+
				"in %s/%s", i, r.Counter, SharedDir, CountersFile)
		}

		if c.Fill(r.Counter) != FillNote {
			return fmt.Errorf("trigger.prior[%d]: counter %q is fill: %s: "+
				"measure fills it, notes would be a second owner",
				i, r.Counter, FillMeasure)
		}

		if len(c.NoteAxes(r.Counter, protocol.ApplyIP)) == 0 &&
			len(c.NoteAxes(r.Counter, protocol.ApplyASN)) == 0 &&
			len(c.NoteAxes(r.Counter, protocol.ApplySession)) == 0 {
			return fmt.Errorf("trigger.prior[%d]: counter %q has no axis the "+
				"channel can reach (ip, asn_net, asn_router, sess)", i, r.Counter)
		}
	}

	return nil
}
