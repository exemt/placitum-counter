package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-counter/internal/audit"
	"github.com/exemt/placitum-counter/internal/body"
	"github.com/exemt/placitum-counter/internal/buckets"
	"github.com/exemt/placitum-counter/internal/config"
	"github.com/exemt/placitum-counter/internal/decide"
	"github.com/exemt/placitum-counter/internal/measure"
	"github.com/exemt/placitum-counter/internal/protocol"
	"github.com/exemt/placitum-counter/internal/queue"
	"github.com/exemt/placitum-shared/dataset"
	"github.com/exemt/placitum-shared/netinfo"
)

type handler struct {
	cfg      *config.Config
	log      *slog.Logger
	nc       *nats.Conn
	audit    *audit.Sink
	store    *config.Store
	loader   *body.Loader
	pool     *queue.Pool
	bkt      *buckets.Store
	lists    *dataset.Publisher
	resolver *netinfo.Resolver
}

func (h *handler) receive(msg *nats.Msg) {
	defer h.recoverInto(msg.Reply, "")

	req, err := protocol.Parse(msg.Data)
	if err != nil {
		rid := ""

		var pe *protocol.ParseError
		if errors.As(err, &pe) {
			rid = pe.RID
		}

		h.log.Warn("message rejected", "error", err.Error(), "bytes", len(msg.Data))
		h.send(msg.Reply, protocol.FallbackReply(rid, h.cfg.Name, decide.CodeMalformedRequest),
			nil, audit.Details{})

		return
	}

	if !h.cfg.Supports(req.V) {
		reply := protocol.ErrorReply(req, decide.CodeUnsupportedVersion)
		reply.V = protocol.Version

		h.send(msg.Reply, reply, req, audit.Details{})

		return
	}

	if req.Release != nil {
		h.log.Debug("release ignored", "rid", req.RID, "reason", req.Release.Reason)

		return
	}

	if req.Phase != protocol.PhaseRequest && req.Phase != protocol.PhaseResponse &&
		req.Phase != protocol.PhaseFrame {
		h.send(msg.Reply, protocol.ErrorReply(req, decide.CodePhaseNotSupported),
			req, audit.Details{})

		return
	}

	h.pool.Submit(&queue.Task{Req: req, Reply: msg.Reply})
}

func (h *handler) evaluate(t *queue.Task, budget time.Duration, shed string) {
	defer h.recoverInto(t.Reply, t.Req.RID)

	if shed != "" {
		reply := protocol.ShedReply(t.Req, shed)
		det := audit.Details{
			Engine: map[string]any{
				"shed":      shed,
				"budget_ms": float64(budget.Microseconds()) / 1000,
			},
		}

		fired := h.overloadOnShed(t, shed, reply, det)

		h.log.Warn("shed", "rid", t.Req.RID, "reason", shed, "budget_ms", budget.Milliseconds(),
			"asks", len(fired.Actions), "lists", len(fired.Bans))

		h.send(t.Reply, reply, t.Req, det)

		return
	}

	reply, det := h.inspect(t, budget)
	h.send(t.Reply, reply, t.Req, det)
}

func (h *handler) inspect(t *queue.Task, budget time.Duration) (*protocol.Reply, audit.Details) {
	req := t.Req

	snap := h.store.Current()

	p, ok := h.profile(snap, req)
	if !ok {
		h.log.Warn("unknown profile", "rid", req.RID,
			"profile", req.Route.Profile)

		return protocol.ErrorReply(req, decide.CodeUnknownProfile), audit.Details{}
	}

	if p.Mode == config.ModeOff {
		return h.plain(req, protocol.VerdictAllow, decide.CodeProfileOff), audit.Details{}
	}

	if !phaseEnabled(p, req.Phase) {
		return h.plain(req, protocol.VerdictAllow, decide.CodePhaseDisabled), audit.Details{}
	}

	ask := decide.EvaluatePrior(req.Prior, p, snap.Counters(), req.Phase)

	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	switch req.Phase {
	case protocol.PhaseResponse:
		return h.measure(ctx, req, p, snap, ask)

	case protocol.PhaseFrame:
		reply, det := h.frame(ctx, req, p, snap, ask)

		reply.Cache = protocol.Bool(false)

		return reply, det
	}

	return h.judge(ctx, req, p, snap, ask, t.Fill)
}

func (h *handler) judge(
	ctx context.Context,
	req *protocol.Request,
	p *config.Profile,
	snap *config.Snapshot,
	ask decide.Ask,
	fill int,
) (*protocol.Reply, audit.Details) {
	if ask.Skip {
		reply := h.plain(req, protocol.VerdictAllow, decide.CodeSkipped)

		return reply, audit.Details{Engine: map[string]any{
			"profile": p.Name,
			"skip":    true,
			"actions": ask.Outcomes,
		}}
	}

	started := time.Now()
	counters := snap.Counters()

	refs := make([]subjectRef, 0, len(p.Request.Judge)+len(p.Request.Outcomes))

	for _, r := range p.Request.Judge {
		refs = append(refs, subjectRef{counter: r.Counter, axis: r.Axis})
	}

	for _, o := range p.Request.Outcomes {
		if o.OnBucket() {
			refs = append(refs, subjectRef{counter: o.If.Counter, axis: o.If.Axis})
		}
	}

	for _, n := range ask.Notes {
		refs = append(refs, subjectRef{counter: n.Counter, axis: n.Axis})
	}

	if needsResolver(refs) && h.resolver == nil {
		h.log.Error("netinfo resolver is not configured", "rid", req.RID,
			"profile", p.Name)

		return protocol.ErrorReply(req, decide.CodeGeoUnavailable), audit.Details{
			Engine: map[string]any{"profile": p.Name, "geo": "unconfigured"},
		}
	}

	headers, err := h.headersFor(ctx, req, refs, counters)
	if err != nil {
		h.log.Error("store fetch failed", "rid", req.RID, "profile", p.Name,
			"error", err.Error())

		return protocol.ErrorReply(req, decide.CodeStoreUnavailable), audit.Details{
			Engine: map[string]any{"profile": p.Name, "store": err.Error()},
		}
	}

	keys := h.subjectsOf(ctx, refs, counters, req.Conn.ClientIP, headers, req.Sessions, "")

	reads := make([]buckets.Ref, 0, len(p.Request.Judge)+len(p.Request.Outcomes))

	for _, r := range p.Request.Judge {
		if key, ok := keys.key(r.Counter, r.Axis); ok {
			reads = append(reads, buckets.Ref{Kind: config.Kind(r.Counter, r.Axis), Key: key})
		}
	}

	for _, o := range p.Request.Outcomes {
		if !o.OnBucket() {
			continue
		}

		if key, ok := keys.key(o.If.Counter, o.If.Axis); ok {
			reads = append(reads,
				buckets.Ref{Kind: config.Kind(o.If.Counter, o.If.Axis), Key: key})
		}
	}

	tiers := snap.Tiers()

	charges, noted := h.noteCharges(ask.Notes, keys, tiers)

	applied, err := h.bkt.Apply(ctx, tiers, charges, reads)
	if err != nil {
		h.log.Error("buckets unavailable", "rid", req.RID, "profile", p.Name,
			"error", err.Error())

		return protocol.ErrorReply(req, decide.CodeBucketsUnavailable), audit.Details{
			Engine: map[string]any{"profile": p.Name, "buckets": err.Error()},
		}
	}

	levels := map[buckets.Ref]float64{}

	for _, l := range applied {
		levels[l.Ref] = l.Percent
	}

	lookup := func(counter, axis string) (float64, string, bool) {
		key, ok := keys.key(counter, axis)
		if !ok {
			return 0, "", false
		}

		return levels[buckets.Ref{Kind: config.Kind(counter, axis), Key: key}], key, true
	}

	d, rows := decide.Judge(p, lookup)

	scored := d.Score

	if d.Verdict == protocol.VerdictScore {
		scored = decide.ScaleScore(d.Score, ask.Percent)
	}

	if d.WouldVerdict == protocol.VerdictScore {
		d.WouldScore = decide.ScaleScore(d.WouldScore, ask.Percent)
	}

	reply := protocol.NewReply(req, d.Verdict)

	if d.Code != "" {
		reply.Reason = &protocol.Reason{Code: d.Code}
	}

	if d.Verdict == protocol.VerdictScore {
		if err := reply.WithScore(scored); err != nil {
			h.log.Error("score out of range", "rid", req.RID, "score", d.Score)

			reply = protocol.ErrorReply(req, decide.CodeInternalError)
		}
	}

	if d.Verdict == protocol.VerdictDeny {
		reply.Response = &protocol.ResponseRef{Name: d.DenyResponse}
	}

	fired := decide.Fire(p.Request.Outcomes, effective(d, scored), req.Conn.ClientIP, lookup)

	more := decide.FireOverload(p.Request.Outcomes, fill, false, req.Conn.ClientIP,
		queue.ReasonQueueLimit)
	fired.Actions = append(fired.Actions, more.Actions...)
	fired.Bans = append(fired.Bans, more.Bans...)
	fired.Names = append(fired.Names, more.Names...)

	if len(fired.Actions) != 0 {
		reply.Actions = fired.Actions
	}

	det := audit.Details{
		EngineMS: float64(time.Since(started).Microseconds()) / 1000,
		Findings: judgeFindings(rows),
		Engine: map[string]any{
			"profile": p.Name,
			"mode":    p.Mode,
			"phase":   req.Phase,
			"judge":   rows,
		},
	}

	if len(ask.Outcomes) != 0 {
		det.Engine["actions"] = ask.Outcomes
	}

	if ask.Percent != 0 && d.Verdict == protocol.VerdictScore {
		det.Engine["score_raw"] = d.Score
		det.Engine["score_scale_percent"] = ask.Percent
		det.Engine["score_scaled"] = scored
	}

	if p.Mode == config.ModeObserve {
		det.Engine["passive"] = true
	}

	if d.WouldVerdict != "" {
		det.Engine["would_verdict"] = d.WouldVerdict
		det.Engine["would_code"] = d.WouldCode

		if d.WouldVerdict == protocol.VerdictScore {
			det.Engine["would_score"] = d.WouldScore
		}
	}

	if len(fired.Names) != 0 {
		det.Engine["outcomes"] = fired.Names
	}

	if len(fired.Levels) != 0 {
		det.Engine["outcome_levels"] = fired.Levels
	}

	if len(noted) != 0 {
		det.Engine["noted"] = noted
	}

	if err := h.publish(ctx, fired.Bans, req); err != nil {
		h.log.Error("geo unavailable for a list write", "rid", req.RID,
			"profile", p.Name, "error", err.Error())

		det.Engine["geo"] = err.Error()

		return protocol.ErrorReply(req, decide.CodeGeoUnavailable), det
	}

	h.log.Info("verdict",
		"rid", req.RID,
		"phase", req.Phase,
		"uri", req.HTTP.URI,
		"profile", p.Name,
		"verdict", reply.Verdict,
		"passive", p.Mode == config.ModeObserve,
		"would_verdict", d.WouldVerdict,
		"would_code", d.WouldCode,
		"reason", d.Code,
		"asks", len(fired.Actions),
		"lists", len(fired.Bans),
		"engine_ms", det.EngineMS,
	)

	return reply, det
}

func (h *handler) measure(
	ctx context.Context,
	req *protocol.Request,
	p *config.Profile,
	snap *config.Snapshot,
	ask decide.Ask,
) (*protocol.Reply, audit.Details) {
	started := time.Now()
	counters := snap.Counters()

	in := measure.Input{
		Method: req.HTTP.Method,
	}

	if req.Response != nil {
		in.Status = req.Response.Status
	}

	wantBody := needsBody(p.Response.Measure)

	locs := []*protocol.Locator{req.Store.Headers, req.RequestStore.Headers}

	if wantBody {
		locs = append(locs, req.Store.Body)
	}

	got := h.loader.LoadMany(ctx, locs...)

	for _, b := range got {
		if !b.Failed() {
			continue
		}

		h.log.Error("store fetch failed", "rid", req.RID, "profile", p.Name,
			"phase", req.Phase, "reason", b.Unavailable)

		return protocol.ErrorReply(req, decide.CodeStoreUnavailable), audit.Details{
			Engine: map[string]any{"profile": p.Name, "store": b.Unavailable},
		}
	}

	if rspHeaders := h.headers(req, got[0]); rspHeaders != nil {
		in.ContentType = headerValue(rspHeaders, "content-type")
	}

	if wantBody {
		in.Body = got[2].Data
		in.BodyTruncated = got[2].Truncated
	}

	if req.Store.Body != nil {
		in.BodySize = req.Store.Body.Size
	}

	values, rows := measure.Run(p.Response.Measure, counters, in)

	reply := h.plain(req, protocol.VerdictAllow, decide.CodeMeasured)

	if len(values) == 0 && len(ask.Notes) == 0 {
		reply.Reason = nil

		det := audit.Details{
			EngineMS: float64(time.Since(started).Microseconds()) / 1000,
			Engine:   map[string]any{"profile": p.Name, "mode": p.Mode, "phase": req.Phase},
		}

		if len(ask.Outcomes) != 0 {
			det.Engine["actions"] = ask.Outcomes
		}

		return reply, det
	}

	var refs []subjectRef

	for _, v := range values {
		for _, axis := range v.Axes {
			refs = append(refs, subjectRef{counter: v.Counter, axis: axis})
		}
	}

	for _, n := range ask.Notes {
		refs = append(refs, subjectRef{counter: n.Counter, axis: n.Axis})
	}

	if needsResolver(refs) && h.resolver == nil {
		h.log.Error("netinfo resolver is not configured", "rid", req.RID,
			"profile", p.Name)

		return protocol.ErrorReply(req, decide.CodeGeoUnavailable), audit.Details{
			Engine: map[string]any{"profile": p.Name, "geo": "unconfigured"},
		}
	}

	if got[1].Failed() {
		h.log.Error("store fetch failed", "rid", req.RID, "profile", p.Name,
			"phase", req.Phase, "reason", got[1].Unavailable)

		return protocol.ErrorReply(req, decide.CodeStoreUnavailable), audit.Details{
			Engine: map[string]any{"profile": p.Name, "store": got[1].Unavailable},
		}
	}

	keys := h.subjectsOf(ctx, refs, counters, req.Conn.ClientIP, h.headers(req, got[1]),
		req.Sessions, "")

	var charges []buckets.Charge

	for _, v := range values {
		for _, axis := range v.Axes {
			key, ok := keys.key(v.Counter, axis)
			if !ok {
				continue
			}

			charges = append(charges, buckets.Charge{
				Ref: buckets.Ref{Kind: config.Kind(v.Counter, axis), Key: key},
				Add: v.Add,
			})
		}
	}

	tiers := snap.Tiers()

	noteCharges, noted := h.noteCharges(ask.Notes, keys, tiers)
	charges = append(charges, noteCharges...)

	levels, err := h.bkt.Apply(ctx, tiers, charges, nil)
	if err != nil {
		h.log.Error("buckets unavailable", "rid", req.RID, "profile", p.Name,
			"phase", req.Phase, "error", err.Error())

		return protocol.ErrorReply(req, decide.CodeBucketsUnavailable), audit.Details{
			Engine: map[string]any{"profile": p.Name, "buckets": err.Error()},
		}
	}

	det := audit.Details{
		EngineMS: float64(time.Since(started).Microseconds()) / 1000,
		Engine: map[string]any{
			"profile":  p.Name,
			"mode":     p.Mode,
			"phase":    req.Phase,
			"measured": rows,
			"levels":   levelRows(levels),
		},
	}

	if len(noted) != 0 {
		det.Engine["noted"] = noted
	}

	if len(ask.Outcomes) != 0 {
		det.Engine["actions"] = ask.Outcomes
	}

	h.log.Info("measured",
		"rid", req.RID,
		"uri", req.HTTP.URI,
		"profile", p.Name,
		"rules", len(rows),
		"notes", len(noted),
		"charges", len(charges),
		"engine_ms", det.EngineMS,
	)

	return reply, det
}

func (h *handler) noteCharges(
	notes []decide.NoteCharge,
	keys *subjectKeys,
	tiers map[string]buckets.Tier,
) ([]buckets.Charge, []map[string]any) {
	if len(notes) == 0 {
		return nil, nil
	}

	var (
		charges []buckets.Charge
		rows    []map[string]any
	)

	for _, n := range notes {
		key, ok := keys.key(n.Counter, n.Axis)
		if !ok {
			continue
		}

		kind := config.Kind(n.Counter, n.Axis)
		add := float64(n.Percent) / 100 * tiers[kind].Max

		charges = append(charges, buckets.Charge{
			Ref: buckets.Ref{Kind: kind, Key: key},
			Add: add,
		})

		rows = append(rows, map[string]any{
			"counter": n.Counter,
			"axis":    n.Axis,
			"key":     key,
			"percent": n.Percent,
			"value":   add,
			"code":    n.Code,
			"from":    n.From,
		})
	}

	return charges, rows
}

func levelRows(levels []buckets.Level) []map[string]any {
	out := make([]map[string]any, 0, len(levels))

	for _, l := range levels {
		out = append(out, map[string]any{
			"bucket":  l.Kind,
			"key":     l.Key,
			"percent": l.Percent,
		})
	}

	return out
}

func judgeFindings(rows []decide.RuleAudit) []audit.Finding {
	var out []audit.Finding

	for _, row := range rows {
		if !row.Fired {
			continue
		}

		severity := audit.SeverityMedium

		if row.Action == config.ActionDeny {
			severity = audit.SeverityHigh
		}

		out = append(out, audit.Finding{
			Code:     row.Code,
			Severity: severity,
			Target:   audit.TargetConn,
			Rule:     row.Counter + ":" + row.Axis,
			Evidence: fmt.Sprintf("level %.1f%%, threshold %g%%", row.Percent, row.At),
		})
	}

	return out
}

func (h *handler) profile(snap *config.Snapshot, req *protocol.Request) (*config.Profile, bool) {
	return snap.Profile(req.Route.Profile)
}

func (h *handler) headersFor(
	ctx context.Context,
	req *protocol.Request,
	refs []subjectRef,
	counters *config.Counters,
) ([]protocol.Header, error) {
	if !hasConfigurable(refs, counters) {
		return nil, nil
	}

	loaded := h.loader.Load(ctx, req.Store.Headers)
	if loaded.Failed() {
		return nil, fmt.Errorf("headers: %s", loaded.Unavailable)
	}

	return h.headers(req, loaded), nil
}

func (h *handler) headers(req *protocol.Request, loaded body.Body) []protocol.Header {
	if !loaded.Available() || len(loaded.Data) == 0 {
		return nil
	}

	var pairs []protocol.Header

	if err := json.Unmarshal(loaded.Data, &pairs); err != nil {
		h.log.Warn("headers blob is not an array of pairs", "rid", req.RID, "error", err.Error())

		return nil
	}

	return pairs
}

func headerValue(pairs []protocol.Header, name string) string {
	for _, p := range pairs {
		if strings.EqualFold(p.Name(), name) {
			return p.Value()
		}
	}

	return ""
}

func needsBody(rules []config.MeasureRule) bool {
	for i := range rules {
		if rules[i].Source == config.SourceRegexCount {
			return true
		}
	}

	return false
}

func phaseEnabled(p *config.Profile, phase string) bool {
	switch phase {
	case protocol.PhaseResponse:
		return p.Response.Enabled

	case protocol.PhaseFrame:
		return p.Frame.Enabled
	}

	return p.Request.Enabled
}

func (h *handler) plain(req *protocol.Request, verdict, code string) *protocol.Reply {
	reply := protocol.NewReply(req, verdict)
	reply.Reason = &protocol.Reason{Code: code}

	return reply
}

func (h *handler) send(subject string, reply *protocol.Reply, req *protocol.Request,
	det audit.Details) {

	if subject == "" {
		h.log.Error("no reply subject in message", "rid", reply.RID)

		return
	}

	payload, err := reply.Marshal()
	if err != nil {
		h.log.Error("reply marshal failed", "rid", reply.RID, "error", err.Error())

		fallback := protocol.FallbackReply(reply.RID, reply.Inspector, decide.CodeInternalError)

		payload, err = fallback.Marshal()
		if err != nil {
			return
		}
	}

	if err := h.nc.Publish(subject, payload); err != nil {
		h.log.Error("respond failed", "rid", reply.RID, "error", err.Error())
	}

	if err := h.audit.Add(req, reply, det); err != nil {
		h.log.Warn("audit publish failed", "rid", reply.RID, "error", err.Error())
	}
}

func (h *handler) recoverInto(subject, rid string) {
	r := recover()
	if r == nil {
		return
	}

	h.log.Error("handler panicked", "rid", rid, "panic", r, "stack", string(debug.Stack()))

	if subject == "" {
		return
	}

	h.send(subject, protocol.FallbackReply(rid, h.cfg.Name, decide.CodeInternalError),
		nil, audit.Details{})
}

func effective(d decide.Decision, scored int) decide.Decision {
	if d.Verdict == protocol.VerdictScore {
		d.Score = scored
	}

	return d
}

func (h *handler) publish(ctx context.Context, bans []decide.Ban, req *protocol.Request) error {
	if len(bans) == 0 || h.lists == nil {
		return nil
	}

	return writeLists(ctx, h.resolver, h.lists, h.log, req.RID, bans)
}

func (h *handler) overloadOnShed(t *queue.Task, shed string, reply *protocol.Reply,
	det audit.Details) decide.Fired {

	if shed != queue.ReasonQueueLimit || t.Req.Phase != protocol.PhaseRequest {
		return decide.Fired{}
	}

	p, ok := h.profile(h.store.Current(), t.Req)
	if !ok || p.Mode == config.ModeOff {
		return decide.Fired{}
	}

	fired := decide.FireOverload(p.Request.Outcomes, t.Fill, true, t.Req.Conn.ClientIP, shed)

	if len(fired.Actions) != 0 {
		reply.Actions = fired.Actions
	}

	if len(fired.Names) != 0 {
		det.Engine["outcomes"] = fired.Names
	}

	if err := h.publish(context.Background(), fired.Bans, t.Req); err != nil {
		h.log.Error("geo unavailable for a list write", "rid", t.Req.RID,
			"profile", p.Name, "error", err.Error())

		det.Engine["geo"] = err.Error()
	}

	return fired
}
