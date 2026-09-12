/*
 * Фаза кадров: одно сообщение на кадр WebSocket в любую сторону, и на нём
 * счётчик делает обе свои работы разом. Правила measure секции frame
 * превращают кадр в заряды (кадр как единица, его байты, вхождения регекса в
 * полезной нагрузке), правила judge той же секции судят уровни -- уже с
 * зарядом этого кадра: Apply кладёт заряды и читает уровни одним походом, и
 * N-й кадр, доливший корзину до порога, получает отказ сам, а не следующий.
 *
 * Отказ на кадре -- закрытие соединения кадром Close из записи
 * deny_response (ws_policy по умолчанию). Направление и опкод -- селекторы
 * правил measure: считать можно отдельно то, что клиент шлёт, и то, что
 * приложение отдаёт. Ось conn -- корзина на соединение: ключ -- conn_id
 * рукопожатия, и она есть только здесь.
 */

package main

import (
	"context"
	"time"

	"github.com/exemt/placitum-counter/internal/audit"
	"github.com/exemt/placitum-counter/internal/buckets"
	"github.com/exemt/placitum-counter/internal/config"
	"github.com/exemt/placitum-counter/internal/decide"
	"github.com/exemt/placitum-counter/internal/measure"
	"github.com/exemt/placitum-counter/internal/protocol"
)

func (h *handler) frame(
	ctx context.Context,
	req *protocol.Request,
	p *config.Profile,
	snap *config.Snapshot,
	ask decide.Ask,
) (*protocol.Reply, audit.Details) {
	started := time.Now()
	counters := snap.Counters()

	direction, opcode := "", ""

	if req.Stream != nil {
		direction, opcode = req.Stream.Direction, req.Stream.Opcode
	}

	in := measure.Input{
		Frame:     true,
		Direction: direction,
		Opcode:    opcode,
	}

	if req.Store.Body != nil {
		in.BodySize = req.Store.Body.Size
	}

	/*
	 * Полезная нагрузка читается только под regex_count; заголовки
	 * рукопожатия -- только под настраиваемые оси. Оба -- одним походом.
	 */
	refs := make([]subjectRef, 0, len(p.Frame.Judge)+len(p.Frame.Outcomes))

	for _, r := range p.Frame.Judge {
		refs = append(refs, subjectRef{counter: r.Counter, axis: r.Axis})
	}

	for _, o := range p.Frame.Outcomes {
		if o.OnBucket() {
			refs = append(refs, subjectRef{counter: o.If.Counter, axis: o.If.Axis})
		}
	}

	for _, n := range ask.Notes {
		refs = append(refs, subjectRef{counter: n.Counter, axis: n.Axis})
	}

	for i := range p.Frame.Measure {
		m := &p.Frame.Measure[i]
		axes := m.Axes

		if len(axes) == 0 {
			axes = counters.AxesOf(m.Counter)
		}

		for _, axis := range axes {
			refs = append(refs, subjectRef{counter: m.Counter, axis: axis})
		}
	}

	wantBody := needsBody(p.Frame.Measure)
	wantHeaders := hasConfigurable(refs, counters)

	var (
		locs    []*protocol.Locator
		headers []protocol.Header
	)

	if wantHeaders {
		locs = append(locs, req.RequestStore.Headers)
	}

	if wantBody {
		locs = append(locs, req.Store.Body)
	}

	/*
	 * Оси анонсов без справочника: ключа взять неоткуда, и корзина по ним
	 * молча выпала бы из суда -- ровно как при недоступном обменнике.
	 */
	if needsResolver(refs) && h.resolver == nil {
		h.log.Error("netinfo resolver is not configured", "rid", req.RID,
			"profile", p.Name)

		return protocol.ErrorReply(req, decide.CodeGeoUnavailable), audit.Details{
			Engine: map[string]any{"profile": p.Name, "geo": "unconfigured"},
		}
	}

	if len(locs) != 0 {
		got := h.loader.LoadMany(ctx, locs...)
		next := 0

		// Недосчёт по нашей вине: см. фазу ответа в handler.go.
		for _, b := range got {
			if !b.Failed() {
				continue
			}

			h.log.Error("store fetch failed", "rid", req.RID, "profile", p.Name,
				"reason", b.Unavailable)

			return protocol.ErrorReply(req, decide.CodeStoreUnavailable), audit.Details{
				Engine: map[string]any{"profile": p.Name, "store": b.Unavailable},
			}
		}

		if wantHeaders {
			headers = h.headers(req, got[next])
			next++
		}

		if wantBody {
			in.Body = got[next].Data
			in.BodyTruncated = got[next].Truncated
		}
	}

	values, measured := measure.Run(p.Frame.Measure, counters, in)

	keys := h.subjectsOf(ctx, refs, counters, req.Conn.ClientIP, headers, req.Sessions, req.ConnID)
	tiers := snap.Tiers()

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

	noteCharges, noted := h.noteCharges(ask.Notes, keys, tiers)
	charges = append(charges, noteCharges...)

	reads := make([]buckets.Ref, 0, len(p.Frame.Judge)+len(p.Frame.Outcomes))

	for _, r := range p.Frame.Judge {
		if key, ok := keys.key(r.Counter, r.Axis); ok {
			reads = append(reads, buckets.Ref{Kind: config.Kind(r.Counter, r.Axis), Key: key})
		}
	}

	for _, o := range p.Frame.Outcomes {
		if !o.OnBucket() {
			continue
		}

		if key, ok := keys.key(o.If.Counter, o.If.Axis); ok {
			reads = append(reads,
				buckets.Ref{Kind: config.Kind(o.If.Counter, o.If.Axis), Key: key})
		}
	}

	applied, err := h.bkt.Apply(ctx, tiers, charges, reads)
	if err != nil {
		// Кадр не посчитан и не судится: общего счёта нет (см. handler.go).
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

	det := audit.Details{
		Engine: map[string]any{
			"profile":   p.Name,
			"mode":      p.Mode,
			"phase":     req.Phase,
			"conn":      req.ConnID,
			"seq":       req.Seq,
			"direction": direction,
			"opcode":    opcode,
			"measured":  measured,
			"levels":    levelRows(applied),
		},
	}

	if len(noted) != 0 {
		det.Engine["noted"] = noted
	}

	if len(ask.Outcomes) != 0 {
		det.Engine["actions"] = ask.Outcomes
	}

	/*
	 * skip снимает суд, но не учёт: заряды этого кадра уже легли -- «не
	 * проверяй» не означает «не запоминай».
	 */
	if ask.Skip {
		det.Engine["skip"] = true
		det.EngineMS = engineMS(started)

		return h.plain(req, protocol.VerdictAllow, decide.CodeSkipped), det
	}

	d, rows := decide.JudgeFrame(p, lookup)
	det.Engine["judge"] = rows
	/* Те же находки, что у суда запроса: повод и корзина у отказа на кадре. */
	det.Findings = judgeFindings(rows)

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
			// Счёт вне диапазона отбраковал бы ответ целиком: инспектор молча
			// выпал бы из решения. Тот же исход, что и в фазе запроса, -- error.
			h.log.Error("score out of range", "rid", req.RID, "score", d.Score)

			reply = protocol.ErrorReply(req, decide.CodeInternalError)
		}
	}

	if d.Verdict == protocol.VerdictDeny {
		reply.Response = &protocol.ResponseRef{Name: d.DenyResponse}
	}

	// Ни одного правила суда и ни одного заряда -- измерено и только.
	if d.Verdict == protocol.VerdictAllow && d.Code == "" {
		reply.Reason = &protocol.Reason{Code: decide.CodeMeasured}
	}

	fired := decide.Fire(p.Frame.Outcomes, effective(d, scored), req.Conn.ClientIP, lookup)

	if len(fired.Actions) != 0 {
		reply.Actions = fired.Actions
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

	det.EngineMS = engineMS(started)

	// Кодер нужен и молчит -- тот же error, что на запросе: см. judge.
	if err := h.publish(ctx, fired.Bans, req); err != nil {
		h.log.Error("geo unavailable for a list write", "rid", req.RID,
			"profile", p.Name, "error", err.Error())

		det.Engine["geo"] = err.Error()

		return protocol.ErrorReply(req, decide.CodeGeoUnavailable), det
	}

	h.log.Info("verdict",
		"rid", req.RID,
		"phase", req.Phase,
		"conn", req.ConnID,
		"seq", req.Seq,
		"direction", direction,
		"opcode", opcode,
		"uri", req.HTTP.URI,
		"profile", p.Name,
		"verdict", reply.Verdict,
		"passive", p.Mode == config.ModeObserve,
		"would_verdict", d.WouldVerdict,
		"reason", d.Code,
		"measured", len(measured),
		"charges", len(charges),
		"asks", len(fired.Actions),
		"lists", len(fired.Bans),
		"engine_ms", det.EngineMS,
	)

	return reply, det
}

func engineMS(started time.Time) float64 {
	return float64(time.Since(started).Microseconds()) / 1000
}
