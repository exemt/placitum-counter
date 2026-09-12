/*
 * Конвейер одного сообщения: разбор -> очередь -> бюджет -> профиль -> фаза.
 *
 * Фаза ответа меряет: правила measure превращают ответ в заряды корзин, ответ
 * всегда allow -- измеритель не должен стоить маршруту ни одного запроса.
 * Фаза запроса судит: уровни корзин против правил judge, наружу вердикт
 * score/deny либо действия соседям.
 *
 * Каждый шаг делегирован своему пакету; здесь только порядок и то, что ответ
 * уходит на каждом пути, включая панику внутри обработки. Молчание неотличимо
 * от перегрузки, см. docs/inspectors.md#контракт.
 *
 * Незнание -- error. Битое сообщение, чужая версия, неизвестный профиль, чужая
 * фаза, недоступные корзины -- всё отвечается вердиктом error с машинным кодом
 * COUNTER_*: измерения не было, и выбирать за маршрут между пропуском и отказом
 * счётчик не вправе. Раньше здесь стоял allow с доводом «счётчик -- эвристика,
 * его поломка не должна стоить запроса»: довод верный, но это решение маршрута,
 * и говорит его waf_exception … inspector pass.
 *
 * allow остаётся там, где счётчику нечего делать: профиль выключен, фаза
 * выключена, просьба соседа сняла проверку.
 */

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
	cfg    *config.Config
	log    *slog.Logger
	nc     *nats.Conn
	audit  *audit.Sink
	store  *config.Store
	loader *body.Loader
	pool   *queue.Pool
	// bkt -- корзины на контурном Redis. Отказ Redis не роняет запрос: счёт
	// уходит в локальную книгу экземпляра той же арифметикой.
	bkt *buckets.Store
	// lists -- публикатор активных наборов: им пишут инициаторы по решению.
	lists *dataset.Publisher
	// resolver -- кодер гео: ключи осей asn_net и asn_router, а инициаторам,
	// которые пишут не адрес (net, net_all, asn), -- анонсы и состав системы.
	// nil -- кодера нет: эти оси молчат, такие строки отвечают error.
	resolver *netinfo.Resolver
}

/*
 * receive исполняется в потоке приёма и обязан быть дешёвым: разбор нужен,
 * потому что без deadline_ms не проверить бюджет, а всё остальное уходит в пул
 * воркеров.
 */
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
		// Своя версия, а не эхо чужой: чужую мы по определению не говорим.
		reply.V = protocol.Version

		h.send(msg.Reply, reply, req, audit.Details{})

		return
	}

	// Состояния между фазами инспектор не держит: связывает их Redis, а не
	// транзакция. Ответа на release нет -- слот в модуле уже закрыт.
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

// evaluate исполняется воркером. shed непустой означает, что работа не
// начиналась: очередь была полна либо бюджет уже вышел. Ответ -- error: под
// нагрузкой счётчик не отказывает всем, но и не выдаёт неизмеренный запрос за
// измеренный; кого пускать, решает маршрут.
func (h *handler) evaluate(t *queue.Task, budget time.Duration, shed string) {
	defer h.recoverInto(t.Reply, t.Req.RID)

	if shed != "" {
		h.log.Warn("shed", "rid", t.Req.RID, "reason", shed, "budget_ms", budget.Milliseconds())

		h.send(t.Reply, protocol.ShedReply(t.Req, shed), t.Req, audit.Details{
			Engine: map[string]any{
				"shed":      shed,
				"budget_ms": float64(budget.Microseconds()) / 1000,
			},
		})

		return
	}

	reply, det := h.inspect(t, budget)
	h.send(t.Reply, reply, t.Req, det)
}

func (h *handler) inspect(t *queue.Task, budget time.Duration) (*protocol.Reply, audit.Details) {
	req := t.Req

	// Снимок берётся один раз на сообщение: профиль и объявления счётчиков
	// обязаны быть из одного поколения.
	snap := h.store.Current()

	p, ok := h.profile(snap, req)
	if !ok {
		h.log.Warn("unknown profile", "rid", req.RID,
			"profile", req.Route.Profile)

		return protocol.ErrorReply(req, decide.CodeUnknownProfile), audit.Details{}
	}

	// Выключенный профиль -- это выключатель, а не отсутствие учёта: ответ с
	// причиной, по которой в аудите видно, что маршрут не считается.
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

		/*
		 * Вердикт счётчика -- не про содержимое кадра: тот же кадр в
		 * следующий раз может долить корзину за порог. Модулю запрещено
		 * повторять его по хешу (waf_frame_cache).
		 */
		reply.Cache = protocol.Bool(false)

		return reply, det
	}

	return h.judge(ctx, req, p, snap, ask)
}

/* --- фаза запроса: суд ------------------------------------------------------ */

func (h *handler) judge(
	ctx context.Context,
	req *protocol.Request,
	p *config.Profile,
	snap *config.Snapshot,
	ask decide.Ask,
) (*protocol.Reply, audit.Details) {
	/*
	 * skip снимает суд, но не учёт: просьба «не проверяй» не означает «не
	 * запоминай», а учёт этой фазы и так не ведётся -- меряет фаза ответа.
	 */
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

	/*
	 * Пары «счётчик, ось», упомянутые правилами: только их субъекты и
	 * резолвятся, причём источник ключа настраиваемой оси может быть свой у
	 * каждого счётчика. Инициаторы по уровню корзины считаются наравне с
	 * судом -- их условие читается тем же походом, а не вторым.
	 */
	refs := make([]subjectRef, 0, len(p.Request.Judge)+len(p.Request.Outcomes))

	for _, r := range p.Request.Judge {
		refs = append(refs, subjectRef{counter: r.Counter, axis: r.Axis})
	}

	for _, o := range p.Request.Outcomes {
		if o.OnBucket() {
			refs = append(refs, subjectRef{counter: o.If.Counter, axis: o.If.Axis})
		}
	}

	// Принятые note этой фазы: их субъекты тоже надо разрешить -- заряд ляжет
	// тем же походом, что и чтение уровней.
	for _, n := range ask.Notes {
		refs = append(refs, subjectRef{counter: n.Counter, axis: n.Axis})
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

	headers, err := h.headersFor(ctx, req, refs, counters)
	if err != nil {
		h.log.Error("store fetch failed", "rid", req.RID, "profile", p.Name,
			"error", err.Error())

		return protocol.ErrorReply(req, decide.CodeStoreUnavailable), audit.Details{
			Engine: map[string]any{"profile": p.Name, "store": err.Error()},
		}
	}

	keys := h.subjectsOf(ctx, refs, counters, req.Conn.ClientIP, headers, req.Sessions, "")

	// Один поход за всеми уровнями: и правила, и инициаторы читают из его
	// результата.
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

	/*
	 * Заряды принятых note ложатся здесь же, до чтения уровней: Apply
	 * возвращает уровень уже с ними, и суд видит сигнал соседа на том же
	 * запросе, а не на следующем. Для заблокированных запросов это
	 * единственная возможность -- фазы ответа у них не будет.
	 */
	charges, noted := h.noteCharges(ask.Notes, keys, tiers)

	applied, err := h.bkt.Apply(ctx, tiers, charges, reads)
	if err != nil {
		/*
		 * Общего счёта по этому запросу нет: судить не по чему. Своя доля
		 * трафика ответила бы порогом экземпляра вместо порога контура -- на
		 * контуре из N нод это тихо умножало бы каждый лимит на N.
		 */
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

	/*
	 * Коэффициент просьб threshold применяется к отдаваемому счёту: пороги --
	 * и правил профиля, и маршрута -- не двигаются, меняется цена поведения
	 * клиента на этом запросе.
	 */
	scored := d.Score

	if d.Verdict == protocol.VerdictScore {
		scored = decide.ScaleScore(d.Score, ask.Percent)
	}

	// В наблюдении коэффициент ложится на решение enforce: по нему судят
	// инициаторы, и оператор видит то же число, которое увидел бы в бою.
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

	// Инициаторы по решению: просьбы уезжают этим же ответом, записи в наборы
	// -- после него.
	fired := decide.Fire(p.Request.Outcomes, effective(d, scored), req.Conn.ClientIP, lookup)

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
		// Тройка чисел коэффициента: без неё вердикт не объяснить.
		det.Engine["score_raw"] = d.Score
		det.Engine["score_scale_percent"] = ask.Percent
		det.Engine["score_scaled"] = scored
	}

	// Наблюдение: passive стоит на каждой записи профиля -- ответ модулю
	// заглушён, -- а would_* только там, где было что глушить.
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

	// Сравнения инициаторов по уровню: по ним видно, почему строка молчала.
	if len(fired.Levels) != 0 {
		det.Engine["outcome_levels"] = fired.Levels
	}

	if len(noted) != 0 {
		det.Engine["noted"] = noted
	}

	/*
	 * Строка требует кодер, а кодер молчит: запись в набор не состоялась.
	 * Молча пропустить нельзя -- бан, которого не было, выглядит как бан, --
	 * поэтому error, и что делать с запросом, решает waf_exception; решение
	 * суда остаётся в записи аудита.
	 */
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

/* --- фаза ответа: учёт ------------------------------------------------------ */

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

	/*
	 * Все объекты обменника этой фазы одним походом: заголовки ответа, заголовки
	 * запроса под настраиваемые оси и тело -- когда его требует набор мер.
	 * Порознь это были до трёх последовательных round-trip внутри бюджета
	 * волны, на каждом запросе.
	 */
	wantBody := needsBody(p.Response.Measure)

	locs := []*protocol.Locator{req.Store.Headers, req.RequestStore.Headers}

	if wantBody {
		locs = append(locs, req.Store.Body)
	}

	got := h.loader.LoadMany(ctx, locs...)

	/*
	 * Объект лежал, а обменник его не отдал. Для измерителя это недосчёт:
	 * регексы по телу дали бы ноль, а тип содержимого -- пустую строку, и
	 * заряды легли бы меньше настоящих. Судить по ним будет фаза запроса
	 * следующего запроса, поэтому молчать нельзя.
	 */
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

	// Заголовки текущей фазы -- заголовки ответа: из них тип содержимого.
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

		// Исходы просьб пишутся и без зарядов: «нет правила» в ответ на note
		// -- ровно тот случай, который потом разбирают.
		if len(ask.Outcomes) != 0 {
			det.Engine["actions"] = ask.Outcomes
		}

		return reply, det
	}

	// Ключи субъектов -- из контекста запроса: куки живут там, а не в ответе.
	var refs []subjectRef

	for _, v := range values {
		for _, axis := range v.Axes {
			refs = append(refs, subjectRef{counter: v.Counter, axis: axis})
		}
	}

	for _, n := range ask.Notes {
		refs = append(refs, subjectRef{counter: n.Counter, axis: n.Axis})
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

	// Принятые note этой фазы -- те же заряды тем же походом.
	noteCharges, noted := h.noteCharges(ask.Notes, keys, tiers)
	charges = append(charges, noteCharges...)

	levels, err := h.bkt.Apply(ctx, tiers, charges, nil)
	if err != nil {
		// Заряды не легли: этот ответ в счёт не попал. Измеритель ничего не
		// решает, но и молчать о недосчёте нельзя -- по этим корзинам будет
		// судить фаза запроса следующего.
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

/*
 * noteCharges -- принятые note в заряды: проценты ёмкости переводятся в
 * единицы счёта здесь, где ёмкости под рукой. Субъекта нет (куки нет, гео
 * промахнулся) -- заряд не состоится, как и у правил measure. Вторым
 * значением -- строки аудита: без них уровень не объяснить, он утёк.
 */
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

// levelRows -- уровни после зарядов для события аудита: по ним видно, как
// близко субъект к порогам, без второго похода в Redis.
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

/* --- находки ---------------------------------------------------------------- */

/*
 * Находки решения суда: по строке на каждое сработавшее правило.
 *
 * Без них запись события говорит только «отказал счётчик»: повод правила в
 * записи модуля не живёт (там класс решения, `inspector`), а уровень корзины
 * не восстановить задним числом -- он утёк. Разбирающий отказ видит код,
 * корзину с осью и, строкой ниже, весь engine с процентами и порогами.
 *
 * Место находки -- `conn`: субъект счёта это свойство клиента (адрес, сессия,
 * личность), а не кусок запроса, и показывать пальцем внутрь запроса счётчику
 * не на что. Строгость -- по действию правила: отказ высокий, счёт средний.
 * Наблюдение находки не глушит: правило сработало, и запись обязана это
 * показать -- иначе калибровать пороги не по чему.
 */
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
			/* Корзина с осью: «какая шкала переполнилась» -- это и есть правило. */
			Rule:     row.Counter + ":" + row.Axis,
			Evidence: fmt.Sprintf("level %.1f%%, threshold %g%%", row.Percent, row.At),
		})
	}

	return out
}

/* --- общее ------------------------------------------------------------------ */

/*
 * profile выбирает профиль по тегу маршрута. Имени нет среди загруженных --
 * применять нечего: отката на default больше не бывает, чужой набор счётчиков
 * считал бы не то, о чём просил маршрут. Вызывающий отвечает вердиктом error.
 */
func (h *handler) profile(snap *config.Snapshot, req *protocol.Request) (*config.Profile, bool) {
	return snap.Profile(req.Route.Profile)
}

/*
 * headersFor -- заголовки запроса, и только когда они нужны: настраиваемым
 * осям (sess, user). Остальные оси собираются из адреса, и ходить в обменник
 * ради них незачем.
 *
 * Ошибка означает, что заголовки лежали, а обменник их не отдал: ключ оси
 * взять неоткуда, и правило по ней молчало бы -- то есть корзина, которой
 * судят этот маршрут, тихо выпала бы из суда.
 */
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

// headers -- разбор уже полученного объекта. Отдельно от похода за ним: на
// фазе ответа объекты забираются пачкой, и разбирать их приходится потом.
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
		// Ответ, который нельзя сериализовать, всё равно должен уйти: иначе
		// волна ждёт до дедлайна впустую.
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

	/*
	 * Аудит после inbox: волна уже получила ответ. Обычный PUB на subject из
	 * сообщения, без JS API. Ошибка сюда не возвращается.
	 */
	if err := h.audit.Add(req, reply, det); err != nil {
		h.log.Warn("audit publish failed", "rid", reply.RID, "error", err.Error())
	}
}

/*
 * Паника внутри обработки одного сообщения обязана быть перехвачена и
 * превращена в allow с машинным кодом причины, а не в падение процесса: баг
 * разбора не должен становиться отказом в обслуживании.
 */
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

/*
 * effective -- решение с тем счётом, который уходит модулю: инициаторы обязаны
 * сравнивать порог с ним, иначе оператор смотрел бы на одно число, а сосед
 * своим коэффициентом двигал другое.
 */
func effective(d decide.Decision, scored int) decide.Decision {
	if d.Verdict == protocol.VerdictScore {
		d.Score = scored
	}

	return d
}

/*
 * publish -- записи инициаторов в активные наборы, см. lists.go: адрес как
 * есть, анонсы и состав системы -- у кодера, в бюджете сообщения; кодер
 * спрашивается только строкой, которой он нужен. Отказ keeper не отменяет
 * ничего: этот запрос уже решён. Ошибка -- кодер нужен и молчит.
 */
func (h *handler) publish(ctx context.Context, bans []decide.Ban, req *protocol.Request) error {
	if len(bans) == 0 || h.lists == nil {
		return nil
	}

	return writeLists(ctx, h.resolver, h.lists, h.log, req.RID, bans)
}
