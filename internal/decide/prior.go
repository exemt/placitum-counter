/*
 * Просьбы соседей против правил приёма профиля.
 *
 * Из словаря канала инспектор применяет три глагола: threshold -- коэффициент
 * к счёту, который он отдаёт модулю (проценты, множитель 1 + delta/100; плюс
 * -- строже, минус -- скидка; пороги не двигаются), skip -- не проверять
 * этот запрос вовсе, и note -- изменить корзину: value -- проценты её ёмкости,
 * плюс доливает, минус снимает, -100 гарантированно обнуляет. Куда класть,
 * называет правило приёма полем counter: имя чужой корзины по проводу не
 * ездит. Исход каждой доставленной просьбы уезжает в kind=inspector: молчание
 * в ответ на просьбу и есть тот случай, который потом разбирают.
 *
 * note снимается на той фазе, где сделана запись, и ровно один раз: заряд
 * должен лечь как можно раньше -- у заблокированного запроса фазы ответа не
 * будет вовсе, а такие запросы и надо копить. Подробности -- у EvaluatePrior.
 */

package decide

import (
	"math"

	"github.com/exemt/placitum-counter/internal/config"
	"github.com/exemt/placitum-counter/internal/protocol"
)

// Границы суммарного коэффициента: -100 -- счёт в ноль, +900 -- вдесятеро.
const (
	PercentMin = -100
	PercentMax = 900
)

// Исход одной просьбы. «Нет правила» -- полноправный исход, а не пропуск.
const (
	OutcomeApplied = "applied"
	OutcomeNoRule  = "no_rule"
	// OutcomeNoCounter -- правило подошло, но у целевой корзины нет оси,
	// в которую разворачивается ось просьбы. Не «нет правила»: правило есть,
	// разбирать надо декларацию корзины.
	OutcomeNoCounter = "no_counter"
)

/*
 * Ask -- что соседи попросили и что из этого прошло через правила профиля.
 * Нулевая структура означает «никто ничего не просил либо ни одно правило не
 * подошло», и это самый частый исход.
 */
type Ask struct {
	// Skip -- не проверять этот запрос вовсе. Действует только через правило с
	// именем отправителя, поэтому это решение оператора, а не соседа.
	Skip bool
	// Percent -- суммарный коэффициент к отдаваемому счёту, прижатый к
	// -100..+900: числа отдельных просьб держит загрузчик отправителя.
	Percent int
	// Notes -- принятые изменения корзин: проценты ёмкости, знак значим.
	// В единицы счёта их переводит вызывающий -- ёмкости у него под рукой
	// там же, где Redis.
	Notes []NoteCharge
	// Outcomes -- по строке на каждую доставленную просьбу, для kind=inspector.
	Outcomes []ActionOutcome
}

// NoteCharge -- одно принятое изменение: корзина из правила, ось уже
// развёрнута из оси провода в объявленную.
type NoteCharge struct {
	Counter string
	Axis    string
	Percent int
	Code    string
	From    string
}

/*
 * ActionOutcome -- что сосед просил и что из этого вышло у нас. Исходы «не
 * доставлено» сюда попасть не могут по построению: пассивный отправитель,
 * переполнение waf_actions_max и урезание по маршруту отсекаются до нас и
 * живут в записи модуля kind=request.
 */
type ActionOutcome struct {
	From  string `json:"from"`
	Do    string `json:"do"`
	Apply string `json:"apply"`
	Code  string `json:"code,omitempty"`
	Delta int    `json:"delta,omitempty"`
	Value int    `json:"value,omitempty"`
	// Counter -- селектор корзины с провода, если просьба его назвала.
	Counter string `json:"counter,omitempty"`

	// Took -- что мы взяли на самом деле: срезанный либо принятый процент.
	Took    int    `json:"took,omitempty"`
	Outcome string `json:"outcome"`
}

/*
 * EvaluatePrior -- все просьбы всех записей prior против правил профиля.
 * phase -- фаза обрабатываемого сообщения.
 *
 * threshold и skip -- про этот запрос, и действуют на любой фазе: секция
 * сквозная, «этот запрос» покрывает обе стороны транзакции.
 *
 * note заряжает корзину, поэтому обязан примениться РОВНО ОДИН раз, и как
 * можно раньше: фазы ответа у заблокированного запроса не будет вовсе, а
 * именно такие запросы и надо копить. Отметка о том, что просьба уже снята,
 * не нужна -- она уже есть: модуль пишет в каждой записи prior фазу, на
 * которой она сделана. Отсюда правило: заряжаем запись на её собственной фазе.
 * Тогда на фазе ответа та же запись фазы запроса приезжает снова (prior
 * сквозная) и пропускается -- она уже снята.
 *
 * Исключение одно: профиль, у которого фаза запроса выключена, на ней не
 * работал и видит записи фазы запроса впервые уже на фазе ответа -- их он и
 * снимает. Отсюда же требование к раскладке волн: счётчик, принимающий note,
 * стоит волной ПОЗЖЕ отправителя -- иначе просьбы на своей фазе он не увидит,
 * а это требование канала вообще, а не наше.
 */
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

/*
 * chargeHere -- снимать ли эту запись на текущей фазе. Пустая фаза записи --
 * сообщение старого образца: считаем её фазой запроса, как её и писал модуль
 * до появления поля.
 */
func chargeHere(recorded, phase string, requestEnabled bool) bool {
	if recorded == "" {
		recorded = protocol.PhaseRequest
	}

	if recorded == phase {
		return true
	}

	/*
	 * Записи фазы запроса на фазе ответа снимает только тот, кто на фазе
	 * запроса не работал: для него это первая встреча, а не вторая.
	 */
	return phase == protocol.PhaseResponse &&
		recorded == protocol.PhaseRequest &&
		!requestEnabled
}

/*
 * deliver -- одна просьба против всех правил профиля. Цикл по действиям
 * снаружи, а не по правилам: исход у просьбы один, сколько бы правил её ни
 * зацепило. Для note каждое подошедшее правило заряжает свою корзину: два
 * правила с одним поводом в быструю и медленную корзины -- обычный приём.
 */
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

		/*
		 * Названная корзина -- селектор поверх правил: проходит только через
		 * правило, которое её и выдаёт. Просьба с корзиной, которой этому
		 * отправителю не выдало ни одно правило, остаётся no_rule -- грант
		 * живёт у получателя, провод только выбирает среди выданного.
		 */
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

/*
 * note -- «изменить корзину»: value с провода -- проценты ёмкости корзины из
 * правила, плюс доливает, минус снимает (-100 при уровне не выше ёмкости
 * гарантированно обнуляет: выше ёмкости уровень не бывает). Ось провода
 * разворачивают декларации: asn заряжает обе ASN-оси -- сигнал один, шкалы
 * две. Потолка нет: границы держат загрузчик отправителя и ёмкость корзины.
 */
func (a *Ask) note(
	r config.PriorRule,
	act protocol.Action,
	from string,
	counters *config.Counters,
	out *ActionOutcome,
) {
	if act.Value == 0 {
		// Менять корзину на ноль -- не изменение: правило сработало, но
		// вливать нечего.
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

// apply -- правило подошло и просьба взята целиком: числа держит загрузчик
// отправителя, получатель их не режет. Несколько подошедших правил складывают
// took -- исход у просьбы один.
func (o *ActionOutcome) apply(took int) {
	o.Outcome = OutcomeApplied
	o.Took += took
}

// noCounter -- правило подошло, но оси для просьбы у корзины нет. Не «нет
// правила»: правило есть, разбирать надо декларацию.
func (o *ActionOutcome) noCounter() {
	if o.Outcome == OutcomeNoRule {
		o.Outcome = OutcomeNoCounter
	}
}

/*
 * ScaleScore -- счёт, умноженный на коэффициент просьб соседей. Применяется к
 * тому, что инспектор отдаёт, а не к порогам: числа конфигурации не двигаются,
 * меняется цена поведения клиента на этом запросе. -100 даёт ноль; верх прижат
 * к 100, как любой score протокола.
 */
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
