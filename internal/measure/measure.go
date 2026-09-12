/*
 * Метрики фазы ответа: правила measure против одного ответа.
 *
 * Чистая функция: предикаты выбирают правила, источники извлекают число,
 * наружу уходят значения по счётчикам. В заряды корзин их превращает
 * обработчик -- у него есть ключи субъектов, а здесь про субъектов не известно
 * ничего.
 *
 * Две тонкости источников, решённые сознательно:
 *
 * size_kb берётся из локатора, а не из тела: размер там полный, даже когда
 * содержимое обрезано превью или снято как body=meta. Маршруту, которому
 * нужны только размерные метрики, тело можно не возить вовсе.
 *
 * regex_count считает по тому, что приехало, и при усечённом теле это
 * осознанный недосчёт: врать себе «превью = тело» нельзя, поэтому флаг
 * усечения уезжает в аудит рядом со значением.
 */

package measure

import (
	"github.com/exemt/placitum-counter/internal/config"
)

// Input -- ответ, каким его видит фаза: инлайновая часть плюс то, что
// приехало из обменника.
type Input struct {
	Method string
	Status int

	// Frame -- сообщение фазы кадров: предикаты правил читают направление и
	// опкод вместо статуса и типа, а Body -- полезная нагрузка кадра.
	Frame     bool
	Direction string
	Opcode    string
	// ContentType -- из заголовков ответа; пусто, если маршрут их не снимает.
	ContentType string

	// Body -- содержимое тела ответа, возможно усечённое превью. nil -- тела
	// нет или не просили.
	Body []byte
	// BodyTruncated -- содержимое неполно: регексы недосчитывают.
	BodyTruncated bool
	// BodySize -- полный размер тела из локатора, байт. Ноль -- неизвестен.
	BodySize int64
}

// Value -- сколько добавить счётчику. Оси уже разрешены: пустой список
// правила развёрнут в объявленные оси счётчика.
type Value struct {
	Counter string
	Axes    []string
	Add     float64
}

// Fired -- строка аудита: какое правило сработало и что намерило.
type Fired struct {
	Counter string   `json:"counter"`
	Source  string   `json:"source"`
	Value   float64  `json:"value"`
	Axes    []string `json:"axes"`
	// Truncated -- значение посчитано по усечённому телу: недосчёт.
	Truncated bool `json:"truncated,omitempty"`
}

/*
 * Run -- все правила против одного ответа. Правила накопительные: срабатывают
 * все совпавшие, каждое со своим значением. Нулевое значение источника
 * (регекс не нашёлся, тело пустое) не заряжает и не пишется: нечего.
 */
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

// extract -- значение источника до множителя. Второе значение -- посчитано ли
// оно по усечённому телу.
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
