/*
 * Суд: уровни корзин против правил judge профиля.
 *
 * Чистая функция от правил и уровней, без ввода-вывода: сколько в корзинах,
 * решает поход в buckets, а здесь только сравнение с порогами. Побеждает самое
 * строгое из совпавших правил: deny поверх любого score, больший score поверх
 * меньшего. Здесь же живёт единственное место, где применяется mode: observe --
 * решение считается как обычно, а наружу уходит allow с пометкой, что решил бы
 * enforce.
 *
 * Коды причин перечислены здесь целиком: набор кодов -- это интерфейс
 * инспектора наружу, по нему строят исключения и читают аудит.
 */

package decide

import (
	"github.com/exemt/placitum-counter/internal/config"
	"github.com/exemt/placitum-counter/internal/overload"
	"github.com/exemt/placitum-counter/internal/protocol"
)

// Коды причин. Все начинаются с COUNTER_, чтобы в аудите их было видно
// отдельно от кодов других инспекторов.
const (
	// CodeLevel -- правило judge сработало, а своего повода не назвало.
	CodeLevel = "COUNTER_LEVEL"

	// CodeObserve -- профиль в наблюдении: суд решил не allow, а модулю ушёл
	// allow. Что решил -- в would_* записи аудита.
	CodeObserve = "COUNTER_OBSERVE"

	// Не подчиняются профилю: расхождение конфигурации и перегрузка -- это не
	// свойства запроса, и профиль о них ничего сказать не может.
	CodeUnknownProfile    = "COUNTER_UNKNOWN_PROFILE"
	CodeSkipped           = "COUNTER_SKIPPED"
	CodePhaseNotSupported = "COUNTER_PHASE_NOT_SUPPORTED"
	CodePhaseDisabled     = "COUNTER_PHASE_DISABLED"
	CodeProfileOff        = "COUNTER_PROFILE_OFF"
	CodeMeasured          = "COUNTER_MEASURED"
	CodeInternalError     = "COUNTER_INTERNAL_ERROR"
	// CodeBucketsUnavailable -- обменник корзин не ответил: общего счёта по
	// этому запросу нет, а по своей доле трафика судить нельзя.
	CodeBucketsUnavailable = "COUNTER_BUCKETS_UNAVAILABLE"
	// CodeStoreUnavailable -- объект лежал в обменнике, а мы его не взяли:
	// ключа настраиваемой оси нет, и её корзина выпала бы из суда молча.
	CodeStoreUnavailable = "COUNTER_STORE_UNAVAILABLE"
	// CodeGeoUnavailable -- правило спрашивает ось анонсов, а справочника гео
	// у процесса нет: ключа этой оси не существует. Тот же код -- у
	// инициатора, который пишет в набор подсеть или систему (write: net |
	// net_all | asn), а кодер молчит: записи не будет, решает waf_exception.
	CodeGeoUnavailable     = "COUNTER_GEO_UNAVAILABLE"
	CodeMalformedRequest   = "COUNTER_MALFORMED_REQUEST"
	CodeUnsupportedVersion = "COUNTER_UNSUPPORTED_VERSION"
)

// Decision -- то, что уходит в ответ, плюс то, что об этом надо записать.
type Decision struct {
	Verdict string
	Score   int
	Code    string
	// DenyResponse -- имя записи каталога waf_deny_response. Заполнено только
	// при deny: код и страницу отдаёт nginx, инспектор называет запись.
	DenyResponse string

	// WouldVerdict непустой означает observe: модулю ушёл allow с кодом
	// CodeObserve, а enforce ответил бы этим. Единственный способ
	// откалибровать пороги, не заперев клиентов.
	WouldVerdict string
	// WouldScore -- счёт, который ушёл бы с этим вердиктом. По нему судят
	// инициаторы: наблюдение глушит только ответ модулю, просьбы соседям и
	// записи в наборы идут как в enforce.
	WouldScore int
	// WouldCode -- повод решения enforce. Едет в аудит и в просьбы соседям:
	// код наблюдения в просьбе никому ничего не сказал бы.
	WouldCode string
}

/*
 * LevelLookup -- уровень корзины для правила: процент заполнения и ключ
 * субъекта. ok == false означает «субъекта на этом запросе нет» -- куки нет,
 * справочник гео промахнулся, -- и правило молчит: судить некого.
 */
type LevelLookup func(counter, axis string) (percent float64, key string, ok bool)

// RuleAudit -- строка события kind=inspector: что сравнивали и что вышло.
// Без неё вердикт не объяснить -- уровень корзины не восстановить задним
// числом, он утёк.
type RuleAudit struct {
	Counter string  `json:"counter"`
	Axis    string  `json:"axis"`
	Key     string  `json:"key,omitempty"`
	Percent float64 `json:"percent"`
	At      float64 `json:"at"`
	Fired   bool    `json:"fired"`
	// Action и Code -- что правило сделало бы и под каким поводом. Повод
	// нужен построчно, а не только у победившего решения: сработать могут
	// несколько правил, и находка каждого называет свой код.
	Action string `json:"action,omitempty"`
	Code   string `json:"code,omitempty"`
	// NoSubject -- субъекта не было: ключ не извлёкся, правило не судило.
	NoSubject bool `json:"no_subject,omitempty"`
}

/*
 * Judge -- решение фазы запроса. Правила независимы и просматриваются все:
 * аудит обязан показать каждое сравнение, а не только победившее.
 */
func Judge(p *config.Profile, lookup LevelLookup) (Decision, []RuleAudit) {
	return judge(p.Request.Judge, denyResponseOf(p), p.Mode, lookup)
}

// JudgeFrame -- решение по кадру: правила секции frame, отказ -- записью
// type=websocket этой секции.
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

	/*
	 * observe: модулю всегда allow, а решение остаётся в записи под своим
	 * поводом -- по нему и видно, на чём пороги сработали бы. Код ответа
	 * при этом один на все случаи, чтобы в записи модуля наблюдение было
	 * видно без похода в kind=inspector.
	 */
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

// codeOf -- повод правила: свой либо общий CodeLevel. Одно место на разбор
// и на находку, чтобы код в записи и код в ответе не разъехались.
func codeOf(r config.JudgeRule) string {
	if r.Code == "" {
		return CodeLevel
	}

	return r.Code
}

// take -- самое строгое из совпавших: deny поверх score, больший score поверх
// меньшего. Код едет с тем правилом, которое победило.
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

/* --- инициаторы по решению --------------------------------------------------- */

/*
 * Ban -- запись в живой набор: кого (Write) и про какой адрес. Анонсы и
 * состав системы по адресу разворачивает обработчик у кодера, в бюджете
 * сообщения: этот пакет кодера не знает. Публикуется запись после решения --
 * этот запрос уже решён, а набор нужен следующим и соседним нодам.
 */
type Ban struct {
	Dataset string
	// Write -- кого писать: addr, net, net_all, asn.
	Write  string
	Addr   string
	TTL    int
	Reason string
}

// Fired -- что сделали инициаторы: просьбы уезжают в ответе рядом с вердиктом,
// записи публикуются после него, имена -- в запись аудита.
type Fired struct {
	Actions []protocol.Action
	Bans    []Ban
	Names   []string
	// Levels -- сравнения строк по уровню корзины, для kind=inspector: без них
	// «почему не сработало» не объяснить, уровень утёк и не восстановим.
	Levels []LevelAudit
}

// LevelAudit -- строка события: какую корзину смотрел инициатор и что вышло.
type LevelAudit struct {
	Counter string  `json:"counter"`
	Axis    string  `json:"axis"`
	Key     string  `json:"key,omitempty"`
	Percent float64 `json:"percent"`
	At      int     `json:"at"`
	// Below -- сравнение было «ниже порога», а не «не ниже».
	Below bool `json:"below,omitempty"`
	Fired bool `json:"fired"`
	// NoSubject -- субъекта не было: ключ не извлёкся, строка не судила.
	NoSubject bool `json:"no_subject,omitempty"`
}

/*
 * Fire -- инициаторы фазы запроса по её решению.
 *
 * Сравнивается тот счёт, который уходит модулю: коэффициент соседа уже в нём,
 * иначе оператор смотрел бы на одно число, а сосед двигал другое.
 *
 * Наблюдение глушит только ответ модулю. Инициаторы судят по решению enforce
 * и стреляют как в бою: просьбы соседям и записи в наборы -- разговор
 * инспекторов между собой, а не вердикт, и observe его не прерывает
 * (docs/inspectors.md, «Наблюдение профиля»).
 */
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
		/*
		 * Два вида условия. По вердикту -- «что фаза решила»; по уровню --
		 * «что в названной корзине», и это единственный способ различить
		 * корзины: вердикт у фазы один, а корзин у счётчика много.
		 */
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

		/*
		 * Адреса нет -- писать некого: сообщение пробы приходит без
		 * conn.client_ip. Подсеть и систему по адресу развернёт обработчик.
		 */
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

/*
 * level -- сравнение строки по уровню корзины; заодно кладёт строку аудита.
 * Пишется каждое сравнение, а не только сработавшее: «инициатор не выстрелил»
 * разбирают ровно по несработавшим.
 */
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

	// Срок архива -- только у archive с set on; ноль в YAML значит "как на
	// маршруте", поэтому на провод едет лишь названный.
	if o.Do == protocol.DoArchive && o.Set == "on" && o.TTL.Seconds() > 0 {
		ttl := int64(o.TTL.Seconds())
		out.TTL = &ttl
	}

	// Исход просьбы -- только у archive с set on; пусто значит "любой".
	// Слова проверены на загрузке профиля, здесь остаётся канонический
	// порядок: провод не должен зависеть от порядка слов в файле.
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

// reason -- повод: свой из строки либо код решения, по которому она сработала.
func reason(o config.Outcome, code string) string {
	if o.Code != "" {
		return o.Code
	}

	return code
}

// outcomeName -- как строка называется в записи аудита: по действию, а не по
// порядковому номеру, -- номер поедет при первой правке таблицы.
func outcomeName(o config.Outcome) string {
	if o.Asks() {
		return o.Do
	}

	return o.List
}

/*
 * FireOverload -- строки перегрузки секции запроса: fill -- заполнение очереди
 * при постановке запроса, shed -- запрос снят по полной очереди
 * (internal/overload). code -- повод строки, у которой свой не назван.
 * Сравнивать с решением нечего: у строки перегрузки его нет.
 */
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

		// Адреса нет -- писать некого; подсеть и систему развернёт обработчик.
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
