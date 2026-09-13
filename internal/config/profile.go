/*
 * Профиль инспектора счётчика: тот самый отдельный конфиг, который задаёт
 * оператор.
 *
 * Профиль выбирается тегом profile= записи waf_inspector и приезжает в
 * route.profile -- тем же механизмом, что у ip, modsec, json и капчи. Один
 * процесс обслуживает сколько угодно профилей: разным маршрутам -- разные
 * метрики и разные пороги.
 *
 * Две фазы -- две разные работы. Фаза ответа меряет: правила measure
 * превращают ответ в заряды счётчиков. Фаза запроса судит: правила judge
 * сравнивают уровни корзин с порогами и выносят вердикт. Сами счётчики -- их
 * имена, оси, ёмкости -- объявлены не здесь, а в общей секции инспектора
 * (counters.go): профиль ссылается на них по имени, и ссылка на необъявленное
 * отвергает поколение целиком.
 *
 * Всё, что можно проверить при загрузке, проверяется здесь: профиль с опечаткой
 * обязан не подняться, а не молча не считать на первом запросе.
 */

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

	// Действия правила judge. allow здесь нет: правило, которое ничего не
	// делает, пишется не строкой, а её отсутствием.
	ActionDeny  = "deny"
	ActionScore = "score"
	ActionAllow = "allow"

	// Источники значения правила measure: единица на ответ, число вхождений
	// регулярного выражения в теле, размер тела в килобайтах из локатора.
	SourceConst      = "const"
	SourceRegexCount = "regex_count"
	SourceSizeKB     = "size_kb"
	// SourceBytes -- размер тела (полезной нагрузки кадра) в байтах: у кадров
	// килобайты слишком крупная единица.
	SourceBytes = "bytes"

	// Селекторы правил measure фазы кадров: направление и опкод кадра.
	DirectionC2S = "c2s"
	DirectionS2C = "s2c"

	OpcodeText         = "text"
	OpcodeBinary       = "binary"
	OpcodeContinuation = "continuation"

	// Триггеры инициаторов: собственный решённый вердикт фазы запроса.
	OnDeny  = ActionDeny
	OnAllow = ActionAllow
	OnScore = ActionScore

	/*
	 * OnLevel -- уровень названной корзины, а не вердикт. Нужен там, где
	 * вердикт ответа не даёт: корзин у счётчика много, а вердикт один, и по
	 * нему не отличить, какая из них перелилась. Плюс запись в набор перестаёт
	 * требовать deny: «уровень дошёл до 40%» -- законный повод занести
	 * субъекта, ничего не решая про этот запрос.
	 */
	OnLevel = "level"

	// OnOverload -- инспектор перегружен: порог at -- заполнение очереди в
	// процентах (internal/overload). Только в секции запроса.
	OnOverload = overload.On

	/*
	 * Кого писать в набор -- те же слова, что у капчи и json. Адрес меняется
	 * дешевле всего. Подсеть -- уже нет: net -- эффективный анонс, самый узкий
	 * (лайт), net_all -- все анонсы, накрывающие адрес, включая чужие широкие
	 * (хард). Автономная система целиком (asn) -- решение другого масштаба. Во
	 * что они разворачиваются, решает netinfo.Values -- одна на всех.
	 */
	WriteAddr   = "addr"
	WriteNet    = "net"
	WriteNetAll = "net_all"
	WriteASN    = "asn"
)

// DefaultName -- профиль, который применяется, когда маршрут не назвал
// никакого. Его отсутствие -- ошибка старта.
const DefaultName = "default"

// ProbeName -- зарезервированное имя: проба шлёт обычное сообщение с этим
// профилем, а его правило judge с at: 0 срабатывает на пустой корзине.
const ProbeName = "_probe"

// DefaultDenyResponse -- запись каталога waf_deny_response на случай, когда
// профиль своей не назвал. Заводится миграцией контроллера.
const DefaultDenyResponse = "counter_limit"

// DefaultFrameDenyResponse -- запись type=websocket для отказа на кадре:
// соединение закрывается кадром Close с её кодом. Миграция 077 контроллера.
const DefaultFrameDenyResponse = "ws_policy"

var (
	nameRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	methodRe = regexp.MustCompile(`^[A-Z]+$`)
	codeRe   = regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`)
)

/*
 * Duration -- срок записи в живом наборе ("1h", "15m"). Отдельный тип, потому
 * что секунды в файле, который правят руками, читаются хуже, чем ошибаются.
 */
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

// Seconds -- срок в секундах: столько его ждёт и событие набора, и контроллер.
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

/* --- документ профиля ------------------------------------------------------ */

type Profile struct {
	// Имя -- имя каталога, а не поле файла: два источника истины для одного
	// имени разъезжаются при первом переименовании.
	Name string `yaml:"-"`

	Mode        string `yaml:"mode"`
	Description string `yaml:"description"`

	Trigger  Trigger       `yaml:"trigger"`
	Request  RequestPhase  `yaml:"request"`
	Response ResponsePhase `yaml:"response"`
	Frame    FramePhase    `yaml:"frame"`
}

/*
 * FramePhase -- кадры WebSocket в обе стороны. На кадре счётчик и меряет, и
 * судит: заряды правил measure ложатся тем же походом, что читает уровни для
 * judge, и кадр, доливший корзину до порога, получает отказ сам. Отказ --
 * закрытие соединения кадром Close из записи deny_response.
 */
type FramePhase struct {
	Enabled      bool          `yaml:"enabled"`
	Measure      []MeasureRule `yaml:"measure"`
	Judge        []JudgeRule   `yaml:"judge"`
	DenyResponse string        `yaml:"deny_response"`
	Outcomes     []Outcome     `yaml:"outcomes"`
}

/*
 * RequestPhase -- суд. Правила judge сравнивают уровни корзин с порогами;
 * побеждает самое строгое из совпавших: deny поверх любого score, больший
 * score поверх меньшего.
 */
type RequestPhase struct {
	Enabled bool        `yaml:"enabled"`
	Judge   []JudgeRule `yaml:"judge"`
	// DenyResponse -- одна запись каталога на фазу: отказ по любому правилу
	// показывает одну и ту же страницу.
	DenyResponse string `yaml:"deny_response"`
	// Outcomes -- инициаторы по решению фазы: просьба соседу либо запись
	// субъекта в живой набор. Форма и семантика те же, что у json.
	Outcomes []Outcome `yaml:"outcomes"`
}

// ResponsePhase -- учёт. Правила measure превращают ответ в заряды; вердикт
// фазы всегда allow -- измеритель не должен стоить маршруту ни одного запроса.
type ResponsePhase struct {
	Enabled bool          `yaml:"enabled"`
	Measure []MeasureRule `yaml:"measure"`
}

/*
 * JudgeRule -- «корзина дошла -> что делать». Порог в процентах заполнения,
 * как captcha_at у капчи: натуральные единицы у каждого счётчика свои, а
 * процент читается одинаково у всех.
 */
type JudgeRule struct {
	Counter string  `yaml:"counter"`
	Axis    string  `yaml:"axis"`
	At      float64 `yaml:"at"`
	Action  string  `yaml:"action"`
	Score   int     `yaml:"score"`
	// Code -- машинный повод; пусто -- COUNTER_LEVEL.
	Code string `yaml:"code"`
}

/*
 * MeasureRule -- «какой ответ -> сколько и в какой счётчик». Правила
 * накопительные: заряжают все совпавшие.
 */
type MeasureRule struct {
	If     Match  `yaml:"if"`
	Source string `yaml:"source"`
	// Regex -- только при source: regex_count. Компилируется на загрузке.
	Regex string `yaml:"regex"`
	// Per -- множитель к значению источника; по умолчанию 1. Минус снимает:
	// «хороший ответ возвращает кредит» пишется отрицательным per.
	Per     *float64 `yaml:"per"`
	Counter string   `yaml:"counter"`
	// Axes -- какие оси заряжать. Пусто -- все объявленные у счётчика.
	Axes []string `yaml:"axes"`

	re *regexp.Regexp
}

// Weight -- множитель с умолчанием.
func (m *MeasureRule) Weight() float64 {
	if m.Per == nil {
		return 1
	}

	return *m.Per
}

// Regexp -- скомпилированное выражение; не nil только у source: regex_count
// после успешной валидации.
func (m *MeasureRule) Regexp() *regexp.Regexp { return m.re }

/*
 * Match -- предикат правила measure над ответом: статус, тип содержимого,
 * метод. Пустое поле -- «любой». Пути здесь сознательно нет: разное поведение
 * на разных путях -- это разные профили на разных маршрутах, а не селектор
 * внутри правила.
 */
type Match struct {
	Status []int `yaml:"status"`
	// ContentType -- список типов; "+json" покрывает суффиксные вроде
	// application/problem+json. Сравнение без параметров и регистра.
	ContentType []string `yaml:"content_type"`
	Methods     []string `yaml:"methods"`

	// Селекторы фазы кадров: направление (c2s, s2c) и опкод (text, binary,
	// continuation). Пусто -- любое. У правил запроса и ответа их нет.
	Direction []string `yaml:"direction"`
	Opcode    []string `yaml:"opcode"`
}

// MatchesFrame -- предикат над кадром: направление и опкод.
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

/* --- умолчания и разбор ---------------------------------------------------- */

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

// ParseProfile разбирает profile.yaml поверх умолчаний.
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

/* --- инициаторы по решению --------------------------------------------------- */

/*
 * outcomeVerbs -- словарь канала действий со стороны ОТПРАВИТЕЛЯ: глагол и
 * оси, с которыми он бывает. Копия словаря здесь неизбежна и осознанна
 * (docs/inspector-actions.md, «Где он лежит»): за словарём по сети горячий
 * путь не ходит. Расширение начинается со схемы провода и реестра
 * контроллера, сюда приезжает следом.
 */
var outcomeVerbs = map[string][]string{
	protocol.DoChallenge: {protocol.ApplyRequest},
	protocol.DoThreshold: {protocol.ApplyRequest},
	protocol.DoSkip:      {protocol.ApplyRequest},
	protocol.DoMutate:    {protocol.ApplyRequest},
	protocol.DoReauth:    {protocol.ApplySession},
	protocol.DoNote: {protocol.ApplyRequest, protocol.ApplyIP,
		protocol.ApplyASN, protocol.ApplySession},
	// Режим вызова соседа: до конца транзакции либо, на кадрах, соединения.
	// Ось пишется явно -- выбор настоящий.
	protocol.DoActive:  {protocol.ApplyRequest, protocol.ApplyConn},
	protocol.DoPassive: {protocol.ApplyRequest, protocol.ApplyConn},
	protocol.DoOff:     {protocol.ApplyRequest, protocol.ApplyConn},
	protocol.DoVote:    {protocol.ApplyRequest, protocol.ApplyConn},
	// Глаголы записи: журнал и архив этого запроса (на кадрах -- кадра либо,
	// с conn, соединения). Исполняет модуль от любого спрошенного
	// инспектора; адресата нет -- запись маршрута.
	protocol.DoAudit:   {protocol.ApplyRequest, protocol.ApplyResponse},
	protocol.DoArchive: {protocol.ApplyRequest, protocol.ApplyResponse},
	// Маркер: метка события на записи. Адресат тот же -- запись маршрута, --
	// но грант ему не нужен: метка ничего не прячет.
	protocol.DoMark: {protocol.ApplyRequest},
	// Очки на маршруте: value со знаком к сумме фазы, исполняет модуль.
	protocol.DoScore: {protocol.ApplyRequest},
}

// auditVerb -- глагол записи: исполняет модуль в адрес записи маршрута,
// поля to нет; сторона set обязательна, срок, предел и набор объектов --
// только у archive с set on.
func auditVerb(do string) bool {
	return do == protocol.DoAudit || do == protocol.DoArchive
}

/*
 * recordVerb -- адресат глагола не сосед, а запись самого маршрута: журнал,
 * архив и маркер. У всех троих поля to нет, все трое исполняются модулем и
 * потому законны на отказе -- в отличие от просьб, которым после deny некуда
 * ехать.
 */
func recordVerb(do string) bool {
	return auditVerb(do) || do == protocol.DoMark || do == protocol.DoScore
}

// archiveObject -- объект обменника, который умеет назвать archive.
func archiveObject(name string) bool {
	return name == "headers" || name == "args" || name == "body"
}

// controlVerb -- глагол исполняет модуль: адресат обязателен, всем такое
// не шлют.
func controlVerb(do string) bool {
	switch do {
	case protocol.DoActive, protocol.DoPassive, protocol.DoOff, protocol.DoVote:
		return true
	}

	return false
}

// checkPhaseAsk -- фаза вызова адресата: только у управляющих глаголов, одно
// из request, response, frame; с осью conn -- только frame либо без поля: до
// конца соединения живут одни кадры. Пусто -- всем вызовам имени.
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

/*
 * Outcome -- строка «когда → что сделать», где «когда» это собственный
 * решённый вердикт фазы запроса. Форма один в один с json: та же строка в
 * панели, та же проверка, тот же Fire.
 */
type Outcome struct {
	On string `yaml:"on"`
	// At -- порог сравнения; обязателен при On == score (счёт) и On == level
	// (проценты заполнения корзины); у overload -- заполнение очереди в
	// процентах, не назван -- край.
	At *int `yaml:"at"`
	// Below -- сравнивать в другую сторону: меньше at вместо «не ниже at».
	Below bool `yaml:"below"`
	// Eq -- точное сравнение: ровно at. С below взаимоисключимы и только у
	// счёта: уровень корзины -- непрерывная величина, и «ровно 40%» на ней не
	// случается.
	Eq bool `yaml:"eq"`
	// If -- какую корзину смотреть; только при On == level, и там обязателен.
	// Отдельной секцией, а не полями наверху: counter наверху уже занят
	// селектором чужой корзины у do: note, и два разных смысла одного имени
	// читались бы как одно.
	If *OutcomeIf `yaml:"if"`

	// Просьба соседу.
	To    string `yaml:"to"`
	Do    string `yaml:"do"`
	Apply string `yaml:"apply"`
	// Phase -- фаза вызова адресата у управляющих глаголов; пусто -- всем
	// вызовам имени.
	Phase string `yaml:"phase"`
	Delta *int   `yaml:"delta"`
	Value *int   `yaml:"value"`
	// Counter -- имя корзины получателя при do: note: селектор поверх его
	// правил приёма. Пусто -- корзину называет правило получателя.
	Counter string `yaml:"counter"`
	// Group и Set -- только при do: mutate, оба обязательны: какую группу
	// модификаторов получателя переключить и куда (on | off).
	Group string `yaml:"group"`
	Set   string `yaml:"set"`
	// Объекты просьбы записи (audit / archive) -- каждый со своей стороной,
	// размером и источником. Срок -- тот же ключ ttl, что у записи в набор:
	// у строки либо просьба, либо запись, и путать нечему.
	Headers *protocol.ObjectSpec `yaml:"headers"`
	Args    *protocol.ObjectSpec `yaml:"args"`
	Body    *protocol.ObjectSpec `yaml:"body"`
	// When -- только у archive с set on: исходы маршрута, на которых просьбу
	// исполнять (when= директивы). Пусто -- любой, включая перенаправление.
	When []string `yaml:"when"`

	// Marker -- только у mark, и там обязателен: метка события на записи.
	Marker string `yaml:"marker"`

	// Запись в живой набор: имя набора, кого писать и срок записи.
	List string `yaml:"list"`
	// Write -- субъект записи: адрес клиента, анонсированный префикс, в
	// который он попал, либо номер автономной системы целиком. Пусто -- addr.
	Write string   `yaml:"write"`
	TTL   Duration `yaml:"ttl"`

	// Code -- повод; пусто означает код решения (COUNTER_* или код правила).
	Code string `yaml:"code"`
}

/*
 * OutcomeIf -- условие по уровню: чья корзина и по какой оси. Порог и
 * направление сравнения остаются наверху (at/below), общие с триггером по
 * счёту: сравнение -- одно понятие, и разводить его по двум местам значило бы
 * писать «ниже» дважды разными словами.
 */
type OutcomeIf struct {
	Counter string `yaml:"counter"`
	Axis    string `yaml:"axis"`
}

// Asks -- эта строка просит соседа (а не пишет в набор).
func (o Outcome) Asks() bool { return o.Do != "" }

// OnBucket -- триггер этой строки -- уровень корзины, а не вердикт фазы.
func (o Outcome) OnBucket() bool { return o.On == OnLevel && o.If != nil }

// Subject -- кого писать в набор; пустое поле означает адрес клиента.
func (o Outcome) Subject() string {
	if o.Write == "" {
		return WriteAddr
	}

	return o.Write
}

/*
 * MatchesLevel -- сработало ли условие по уровню корзины. ok == false означает
 * «субъекта на этом запросе нет» (куки нет, гео промахнулся): судить некого,
 * и строка молчит -- ровно как правило judge в том же случае.
 */
func (o Outcome) MatchesLevel(percent float64, ok bool) bool {
	if !o.OnBucket() || !ok || o.At == nil {
		return false
	}

	if o.Below {
		return percent < float64(*o.At)
	}

	return percent >= float64(*o.At)
}

// Matches -- дёргает ли этот исход инициатор. Строки по уровню корзины сюда
// не попадают: их условие -- не вердикт, см. MatchesLevel.
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

/*
 * validateOutcome -- всё, что можно поймать до трафика. Ошибка здесь стоила бы
 * не строки в логе, а отбракованного модулем ответа: действие неверной формы
 * модуль отвергает вместе со всем ответом инспектора.
 */
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

		// Сравнение одно: «ровно at» и «ниже at» разом не бывают.
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

		/*
		 * Уровень -- непрерывная величина: «ровно 40%» на ней не случается, и
		 * строка с eq молчала бы всегда. Полосу «от и до» одной строкой не
		 * пишут: это два инициатора.
		 */
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

		// Ось conn -- до конца соединения -- есть только у кадров; на
		// запросе модуль отбраковал бы ответ целиком.
		if o.Apply == protocol.ApplyConn && section != "frame" {
			return fmt.Errorf("%s: apply conn is only for the frame section", where)
		}

		// У кадра записи ответа нет: просьба про неё с кадра -- ошибка профиля.
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

	// Запись без срока пережила бы причину, по которой её сделали.
	if o.TTL.Seconds() <= 0 {
		return fmt.Errorf("%s: list needs ttl", where)
	}

	return nil
}

func validateOutcomeAsk(where string, o Outcome) error {
	/*
	 * Просьба на отказе никуда не доедет: deny обрывает фазу, поздних волн не
	 * будет, и правило, собранное мышью, молча ничего бы не делало.
	 * Исключение -- глаголы записи: их исполняет модуль, а отказ -- главный
	 * случай, когда запрос стоит сохранить.
	 */
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

	// Ось досочиняется там, где выбора нет: у note их четыре, и угадывать,
	// про кого сказано, нельзя -- решения по осям разные.
	// У глаголов записи умолчание -- запись запроса: профили, писанные до
	// оси response, читаются как прежде.
	if o.Apply == "" && len(axes) != 1 && !auditVerb(o.Do) {
		return fmt.Errorf("%s: %s needs apply", where, o.Do)
	}

	// Управляющий глагол без адресата -- бессмыслица: режим ставят одному
	// вызову, не "всем"; модуль такую просьбу отвергает.
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

	// Очки: адресат -- сумма самого маршрута, названный сосед здесь та же
	// битая форма, что у записи; value обязателен и со знаком -- ноль на
	// проводе не отличается от отсутствия.
	if o.Do == protocol.DoScore {
		if o.To != "" && o.To != "*" {
			return fmt.Errorf("%s: %s takes no to: the module adds to the route's own sum", where, o.Do)
		}

		if o.Value == nil || *o.Value == 0 {
			return fmt.Errorf("%s: score needs a non-zero value", where)
		}
	}

	// Корзина -- селектор note: у прочих глаголов ей нечего значить.
	if o.Counter != "" {
		if o.Do != protocol.DoNote {
			return fmt.Errorf("%s: counter is only for %q", where, protocol.DoNote)
		}

		if !nameRe.MatchString(o.Counter) {
			return fmt.Errorf("%s: bad counter name %q", where, o.Counter)
		}
	}

	// Группа и сторона -- только у mutate, и у mutate -- обе: "переключить"
	// без имени и стороны не просьба, а полуфраза.
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

	/*
	 * Метка -- только у mark, и у mark она обязательна: "пометить" без метки
	 * не просьба. Адресат -- запись маршрута, поэтому названный сосед здесь
	 * та же битая форма, что у глаголов записи.
	 */
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

	// Глагол записи: адресат -- запись маршрута, поля to нет; сторона
	// обязательна; срок, предел и набор объектов -- только у archive с set on.
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

		// Исход: только два слова и каждое не дважды -- как на проводе.
		if _, err := protocol.CheckArchiveWhen(o.When); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}

		// У записи ответа строки запроса нет.
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

// Axis -- ось просьбы с досочинённой единственной: то, что уедет на провод.
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

/*
 * Повод -- тот же алфавит, что у reason.code модуля: за повод не из него
 * модуль отбраковывает ответ целиком, то есть опечатка стоила бы вердикта.
 */
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

/* --- просьбы соседей -------------------------------------------------------- */

// AnyInspector в правиле prior -- сигнал принимается от любого соседа. Для
// этого инспектора он не проходит валидацию никогда: skip ослабляет всегда, у
// threshold знак (то есть скидку) выбирает отправитель на проводе.
const AnyInspector = "*"

/*
 * Trigger -- правила приёма чужих просьб. Из словаря инспектор применяет три
 * глагола:
 *
 *   threshold -- коэффициент к счёту, который инспектор отдаёт модулю:
 *               проценты, множитель 1 + delta/100. Пороги правил judge не
 *               двигаются.
 *   skip      -- не судить этот запрос. Учёт фазы ответа skip не снимает:
 *               мерить -- не проверять, и просьба «не проверяй» не означает
 *               «не запоминай».
 *   note      -- изменить корзину: value -- проценты её ёмкости, плюс
 *               доливает, минус снимает, -100 гарантированно обнуляет. Куда
 *               класть, называет правило полем counter -- имя чужой корзины
 *               по проводу не ездит, -- и корзина обязана быть fill: note:
 *               владелец у шкалы один. Заряды ложатся на фазе ответа, там же,
 *               где весь учёт; суд читает их со следующего запроса субъекта.
 */
type Trigger struct {
	Prior []PriorRule `yaml:"prior"`
}

type PriorRule struct {
	From   string   `yaml:"from"`
	Accept []string `yaml:"accept"`
	// Apply -- какие оси провода правило принимает; пусто -- любая допустимая
	// при этих глаголах. У threshold и skip ось одна -- этот запрос; выбор
	// настоящий только у note: «верю про адрес, но не про его сеть» -- обычная
	// позиция, цена ошибки на этих осях разная.
	Apply []string `yaml:"apply"`
	Codes []string `yaml:"codes"`
	// Counter -- корзина, которую наполняют принятые note; обязателен при
	// accept: [note]. Границы чисел держат загрузчик отправителя (delta не
	// шире -100..+900, value не шире +-100) и ёмкость корзины.
	Counter string `yaml:"counter"`

	// Deprecated: потолок на |delta| умер -- правило приёма решает «от кого,
	// что и по какому поводу», числа держит отправитель. Ключ читается и
	// игнорируется одно поколение, чтобы раскатка нового формата не
	// спотыкалась о профили, напечатанные до неё; потом станет ошибкой.
	MaxPercent int `yaml:"max_percent"`
}

// Accepts -- принимает ли правило этот глагол.
func (r PriorRule) Accepts(verb string) bool {
	for _, v := range r.Accept {
		if v == verb {
			return true
		}
	}

	return false
}

// WantsAxis -- проходит ли ось через фильтр правила. Пустой список означает
// «любая допустимая при этих глаголах».
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

// WantsCode -- проходит ли повод действия через фильтр правила. Пустой список
// означает «любой повод», в том числе отсутствующий.
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

/*
 * validatePrior -- ограничения загрузчика. Модель угрозы одна: один инспектор
 * скомпрометирован или сломан. Все три наших глагола умеют ослаблять -- skip
 * всегда, у threshold и note знак выбирает отправитель, -- поэтому послабление
 * требует имени отправителя, и широковещательного правила у этого инспектора
 * не бывает вовсе.
 */
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

	/*
	 * Оси фильтра -- только те, с которыми выбранные глаголы бывают на проводе
	 * и которые здесь могут во что-то попасть: у threshold и skip это сам
	 * запрос, у note -- субъект (адрес, сеть, сессия). request у note корзины
	 * не имеет, и правило с такой парой не сработало бы никогда.
	 */
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

	// Корзина -- адресат принятых note, и только их: у прочих глаголов ей
	// нечего значить, и молча висящее поле скрывало бы опечатку в accept.
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

/* --- проверка -------------------------------------------------------------- */

/*
 * Validate проверяет форму профиля: всё, что не требует общей секции.
 * Ссылки на счётчики и оси сверяет загрузчик каталога -- там, где обе стороны
 * уже прочитаны.
 */
func (p *Profile) Validate() error {
	switch p.Mode {
	case ModeEnforce, ModeObserve, ModeOff:
	default:
		return fmt.Errorf("mode must be enforce, observe or off, got %q", p.Mode)
	}

	// Правила приёма проверяются и у выключенного профиля: опечатка обязана
	// быть видна тогда, когда её сделали, а не когда профиль включат обратно.
	for i, r := range p.Trigger.Prior {
		if err := validatePrior(i, r); err != nil {
			return err
		}
	}

	// То же и с инициаторами: они -- вторая сторона того же канала.
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

/*
 * validateJudges -- правила суда одной фазы. Отказ без записи каталога
 * модуль применить не сможет: код и страницу (у кадров -- кадр Close)
 * отдаёт nginx по символьному имени.
 */
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

	// Соединение есть только у кадров: у запроса субъекта по этой оси нет,
	// и правило молчало бы всегда, выглядя рабочим.
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
		// У кадра нет ни статуса, ни типа, ни метода: селекторы -- другие.
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

/*
 * ValidateAgainst -- ссылки профиля против общей секции. Живёт отдельно от
 * Validate, потому что требует обе стороны: форму проверяет профиль сам,
 * связность -- загрузчик каталога.
 */
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

		// Владелец у шкалы один: мерная корзина не принимает note, сигнальную
		// не меряют. Уровень обязан объясняться одним входом.
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

	// Инициаторы по уровню смотрят названную корзину: ссылка на необъявленную
	// молчала бы навсегда, а выглядела бы как рабочее правило.
	for i, o := range p.Request.Outcomes {
		if !o.OnBucket() {
			continue
		}

		if !c.HasAxis(o.If.Counter, o.If.Axis) {
			return fmt.Errorf("request.outcomes[%d]: counter %q has no axis %q declared "+
				"in %s/%s", i, o.If.Counter, o.If.Axis, SharedDir, CountersFile)
		}
	}

	// Секция кадров -- те же три проверки: суд, мера, инициаторы по уровню.
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

		/*
		 * Хотя бы одна ось корзины обязана быть достижима с провода: ip, обе
		 * ASN и sess. Корзина из одной оси user словам соседей недоступна --
		 * канал такой оси не знает, и правило не сработало бы никогда.
		 */
		if len(c.NoteAxes(r.Counter, protocol.ApplyIP)) == 0 &&
			len(c.NoteAxes(r.Counter, protocol.ApplyASN)) == 0 &&
			len(c.NoteAxes(r.Counter, protocol.ApplySession)) == 0 {
			return fmt.Errorf("trigger.prior[%d]: counter %q has no axis the "+
				"channel can reach (ip, asn_net, asn_router, sess)", i, r.Counter)
		}
	}

	return nil
}
