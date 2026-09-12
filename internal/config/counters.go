/*
 * Объявления счётчиков: общая секция инспектора, не профиля.
 *
 * Счётчик -- семейство корзин, по одной на пару (ось, субъект). Объявляется
 * заранее и один раз на инспектор: профили ссылаются на него по имени, и ссылка
 * на необъявленный счётчик отвергает поколение целиком. Ключи Redis без
 * профиля -- cnt:bkt:<счётчик>:<ось>:<субъект>, -- поэтому два маршрута с
 * разными профилями намеренно греют один счёт: «получил много объектов» --
 * факт про субъекта, а не про маршрут.
 *
 * Лежит в profiles/_shared/counters.yaml. Каталог _shared -- не профиль (в нём
 * нет profile.yaml), а раскатка из KV возит его тем же манифестом, что и
 * профили: псевдопрофиль _shared с одним файлом.
 */

package config

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/exemt/placitum-counter/internal/buckets"
	"github.com/exemt/placitum-counter/internal/protocol"
)

// SharedDir -- каталог общей секции внутри каталога профилей.
const (
	SharedDir    = "_shared"
	CountersFile = "counters.yaml"
)

/*
 * Оси субъектов. Четыре первых -- те же, что у корзин капчи, и смысл у них
 * один на весь контур (docs/buckets.md репозитория captcha). user -- новая:
 * стабильный ключ клиента из настраиваемого источника, а не проверенная
 * личность -- личность знает только auth, и тащить сюда верификацию чужих
 * токенов не надо.
 */
const (
	AxisIP     = "ip"
	AxisNet    = "asn_net"
	AxisRouter = "asn_router"
	AxisSess   = "sess"
	AxisUser   = "user"
	// AxisConn -- соединение: ключ -- conn_id рукопожатия WebSocket. Есть
	// только на фазе кадров; у запроса и ответа субъекта по этой оси нет.
	AxisConn = "conn"
)

var knownAxes = []string{AxisIP, AxisNet, AxisRouter, AxisSess, AxisUser, AxisConn}

/*
 * Владение шкалой. Корзину наполняет ровно один вход: либо собственные правила
 * measure (fill: measure, умолчание), либо note соседей (fill: note). Два входа
 * в одну шкалу означали бы двух владельцев одной ответственности: уровень,
 * который не объяснить ни правилами профиля, ни чужими просьбами по
 * отдельности. Судят правила judge корзины обоих владений одинаково.
 */
const (
	FillMeasure = "measure"
	FillNote    = "note"
)

// AxisTier -- ёмкость и потери одной оси счётчика. У осей свои числа намеренно:
// подсеть терпит больше адреса.
type AxisTier struct {
	// Max -- ёмкость в натуральных единицах счётчика (вхождения, килобайты).
	Max float64 `yaml:"max"`
	// Loss -- потери, процентов ёмкости в секунду.
	Loss float64 `yaml:"loss"`
}

type Counter struct {
	// Unit -- подпись единицы для панели и аудита. На арифметику не влияет.
	Unit string              `yaml:"unit"`
	Axes map[string]AxisTier `yaml:"axes"`
	// Fill -- кто наполняет: measure (правила фазы ответа, умолчание) либо
	// note (просьбы соседей). Пусто -- measure: старые декларации читаются
	// без правки.
	Fill string `yaml:"fill"`
	/*
	 * Subjects -- свои источники ключей настраиваемых осей этого счётчика:
	 * «на эту куку заведён счётчик» видно прямо в объявлении. nil или пустое
	 * поле -- общие источники секции subjects. Так один счётчик ключуется
	 * кукой клиренса капчи, соседний -- кукой сессии калитки, и живут они
	 * независимо.
	 */
	Subjects *Subjects `yaml:"subjects"`
}

/*
 * Источники ключей настраиваемых осей. sess по умолчанию читает куку клиренса
 * капчи; подпись инспектор не проверяет -- ему нужен стабильный ключ, а не
 * доказательство. Вращающий куку бот уходит от sess, но не от ip и asn: оси
 * для того и несколько.
 */
type Subjects struct {
	Sess SessSubject `yaml:"sess"`
	User UserSubject `yaml:"user"`
}

type SessSubject struct {
	Cookie string `yaml:"cookie"`
}

// UserSubject -- откуда брать ключ оси user: "cookie:<имя>", "header:<имя>"
// либо "session:user" / "session:sid". Пусто -- ось выключена, ссылка на неё
// не грузится.
type UserSubject struct {
	From string `yaml:"from"`
}

/*
 * Виды источников ключа оси user. cookie и header читают то, что прислал
 * клиент: ключ стабилен, но личностью не является и вращается вместе с кукой.
 * session берёт то, что о клиенте сказала калитка (секция sessions сообщения
 * модуля): SubjectUser -- логин, одна корзина на человека, сколько бы у него
 * ни было сессий и устройств; SubjectSID -- идентификатор сессии, корзина на
 * вход. Подделать их клиент не может -- их называет не он.
 */
const (
	FromCookie  = "cookie"
	FromHeader  = "header"
	FromSession = "session"

	SubjectUser = "user"
	SubjectSID  = "sid"
)

/*
 * SplitFrom -- разбор источника на вид и имя. Пустая строка -- ось выключена,
 * и это не ошибка: ok=false здесь означает «источника нет или он не той
 * формы», а разбирается ли форма, решает вызывающий.
 */
func SplitFrom(from string) (kind, name string, ok bool) {
	kind, name, ok = strings.Cut(from, ":")
	if !ok || name == "" {
		return "", "", false
	}

	switch kind {
	case FromCookie, FromHeader:
		return kind, name, true

	case FromSession:
		if name == SubjectUser || name == SubjectSID {
			return kind, name, true
		}
	}

	return "", "", false
}

// WantsHeaders -- нужен ли источнику снимок заголовков запроса. У session не
// нужен: личность приезжает в самом сообщении.
func WantsHeaders(from string) bool {
	kind, _, ok := SplitFrom(from)

	return ok && (kind == FromCookie || kind == FromHeader)
}

const DefaultSessCookie = "waf_cid"

type Counters struct {
	Counters map[string]Counter `yaml:"counters"`
	Subjects Subjects           `yaml:"subjects"`
}

// Kind -- имя корзины для пакета buckets: пара "счётчик:ось".
func Kind(counter, axis string) string { return counter + ":" + axis }

// SessCookie -- кука оси sess счётчика: из объявления, иначе общая.
func (c *Counters) SessCookie(counter string) string {
	if cnt, ok := c.Counters[counter]; ok && cnt.Subjects != nil &&
		cnt.Subjects.Sess.Cookie != "" {
		return cnt.Subjects.Sess.Cookie
	}

	return c.Subjects.Sess.Cookie
}

// UserFrom -- источник оси user счётчика ("cookie:<имя>" | "header:<имя>"):
// из объявления, иначе общий. Пусто -- ось у этого счётчика без ключа.
func (c *Counters) UserFrom(counter string) string {
	if cnt, ok := c.Counters[counter]; ok && cnt.Subjects != nil &&
		cnt.Subjects.User.From != "" {
		return cnt.Subjects.User.From
	}

	return c.Subjects.User.From
}

// Tiers -- все объявленные корзины в форме пакета buckets. Считается один раз
// на снимок: на горячем пути карта только читается.
func (c *Counters) Tiers() map[string]buckets.Tier {
	out := map[string]buckets.Tier{}

	for name, cnt := range c.Counters {
		for axis, tier := range cnt.Axes {
			out[Kind(name, axis)] = buckets.Tier{Max: tier.Max, Loss: tier.Loss}
		}
	}

	return out
}

// AxesOf -- объявленные оси счётчика в устойчивом порядке словаря осей.
func (c *Counters) AxesOf(counter string) []string {
	cnt, ok := c.Counters[counter]
	if !ok {
		return nil
	}

	var out []string

	for _, axis := range knownAxes {
		if _, ok := cnt.Axes[axis]; ok {
			out = append(out, axis)
		}
	}

	return out
}

// HasAxis -- объявлена ли ось у счётчика.
func (c *Counters) HasAxis(counter, axis string) bool {
	cnt, ok := c.Counters[counter]
	if !ok {
		return false
	}

	_, ok = cnt.Axes[axis]

	return ok
}

// Fill -- владение счётчика; на необъявленное имя отвечает measure, ссылку
// ловит валидация связности, а не этот геттер.
func (c *Counters) Fill(counter string) string {
	cnt, ok := c.Counters[counter]
	if !ok || cnt.Fill == "" {
		return FillMeasure
	}

	return cnt.Fill
}

/*
 * NoteAxes -- объявленные оси счётчика, в которые разворачивается ось провода:
 * ip -- адрес, asn -- обе ASN-оси (сигнал один, шкалы две: подсеть греется
 * быстро, вся система медленно), session -- ключ сессии. user с провода
 * недостижима -- канал такой оси не знает, -- а request корзины не имеет.
 */
func (c *Counters) NoteAxes(counter, wireAxis string) []string {
	var want []string

	switch wireAxis {
	case protocol.ApplyIP:
		want = []string{AxisIP}

	case protocol.ApplyASN:
		want = []string{AxisNet, AxisRouter}

	case protocol.ApplySession:
		want = []string{AxisSess}

	default:
		return nil
	}

	var out []string

	for _, axis := range want {
		if c.HasAxis(counter, axis) {
			out = append(out, axis)
		}
	}

	return out
}

// ParseCounters разбирает counters.yaml. Пустой файл недопустим: инспектор без
// единого счётчика не считает ничего, и это должно быть видно на загрузке, а
// не на первом запросе.
func ParseCounters(raw []byte) (*Counters, error) {
	c := &Counters{}

	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)

	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("%s: %w", CountersFile, err)
	}

	if c.Subjects.Sess.Cookie == "" {
		c.Subjects.Sess.Cookie = DefaultSessCookie
	}

	return c, c.validate()
}

func (c *Counters) validate() error {
	if len(c.Counters) == 0 {
		return fmt.Errorf("%s: no counters declared", CountersFile)
	}

	for name, cnt := range c.Counters {
		if !nameRe.MatchString(name) {
			return fmt.Errorf("%s: bad counter name %q", CountersFile, name)
		}

		switch cnt.Fill {
		case "", FillMeasure, FillNote:
		default:
			return fmt.Errorf("counter %s: fill must be %s or %s, got %q",
				name, FillMeasure, FillNote, cnt.Fill)
		}

		if len(cnt.Axes) == 0 {
			return fmt.Errorf("counter %s: no axes: a counter without axes counts nobody", name)
		}

		for axis, tier := range cnt.Axes {
			if !hasString(knownAxes, axis) {
				return fmt.Errorf("counter %s: unknown axis %q (known: %s)",
					name, axis, strings.Join(knownAxes, ", "))
			}

			if tier.Max <= 0 {
				return fmt.Errorf("counter %s: axis %s: max must be positive", name, axis)
			}

			if tier.Loss <= 0 || tier.Loss > 100 {
				return fmt.Errorf("counter %s: axis %s: loss must be within (0..100] "+
					"percent per second", name, axis)
			}

			if axis == AxisUser && c.UserFrom(name) == "" {
				return fmt.Errorf("counter %s: axis user needs subjects.user.from "+
					"(shared or declared on the counter)", name)
			}
		}

		if cnt.Subjects != nil {
			if err := cnt.Subjects.validate(); err != nil {
				return fmt.Errorf("counter %s: %w", name, err)
			}
		}
	}

	return c.Subjects.validate()
}

func (s *Subjects) validate() error {
	if s.User.From == "" {
		return nil
	}

	if _, _, ok := SplitFrom(s.User.From); !ok {
		return fmt.Errorf("subjects.user.from must be cookie:<name>, header:<name>, "+
			"session:user or session:sid, got %q", s.User.From)
	}

	return nil
}
