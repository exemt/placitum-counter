/*
 * Ключи субъектов по осям одного запроса.
 *
 * Ось называет субъекта, ключ -- то, чем он ляжет в Redis. Пустой ключ --
 * субъекта на этом запросе нет: куки нет, справочник гео ещё не ответил, -- и
 * это не ошибка: правило по такой оси молчит, остальные работают.
 *
 * Значения настраиваемых осей (sess, user) уезжают в ключ хешем: инспектору
 * нужен стабильный идентификатор, а не содержимое куки, и класть токены
 * клиентов в ключи Redis незачем. Подпись клиренса здесь не проверяется --
 * это дело капчи; вращающий куку бот уходит от sess, но не от ip и asn.
 */

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/exemt/placitum-counter/internal/buckets"
	"github.com/exemt/placitum-counter/internal/config"
	"github.com/exemt/placitum-counter/internal/protocol"
)

// subjectRef -- пара «счётчик, ось»: у настраиваемых осей источник ключа может
// быть свой на счётчик, поэтому осей самих по себе недостаточно.
type subjectRef struct {
	counter string
	axis    string
}

/*
 * subjectKeys -- ключи субъектов запроса. Оси адреса общие (считаются из
 * ClientIP), а настраиваемые (sess, user) зависят от счётчика: источник ключа
 * может быть переопределён в его объявлении. Значения читаются по одному разу
 * на источник, а не на счётчик: два счётчика на одной куке делят одно чтение.
 */
type subjectKeys struct {
	counters *config.Counters
	byAxis   map[string]string // ip, asn_net, asn_router
	bySource map[string]string // "cookie:<имя>" / "header:<имя>" -> хеш значения
}

// key -- ключ субъекта корзины «счётчик:ось». false -- субъекта на этом
// запросе нет: куки нет, гео промахнулся, ось без источника.
func (k *subjectKeys) key(counter, axis string) (string, bool) {
	switch axis {
	case config.AxisSess:
		v, ok := k.bySource["cookie:"+k.counters.SessCookie(counter)]

		return v, ok

	case config.AxisUser:
		from := k.counters.UserFrom(counter)
		if from == "" {
			return "", false
		}

		v, ok := k.bySource[from]

		return v, ok
	}

	v, ok := k.byAxis[axis]

	return v, ok
}

/*
 * needsResolver -- есть ли среди пар оси, которым нужен справочник анонсов.
 * Без него они молча промахиваются: ключа нет, корзина не читается и не
 * заряжается, то есть правило по asn_net или asn_router не работает вовсе.
 */
func needsResolver(refs []subjectRef) bool {
	for _, r := range refs {
		if r.axis == config.AxisNet || r.axis == config.AxisRouter {
			return true
		}
	}

	return false
}

/*
 * hasConfigurable -- есть ли среди пар оси, которым нужны заголовки запроса.
 * Ось user с источником session к ним не относится: личность приезжает в
 * самом сообщении, и снимок заголовков ради неё тянуть незачем.
 */
func hasConfigurable(refs []subjectRef, counters *config.Counters) bool {
	for _, r := range refs {
		if r.axis == config.AxisSess {
			return true
		}

		if r.axis == config.AxisUser && config.WantsHeaders(counters.UserFrom(r.counter)) {
			return true
		}
	}

	return false
}

/*
 * subjectsOf собирает ключи для перечисленных пар «счётчик, ось». Заголовки
 * нужны только настраиваемым осям, и подгружает их вызывающий -- на фазе
 * запроса это store.headers, на фазе ответа -- request_store.headers: куки
 * живут в запросе, к какой бы фазе ни относилось сообщение.
 *
 * sessions -- секция того же сообщения: личности, которые назвали соседи. Они
 * сквозные по фазам, поэтому фаза ответа считает по тому же человеку, что
 * фаза запроса, ничего не перечитывая.
 */
func (h *handler) subjectsOf(
	ctx context.Context,
	refs []subjectRef,
	counters *config.Counters,
	clientIP string,
	headers []protocol.Header,
	sessions []protocol.Session,
	connID string,
) *subjectKeys {
	keys := &subjectKeys{
		counters: counters,
		byAxis:   map[string]string{},
		bySource: map[string]string{},
	}

	var needIP, needNet, needRouter, needConn bool

	sources := map[string]bool{}

	for _, r := range refs {
		switch r.axis {
		case config.AxisIP:
			needIP = true

		case config.AxisNet:
			needNet = true

		case config.AxisRouter:
			needRouter = true

		case config.AxisConn:
			needConn = true

		case config.AxisSess:
			sources["cookie:"+counters.SessCookie(r.counter)] = true

		case config.AxisUser:
			if from := counters.UserFrom(r.counter); from != "" {
				sources[from] = true
			}
		}
	}

	if needIP && clientIP != "" {
		keys.byAxis[config.AxisIP] = buckets.IPKey(clientIP)
	}

	// Соединение -- ключ рукопожатия как есть: он уже уникален в контуре.
	if needConn && connID != "" {
		keys.byAxis[config.AxisConn] = "conn:" + connID
	}

	if (needNet || needRouter) && clientIP != "" {
		network, router := h.resolver.Resolve(ctx, clientIP)

		if needNet && network != "" {
			keys.byAxis[config.AxisNet] = network
		}

		if needRouter && router != "" {
			keys.byAxis[config.AxisRouter] = router
		}
	}

	for src := range sources {
		kind, name, _ := strings.Cut(src, ":")

		var v string

		switch kind {
		case config.FromCookie:
			v = cookieValue(headers, name)

		case config.FromHeader:
			for _, h := range headers {
				if strings.EqualFold(h.Name(), name) {
					v = h.Value()

					break
				}
			}

		case config.FromSession:
			v = sessionValue(sessions, name)
		}

		if v != "" {
			keys.bySource[src] = subjectHash(v)
		}
	}

	return keys
}

// subjectHash -- стабильный короткий ключ значения. 16 hex-знаков хватает:
// коллизия стоит одного слитого счёта, а не решения.
func subjectHash(value string) string {
	sum := sha256.Sum256([]byte(value))

	return hex.EncodeToString(sum[:8])
}

/*
 * sessionValue -- логин или идентификатор сессии из секции sessions.
 *
 * Берутся только проверенные записи: непроверенная -- это то, что клиент
 * прислал сам (чужой токен, который отправитель разобрал, но подпись не
 * сверял), и ключ счёта, которым управляет клиент, -- это не счёт.
 *
 * Записей бывает несколько: две калитки, своя сессия и сессия приложения.
 * Выбор обязан быть один и тот же на каждом запросе, иначе корзина субъекта
 * прыгала бы между ключами, поэтому побеждает наименьшая пара
 * (отправитель, источник), а не первая приехавшая.
 */
func sessionValue(sessions []protocol.Session, field string) string {
	var best, bestKey string

	for _, s := range sessions {
		if !s.Verified {
			continue
		}

		var v string

		switch field {
		case config.SubjectUser:
			v = s.User

		case config.SubjectSID:
			v = s.ID
		}

		if v == "" {
			continue
		}

		key := s.Inspector + "\x00" + s.Source

		if best == "" || key < bestKey {
			best, bestKey = v, key
		}
	}

	return best
}

// cookieValue -- значение куки из заголовков запроса. Копия разбора капчи:
// заголовков Cookie бывает несколько, значения в кавычках встречаются.
func cookieValue(pairs []protocol.Header, name string) string {
	if name == "" {
		return ""
	}

	for _, h := range pairs {
		if !strings.EqualFold(h.Name(), "cookie") {
			continue
		}

		if v := cookieFrom(h.Value(), name); v != "" {
			return v
		}
	}

	return ""
}

func cookieFrom(line, name string) string {
	for len(line) > 0 {
		var part string

		if i := strings.IndexByte(line, ';'); i >= 0 {
			part, line = line[:i], line[i+1:]
		} else {
			part, line = line, ""
		}

		part = strings.TrimSpace(part)

		key, value, ok := strings.Cut(part, "=")
		if !ok || strings.TrimSpace(key) != name {
			continue
		}

		return strings.Trim(strings.TrimSpace(value), `"`)
	}

	return ""
}
