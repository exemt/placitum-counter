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

type subjectRef struct {
	counter string
	axis    string
}

type subjectKeys struct {
	counters *config.Counters
	byAxis   map[string]string
	bySource map[string]string
}

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

func needsResolver(refs []subjectRef) bool {
	for _, r := range refs {
		if r.axis == config.AxisNet || r.axis == config.AxisRouter {
			return true
		}
	}

	return false
}

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

func subjectHash(value string) string {
	sum := sha256.Sum256([]byte(value))

	return hex.EncodeToString(sum[:8])
}

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
