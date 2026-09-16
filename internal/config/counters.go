package config

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/exemt/placitum-counter/internal/buckets"
	"github.com/exemt/placitum-counter/internal/protocol"
)

const (
	SharedDir    = "_shared"
	CountersFile = "counters.yaml"
)

const (
	AxisIP     = "ip"
	AxisNet    = "asn_net"
	AxisRouter = "asn_router"
	AxisSess   = "sess"
	AxisUser   = "user"
	AxisConn   = "conn"
)

var knownAxes = []string{AxisIP, AxisNet, AxisRouter, AxisSess, AxisUser, AxisConn}

const (
	FillMeasure = "measure"
	FillNote    = "note"
)

type AxisTier struct {
	Max  float64 `yaml:"max"`
	Loss float64 `yaml:"loss"`
}

type Counter struct {
	Unit     string              `yaml:"unit"`
	Axes     map[string]AxisTier `yaml:"axes"`
	Fill     string              `yaml:"fill"`
	Subjects *Subjects           `yaml:"subjects"`
}

type Subjects struct {
	Sess SessSubject `yaml:"sess"`
	User UserSubject `yaml:"user"`
}

type SessSubject struct {
	Cookie string `yaml:"cookie"`
}

type UserSubject struct {
	From string `yaml:"from"`
}

const (
	FromCookie  = "cookie"
	FromHeader  = "header"
	FromSession = "session"

	SubjectUser = "user"
	SubjectSID  = "sid"
)

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

func WantsHeaders(from string) bool {
	kind, _, ok := SplitFrom(from)

	return ok && (kind == FromCookie || kind == FromHeader)
}

const DefaultSessCookie = "waf_cid"

type Counters struct {
	Counters map[string]Counter `yaml:"counters"`
	Subjects Subjects           `yaml:"subjects"`
}

func Kind(counter, axis string) string { return counter + ":" + axis }

func (c *Counters) SessCookie(counter string) string {
	if cnt, ok := c.Counters[counter]; ok && cnt.Subjects != nil &&
		cnt.Subjects.Sess.Cookie != "" {
		return cnt.Subjects.Sess.Cookie
	}

	return c.Subjects.Sess.Cookie
}

func (c *Counters) UserFrom(counter string) string {
	if cnt, ok := c.Counters[counter]; ok && cnt.Subjects != nil &&
		cnt.Subjects.User.From != "" {
		return cnt.Subjects.User.From
	}

	return c.Subjects.User.From
}

func (c *Counters) Tiers() map[string]buckets.Tier {
	out := map[string]buckets.Tier{}

	for name, cnt := range c.Counters {
		for axis, tier := range cnt.Axes {
			out[Kind(name, axis)] = buckets.Tier{Max: tier.Max, Loss: tier.Loss}
		}
	}

	return out
}

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

func (c *Counters) HasAxis(counter, axis string) bool {
	cnt, ok := c.Counters[counter]
	if !ok {
		return false
	}

	_, ok = cnt.Axes[axis]

	return ok
}

func (c *Counters) Fill(counter string) string {
	cnt, ok := c.Counters[counter]
	if !ok || cnt.Fill == "" {
		return FillMeasure
	}

	return cnt.Fill
}

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
