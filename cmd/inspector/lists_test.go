package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/exemt/placitum-counter/internal/config"
	"github.com/exemt/placitum-counter/internal/decide"
	"github.com/exemt/placitum-shared/netinfo"
)

/* --- заглушки ------------------------------------------------------------ */

type geoStub struct {
	values map[string][]string
	err    error
	// calls -- с каким охватом спрашивали: кодер нужен только подсети и системе.
	calls []string
}

func (g *geoStub) Write(_ context.Context, write, addr string) ([]string, error) {
	g.calls = append(g.calls, write+" "+addr)

	if g.err != nil {
		return nil, g.err
	}

	return g.values[write], nil
}

type listsStub struct {
	writes []string
	ttl    []time.Duration
}

func (l *listsStub) AddMany(name string, values []string, ttl time.Duration, _ string) error {
	l.writes = append(l.writes, name+"="+strings.Join(values, ","))
	l.ttl = append(l.ttl, ttl)

	return nil
}

func banRow(set, write string) decide.Ban {
	return decide.Ban{Dataset: set, Write: write, Addr: "8.8.8.143", TTL: 60, Reason: "COUNTER_DENY"}
}

var quietLog = slog.New(slog.NewTextHandler(io.Discard, nil))

/* --- тесты --------------------------------------------------------------- */

/*
 * Четыре охвата одного запроса: адрес -- без кодера, анонсы и система -- у
 * кодера, каждая строка -- одна пачка со своим сроком.
 */
func TestWriteListsScopes(t *testing.T) {
	geo := &geoStub{values: map[string][]string{
		netinfo.WriteNet:    {"8.8.8.0/24"},
		netinfo.WriteNetAll: {"8.8.8.0/24", "8.0.0.0/9"},
		netinfo.WriteASN:    {"8.8.4.0/24", "8.8.8.0/24"},
	}}
	lists := &listsStub{}

	err := writeLists(context.Background(), geo, lists, quietLog, "rid", []decide.Ban{
		banRow("ip", config.WriteAddr), banRow("net", config.WriteNet),
		banRow("all", config.WriteNetAll), banRow("asn", config.WriteASN),
	})
	if err != nil {
		t.Fatal(err)
	}

	want := "ip=8.8.8.143 net=8.8.8.0/24 all=8.8.8.0/24,8.0.0.0/9 asn=8.8.4.0/24,8.8.8.0/24"

	if got := strings.Join(lists.writes, " "); got != want {
		t.Fatalf("writes %s, want %s", got, want)
	}

	if len(geo.calls) != 3 {
		t.Fatalf("the coder is for net, net_all and asn only: %v", geo.calls)
	}

	if lists.ttl[0] != time.Minute {
		t.Fatalf("ttl %s", lists.ttl[0])
	}
}

/* Кодер молчит: адрес ложится, строка подсети -- ошибка вызывающему, без записи. */
func TestWriteListsGeoDown(t *testing.T) {
	lists := &listsStub{}

	err := writeLists(context.Background(), &geoStub{err: netinfo.ErrUnavailable}, lists, quietLog,
		"rid", []decide.Ban{banRow("all", config.WriteNetAll), banRow("ip", config.WriteAddr)})
	if !errors.Is(err, netinfo.ErrUnavailable) {
		t.Fatalf("expected geo unavailable, got %v", err)
	}

	if strings.Join(lists.writes, " ") != "ip=8.8.8.143" {
		t.Fatalf("the address does not depend on the coder: %v", lists.writes)
	}
}

/* Кодер не знает адреса: записи нет и ошибки нет -- системы у адреса просто нет. */
func TestWriteListsUnknownAddress(t *testing.T) {
	lists := &listsStub{}

	if err := writeLists(context.Background(), &geoStub{}, lists, quietLog, "rid",
		[]decide.Ban{banRow("asn", config.WriteASN)}); err != nil {
		t.Fatal(err)
	}

	if len(lists.writes) != 0 {
		t.Fatalf("nothing to write: %v", lists.writes)
	}
}
