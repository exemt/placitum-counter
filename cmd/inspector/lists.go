package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/exemt/placitum-counter/internal/decide"
	"github.com/exemt/placitum-shared/netinfo"
)

type geoWriter interface {
	Write(ctx context.Context, write, addr string) ([]string, error)
}

type listWriter interface {
	AddMany(name string, values []string, ttl time.Duration, reason string) error
}

func writeLists(ctx context.Context, geo geoWriter, lists listWriter, log *slog.Logger,
	rid string, bans []decide.Ban) error {

	var failed error

	for _, ban := range bans {
		values := []string{ban.Addr}

		if netinfo.Networked(ban.Write) {
			got, err := geo.Write(ctx, ban.Write, ban.Addr)
			if err != nil {
				if failed == nil {
					failed = err
				}

				continue
			}

			if len(got) == 0 {
				log.Warn("list write skipped: coder knows nothing about the address",
					"rid", rid, "set", ban.Dataset, "write", ban.Write, "addr", ban.Addr)

				continue
			}

			values = got
		}

		if err := lists.AddMany(ban.Dataset, values, time.Duration(ban.TTL)*time.Second,
			ban.Reason); err != nil {
			log.Warn("list publish failed", "rid", rid, "set", ban.Dataset, "error", err.Error())
		}
	}

	return failed
}
