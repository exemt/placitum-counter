package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/exemt/placitum-counter/internal/buckets"
)

const profileFile = "profile.yaml"

type Snapshot struct {
	Gen         int64
	Fingerprint string

	byName   map[string]*Profile
	names    []string
	counters *Counters
	tiers    map[string]buckets.Tier
}

func (s *Snapshot) Profile(name string) (*Profile, bool) {
	if s == nil {
		return nil, false
	}

	if name == "" {
		name = DefaultName
	}

	p, ok := s.byName[name]

	return p, ok
}

func (s *Snapshot) Names() []string {
	if s == nil {
		return nil
	}

	return s.names
}

func (s *Snapshot) Counters() *Counters {
	if s == nil {
		return nil
	}

	return s.counters
}

func (s *Snapshot) Tiers() map[string]buckets.Tier {
	if s == nil {
		return nil
	}

	return s.tiers
}

func (s *Snapshot) All() []*Profile {
	if s == nil {
		return nil
	}

	out := make([]*Profile, 0, len(s.names))

	for _, name := range s.names {
		out = append(out, s.byName[name])
	}

	return out
}

type Store struct {
	mu   sync.Mutex
	dir  string
	base string
	log  *slog.Logger
	cur  atomic.Pointer[Snapshot]
	gen  atomic.Int64
}

func LoadProfiles(dir string, log *slog.Logger) (*Store, error) {
	s := &Store{dir: dir, base: dir, log: log}

	snap, err := s.read()
	if err != nil {
		return nil, err
	}

	s.cur.Store(snap)

	return s, nil
}

func (s *Store) Current() *Snapshot { return s.cur.Load() }

func (s *Store) Dir() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.dir
}

func (s *Store) ReloadFrom(dir string) error {
	s.mu.Lock()
	prev := s.dir
	s.dir = dir
	s.mu.Unlock()

	snap, err := s.read()
	if err != nil {
		s.mu.Lock()
		s.dir = prev
		s.mu.Unlock()

		return err
	}

	s.cur.Store(snap)

	return nil
}

func (s *Store) Reload() (bool, error) {
	fp, err := fingerprint(s.Dir())
	if err != nil {
		return false, err
	}

	if cur := s.cur.Load(); cur != nil && cur.Fingerprint == fp {
		return false, nil
	}

	snap, err := s.read()
	if err != nil {
		return false, err
	}

	s.cur.Store(snap)

	return true, nil
}

func (s *Store) Watch(ctx context.Context, every time.Duration) {
	if every <= 0 {
		return
	}

	tick := time.NewTicker(every)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-tick.C:
			changed, err := s.Reload()
			if err != nil {
				s.log.Error("profiles reload failed", "error", err.Error())

				continue
			}

			if changed {
				snap := s.Current()
				s.log.Info("profiles reloaded",
					"gen", snap.Gen,
					"profiles", snap.Names(),
					"fingerprint", snap.Fingerprint,
				)
			}
		}
	}
}

func (s *Store) read() (*Snapshot, error) {
	dir := s.Dir()

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("profiles: %w", err)
	}

	snap := &Snapshot{byName: map[string]*Profile{}}

	rawCounters, err := os.ReadFile(filepath.Join(dir, SharedDir, CountersFile))
	if err != nil {
		return nil, fmt.Errorf("profiles: shared counters: %w", err)
	}

	counters, err := ParseCounters(rawCounters)
	if err != nil {
		return nil, err
	}

	snap.counters = counters
	snap.tiers = counters.Tiers()

	for _, e := range entries {
		if !e.IsDir() || e.Name() == SharedDir {
			continue
		}

		p, err := readProfile(dir, e.Name(), counters)
		if err != nil {
			return nil, err
		}

		if p == nil {
			continue
		}

		snap.byName[e.Name()] = p
		snap.names = append(snap.names, e.Name())
	}

	if _, ok := snap.byName[ProbeName]; !ok && s.base != dir {
		p, err := readProfile(s.base, ProbeName, counters)
		if err != nil {
			s.log.Warn("probe profile skipped", "base", s.base, "error", err.Error())
		} else if p != nil {
			snap.byName[ProbeName] = p
			snap.names = append(snap.names, ProbeName)
		}
	}

	if _, ok := snap.byName[DefaultName]; !ok {
		return nil, fmt.Errorf("profiles: %s is missing in %s", DefaultName, dir)
	}

	sort.Strings(snap.names)

	fp, err := fingerprint(dir)
	if err != nil {
		return nil, err
	}

	snap.Fingerprint = fp
	snap.Gen = s.gen.Add(1)

	return snap, nil
}

func readProfile(dir, name string, counters *Counters) (*Profile, error) {
	raw, err := os.ReadFile(filepath.Join(dir, name, profileFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}

		return nil, fmt.Errorf("profiles: %w", err)
	}

	p, err := ParseProfile(name, raw)
	if err != nil {
		return nil, err
	}

	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("profile %s: %w", name, err)
	}

	if err := p.ValidateAgainst(counters); err != nil {
		return nil, fmt.Errorf("profile %s: %w", name, err)
	}

	return p, nil
}

func fingerprint(dir string) (string, error) {
	sum := sha256.New()

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}

		_, _ = sum.Write([]byte(filepath.ToSlash(rel)))
		_, _ = sum.Write([]byte{0})
		_, _ = sum.Write([]byte(strconv.FormatInt(info.Size(), 10)))
		_, _ = sum.Write([]byte{0})
		_, _ = sum.Write([]byte(strconv.FormatInt(info.ModTime().UnixNano(), 10)))
		_, _ = sum.Write([]byte{0})

		return nil
	})
	if err != nil {
		return "", fmt.Errorf("profiles: %w", err)
	}

	return hex.EncodeToString(sum.Sum(nil)), nil
}
