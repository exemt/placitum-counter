/*
 * Каталог профилей и его горячая перезагрузка.
 *
 * Снимок неизменяем и подменяется целиком: правка одного профиля не должна
 * оставлять контур в состоянии «половина старого, половина нового». Ошибка
 * разбора любого профиля -- как и общей секции счётчиков -- отвергает всё
 * поколение, а действующий набор при этом не трогают, как у modsec с его
 * apply_failed.
 *
 * Общая секция счётчиков читается из _shared/counters.yaml того же каталога:
 * профили ссылаются на счётчики по имени, и связность проверяется здесь --
 * единственном месте, где прочитаны обе стороны.
 *
 * Отпечаток -- имя, размер и mtime файлов. Читать содержимое раз в секунду
 * ради сравнения незачем: профиль правят руками либо подменяют каталогом
 * целиком.
 */

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

// Counters -- общая секция снимка. Не nil у любого живого снимка: каталог без
// counters.yaml не загружается.
func (s *Snapshot) Counters() *Counters {
	if s == nil {
		return nil
	}

	return s.counters
}

// Tiers -- корзины всех счётчиков в форме пакета buckets. Карта собрана при
// загрузке и на горячем пути только читается.
func (s *Snapshot) Tiers() map[string]buckets.Tier {
	if s == nil {
		return nil
	}

	return s.tiers
}

// All -- профили в лексическом порядке имён.
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
	mu  sync.Mutex
	dir string
	// base -- каталог образа, с которого store начал. Там живёт профиль пробы
	// (ProbeName): поколение контроллера его не везёт, а read() достаёт
	// оттуда, когда читает другой каталог.
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

// Dir -- каталог, по которому сейчас читают. Нужен раскатке: она кладёт новое
// поколение рядом и переключает сюда.
func (s *Store) Dir() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.dir
}

/*
 * ReloadFrom переключает каталог и читает его целиком. Провал не трогает ни
 * действующий снимок, ни каталог: поколение, которое не разобралось, не должно
 * оставлять контур ни с половиной профилей, ни без них.
 */
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

// Reload перечитывает каталог, если изменился отпечаток. Первое значение --
// была ли подмена.
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
				// Битое поколение не подменяет действующее: инспектор
				// продолжает работать по последнему исправному набору.
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

	/*
	 * Проба (ProbeName) живёт в образе: в каталоге контроллера такого имени
	 * нет, и поколение её не везёт. Healthcheck ходит с ней всегда, поэтому
	 * дерево поколения дополняется пробой из базового каталога. Провал пробы
	 * поколение не роняет: без неё инспектор работает, а проба покраснеет и
	 * скажет почему.
	 */
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

/*
 * readProfile читает один профиль каталога. Нет файла -- нет профиля (nil без
 * ошибки): подкаталог без profile.yaml -- не профиль, а что-то рядом.
 */
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

	// Связность: ссылка на необъявленный счётчик или ось отвергает
	// поколение, как любая другая опечатка профиля.
	if err := p.ValidateAgainst(counters); err != nil {
		return nil, fmt.Errorf("profile %s: %w", name, err)
	}

	return p, nil
}

/*
 * fingerprint -- имя, размер и mtime всех файлов каталога. Содержимое не
 * читается: этого достаточно, чтобы увидеть правку, и дёшево настолько, что
 * опрос раз в секунду не виден в профиле процесса.
 */
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
