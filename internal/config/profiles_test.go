package config

import (
	"log/slog"
	"path/filepath"
	"testing"
)

// Профили из образа обязаны подниматься: опечатка в counters.yaml или в
// bootstrap-профиле иначе ловится только стартом контейнера.
func TestBootstrapProfilesLoad(t *testing.T) {
	dir, err := filepath.Abs(filepath.Join("..", "..", "profiles"))
	if err != nil {
		t.Fatal(err)
	}

	store, err := LoadProfiles(dir, slog.Default())
	if err != nil {
		t.Fatal(err)
	}

	snap := store.Current()

	if _, ok := snap.Profile(DefaultName); !ok {
		t.Fatal("default profile is missing")
	}

	if _, ok := snap.Profile(ProbeName); !ok {
		t.Fatal("_probe profile is missing")
	}

	if len(snap.Counters().Counters) == 0 {
		t.Fatal("no counters declared")
	}

	// _shared -- не профиль: каталог общей секции не должен подниматься именем.
	if _, ok := snap.Profile(SharedDir); ok {
		t.Fatal("_shared has been loaded as a profile")
	}

	if len(snap.Tiers()) == 0 {
		t.Fatal("no tiers built")
	}
}
