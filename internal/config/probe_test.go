package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

// Поколение контроллера пробу не везёт: в его каталоге такого имени нет. После
// ReloadFrom на дерево без _probe снимок обязан взять её из каталога образа,
// а профили образа, которых в поколении нет, -- не тащить.
func TestProbeSurvivesGeneration(t *testing.T) {
	base, err := filepath.Abs(filepath.Join("..", "..", "profiles"))
	if err != nil {
		t.Fatal(err)
	}

	store, err := LoadProfiles(base, slog.Default())
	if err != nil {
		t.Fatal(err)
	}

	gen := t.TempDir()
	copyTree(t, filepath.Join(base, SharedDir), filepath.Join(gen, SharedDir))
	copyTree(t, filepath.Join(base, DefaultName), filepath.Join(gen, DefaultName))

	if err := store.ReloadFrom(gen); err != nil {
		t.Fatal(err)
	}

	snap := store.Current()

	if _, ok := snap.Profile(ProbeName); !ok {
		t.Fatal("_probe is gone after the generation")
	}

	if _, ok := snap.Profile("stand"); ok {
		t.Fatal("image profile leaked into the generation")
	}
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()

	err := filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o750)
		}

		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		return os.WriteFile(filepath.Join(dst, rel), raw, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}
