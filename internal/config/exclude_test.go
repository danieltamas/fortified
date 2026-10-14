package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArchiveExcludeAcceptance(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		valid      bool
	}{
		{"relative", "data", false},
		{"unclean dot", "/home/docker/psql/./data", false},
		{"unclean parent", "/home/docker/psql/data/../other", false},
		{"trailing slash", "/home/docker/psql/data/", false},
		{"equal", "/home/docker/psql", false},
		{"shared prefix sibling", "/home/docker/psqlx/data", false},
		{"outside", "/etc/postgresql", false},
		{"empty", "", false},
		{"child", "/home/docker/psql/data", true},
		{"nested child", "/home/docker/psql/data/18/main", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Exercise fleet.yaml decoding and validation, not a private predicate.
			base, err := os.ReadFile("testdata/valid.yaml")
			if err != nil {
				t.Fatal(err)
			}
			yaml := strings.Replace(string(base), "    archive:\n", "    archive:\n      - path: /home/docker/psql\n        exclude: [\""+tc.path+"\"]\n", 1)
			file := filepath.Join(t.TempDir(), "fleet.yaml")
			if err := os.WriteFile(file, []byte(yaml), 0o600); err != nil { //nolint:gosec // file is under t.TempDir(), not untrusted input
				t.Fatal(err)
			}
			fleet, err := Load(file)
			if !tc.valid {
				if !errors.Is(err, ErrInvalidExclude) {
					t.Fatalf("Load exclude %q: %v, want ErrInvalidExclude", tc.path, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load valid exclude: %v", err)
			}
			got := fleet.Servers["host-2-example"].Archive[0].Exclude
			if len(got) != 1 || got[0] != tc.path {
				t.Fatalf("decoded excludes = %v, want [%s]", got, tc.path)
			}
		})
	}
}

func TestArchiveExcludeCannotEqualRootAcceptance(t *testing.T) {
	fleet, err := Load("testdata/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	srv := fleet.Servers["host-2-example"]
	srv.Archive = []ArchivePath{{Path: "/", Exclude: []string{"/"}}}
	fleet.Servers["host-2-example"] = srv
	if err := Validate(fleet); !errors.Is(err, ErrInvalidExclude) {
		t.Fatalf("exclude equal to root: %v, want ErrInvalidExclude", err)
	}
}
