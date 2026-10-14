package config

import (
	"errors"
	"testing"
)

// Excludes belong to the entire Borg invocation, even when the excluded
// path is explicitly listed by a different entry or has a glob.
func TestArchiveCrossEntryExcludeAcceptance(t *testing.T) {
	for _, tc := range []struct {
		name         string
		path         string
		glob         string
		wantExcluded bool
	}{
		{"equal", "/srv/app/data", "", true},
		{"descendant", "/srv/app/data/nested", "", true},
		{"clean equal", "/srv/app/data/.", "", true},
		{"clean descendant", "/srv/app/tmp/../data/nested/", "", true},
		{"glob equal", "/srv/app/data", "*", true},
		{"glob descendant", "/srv/app/data/nested", "*.yaml", true},
		{"glob clean descendant", "/srv/app/data/./nested", "*", true},
		{"sibling prefix", "/srv/app/database", "", false},
		{"ancestor", "/srv/app", "", false},
		{"unrelated", "/etc/ssh", "", false},
		{"glob sibling", "/srv/app/data-old", "*", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, excludeFirst := range []bool{true, false} {
				fleet, err := Load("testdata/valid.yaml")
				if err != nil {
					t.Fatal(err)
				}
				owner := ArchivePath{Path: "/srv/app", Exclude: []string{"/srv/app/data"}}
				entry := ArchivePath{Path: tc.path, Glob: tc.glob}
				archive := []ArchivePath{owner, entry}
				if !excludeFirst {
					archive = []ArchivePath{entry, owner}
				}
				srv := fleet.Servers["host-2-example"]
				srv.Archive = archive
				fleet.Servers["host-2-example"] = srv
				err = Validate(fleet)
				if tc.wantExcluded {
					if !errors.Is(err, ErrExcludedArchivePath) {
						t.Errorf("excludeFirst=%v: Validate = %v, want ErrExcludedArchivePath", excludeFirst, err)
					}
				} else if err != nil {
					t.Errorf("excludeFirst=%v: valid archive rejected: %v", excludeFirst, err)
				}
			}
		})
	}
}
