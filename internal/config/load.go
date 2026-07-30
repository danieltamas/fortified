package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Load reads and validates the fleet config at path.
func Load(path string) (*Fleet, error) {
	f, err := os.Open(path) //nolint:gosec // path is an operator-supplied config location (--config), not untrusted input
	if err != nil {
		return nil, fmt.Errorf("config: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)

	var fleet Fleet
	if err := dec.Decode(&fleet); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}

	if err := Validate(&fleet); err != nil {
		return nil, err
	}

	for id, srv := range fleet.Servers {
		if srv.Retention == nil {
			r := DefaultRetention
			srv.Retention = &r
			fleet.Servers[id] = srv
		}
	}
	return &fleet, nil
}
