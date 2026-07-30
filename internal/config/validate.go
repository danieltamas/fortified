package config

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// ErrUnresolvedTODO means a config value is still the literal
// placeholder discover --emit-config writes for anything it couldn't
// infer. Onboard must refuse to proceed past this (SPEC.md §5).
var ErrUnresolvedTODO = errors.New("config: contains an unresolved TODO value")

// ErrPlaintextSecret means a field that must hold a secret reference
// (env:// or secret://) instead holds a literal value.
var ErrPlaintextSecret = errors.New("config: expected a secret reference (env:// or secret://), not a literal value")

// ErrMissingField means a required field was empty.
var ErrMissingField = errors.New("config: missing required field")

// Validate checks fleet for unresolved TODO placeholders, missing
// required fields, and plaintext secrets — the same check Load runs
// on every read, exported so a caller that builds a Fleet in memory
// (discover's auto-write path) can run it before ever touching disk.
func Validate(fleet *Fleet) error {
	if path := findTODO(reflect.ValueOf(fleet), ""); path != "" {
		return fmt.Errorf("%s: %w", path, ErrUnresolvedTODO)
	}

	ids := make([]string, 0, len(fleet.Servers))
	for id := range fleet.Servers {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		if err := validateServer(id, fleet.Servers[id]); err != nil {
			return err
		}
	}
	return nil
}

func validateServer(id string, srv Server) error {
	prefix := fmt.Sprintf("servers.%s", id)

	if srv.SSH.Host == "" {
		return fmt.Errorf("%s.ssh.host: %w", prefix, ErrMissingField)
	}
	if srv.SSH.Port == 0 {
		return fmt.Errorf("%s.ssh.port: %w", prefix, ErrMissingField)
	}
	if srv.SSH.User == "" {
		return fmt.Errorf("%s.ssh.user: %w", prefix, ErrMissingField)
	}
	if srv.Provider == "" {
		return fmt.Errorf("%s.provider: %w", prefix, ErrMissingField)
	}
	if srv.Destination == "" {
		return fmt.Errorf("%s.destination: %w", prefix, ErrMissingField)
	}

	if srv.EncryptionKeyRef == "" {
		return fmt.Errorf("%s.encryption_key_ref: %w", prefix, ErrMissingField)
	}
	if !isSecretRef(srv.EncryptionKeyRef) {
		return fmt.Errorf("%s.encryption_key_ref: %w", prefix, ErrPlaintextSecret)
	}

	for i, db := range srv.Databases {
		if db.AuthRef != "" && !isSecretRef(db.AuthRef) {
			return fmt.Errorf("%s.databases[%d].auth_ref: %w", prefix, i, ErrPlaintextSecret)
		}
	}

	if srv.Provider == "hetzner" {
		if err := validateHetznerConfig(prefix, srv.Hetzner); err != nil {
			return err
		}
	}
	return nil
}

func validateHetznerConfig(prefix string, cfg *HetznerConfig) error {
	if cfg == nil {
		return fmt.Errorf("%s.hetzner: %w", prefix, ErrMissingField)
	}
	if cfg.MainAccount.Host == "" {
		return fmt.Errorf("%s.hetzner.main_account.host: %w", prefix, ErrMissingField)
	}
	if cfg.MainAccount.Port == 0 {
		return fmt.Errorf("%s.hetzner.main_account.port: %w", prefix, ErrMissingField)
	}
	if cfg.MainAccount.User == "" {
		return fmt.Errorf("%s.hetzner.main_account.user: %w", prefix, ErrMissingField)
	}
	if cfg.HCloudTokenRef == "" {
		return fmt.Errorf("%s.hetzner.hcloud_token_ref: %w", prefix, ErrMissingField)
	}
	if !isSecretRef(cfg.HCloudTokenRef) {
		return fmt.Errorf("%s.hetzner.hcloud_token_ref: %w", prefix, ErrPlaintextSecret)
	}
	return nil
}

func isSecretRef(v string) bool {
	return strings.HasPrefix(v, "env://") || strings.HasPrefix(v, "secret://")
}

// findTODO walks fleet's fields looking for a literal "TODO" string
// value anywhere, so any field discover --emit-config left as a
// placeholder is caught — not just the two fields we happen to name
// explicitly elsewhere.
func findTODO(v reflect.Value, path string) string {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return ""
		}
		return findTODO(v.Elem(), path)
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			name := t.Field(i).Name
			if found := findTODO(v.Field(i), joinPath(path, name)); found != "" {
				return found
			}
		}
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			if found := findTODO(iter.Value(), joinPath(path, fmt.Sprint(iter.Key()))); found != "" {
				return found
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if found := findTODO(v.Index(i), fmt.Sprintf("%s[%d]", path, i)); found != "" {
				return found
			}
		}
	case reflect.String:
		if v.String() == "TODO" {
			return path
		}
	}
	return ""
}

func joinPath(base, next string) string {
	if base == "" {
		return next
	}
	return base + "." + next
}
