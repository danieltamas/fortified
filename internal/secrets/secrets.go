// Package secrets resolves secret references to their values at
// runtime, never persisting or logging them. env://VAR always works
// with no external dependency; secret://path/name shells out to the
// Infisical CLI (SPEC.md §1's env-var fallback requirement).
package secrets

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/danieltamas/fortified/internal/sshx"
)

// ErrEnvVarNotSet distinguishes an "env://VAR" reference whose VAR is
// cleanly unset from any other resolution failure (a malformed ref, an
// Infisical CLI error) — callers that want to react specifically to
// "nothing here yet" (e.g. onboard offering to generate a passphrase)
// must not paper over a different kind of failure the same way.
var ErrEnvVarNotSet = errors.New("secrets: environment variable not set")

// GeneratePassphrase returns a new, strong, random passphrase — 256
// bits of entropy, URL-safe base64 so the result is plain shell-safe
// text (no characters needing quoting in an `export VAR=...` line).
func GeneratePassphrase() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("secrets: generate passphrase: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Resolver resolves secret references. It relies on the Infisical
// CLI's own already-configured project/auth context (a
// .infisical.json + `infisical login`, or INFISICAL_TOKEN in the
// control host's ambient environment) — fortified does not manage
// Infisical project/environment selection itself.
type Resolver struct {
	Runner sshx.Runner
}

// Resolve returns ref's value. ref must be "env://VAR" or
// "secret://path/.../name". The returned value must never be logged,
// echoed into state, or included in any error message — callers are
// responsible for that once they have it.
func (r Resolver) Resolve(ctx context.Context, ref string) (string, error) {
	switch {
	case strings.HasPrefix(ref, "env://"):
		return r.resolveEnv(ref)
	case strings.HasPrefix(ref, "secret://"):
		return r.resolveInfisical(ctx, ref)
	default:
		return "", fmt.Errorf("secrets: %q is not a valid reference (want env:// or secret://)", ref)
	}
}

func (r Resolver) resolveEnv(ref string) (string, error) {
	name := strings.TrimPrefix(ref, "env://")
	val, ok := os.LookupEnv(name)
	if !ok {
		return "", fmt.Errorf("%w: %s (referenced as %s)", ErrEnvVarNotSet, name, ref)
	}
	return val, nil
}

func (r Resolver) resolveInfisical(ctx context.Context, ref string) (string, error) {
	rest := strings.TrimPrefix(ref, "secret://")
	segments := strings.Split(rest, "/")
	if len(segments) < 2 {
		return "", fmt.Errorf("secrets: %q needs a path and a name (want secret://path/.../name)", ref)
	}
	name := segments[len(segments)-1]
	path := "/" + strings.Join(segments[:len(segments)-1], "/")

	result, err := r.Runner.Run(ctx, sshx.ReadOnly, "infisical",
		[]string{"secrets", "get", name, "--plain", "--path", path},
		sshx.RunOptions{})
	if err != nil {
		return "", fmt.Errorf("secrets: resolve %s: %w", ref, err)
	}
	return strings.TrimRight(result.Stdout, "\n"), nil
}
