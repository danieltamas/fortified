package discover

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/danieltamas/fortified/internal/sshx"
)

// dockerInspectEntry is the subset of `docker inspect <container>`
// fields discover's database classification actually needs.
type dockerInspectEntry struct {
	Config struct {
		Image string   `json:"Image"`
		Env   []string `json:"Env"`
	} `json:"Config"`
	Mounts []struct {
		Type        string `json:"Type"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
	} `json:"Mounts"`
	NetworkSettings struct {
		Networks map[string]json.RawMessage `json:"Networks"`
		Ports    map[string]json.RawMessage `json:"Ports"`
	} `json:"NetworkSettings"`
}

// engineDataDirSource returns the host source of the mount that holds
// kind's data directory inside entry, or "" when no mount does. The
// mount may be the directory itself or a parent of it: postgres 18+
// images mount /var/lib/postgresql with PGDATA below it.
func engineDataDirSource(kind string, entry dockerInspectEntry) string {
	var dataDir string
	switch kind {
	case "postgres":
		dataDir = "/var/lib/postgresql/data"
		for _, e := range entry.Config.Env {
			if name, value, found := strings.Cut(e, "="); found && name == "PGDATA" && value != "" {
				dataDir = value
			}
		}
	case "mariadb":
		dataDir = "/var/lib/mysql"
	case "cockroachdb":
		dataDir = "/cockroach/cockroach-data"
	default:
		return ""
	}
	var source, bestDest string
	for _, m := range entry.Mounts {
		dest := strings.TrimSuffix(m.Destination, "/")
		if m.Source == "" || (dataDir != dest && !strings.HasPrefix(dataDir, dest+"/")) {
			continue
		}
		if len(dest) > len(bestDest) {
			source, bestDest = m.Source, dest
		}
	}
	return source
}

// engineKind classifies a container's Kind from its image, or ""
// if it isn't a database engine discover knows how to dump.
func engineKind(image string) string {
	switch {
	case strings.HasPrefix(image, "postgres"):
		return "postgres"
	case strings.HasPrefix(image, "mysql"), strings.HasPrefix(image, "mariadb"):
		return "mariadb"
	case strings.HasPrefix(image, "cockroachdb/cockroach"):
		return "cockroachdb"
	default:
		return ""
	}
}

// requiredAuthEnvVar names the env var that, if present, means backup
// can authenticate to this engine without an operator-supplied
// auth_ref. Only mariadb is checked this way — postgres's own
// docker-exec dumps use peer auth inside the container (`docker exec
// -u postgres <c> pg_dumpall`), which pg_hba.conf may or may not
// actually allow (see postgresPeerAuthWorks's doc comment), so
// postgres is verified with a live probe instead of an env var check.
func requiredAuthEnvVar(kind string) string {
	if kind == "mariadb" {
		return "MYSQL_ROOT_PASSWORD"
	}
	return ""
}

// postgresConfiguredUsername returns the actual postgres superuser
// role/OS-user env declares this container was initialized with —
// see DatabaseInstance.Username's doc comment for why POSTGRES_USER
// can replace "postgres" entirely rather than add a second role.
// Always returns a real username, defaulting to "postgres" when
// POSTGRES_USER is absent or empty.
func postgresConfiguredUsername(env []string) string {
	const prefix = "POSTGRES_USER="
	for _, e := range env {
		if v, ok := strings.CutPrefix(e, prefix); ok {
			if v != "" {
				return v
			}
			break
		}
	}
	return "postgres"
}

// postgresProbeUsername extracts the same custom-or-not signal from a
// raw, not-yet-classified `docker inspect` result — used by inspect.go
// to construct its live auth probe's `-U <role>` before
// classifyDatabases has run at all. Empty means the default
// "postgres" role (no POSTGRES_USER override, or a result that fails
// to parse/is missing — classifyDatabases is what surfaces a
// genuinely missing docker inspect result as a hard "incomplete"
// finding, not this best-effort probe).
func postgresProbeUsername(inspectResult sshx.Result) string {
	var entries []dockerInspectEntry
	if err := json.Unmarshal([]byte(inspectResult.Stdout), &entries); err != nil || len(entries) == 0 {
		return ""
	}
	username := postgresConfiguredUsername(entries[0].Config.Env)
	if username == "postgres" {
		return ""
	}
	return username
}

// postgresPeerAuthWorks reports whether inspect.go's live peer-auth
// probe (postgresAuthProbeKey) actually succeeded for container —
// verified live: a postgres container is not guaranteed to allow
// passwordless local-socket connections just because it's postgres.
// Some deployments configure pg_hba.conf to require a password even
// for local connections, in which case the exact command backup's own
// dump/size-estimation steps run fails with "no password supplied" —
// discovered only after onboarding, not at discover time, before this
// probe existed. A container the probe never ran against (e.g. an
// older Capture fixture, or Inspect skipped it) is treated as
// unresolved — never silently assumed to work.
func postgresPeerAuthWorks(container string, cap *Capture) bool {
	r, ok := cap.get(postgresAuthProbeKey(container))
	return ok && r.ExitCode == 0
}

// cockroachInsecureReachable reports whether inspect.go's live
// reachability probe (cockroachAuthProbeKey) actually succeeded for
// container — fortified only supports CockroachDB clusters started
// with --insecure (verified live against a real cluster); a secure
// cluster requiring client certs isn't supported, and this probe is
// what tells the two apart instead of assuming insecure mode.
func cockroachInsecureReachable(container string, cap *Capture) bool {
	r, ok := cap.get(cockroachAuthProbeKey(container))
	return ok && r.ExitCode == 0
}

// classifyDatabases builds a DatabaseInstance for every container
// whose image discover recognizes as a database engine, using its
// docker inspect entry (Capture key "docker_inspect_<container>").
// Containers a golden test's Capture never inspected are skipped, not
// silently guessed at — the caller decides whether that's incomplete.
func classifyDatabases(containers []Container, cap *Capture) ([]DatabaseInstance, []string, error) {
	var (
		databases []DatabaseInstance
		missing   []string
	)

	for _, c := range containers {
		kind := engineKind(c.Image)
		if kind == "" {
			continue
		}

		r, ok := cap.get(dockerInspectKey(c.Name))
		if !ok || commandMissing(r) {
			missing = append(missing, c.Name)
			continue
		}

		var entries []dockerInspectEntry
		if err := json.Unmarshal([]byte(r.Stdout), &entries); err != nil {
			return nil, nil, fmt.Errorf("discover: parse docker inspect for %s: %w", c.Name, err)
		}
		if len(entries) == 0 {
			missing = append(missing, c.Name)
			continue
		}
		entry := entries[0]

		authResolved := hasEnvVar(entry.Config.Env, requiredAuthEnvVar(kind))
		switch kind {
		case "postgres":
			authResolved = postgresPeerAuthWorks(c.Name, cap)
		case "cockroachdb":
			authResolved = cockroachInsecureReachable(c.Name, cap)
		}

		var dataMounts []string
		for _, m := range entry.Mounts {
			dataMounts = append(dataMounts, m.Source)
		}
		sort.Strings(dataMounts)

		var networks []string
		for name := range entry.NetworkSettings.Networks {
			networks = append(networks, name)
		}
		sort.Strings(networks)

		var ports []string
		for port := range entry.NetworkSettings.Ports {
			ports = append(ports, port)
		}
		sort.Strings(ports)

		var username string
		if kind == "postgres" {
			if actual := postgresConfiguredUsername(entry.Config.Env); actual != "postgres" {
				username = actual
			}
		}

		databases = append(databases, DatabaseInstance{
			Kind:           kind,
			Container:      c.Name,
			Image:          entry.Config.Image,
			Networks:       networks,
			ExposedPorts:   ports,
			DataMountPaths: dataMounts,
			DataDir:        engineDataDirSource(kind, entry),
			DumpStrategy:   DumpStrategyDockerExec,
			AuthResolved:   authResolved,
			Username:       username,
		})
	}

	sort.Slice(databases, func(i, j int) bool { return databases[i].Container < databases[j].Container })
	sort.Strings(missing)
	return databases, missing, nil
}

func hasEnvVar(env []string, name string) bool {
	if name == "" {
		return false
	}
	prefix := name + "="
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			return true
		}
	}
	return false
}
