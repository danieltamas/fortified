package discover

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// dockerPSEntry mirrors the fields `docker ps -a --format '{{json .}}'`
// emits, one JSON object per line (NDJSON).
type dockerPSEntry struct {
	Names  string `json:"Names"`
	Image  string `json:"Image"`
	State  string `json:"State"`
	Ports  string `json:"Ports"`
	Labels string `json:"Labels"`
}

// parseDockerPS parses `docker ps -a` NDJSON output into Containers.
func parseDockerPS(cap *Capture) ([]Container, error) {
	r, ok := cap.get(cmdDockerPS)
	if !ok || commandMissing(r) {
		return nil, nil
	}

	var containers []Container
	for _, line := range strings.Split(strings.TrimSpace(r.Stdout), "\n") {
		if line == "" {
			continue
		}
		var entry dockerPSEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return nil, fmt.Errorf("discover: parse docker ps line %q: %w", line, err)
		}
		containers = append(containers, Container{
			Name:    entry.Names,
			Image:   entry.Image,
			State:   entry.State,
			Ports:   entry.Ports,
			Project: composeProjectLabel(entry.Labels),
		})
	}
	return containers, nil
}

// composeProjectLabel extracts com.docker.compose.project from
// docker's comma-joined Labels string.
func composeProjectLabel(labels string) string {
	for _, kv := range strings.Split(labels, ",") {
		if name, value, found := strings.Cut(kv, "="); found && name == "com.docker.compose.project" {
			return value
		}
	}
	return ""
}

// parseContainerBindMounts extracts every container's bind-mount
// source paths from its already-captured `docker inspect` output
// (Inspect now runs this for every container, not just recognized
// database engines — see inspect.go) — real archive-path candidates
// that a compose-file-directory heuristic alone misses for any
// container started without a nearby compose file (verified live:
// dgraph, redis-stack, telegram-bot-api, and others on a real fleet).
//
// Unlike classifyDatabases, a container with no captured inspect entry
// is silently skipped, not reported as incomplete: these are proposals
// for operator review (archivePaths' own contract), not a correctness-
// critical database classification, so a soft gap here just means one
// fewer suggestion, never a silently-skipped backup.
func parseContainerBindMounts(containers []Container, cap *Capture) []string {
	seen := make(map[string]bool)
	var paths []string
	for _, c := range containers {
		r, ok := cap.get(dockerInspectKey(c.Name))
		if !ok || commandMissing(r) {
			continue
		}
		var entries []dockerInspectEntry
		if err := json.Unmarshal([]byte(r.Stdout), &entries); err != nil || len(entries) == 0 {
			continue
		}
		for _, m := range entries[0].Mounts {
			if m.Type != "bind" || m.Source == "" {
				continue
			}
			// Ephemeral runtime sockets/pipes, never real data worth
			// archiving (e.g. a container bind-mounting a control
			// socket like /var/run/nginx-reload.sock).
			if strings.HasPrefix(m.Source, "/var/run/") || strings.HasPrefix(m.Source, "/run/") {
				continue
			}
			if !seen[m.Source] {
				seen[m.Source] = true
				paths = append(paths, m.Source)
			}
		}
	}
	sort.Strings(paths)
	return paths
}

// parseComposeFiles parses `find ... -iname docker-compose*.yml`
// output into a sorted list of paths.
//
// Verified live against a real server (a WSL2 Ubuntu box): its sshd
// merges the remote find's own stderr diagnostics ("find: '/root':
// Permission denied" — expected and harmless, since the scan walks
// the whole filesystem as a non-root user) into what fortified reads
// back as this command's stdout, corrupting the path list with
// garbage entries that would otherwise end up as literal archive:
// paths. find's own stdout only ever contains real matches for the
// exact glob searched for, so any line not plausibly a docker-compose
// path (case-insensitive .yml/.yaml suffix) is dropped rather than
// trusted — a targeted filter, not a general "does this look like a
// path" heuristic, since the search pattern is known exactly.
func parseComposeFiles(cap *Capture) []string {
	r, ok := cap.get(cmdDockerComposeFiles)
	if !ok || commandMissing(r) {
		return nil
	}
	var files []string
	for _, line := range strings.Split(strings.TrimSpace(r.Stdout), "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if line == "" || (!strings.HasSuffix(lower, ".yml") && !strings.HasSuffix(lower, ".yaml")) {
			continue
		}
		files = append(files, line)
	}
	return files
}
