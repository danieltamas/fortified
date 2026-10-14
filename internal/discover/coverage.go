package discover

import (
	"context"
	"fmt"
	"sort"

	"github.com/danieltamas/fortified/internal/config"
	"github.com/danieltamas/fortified/internal/sshx"
)

// sshTransportExitCode is ssh's own exit status when the connection
// itself failed, as opposed to the remote command's status.
const sshTransportExitCode = 255

// remoteCommandNotFoundExitCode is the remote shell's status for a
// command that isn't installed. Only that means docker is absent:
// commandMissing's "No such file or directory" text also matches a
// missing docker socket, which leaves docker present but unreadable.
const remoteCommandNotFoundExitCode = 127

// ScanArchiveCandidates re-derives discover's archive proposal
// (archiveCandidates) from a fresh read-only scan of the target —
// only the steps that feed it (container list and inspect, compose
// file search, well-known state paths), not discover's full
// inspection, so a backup can afford to run it every time.
func ScanArchiveCandidates(ctx context.Context, runner sshx.Runner) ([]config.ArchivePath, error) {
	needed := map[commandKey]bool{cmdDockerPS: true, cmdDockerComposeFiles: true, cmdSystemdCustomUnits: true}
	for _, c := range knownStateChecks {
		needed[c.key] = true
	}

	// Per-command failures are expected here (ls of an absent path,
	// find hitting an unreadable directory, docker not installed), the
	// same as in Inspect — but a lost connection, a docker ps that
	// failed for any reason but docker's absence, or a container that
	// couldn't be inspected would silently shrink the candidate list,
	// and a short list reads as "everything is covered". An error with
	// no ordinary remote exit status is never the command's answer: ssh
	// exits 255 when the connection fails, and a client-side timeout or
	// kill reports exit 0 or -1.
	cap := newCapture()
	for _, c := range readOnlyCommands {
		if !needed[c.key] {
			continue
		}
		result, err := runner.Run(ctx, sshx.ReadOnly, c.cmd, c.args, sshx.RunOptions{})
		if err != nil && (result.ExitCode <= 0 || result.ExitCode == sshTransportExitCode) {
			return nil, fmt.Errorf("discover: %s: %w", c.cmd, err)
		}
		if err != nil && c.key == cmdDockerPS && result.ExitCode != remoteCommandNotFoundExitCode {
			return nil, fmt.Errorf("discover: docker ps: %w", err)
		}
		cap.Results[c.key] = result
	}
	containers, err := parseDockerPS(cap)
	if err != nil {
		return nil, err
	}
	for _, c := range containers {
		result, err := runner.Run(ctx, sshx.ReadOnly, "docker", []string{"inspect", c.Name}, sshx.RunOptions{})
		if err != nil {
			return nil, fmt.Errorf("discover: docker inspect %s: %w", c.Name, err)
		}
		cap.Results[dockerInspectKey(c.Name)] = result
	}
	databases, missing, err := classifyDatabases(containers, cap)
	if err != nil {
		return nil, fmt.Errorf("discover: classify databases: %w", err)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("discover: no docker inspect data for %v", missing)
	}

	return archiveCandidates(&Report{
		ComposeFiles:        parseComposeFiles(cap),
		KnownStatePaths:     parseKnownStatePaths(cap),
		Containers:          containers,
		ContainerBindMounts: parseContainerBindMounts(containers, cap),
		Databases:           databases,
	}), nil
}

// UncoveredPaths returns every candidate path that archive doesn't
// cover: a candidate is covered only by a glob-less archive entry
// whose Path equals or contains it, and only if it isn't inside any
// entry's excludes — backup passes every exclude to the one borg
// create run, so an exclude listed under one entry skips that path
// under all of them. A glob entry archives only what its pattern
// matches, so it never vouches for a whole directory.
func UncoveredPaths(candidates, archive []config.ArchivePath) []string {
	var excludes []string
	for _, a := range archive {
		excludes = append(excludes, a.Exclude...)
	}
	var uncovered []string
	for _, c := range candidates {
		covered := false
		for _, a := range archive {
			if a.Glob == "" && underAny(c.Path, []string{a.Path}) && !underAny(c.Path, excludes) {
				covered = true
				break
			}
		}
		if !covered {
			uncovered = append(uncovered, c.Path)
		}
	}
	sort.Strings(uncovered)
	return uncovered
}
