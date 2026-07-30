// Package discover inspects a target server's real layout over SSH —
// filesystem/volume manager, RAID, Docker inventory, and database
// exposure — before any command is allowed to mutate it (SPEC.md §3).
// Parse turns a raw Capture (real SSH output, or a golden-test
// fixture) into a structured Report; Inspect (inspect.go) is what
// actually runs the SSH commands live.
package discover

import (
	"fmt"
	"strings"
)

// requiredCommands must be present in a Capture for Parse to consider
// the report complete. Missing any of them means the finding those
// commands feed can't be trusted — Parse marks the report Incomplete
// rather than silently reporting a zero value as a real finding.
var requiredCommands = []commandKey{
	cmdLsblk, cmdPVs, cmdVGs, cmdLVs, cmdZpoolList, cmdBtrfsFilesystem,
	cmdProcMdstat, cmdDockerPS, cmdDockerComposeFiles, cmdSSTlnp,
	cmdBorgVersion, cmdDockerVersion,
}

// Parse builds a Report from a raw Capture. egressIP is the control
// host's own public IP (see EgressIPFunc), used only for the exposure
// vantage-point check — pass "" if it couldn't be resolved.
func Parse(serverID string, cap *Capture, egressIP string) (*Report, error) {
	report := &Report{
		ServerID:        serverID,
		VolumeManager:   parseVolumeManager(cap),
		RAID:            parseRAID(cap),
		ComposeFiles:    parseComposeFiles(cap),
		KnownStatePaths: parseKnownStatePaths(cap),
		Prerequisites:   parsePrerequisites(cap),
	}

	containers, err := parseDockerPS(cap)
	if err != nil {
		return nil, err
	}
	report.Containers = containers
	report.ContainerBindMounts = parseContainerBindMounts(containers, cap)

	databases, missingInspect, err := classifyDatabases(containers, cap)
	if err != nil {
		return nil, err
	}
	databases = append(databases, classifyNativeDatabases(cap)...)
	report.Databases = databases

	bindings := parsePortBindings(cap)
	firewallText := firewallRuleText(cap)
	report.Exposure = findExposure(bindings, containers, egressIP, firewallText)

	report.IncompleteReasons = missingCommands(cap)
	for _, name := range missingInspect {
		report.IncompleteReasons = append(report.IncompleteReasons,
			fmt.Sprintf("docker inspect for %s was not captured", name))
	}
	report.Incomplete = len(report.IncompleteReasons) > 0

	return report, nil
}

func firewallRuleText(cap *Capture) string {
	var b strings.Builder
	for _, key := range []commandKey{cmdIptablesS, cmdNftRuleset, cmdUfwStatus} {
		if r, ok := cap.get(key); ok {
			b.WriteString(r.Stdout)
			b.WriteString("\n")
		}
	}
	return b.String()
}

func missingCommands(cap *Capture) []string {
	var missing []string
	for _, key := range requiredCommands {
		if _, ok := cap.get(key); !ok {
			missing = append(missing, string(key)+" was not captured")
		}
	}
	return missing
}
