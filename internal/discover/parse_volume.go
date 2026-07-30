package discover

import "strings"

// parseVolumeManager reconciles pvs/vgs/lvs, zpool list, and btrfs
// filesystem show into VolumeManagerInfo. A command that isn't
// installed and a command that's installed but lists nothing both
// mean "not in use" here — the tool being present with an empty
// listing is exactly what an unused-but-installed package manager
// looks like.
func parseVolumeManager(cap *Capture) VolumeManagerInfo {
	return VolumeManagerInfo{
		HasLVM:   hasListing(cap, cmdPVs) || hasListing(cap, cmdVGs) || hasListing(cap, cmdLVs),
		HasZFS:   hasListing(cap, cmdZpoolList),
		HasBtrfs: hasListing(cap, cmdBtrfsFilesystem),
	}
}

// hasListing reports whether a command produced real, non-empty
// output — as opposed to being absent or reporting nothing.
func hasListing(cap *Capture, key commandKey) bool {
	r, ok := cap.get(key)
	if !ok || commandMissing(r) {
		return false
	}
	return strings.TrimSpace(r.Stdout) != ""
}

// parseRAID reads /proc/mdstat. RAID is informational only (SKILL.md:
// RAID is not a backup) — Present just says software RAID exists.
func parseRAID(cap *Capture) RAIDInfo {
	r, ok := cap.get(cmdProcMdstat)
	if !ok || commandMissing(r) {
		return RAIDInfo{}
	}

	var arrays []string
	for _, line := range strings.Split(r.Stdout, "\n") {
		if strings.HasPrefix(line, "md") && strings.Contains(line, "active") {
			arrays = append(arrays, strings.TrimSpace(line))
		}
	}
	return RAIDInfo{Present: len(arrays) > 0, Arrays: arrays}
}

// parsePrerequisites reads borg/docker version output.
func parsePrerequisites(cap *Capture) Prerequisites {
	var p Prerequisites
	if r, ok := cap.get(cmdBorgVersion); ok && !commandMissing(r) && strings.TrimSpace(r.Stdout) != "" {
		p.BorgInstalled = true
		p.BorgVersion = strings.TrimSpace(r.Stdout)
	}
	if r, ok := cap.get(cmdDockerVersion); ok && !commandMissing(r) && strings.TrimSpace(r.Stdout) != "" {
		p.DockerInstalled = true
		p.DockerVersion = strings.TrimSpace(r.Stdout)
	}
	return p
}
