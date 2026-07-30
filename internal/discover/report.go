package discover

// Report is discover's structured output for one server (SPEC.md §3,
// §5) — the operator reviews this before onboard, and onboard refuses
// to proceed past an incomplete one.
type Report struct {
	ServerID            string             `json:"server_id"`
	VolumeManager       VolumeManagerInfo  `json:"volume_manager"`
	RAID                RAIDInfo           `json:"raid"`
	Containers          []Container        `json:"containers"`
	ComposeFiles        []string           `json:"compose_files,omitempty"`
	KnownStatePaths     []string           `json:"known_state_paths,omitempty"`
	ContainerBindMounts []string           `json:"container_bind_mounts,omitempty"`
	Databases           []DatabaseInstance `json:"databases,omitempty"`
	Exposure            []ExposureFinding  `json:"exposure,omitempty"`
	Prerequisites       Prerequisites      `json:"prerequisites"`
	Incomplete          bool               `json:"incomplete"`
	IncompleteReasons   []string           `json:"incomplete_reasons,omitempty"`
}

// VolumeManagerInfo records which volume manager (if any) manages the
// target's disks. NoLiveSnapshot is SPEC.md §5's first mandatory flag:
// when none of these are present, database backups MUST go through
// the engine, never a raw file copy.
type VolumeManagerInfo struct {
	HasLVM   bool `json:"has_lvm"`
	HasZFS   bool `json:"has_zfs"`
	HasBtrfs bool `json:"has_btrfs"`
}

// NoLiveSnapshot is true when no host-level live-snapshot mechanism is
// available.
func (v VolumeManagerInfo) NoLiveSnapshot() bool {
	return !v.HasLVM && !v.HasZFS && !v.HasBtrfs
}

// RAIDInfo records mdadm software RAID presence. RAID is never a
// backup (SKILL.md) — this is informational, not a safety signal.
type RAIDInfo struct {
	Present bool     `json:"present"`
	Arrays  []string `json:"arrays,omitempty"`
}

// Container is one entry from `docker ps -a`.
type Container struct {
	Name    string `json:"name"`
	Image   string `json:"image"`
	State   string `json:"state"`
	Ports   string `json:"ports,omitempty"`
	Project string `json:"project,omitempty"`
}

// PortBinding is one LISTEN socket from `ss -tlnp`.
type PortBinding struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	Process string `json:"process"`
}

// ExposureFinding is a DB/cache port bound to a non-loopback address —
// SPEC.md §5's second mandatory flag. Severity is "exposed" when
// reconciled against firewall rules and the control host's own egress
// IP shows it's genuinely reachable, or "unverifiable" when the
// control host's own vantage point can't rule out a false positive
// (SPEC.md §5 / SKILL.md Step 0's last bullet — never silently
// downgrade an unverifiable finding to "not exposed").
type ExposureFinding struct {
	Container string `json:"container,omitempty"`
	Address   string `json:"address"`
	Port      int    `json:"port"`
	Process   string `json:"process"`
	Severity  string `json:"severity"`
	Reason    string `json:"reason"`
}

const (
	SeverityExposed      = "exposed"
	SeverityUnverifiable = "unverifiable"
)

// Prerequisites records target-side tool presence and versions
// (SPEC.md §3) — onboard refuses to proceed if borg is missing.
type Prerequisites struct {
	BorgInstalled   bool   `json:"borg_installed"`
	BorgVersion     string `json:"borg_version,omitempty"`
	DockerInstalled bool   `json:"docker_installed"`
	DockerVersion   string `json:"docker_version,omitempty"`
}
