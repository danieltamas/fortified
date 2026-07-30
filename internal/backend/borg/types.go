// Package borg implements the Backend interface (SPEC.md §3) against
// the borg binary: repo init, archive create/restore, integrity
// check, and prune. Runner determines execution locality — the same
// code works against a local t.TempDir() repo (Layer 3 integration
// tests) or against the target over SSH (production, via sshx.Session
// — SPEC.md §3's execution topology puts borg and the append-only key
// on the target, never the control host).
package borg

// Policy is prune's typed retention policy (PLAN.md §1 default:
// keep-daily=7, keep-weekly=4, keep-monthly=6) — never raw borg flags
// exposed to callers.
type Policy struct {
	KeepDaily   int
	KeepWeekly  int
	KeepMonthly int
}

// ArchiveID identifies one created archive within a repo.
type ArchiveID string

// Manifest is the verification baseline recorded at backup time
// (SPEC.md §4) — it ships inside the archive and is also stored in
// the server's state record; verify's job is proving a restore
// matches it.
type Manifest struct {
	Databases []DatabaseManifest `json:"databases"`
}

// DatabaseManifest is one database's baseline: a SHA-256 of its dump
// file and per-table row counts, queried through the same engine
// connection the dump used.
type DatabaseManifest struct {
	Container string           `json:"container"`
	SHA256    string           `json:"sha256"`
	RowCounts map[string]int64 `json:"row_counts"`
}
