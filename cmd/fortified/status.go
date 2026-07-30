package main

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/danieltamas/fortified/internal/config"
	"github.com/danieltamas/fortified/internal/orchestrate"
	"github.com/danieltamas/fortified/internal/report"
	"github.com/danieltamas/fortified/internal/state"
)

// newStatusCmd reports what's actually in a server's repo: every
// archive present, the latest one's size, the whole repo's
// deduplicated size, and the locally-recorded last-backup/
// last-passing-verify timestamps. Read-only, but still lock-taking —
// same reasoning as audit-keys: it reads remote state a concurrent
// onboard/backup/verify run might be mid-write to. --all gives a
// compact one-row-per-server overview across the whole fleet instead.
func newStatusCmd(jsonOutput *bool) *cobra.Command {
	var (
		configPath string
		wait       bool
		all        bool
		live       bool
		direct     string
	)

	cmd := &cobra.Command{
		Use:   "status [server-id]",
		Short: "Show what's in a server's backup repo, or a one-row-per-server overview with --all",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if direct != "" {
				if all || live {
					return fmt.Errorf("status: --direct cannot be combined with --all or --live")
				}
				if len(args) != 1 {
					return fmt.Errorf("status: --direct requires exactly one server-id")
				}
				return statusDirect(cmd, configPath, args[0], direct, *jsonOutput)
			}
			if all {
				if len(args) != 0 {
					return fmt.Errorf("status: pass either a server-id or --all, not both")
				}
				fleet, err := config.Load(configPath)
				if err != nil {
					return err
				}
				return statusAll(cmd, configPath, fleet, wait, *jsonOutput, live)
			}
			if len(args) != 1 {
				return fmt.Errorf("status: exactly one server-id is required (or --all)")
			}
			return statusOne(cmd, configPath, args[0], wait, *jsonOutput)
		},
	}

	cmd.Flags().StringVar(&configPath, "config", defaultConfigPath(), "path to fleet.yaml")
	cmd.Flags().BoolVar(&wait, "wait", false, "block until the server's lock is free instead of failing fast")
	cmd.Flags().BoolVar(&all, "all", false, "show a compact overview across every configured server instead of one server's full detail")
	cmd.Flags().BoolVar(&live, "live", false, "with --all, contact every server directly instead of reading each one's last-cached status")
	cmd.Flags().StringVar(&direct, "direct", "", "bypass the target entirely and read the Storage Box directly using this private key file — for when the origin server itself is gone; you supply the key, fortified never generates or stores one for this")

	return cmd
}

func statusOne(cmd *cobra.Command, configPath, serverID string, wait, jsonOutput bool) error {
	ctx := cmd.Context()

	stateDir, err := defaultStateDir()
	if err != nil {
		return err
	}
	return state.WithLock(stateDir, serverID, "status", wait, func() error {
		wired, err := buildDeps(ctx, "status", configPath, serverID, false, cmd.OutOrStdout(), cmd.ErrOrStderr())
		if err != nil {
			return err
		}
		defer wired.Cleanup()

		rep, err := orchestrate.Status(ctx, wired.Deps)
		if err != nil {
			return err
		}
		r := report.Reporter{JSON: jsonOutput}
		if err := r.Render(cmd.OutOrStdout(), rep, func() report.Table { return statusTable(rep) }); err != nil {
			return err
		}
		if !jsonOutput {
			printStatusPathLists(cmd.OutOrStdout(), rep)
		}
		return nil
	})
}

// statusAll shows one compact row per configured server — what's been
// backed up, when, and how big, fleet-wide — without each server's
// full per-database/per-path breakdown (status <server-id> still
// gives that level of detail).
//
// By default this reads each server's last-cached status (written by
// Status itself, so any prior backup or status run already populated
// it) straight off local disk — no SSH, no dependency on every server
// being reachable, and instant even for a large fleet. --live instead
// contacts every server directly, same as running status <server-id>
// on each one in turn; one server's failure there is reported but
// never hides the others' rows (same fault-tolerance as backup --all).
func statusAll(cmd *cobra.Command, configPath string, fleet *config.Fleet, wait, jsonOutput, live bool) error {
	ids := make([]string, 0, len(fleet.Servers))
	for id := range fleet.Servers {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	stateDir, err := defaultStateDir()
	if err != nil {
		return err
	}

	// One entry per configured server, in order, whether it succeeded
	// or not — a server that fails to report (unreachable over SSH, a
	// missing secret) must still show up in the overview as failed,
	// not silently vanish from it: the whole point of a fleet-wide
	// view is spotting exactly that kind of gap.
	results := make([]fleetStatusResult, 0, len(ids))
	var failed []string
	for _, id := range ids {
		if !live {
			rep, ok, cacheErr := orchestrate.LoadStatusCache(stateDir, id)
			if cacheErr != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s: FAILED: %v\n", id, cacheErr)
				failed = append(failed, id)
				results = append(results, fleetStatusResult{ServerID: id, Err: cacheErr.Error()})
				continue
			}
			if !ok {
				results = append(results, fleetStatusResult{ServerID: id, NoCache: true})
				continue
			}
			results = append(results, fleetStatusResult{ServerID: id, Report: &rep})
			continue
		}

		var rep orchestrate.StatusReport
		lockErr := state.WithLock(stateDir, id, "status", wait, func() error {
			wired, err := buildDeps(cmd.Context(), "status", configPath, id, false, cmd.OutOrStdout(), cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			defer wired.Cleanup()
			rep, err = orchestrate.Status(cmd.Context(), wired.Deps)
			return err
		})
		if lockErr != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s: FAILED: %v\n", id, lockErr)
			failed = append(failed, id)
			results = append(results, fleetStatusResult{ServerID: id, Err: lockErr.Error()})
			continue
		}
		results = append(results, fleetStatusResult{ServerID: id, Report: &rep})
	}

	r := report.Reporter{JSON: jsonOutput}
	if err := r.Render(cmd.OutOrStdout(), results, func() report.Table { return fleetStatusTable(results) }); err != nil {
		return err
	}
	if !jsonOutput && !live {
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "(showing each server's last-cached status — pass --live to contact every server directly instead)")
	}

	if len(failed) > 0 {
		return fmt.Errorf("status --all: %d/%d servers failed: %v", len(failed), len(ids), failed)
	}
	return nil
}

// fleetStatusResult is one server's --all row: exactly one of Report,
// NoCache, or Err is set. JSON-tagged so --all --json gives every
// server's result, including failures, in one structured document.
type fleetStatusResult struct {
	ServerID string                    `json:"server_id"`
	Report   *orchestrate.StatusReport `json:"report,omitempty"`
	// NoCache means the (non-live) cache read found nothing yet — a
	// server that's never had backup or "status <server-id>" run
	// against it since caching was introduced. Distinct from Err: this
	// isn't a failure, just nothing to show yet.
	NoCache bool   `json:"no_cache,omitempty"`
	Err     string `json:"error,omitempty"`
}

// fleetStatusTable is the --all overview: one row per configured
// server, sorted alphabetically (matching backup --all's own
// ordering) rather than by size or recency — a fleet operator scans
// this looking for a specific server, not a leaderboard. A server
// that failed to report gets its own row (STATUS: FAILED) rather than
// silently dropping out of the table.
func fleetStatusTable(results []fleetStatusResult) report.Table {
	rows := make([][]string, 0, len(results))
	for _, res := range results {
		if res.NoCache {
			rows = append(rows, []string{res.ServerID, "no cache yet", "-", "-", "-", "-", "-"})
			continue
		}
		if res.Report == nil {
			rows = append(rows, []string{res.ServerID, "FAILED", "-", "-", "-", "-", "-"})
			continue
		}
		rep := *res.Report
		if !rep.RepoInitialized {
			rows = append(rows, []string{rep.ServerID, "not onboarded", "-", "-", "-", "-", "-"})
			continue
		}
		latestSize := "-"
		if rep.LatestArchive != nil {
			latestSize = humanBytes(rep.LatestArchive.DeduplicatedSize)
		}
		repoSize := "-"
		if rep.Repo != nil {
			repoSize = humanBytes(rep.Repo.UniqueCompressedSize)
		}
		status := "onboarded"
		if rep.AppendOnlyLifted {
			status = "onboarded (KEY UNRESTRICTED — re-run onboard)"
		}
		rows = append(rows, []string{
			rep.ServerID,
			status,
			formatOptionalTime(rep.LastBackup),
			formatOptionalTime(rep.LastPassingVerify),
			strconv.Itoa(len(rep.Archives)),
			latestSize,
			repoSize,
		})
	}
	if len(rows) == 0 {
		rows = [][]string{{"(no servers configured)", "", "", "", "", "", ""}}
	}
	return report.Table{
		Headers:    []string{"SERVER", "STATUS", "LAST BACKUP", "LAST VERIFY", "ARCHIVES", "LATEST SIZE", "REPO SIZE"},
		Rows:       rows,
		RightAlign: []bool{false, false, false, false, true, true, true},
	}
}

func statusTable(rep orchestrate.StatusReport) report.Table {
	rows := [][]string{
		{"server", rep.ServerID},
		{"repo initialized", strconv.FormatBool(rep.RepoInitialized)},
	}
	if rep.AppendOnlyLifted {
		rows = append(rows, []string{"automation key", "UNRESTRICTED — an interrupted onboard left append-only lifted; re-run onboard to restore it"})
	}
	rows = append(rows,
		[]string{"last backup", formatOptionalTime(rep.LastBackup)},
		[]string{"last passing verify", formatOptionalTime(rep.LastPassingVerify)},
		[]string{"databases backed up", strconv.Itoa(len(rep.Databases)) + " (see list below)"},
		[]string{"archive paths configured", strconv.Itoa(len(rep.ArchivePaths)) + " (see list below)"},
		[]string{"archives", strconv.Itoa(len(rep.Archives))},
	)
	if rep.LatestArchive != nil {
		a := rep.LatestArchive
		rows = append(rows,
			[]string{"latest archive", a.Name},
			[]string{"latest archive end", a.End},
			[]string{"latest archive size", fmt.Sprintf("%s original, %s compressed, %s deduplicated", humanBytes(a.OriginalSize), humanBytes(a.CompressedSize), humanBytes(a.DeduplicatedSize))},
		)
	}
	if rep.Repo != nil {
		rows = append(rows, []string{"repo total size (deduplicated)", humanBytes(rep.Repo.UniqueCompressedSize)})
	}
	return report.Table{Headers: []string{"FIELD", "VALUE"}, Rows: rows}
}

func formatOptionalTime(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.UTC().Format(time.RFC3339)
}

// printStatusPathLists prints per-database sizes and per-path sizes as
// proper tables, largest first — the summary table crams these into
// one cell, which is unreadable once there are more than a couple of
// entries (a real self-hosted fleet easily has 10-30 archive paths,
// and one container can itself hold several distinct databases).
func printStatusPathLists(w io.Writer, rep orchestrate.StatusReport) {
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintf(w, "Databases backed up (%d container(s)), grouped by container, largest first within each:\n", len(rep.Databases))
	_ = report.WriteTable(w, databaseSizeTable(rep.Databases))

	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "Archive paths currently configured, largest first — may not exactly match the latest archive if fleet.yaml changed since:")
	_ = report.WriteTable(w, archivePathSizeTable(rep.ArchivePaths, rep.ArchivePathSizes))
}

type databaseSizeRow struct {
	container string
	kind      string
	database  string
	size      int64
}

// databaseSizeTable groups rows by container (mysql's own databases
// together, then psql's, in whatever order rep.Databases already
// lists them — that's discover/config order, not re-sorted globally),
// sorting only *within* each container's own group by size descending
// — a flat cross-container sort by size interleaves e.g. mysql's
// biggest schema between two of psql's, which reads as noise once
// there's more than one container. A dashed rule (report.SeparatorRow)
// between each group makes the boundary easy to spot at a glance.
func databaseSizeTable(databases []orchestrate.DatabaseSize) report.Table {
	var cells [][]string
	for i, db := range databases {
		if i > 0 {
			cells = append(cells, report.SeparatorRow)
		}
		group := make([]databaseSizeRow, 0, len(db.Databases))
		for name, size := range db.Databases {
			group = append(group, databaseSizeRow{container: db.Container, kind: db.Kind, database: name, size: size})
		}
		sort.Slice(group, func(i, j int) bool { return group[i].size > group[j].size })
		for _, r := range group {
			cells = append(cells, []string{r.container, r.kind, r.database, humanBytes(r.size)})
		}
	}
	if len(cells) == 0 {
		cells = [][]string{{"(none)", "", "", ""}}
	}
	return report.Table{
		Headers:    []string{"CONTAINER", "KIND", "DATABASE", "SIZE"},
		Rows:       cells,
		RightAlign: []bool{false, false, false, true},
	}
}

type archivePathSizeRow struct {
	path      string
	size      int64
	available bool
}

func archivePathSizeTable(paths []string, sizes map[string]int64) report.Table {
	rows := make([]archivePathSizeRow, 0, len(paths))
	for _, p := range paths {
		size, ok := sizes[p]
		rows = append(rows, archivePathSizeRow{path: p, size: size, available: ok})
	}
	// Unavailable sizes sort last, never mixed into the middle of an
	// otherwise size-descending list.
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].available != rows[j].available {
			return rows[i].available
		}
		return rows[i].size > rows[j].size
	})

	cells := make([][]string, 0, len(rows))
	for _, r := range rows {
		sizeStr := "(size unavailable)"
		if r.available {
			sizeStr = humanBytes(r.size)
		}
		cells = append(cells, []string{r.path, sizeStr})
	}
	if len(cells) == 0 {
		cells = [][]string{{"(none)", ""}}
	}
	return report.Table{
		Headers:    []string{"PATH", "SIZE"},
		Rows:       cells,
		RightAlign: []bool{false, true},
	}
}

// humanBytes renders n as a human-readable size (decimal units — KB,
// MB, GB — matching df/borg's own convention closely enough for a
// status summary, not a precise binary measurement).
func humanBytes(n int64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
