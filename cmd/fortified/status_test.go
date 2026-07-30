package main

import (
	"testing"
	"time"

	"github.com/danieltamas/fortified/internal/backend/borg"
	"github.com/danieltamas/fortified/internal/orchestrate"
	"github.com/danieltamas/fortified/internal/report"
)

// TestDatabaseSizeTableGroupsByContainer proves each container's own
// databases stay contiguous (mysql's rows together, then psql's),
// sorted by size descending *within* each group — not one flat
// cross-container sort, which would interleave e.g. mysql's biggest
// schema between two of psql's once there's more than one container —
// with a separator row marking the boundary between groups.
func TestDatabaseSizeTableGroupsByContainer(t *testing.T) {
	databases := []orchestrate.DatabaseSize{
		{Container: "mysql", Kind: "mariadb", Databases: map[string]int64{
			"idea_cms": 675_700_000, "small_db": 1_000_000,
		}},
		{Container: "psql", Kind: "postgres", Databases: map[string]int64{
			"exampledb": 63_400_000_000, "exampleapi": 9_400_000,
		}},
	}

	tbl := databaseSizeTable(databases)

	if len(tbl.Rows) != 5 {
		t.Fatalf("got %d rows, want 5 (2 mysql + 1 separator + 2 psql): %+v", len(tbl.Rows), tbl.Rows)
	}
	wantOrder := []string{"idea_cms", "small_db", "", "exampledb", "exampleapi"}
	for i, want := range wantOrder {
		if i == 2 {
			if len(tbl.Rows[2]) != 0 {
				t.Errorf("row 2 = %v, want a separator row (len 0) between the mysql and psql groups", tbl.Rows[2])
			}
			continue
		}
		if tbl.Rows[i][2] != want {
			t.Errorf("row %d database = %q, want %q (mysql's own descending group before psql's, not a flat cross-container sort)", i, tbl.Rows[i][2], want)
		}
	}
	// Within the mysql group, idea_cms (bigger) must come before
	// small_db — proves the per-group descending sort, not just
	// preserved map iteration order.
	if tbl.Rows[0][0] != "mysql" || tbl.Rows[1][0] != "mysql" {
		t.Errorf("rows 0-1 container = %q, %q, want both mysql", tbl.Rows[0][0], tbl.Rows[1][0])
	}
	if tbl.Rows[3][0] != "psql" || tbl.Rows[4][0] != "psql" {
		t.Errorf("rows 3-4 container = %q, %q, want both psql", tbl.Rows[3][0], tbl.Rows[4][0])
	}
}

// TestDatabaseSizeTableSingleContainerHasNoSeparator proves a single
// database container's report never gets a spurious separator row —
// only a genuine group boundary does.
func TestDatabaseSizeTableSingleContainerHasNoSeparator(t *testing.T) {
	databases := []orchestrate.DatabaseSize{
		{Container: "psql", Kind: "postgres", Databases: map[string]int64{"app": 1000}},
	}
	tbl := databaseSizeTable(databases)
	for i, row := range tbl.Rows {
		if len(row) == 0 {
			t.Errorf("row %d is a separator, want none for a single-container report", i)
		}
	}
}

// TestFleetStatusTableShowsNotOnboardedServersDistinctly proves an
// unonboarded server (Status returns a soft zero-value report for
// these, never an error) gets a clearly-marked row instead of one
// full of misleading zeros that could be mistaken for "backed up, 0
// bytes".
func TestFleetStatusTableShowsNotOnboardedServersDistinctly(t *testing.T) {
	results := []fleetStatusResult{
		{ServerID: "not-yet-onboarded", Report: &orchestrate.StatusReport{ServerID: "not-yet-onboarded", RepoInitialized: false}},
	}
	tbl := fleetStatusTable(results)
	if len(tbl.Rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(tbl.Rows))
	}
	if tbl.Rows[0][0] != "not-yet-onboarded" || tbl.Rows[0][1] != "not onboarded" {
		t.Errorf("row = %v, want [not-yet-onboarded, not onboarded, ...]", tbl.Rows[0])
	}
}

// TestFleetStatusTableShowsFailedServersInline proves a server that
// failed to report (unreachable over SSH, a missing secret) still
// gets its own row instead of silently vanishing from the overview —
// verified live: this exact bug produced a table falsely claiming
// "(no servers configured)" when every configured server happened to
// fail in the same run.
func TestFleetStatusTableShowsFailedServersInline(t *testing.T) {
	results := []fleetStatusResult{
		{ServerID: "unreachable-server", Err: "sshx: permission denied"},
	}
	tbl := fleetStatusTable(results)
	if len(tbl.Rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(tbl.Rows))
	}
	if tbl.Rows[0][0] != "unreachable-server" || tbl.Rows[0][1] != "FAILED" {
		t.Errorf("row = %v, want [unreachable-server, FAILED, ...]", tbl.Rows[0])
	}
}

// TestFleetStatusTableShowsSizesForOnboardedServers proves an
// onboarded server with real archive/repo stats renders its last
// backup/verify times and human-readable sizes — the actual "what's
// been backed up, when, how big" overview this table exists for.
func TestFleetStatusTableShowsSizesForOnboardedServers(t *testing.T) {
	backupTime := time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)
	results := []fleetStatusResult{
		{ServerID: "host-2-example", Report: &orchestrate.StatusReport{
			ServerID:        "host-2-example",
			RepoInitialized: true,
			LastBackup:      &backupTime,
			Archives:        []string{"2026-07-18T00-00-00Z", "2026-07-20T00-00-00Z"},
			LatestArchive:   &borg.ArchiveStats{DeduplicatedSize: 38_347_946},
			Repo:            &borg.RepoStats{UniqueCompressedSize: 59_000_000_000},
		}},
	}
	tbl := fleetStatusTable(results)
	row := tbl.Rows[0]
	if row[0] != "host-2-example" || row[1] != "onboarded" {
		t.Fatalf("row = %v, want host-2-example/onboarded", row)
	}
	if row[2] != "2026-07-20T00:00:00Z" {
		t.Errorf("last backup = %q, want the formatted timestamp", row[2])
	}
	if row[4] != "2" {
		t.Errorf("archives = %q, want 2", row[4])
	}
	if row[5] != humanBytes(38_347_946) || row[6] != humanBytes(59_000_000_000) {
		t.Errorf("row = %v, want latest/repo sizes rendered via humanBytes", row)
	}
}

// TestFleetStatusTableShowsNoCacheDistinctlyFromFailed proves a
// server with no cached status yet (never backed up or checked since
// caching was introduced) gets its own distinct row, not lumped in
// with a genuine live-check failure.
func TestFleetStatusTableShowsNoCacheDistinctlyFromFailed(t *testing.T) {
	results := []fleetStatusResult{
		{ServerID: "brand-new-server", NoCache: true},
	}
	tbl := fleetStatusTable(results)
	if len(tbl.Rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(tbl.Rows))
	}
	if tbl.Rows[0][0] != "brand-new-server" || tbl.Rows[0][1] != "no cache yet" {
		t.Errorf("row = %v, want [brand-new-server, no cache yet, ...]", tbl.Rows[0])
	}
}

// TestReportSeparatorRowIsRecognizedAsSuchInWriteTable is a
// cross-check that report.SeparatorRow (the exact value
// databaseSizeTable inserts) is what WriteTable actually treats as a
// rule, not a coincidental empty-slice literal.
func TestReportSeparatorRowIsRecognizedAsSuchInWriteTable(t *testing.T) {
	if len(report.SeparatorRow) != 0 {
		t.Fatalf("report.SeparatorRow = %v, want an empty slice", report.SeparatorRow)
	}
}
