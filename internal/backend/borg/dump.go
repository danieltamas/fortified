package borg

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/danieltamas/fortified/internal/discover"
	"github.com/danieltamas/fortified/internal/sshx"
)

// dumpDatabase dumps db into workspaceDir and returns its manifest
// entry (SHA-256 + per-table row counts). It consumes db's recipe
// verbatim — no re-deriving a dump command from db.Container's name —
// per SPEC.md §3. resolvedAuth is the container's already-resolved
// credential when discover couldn't auto-resolve one itself (config's
// auth_ref, resolved by the caller); empty falls back to reading the
// container's own env. liveOutput, if non-nil, receives a live
// self-overwriting progress line while the dump itself runs (pg_dumpall/
// mysqldump/cockroach dump report nothing on their own, unlike `borg
// create --progress`) — same nil-safe io.Writer convention as
// CreateArchive's own liveOutput.
func (b Backend) dumpDatabase(ctx context.Context, workspaceDir string, db discover.DatabaseInstance, resolvedAuth string, liveOutput io.Writer) (DatabaseManifest, error) {
	dumpPath := filepath.Join(workspaceDir, db.Container+".sql")

	switch db.DumpStrategy {
	case discover.DumpStrategyDockerExec:
		switch db.Kind {
		case "postgres":
			return b.dumpPostgres(ctx, db.Container, dumpPath, resolvedAuth, db.Username, liveOutput)
		case "mariadb":
			return b.dumpMariaDB(ctx, db.Container, dumpPath, resolvedAuth, liveOutput)
		case "cockroachdb":
			return b.dumpCockroachDB(ctx, db.Container, dumpPath, liveOutput)
		default:
			return DatabaseManifest{}, fmt.Errorf("borg: unsupported database kind %q for %s — discover never should have classified this", db.Kind, db.Container)
		}
	case discover.DumpStrategyNative:
		switch db.Kind {
		case "postgres":
			return b.dumpNativePostgres(ctx, dumpPath, resolvedAuth, liveOutput)
		case "mariadb":
			return b.dumpNativeMySQL(ctx, dumpPath, resolvedAuth, liveOutput)
		default:
			return DatabaseManifest{}, fmt.Errorf("borg: unsupported native database kind %q for %s — discover never should have classified this", db.Kind, db.Container)
		}
	default:
		return DatabaseManifest{}, fmt.Errorf("borg: dump strategy %q for %s is not supported", db.DumpStrategy, db.Container)
	}
}

// postgresUser resolves the actual database role to connect as —
// username empty means the common case (discover found no custom
// POSTGRES_USER), which is "postgres"; a non-empty username is
// discover.DatabaseInstance.Username, the role that image was
// actually initialized with instead. This is the ROLE (psql's -U),
// never the docker-exec OS user: verified live that the official
// postgres image never creates a matching OS/container account for a
// custom POSTGRES_USER — only "postgres" (uid 999) exists to `docker
// exec -u` as, regardless of which role owns the database.
func postgresUser(username string) string {
	if username == "" {
		return "postgres"
	}
	return username
}

// roleFlag returns " -U <username>" (ready to append to a script
// string), or "" when username is empty — the common case, where
// omitting -U keeps pg_dumpall's own invocation text identical to
// before custom-username support existed, since docker exec -u
// postgres already makes "postgres" its implicit default role.
// username is auto-detected from a container's own POSTGRES_USER env
// var with no validation — verified live this was exploitable
// unquoted: a container whose POSTGRES_USER is set to something like
// `a; touch /tmp/pwn; #` would have that text spliced directly into a
// root-context sh -c script at every backup.
func roleFlag(username string) string {
	if username == "" {
		return ""
	}
	return " -U " + shellSingleQuote(username)
}

// dumpPostgres uses peer/socket auth inside the container
// (`docker exec -u postgres`, resolvedAuth == "") whenever discover's
// live probe found that actually works — the common case. Some
// deployments harden pg_hba.conf to require a password even for local
// connections, in which case resolvedAuth carries the operator-
// supplied auth_ref (already resolved by the caller) and the
// connection goes over TCP loopback instead, authenticated via
// PGPASSWORD — verified live: a container configured this way fails
// the peer-auth command outright with "no password supplied", not a
// permissions error, so there's no safe way to detect and fall back to
// this automatically per-call; discover's probe is what decides which
// path a given container uses. username is
// discover.DatabaseInstance.Username: without an explicit -U, psql
// defaults to requesting a role named after the connecting OS user
// ("postgres"), which doesn't exist at all once a custom POSTGRES_USER
// replaced it (verified live: "role postgres does not exist", not an
// auth failure) — -U <actual-role> is what actually connects.
func (b Backend) dumpPostgres(ctx context.Context, container, dumpPath, resolvedAuth, username string, liveOutput io.Writer) (DatabaseManifest, error) {
	user := postgresUser(username)
	var script string
	var env []string
	if resolvedAuth == "" {
		script = fmt.Sprintf("docker exec -u postgres %s pg_dumpall%s > %s", container, roleFlag(username), shellSingleQuote(dumpPath))
	} else {
		// PGPASSWORD travels via opts.Env, never argv or the audit log —
		// and "-e PGPASSWORD" (bare name, no "=value") tells docker to
		// forward it from its own already-inherited environment rather
		// than take a literal value here: docker exec's *own* process
		// argv is visible via `ps` for this dump's entire duration, not
		// just an instant, so `-e PGPASSWORD="$PGPASSWORD"` (the value,
		// shell-expanded before exec) would leak the plaintext password
		// to anyone who ran `ps` while a dump was in flight. Bare -e
		// avoids that: only the variable *name* ever appears in argv.
		script = fmt.Sprintf(`docker exec -e PGPASSWORD %s pg_dumpall -h 127.0.0.1 -U %s > %s`, container, shellSingleQuote(user), shellSingleQuote(dumpPath))
		env = []string{"PGPASSWORD=" + resolvedAuth}
	}
	// Only bother estimating a size when someone's actually watching —
	// same "don't pay for it unwatched" principle as
	// startDumpProgressPoller itself; an estimate that fails to
	// resolve just means the live line omits a percentage, never
	// blocks the dump.
	var estimatedSize int64
	if liveOutput != nil {
		estimatedSize, _ = b.postgresDatabaseSize(ctx, container, resolvedAuth, username)
	}
	stopProgress := b.startDumpProgressPoller(ctx, container, dumpPath, estimatedSize, liveOutput)
	_, err := b.Runner.Run(ctx, sshx.Mutating, "sh", []string{"-c", script}, sshx.RunOptions{Env: env, Timeout: sshx.LongRunningTimeout})
	stopProgress()
	if err != nil {
		return DatabaseManifest{}, fmt.Errorf("pg_dumpall for %s: %w", container, err)
	}

	sha, err := b.sha256File(ctx, dumpPath)
	if err != nil {
		return DatabaseManifest{}, err
	}
	rowCounts, err := b.postgresRowCounts(ctx, container, resolvedAuth, username)
	if err != nil {
		return DatabaseManifest{}, err
	}
	return DatabaseManifest{Container: container, SHA256: sha, RowCounts: rowCounts}, nil
}

func (b Backend) dumpMariaDB(ctx context.Context, container, dumpPath, resolvedAuth string, liveOutput io.Writer) (DatabaseManifest, error) {
	password, err := b.mariaDBRootPassword(ctx, container, resolvedAuth)
	if err != nil {
		return DatabaseManifest{}, fmt.Errorf("resolve auth for %s: %w", container, err)
	}

	// The value travels via opts.Env, which Session.Run delivers through
	// the remote command line's `env` prefix and which audit never logs
	// (SPEC.md §3/§4). "-e MYSQL_PWD" here is deliberately the bare
	// variable name, not "=$MYSQL_PWD": docker exec's *own* process argv
	// stays visible via `ps` for this dump's entire duration (not a
	// brief instant), so a shell-expanded literal value would leak the
	// plaintext root password to anyone running `ps` mid-dump. The bare
	// name tells docker to forward the value from its own already-
	// inherited environment instead, so only the name ever reaches argv.
	//
	// --single-transaction is required, not just a consistency nicety:
	// verified live, plain `mysqldump --all-databases` issues LOCK
	// TABLES by default, and LOCK TABLES on a database containing a
	// view whose DEFINER user no longer exists fails outright ("The
	// user specified as a definer ... does not exist"), aborting the
	// entire dump — not just that one view. --single-transaction dumps
	// from a consistent InnoDB snapshot instead of taking table locks,
	// which both fixes this and is the standard recommended flag for
	// backing up a live server anyway.
	script := fmt.Sprintf(`docker exec -e MYSQL_PWD %s mysqldump --all-databases --single-transaction -u root > %s`, container, shellSingleQuote(dumpPath))
	// Pass the already-resolved password, not resolvedAuth: mariaDBRootPassword
	// short-circuits on a non-empty value, so this never re-resolves it
	// with a second docker inspect. Only bother at all when someone's
	// actually watching, same as the postgres/cockroachdb dumps.
	var estimatedSize int64
	if liveOutput != nil {
		estimatedSize, _ = b.mariaDBDatabaseSize(ctx, container, password)
	}
	stopProgress := b.startDumpProgressPoller(ctx, container, dumpPath, estimatedSize, liveOutput)
	_, err = b.Runner.Run(ctx, sshx.Mutating, "sh", []string{"-c", script}, sshx.RunOptions{
		Env:     []string{"MYSQL_PWD=" + password},
		Timeout: sshx.LongRunningTimeout,
	})
	stopProgress()
	if err != nil {
		return DatabaseManifest{}, fmt.Errorf("mysqldump for %s: %w", container, err)
	}

	sha, err := b.sha256File(ctx, dumpPath)
	if err != nil {
		return DatabaseManifest{}, err
	}
	rowCounts, err := b.mariaDBRowCounts(ctx, container, password)
	if err != nil {
		return DatabaseManifest{}, err
	}
	return DatabaseManifest{Container: container, SHA256: sha, RowCounts: rowCounts}, nil
}

// mariaDBRootPassword returns resolvedAuth directly when non-empty —
// the config-supplied auth_ref, already resolved by the caller via
// internal/secrets for a database discover couldn't auto-resolve auth
// for (SPEC.md §3). Otherwise it re-reads MYSQL_ROOT_PASSWORD live from
// the container's own env via docker inspect, the same source discover
// used to set AuthResolved=true — never persisted anywhere either way
// (AuthResolved is a discover-time signal, not a stored value).
func (b Backend) mariaDBRootPassword(ctx context.Context, container, resolvedAuth string) (string, error) {
	if resolvedAuth != "" {
		return resolvedAuth, nil
	}

	result, err := b.Runner.Run(ctx, sshx.ReadOnly, "docker",
		[]string{"inspect", "-f", "{{json .Config.Env}}", container}, sshx.RunOptions{})
	if err != nil {
		return "", fmt.Errorf("inspect %s: %w", container, err)
	}
	var env []string
	if err := json.Unmarshal([]byte(result.Stdout), &env); err != nil {
		return "", fmt.Errorf("parse docker inspect env for %s: %w", container, err)
	}
	for _, e := range env {
		if name, value, found := strings.Cut(e, "="); found && name == "MYSQL_ROOT_PASSWORD" {
			return value, nil
		}
	}
	return "", fmt.Errorf("MYSQL_ROOT_PASSWORD not found in %s's environment — config must supply auth_ref", container)
}

// MariaDBRootPassword resolves container's MariaDB root credential —
// exported so verify can authenticate the same way dump did, e.g. to
// look up the password a throwaway verification container should be
// started with.
func (b Backend) MariaDBRootPassword(ctx context.Context, container, resolvedAuth string) (string, error) {
	return b.mariaDBRootPassword(ctx, container, resolvedAuth)
}

func (b Backend) sha256File(ctx context.Context, path string) (string, error) {
	result, err := b.Runner.Run(ctx, sshx.ReadOnly, "sha256sum", []string{path}, sshx.RunOptions{Timeout: sshx.LongRunningTimeout})
	if err != nil {
		return "", fmt.Errorf("sha256sum %s: %w", path, err)
	}
	fields := strings.Fields(result.Stdout)
	if len(fields) == 0 {
		return "", fmt.Errorf("sha256sum %s produced no output", path)
	}
	return fields[0], nil
}

// SHA256File computes path's SHA-256 — exported so verify can compare
// a restored dump file against the manifest's recorded baseline,
// exactly as CreateArchive computed it in the first place.
func (b Backend) SHA256File(ctx context.Context, path string) (string, error) {
	return b.sha256File(ctx, path)
}

// RowCounts counts container's tables for whichever engine kind names
// — the same dispatch dumpDatabase uses, exported so verify can
// re-derive row counts from a throwaway container loaded with a
// restored dump, to compare against the manifest recorded at backup
// time.
func (b Backend) RowCounts(ctx context.Context, kind, container, resolvedAuth string) (map[string]int64, error) {
	switch kind {
	case "postgres":
		// Always the default "postgres" role: every caller of this
		// exported dispatcher targets a throwaway verify container
		// (see verifyPostgres), which is always started fresh without
		// a custom POSTGRES_USER, regardless of what the original
		// production container used — the restored dump's own
		// CREATE ROLE statements recreate any custom role as data, not
		// as the container's bootstrap superuser.
		return b.postgresRowCounts(ctx, container, resolvedAuth, "")
	case "mariadb":
		return b.mariaDBRowCounts(ctx, container, resolvedAuth)
	case "cockroachdb":
		databases, err := b.cockroachDatabases(ctx, container)
		if err != nil {
			return nil, fmt.Errorf("list databases in %s: %w", container, err)
		}
		return b.cockroachRowCounts(ctx, container, databases)
	default:
		return nil, fmt.Errorf("borg: unsupported database kind %q for %s", kind, container)
	}
}

// postgresRowCounts counts every table in every real (non-template)
// database in the cluster, keyed "<database>.<schema>.<table>".
// pg_dumpall (dumpPostgres) dumps the whole cluster, not just one
// database — unlike MySQL/MariaDB, Postgres has no catalog view that
// spans databases from a single connection (information_schema.tables
// only ever shows the current connection's own database), so counting
// via a single default connection would silently omit every table in
// any database other than the one psql happens to default-connect to.
// A real app almost never lives in that default "postgres" database,
// so this must enumerate and connect to each one in turn.
func (b Backend) postgresRowCounts(ctx context.Context, container, resolvedAuth, username string) (map[string]int64, error) {
	databases, err := b.postgresDatabases(ctx, container, resolvedAuth, username)
	if err != nil {
		return nil, err
	}
	counts := make(map[string]int64)
	for _, db := range databases {
		dbCounts, err := b.postgresRowCountsInDatabase(ctx, container, db, resolvedAuth, username)
		if err != nil {
			return nil, err
		}
		for table, n := range dbCounts {
			counts[db+"."+table] = n
		}
	}
	return counts, nil
}

// postgresDatabases lists every database pg_dumpall would dump — every
// entry in pg_database except the two built-in, always-empty templates.
func (b Backend) postgresDatabases(ctx context.Context, container, resolvedAuth, username string) ([]string, error) {
	const listQuery = "SELECT datname FROM pg_database WHERE NOT datistemplate ORDER BY 1"
	out, err := b.postgresQuery(ctx, container, resolvedAuth, username, "", listQuery)
	if err != nil {
		return nil, fmt.Errorf("list databases in %s: %w", container, err)
	}
	return splitNonEmptyLines(out), nil
}

// postgresRowCountsInDatabase lists one database's tables, then counts
// all of them in a single combined query (one docker-exec round-trip
// either way, not one-plus-N) — a schema with hundreds of tables would
// otherwise spawn a remote process per table on every backup run.
func (b Backend) postgresRowCountsInDatabase(ctx context.Context, container, db, resolvedAuth, username string) (map[string]int64, error) {
	const listQuery = "SELECT table_schema || '.' || table_name FROM information_schema.tables " +
		"WHERE table_type='BASE TABLE' AND table_schema NOT IN ('pg_catalog','information_schema') ORDER BY 1"
	out, err := b.postgresQuery(ctx, container, resolvedAuth, username, db, listQuery)
	if err != nil {
		return nil, fmt.Errorf("list tables in %s/%s: %w", container, db, err)
	}
	tables := splitNonEmptyLines(out)
	if len(tables) == 0 {
		return map[string]int64{}, nil
	}

	countOut, err := b.postgresQuery(ctx, container, resolvedAuth, username, db, postgresUnionCountQuery(tables))
	if err != nil {
		return nil, fmt.Errorf("count rows in %s/%s: %w", container, db, err)
	}
	return parseCountLines(container, countOut)
}

// postgresQuery runs one query against container's postgres server —
// via peer auth inside the container when resolvedAuth is empty (the
// common case, confirmed by discover's live probe), or via a TCP
// loopback connection authenticated with PGPASSWORD when resolvedAuth
// is set (a container whose pg_hba.conf requires a password even for
// local connections). database, if non-empty, connects to that
// database instead of psql's own default. username is
// discover.DatabaseInstance.Username (empty means the default
// "postgres" role/OS-user).
func (b Backend) postgresQuery(ctx context.Context, container, resolvedAuth, username, database, query string) (string, error) {
	user := postgresUser(username)
	if resolvedAuth == "" {
		args := []string{"exec", "-u", "postgres", container, "psql"}
		if username != "" {
			args = append(args, "-U", user)
		}
		if database != "" {
			args = append(args, "-d", database)
		}
		args = append(args, "-tAc", query)
		result, err := b.Runner.Run(ctx, sshx.ReadOnly, "docker", args, sshx.RunOptions{})
		if err != nil {
			return "", err
		}
		return result.Stdout, nil
	}

	// "-e PGPASSWORD" (bare name, no "=value") tells docker to forward
	// the value from its own inherited environment rather than take a
	// literal here — this query's docker exec process is short-lived,
	// but the principle is the same one dumpPostgres's own comment
	// explains at length: only the variable name should ever reach any
	// process's argv, never the value itself.
	dbFlag := ""
	if database != "" {
		dbFlag = " -d " + shellSingleQuote(database)
	}
	script := fmt.Sprintf(`docker exec -e PGPASSWORD %s psql -h 127.0.0.1 -U %s%s -tAc %s`,
		container, shellSingleQuote(user), dbFlag, shellSingleQuote(query))
	result, err := b.Runner.Run(ctx, sshx.ReadOnly, "sh", []string{"-c", script}, sshx.RunOptions{
		Env: []string{"PGPASSWORD=" + resolvedAuth},
	})
	if err != nil {
		return "", err
	}
	return result.Stdout, nil
}

func (b Backend) mariaDBRowCounts(ctx context.Context, container, password string) (map[string]int64, error) {
	const listQuery = "SELECT concat(table_schema,'.',table_name) FROM information_schema.tables " +
		"WHERE table_type='BASE TABLE' AND table_schema NOT IN ('mysql','information_schema','performance_schema','sys') ORDER BY 1"
	listOut, err := b.mysqlQuery(ctx, container, password, listQuery)
	if err != nil {
		return nil, fmt.Errorf("list tables in %s: %w", container, err)
	}
	tables := splitNonEmptyLines(listOut)
	if len(tables) == 0 {
		return map[string]int64{}, nil
	}

	countOut, err := b.mysqlQuery(ctx, container, password, mariaDBUnionCountQuery(tables))
	if err != nil {
		return nil, fmt.Errorf("count rows in %s: %w", container, err)
	}
	return parseCountLines(container, countOut)
}

// postgresUnionCountQuery and mariaDBUnionCountQuery each build one
// query returning "table|count" per line — a single concatenated text
// column, so the result is parsed identically regardless of the CLI's
// own column-separator convention (psql's "|" vs mysql's tab).
func postgresUnionCountQuery(tables []string) string {
	parts := make([]string, len(tables))
	for i, t := range tables {
		parts[i] = fmt.Sprintf("SELECT %s || '|' || count(*)::text FROM %s", sqlStringLiteral(t), pgQuoteQualifiedIdent(t))
	}
	return strings.Join(parts, " UNION ALL ")
}

// pgQuoteQualifiedIdent double-quotes each dot-separated part of a
// "schema.table" identifier. Verified live this matters:
// information_schema.tables preserves a table's real stored case
// (e.g. "_app_gamesTofiles", created via a quoted CREATE TABLE — common
// with ORMs like Prisma), but Postgres's standard unquoted-identifier
// folding lowercases any bare reference to it, so `FROM
// public._app_gamesTofiles` looks for "_app_gamestofiles" instead and
// fails with "relation ... does not exist" even though the table is
// right there. MariaDB's mariaDBUnionCountQuery doesn't need this: it
// has no equivalent unquoted-identifier case-folding rule.
func pgQuoteQualifiedIdent(qualified string) string {
	schema, table, ok := strings.Cut(qualified, ".")
	if !ok {
		return pgQuoteIdent(qualified)
	}
	return pgQuoteIdent(schema) + "." + pgQuoteIdent(table)
}

// pgQuoteIdent double-quotes a single Postgres identifier, escaping
// any embedded double quote by doubling it (the standard SQL rule).
func pgQuoteIdent(ident string) string {
	return `"` + strings.ReplaceAll(ident, `"`, `""`) + `"`
}

func mariaDBUnionCountQuery(tables []string) string {
	parts := make([]string, len(tables))
	for i, t := range tables {
		parts[i] = fmt.Sprintf("SELECT concat(%s, '|', count(*)) FROM %s", sqlStringLiteral(t), mysqlQuoteQualifiedIdent(t))
	}
	return strings.Join(parts, " UNION ALL ")
}

// mysqlQuoteQualifiedIdent backtick-quotes each dot-separated part of
// a "schema.table" identifier — the MySQL/MariaDB equivalent of
// pgQuoteQualifiedIdent. Unlike the postgres path, these table names
// were never adversarially confirmed exploitable, but they come from
// the same kind of live information_schema listing (an operator-
// created table name containing a space or backtick would otherwise
// break this UNION ALL query), so this closes the same class of gap
// found by cross-vendor review.
func mysqlQuoteQualifiedIdent(qualified string) string {
	schema, table, ok := strings.Cut(qualified, ".")
	if !ok {
		return mysqlQuoteIdent(qualified)
	}
	return mysqlQuoteIdent(schema) + "." + mysqlQuoteIdent(table)
}

// mysqlQuoteIdent backtick-quotes a single MySQL/MariaDB identifier,
// escaping any embedded backtick by doubling it (the standard rule).
func mysqlQuoteIdent(ident string) string {
	return "`" + strings.ReplaceAll(ident, "`", "``") + "`"
}

func sqlStringLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func parseCountLines(container, output string) (map[string]int64, error) {
	counts := make(map[string]int64)
	for _, line := range splitNonEmptyLines(output) {
		name, countStr, found := strings.Cut(line, "|")
		if !found {
			return nil, fmt.Errorf("parse row count line %q for %s: unexpected format", line, container)
		}
		n, err := strconv.ParseInt(strings.TrimSpace(countStr), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse row count %q for %s: %w", line, container, err)
		}
		counts[name] = n
	}
	return counts, nil
}

// mysqlQuery runs one query against container's mysql/mariadb server,
// authenticating via bare "-e MYSQL_PWD" (see dumpMariaDB's comment on
// why the literal password must never reach docker's own argv).
func (b Backend) mysqlQuery(ctx context.Context, container, password, query string) (string, error) {
	script := fmt.Sprintf(`docker exec -e MYSQL_PWD %s mysql -N -B -u root -e %s`, container, shellSingleQuote(query))
	result, err := b.Runner.Run(ctx, sshx.ReadOnly, "sh", []string{"-c", script}, sshx.RunOptions{
		Env: []string{"MYSQL_PWD=" + password},
	})
	if err != nil {
		return "", err
	}
	return result.Stdout, nil
}

// shellSingleQuote POSIX single-quotes s for embedding in a shell
// script string this package builds itself (as opposed to
// internal/sshx's shellQuoteIfNeeded, which quotes whole argv words
// for the ssh-argv-rejoining problem — this quotes a query value
// inside an already-constructed script).
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
