package borg

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/danieltamas/fortified/internal/sshx"
)

// nativeMySQLDebianCnf is the standard Debian/Ubuntu package-
// maintainer credential file (root-readable only), used to
// authenticate mysql/mariadb administratively without needing any
// operator-supplied password — verified live against two real
// servers.
const nativeMySQLDebianCnf = "/etc/mysql/debian.cnf"

// nativePostgresContainer and nativeMySQLContainer are synthetic
// manifest/container identifiers for a native (non-Docker) database —
// there is no real container name, but every other layer (manifest,
// verify, status) keys off a container string, so a fixed, predictable
// name fills that role.
const (
	nativePostgresContainer = "postgresql"
	nativeMySQLContainer    = "mysql"
)

// dumpNativePostgres dumps a postgres server installed as a regular OS
// package (a systemd service), not inside Docker — verified live
// against two real servers: peer auth via `su - postgres` never needs
// a password when the caller is already root (the SSH login user for
// every server in the fleet), since the default Debian/Ubuntu
// postgresql package configures pg_hba.conf for local peer auth out of
// the box — discover's own live probe is what confirms this rather
// than assuming it, the same reasoning as the Docker postgres path.
// The redirect (`>`) runs in the outer (root) shell, not inside `su`'s
// own context, so it can write into workspaceDir even though postgres
// itself has no access there — verified live: `su`'s child process
// stdout is inherited by the parent shell exactly like any other
// subprocess.
//
// resolvedAuth, when non-empty (config's auth_ref for the synthetic
// "postgresql" container, resolved by the caller), falls back to a
// TCP/PGPASSWORD connection instead — the only escape hatch for a
// server discover found AuthResolved=false on (peer auth failed, e.g.
// pg_hba.conf hardened to require a password even locally). Without
// this, such a server could never be backed up at all — found by
// cross-vendor review.
func (b Backend) dumpNativePostgres(ctx context.Context, dumpPath, resolvedAuth string, liveOutput io.Writer) (DatabaseManifest, error) {
	var script string
	var env []string
	if resolvedAuth == "" {
		script = fmt.Sprintf(`su - postgres -c pg_dumpall > %s`, shellSingleQuote(dumpPath))
	} else {
		script = fmt.Sprintf(`PGPASSWORD="$PGPASSWORD" pg_dumpall -h 127.0.0.1 -U postgres > %s`, shellSingleQuote(dumpPath))
		env = []string{"PGPASSWORD=" + resolvedAuth}
	}

	var estimatedSize int64
	if liveOutput != nil {
		estimatedSize, _ = b.nativePostgresDatabaseSize(ctx, resolvedAuth)
	}
	stopProgress := b.startDumpProgressPoller(ctx, nativePostgresContainer, dumpPath, estimatedSize, liveOutput)
	_, err := b.Runner.Run(ctx, sshx.Mutating, "sh", []string{"-c", script}, sshx.RunOptions{Env: env, Timeout: sshx.LongRunningTimeout})
	stopProgress()
	if err != nil {
		return DatabaseManifest{}, fmt.Errorf("pg_dumpall (native) for %s: %w", nativePostgresContainer, err)
	}

	sha, err := b.sha256File(ctx, dumpPath)
	if err != nil {
		return DatabaseManifest{}, err
	}
	rowCounts, err := b.nativePostgresRowCounts(ctx, resolvedAuth)
	if err != nil {
		return DatabaseManifest{}, err
	}
	return DatabaseManifest{Container: nativePostgresContainer, SHA256: sha, RowCounts: rowCounts}, nil
}

// nativePostgresQuery runs one query against the native postgres
// server: via `su - postgres` (peer auth) when resolvedAuth is empty —
// the common case, reusing the same query-string helpers
// (postgresUnionCountQuery, etc.) the Docker postgres path already
// uses — or over a TCP loopback connection authenticated with
// PGPASSWORD when resolvedAuth is set, mirroring dumpNativePostgres's
// own fallback.
func (b Backend) nativePostgresQuery(ctx context.Context, resolvedAuth, database, query string) (string, error) {
	if resolvedAuth == "" {
		psqlArgs := "psql"
		if database != "" {
			psqlArgs += " -d " + shellSingleQuote(database)
		}
		psqlArgs += " -tAc " + shellSingleQuote(query)

		result, err := b.Runner.Run(ctx, sshx.ReadOnly, "su", []string{"-", "postgres", "-c", psqlArgs}, sshx.RunOptions{})
		if err != nil {
			return "", err
		}
		return result.Stdout, nil
	}

	dbFlag := ""
	if database != "" {
		dbFlag = " -d " + shellSingleQuote(database)
	}
	script := fmt.Sprintf(`PGPASSWORD="$PGPASSWORD" psql -h 127.0.0.1 -U postgres%s -tAc %s`, dbFlag, shellSingleQuote(query))
	result, err := b.Runner.Run(ctx, sshx.ReadOnly, "sh", []string{"-c", script}, sshx.RunOptions{
		Env: []string{"PGPASSWORD=" + resolvedAuth},
	})
	if err != nil {
		return "", err
	}
	return result.Stdout, nil
}

func (b Backend) nativePostgresDatabases(ctx context.Context, resolvedAuth string) ([]string, error) {
	const listQuery = "SELECT datname FROM pg_database WHERE NOT datistemplate ORDER BY 1"
	out, err := b.nativePostgresQuery(ctx, resolvedAuth, "", listQuery)
	if err != nil {
		return nil, fmt.Errorf("list databases (native postgres): %w", err)
	}
	return splitNonEmptyLines(out), nil
}

func (b Backend) nativePostgresRowCounts(ctx context.Context, resolvedAuth string) (map[string]int64, error) {
	databases, err := b.nativePostgresDatabases(ctx, resolvedAuth)
	if err != nil {
		return nil, err
	}
	const listQuery = "SELECT table_schema || '.' || table_name FROM information_schema.tables " +
		"WHERE table_type='BASE TABLE' AND table_schema NOT IN ('pg_catalog','information_schema') ORDER BY 1"

	counts := make(map[string]int64)
	for _, db := range databases {
		out, err := b.nativePostgresQuery(ctx, resolvedAuth, db, listQuery)
		if err != nil {
			return nil, fmt.Errorf("list tables in %s (native postgres): %w", db, err)
		}
		tables := splitNonEmptyLines(out)
		if len(tables) == 0 {
			continue
		}
		countOut, err := b.nativePostgresQuery(ctx, resolvedAuth, db, postgresUnionCountQuery(tables))
		if err != nil {
			return nil, fmt.Errorf("count rows in %s (native postgres): %w", db, err)
		}
		dbCounts, err := parseCountLines(nativePostgresContainer, countOut)
		if err != nil {
			return nil, err
		}
		for table, n := range dbCounts {
			counts[db+"."+table] = n
		}
	}
	return counts, nil
}

// nativePostgresDatabaseSize is postgresDatabaseSize for the native
// server: table data per database, never pg_database_size's on-disk
// total.
func (b Backend) nativePostgresDatabaseSize(ctx context.Context, resolvedAuth string) (int64, error) {
	databases, err := b.nativePostgresDatabases(ctx, resolvedAuth)
	if err != nil {
		return 0, fmt.Errorf("size of %s (native postgres): %w", nativePostgresContainer, err)
	}
	var total int64
	for _, db := range databases {
		out, err := b.nativePostgresQuery(ctx, resolvedAuth, db, postgresTableDataSizeQuery)
		if err != nil {
			return 0, fmt.Errorf("size of %s (native postgres) database %s: %w", nativePostgresContainer, db, err)
		}
		size, err := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("size of %s (native postgres) database %s: %w", nativePostgresContainer, db, err)
		}
		total += size
	}
	return total, nil
}

// NativePostgresDatabaseSizes returns every real database's own size
// on the native postgres server, name -> size in bytes — the native
// equivalent of PostgresDatabaseSizes, used by `fortified status`.
func (b Backend) NativePostgresDatabaseSizes(ctx context.Context, resolvedAuth string) (map[string]int64, error) {
	const query = "SELECT datname, pg_database_size(datname) FROM pg_database WHERE NOT datistemplate ORDER BY datname"
	out, err := b.nativePostgresQuery(ctx, resolvedAuth, "", query)
	if err != nil {
		return nil, fmt.Errorf("database sizes for %s (native postgres): %w", nativePostgresContainer, err)
	}
	sizes := make(map[string]int64)
	for _, line := range splitNonEmptyLines(out) {
		name, sizeStr, ok := strings.Cut(line, "|")
		if !ok {
			continue
		}
		size, err := strconv.ParseInt(strings.TrimSpace(sizeStr), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("database sizes for %s (native postgres): parse size for %s: %w", nativePostgresContainer, name, err)
		}
		sizes[name] = size
	}
	return sizes, nil
}

// dumpNativeMySQL dumps a mysql/mariadb server installed as a regular
// OS package, authenticating via the standard Debian/Ubuntu
// maintenance credential file rather than any operator-supplied
// password — verified live against two real servers. --defaults-file
// is a plain path, not a secret, so (unlike MYSQL_PWD) it travels
// safely as an ordinary argv word with no env/sh -c indirection
// needed.
//
// resolvedAuth, when non-empty, falls back to a TCP/MYSQL_PWD
// connection instead of the debian.cnf credential — the escape hatch
// for a server discover found AuthResolved=false on (no readable
// debian.cnf, e.g. a non-Debian distro or a hardened environment),
// mirroring dumpNativePostgres's own fallback. Found by cross-vendor
// review: without this, such a server could never be backed up.
func (b Backend) dumpNativeMySQL(ctx context.Context, dumpPath, resolvedAuth string, liveOutput io.Writer) (DatabaseManifest, error) {
	var script string
	var env []string
	if resolvedAuth == "" {
		script = fmt.Sprintf("mysqldump --defaults-file=%s --all-databases --single-transaction > %s", nativeMySQLDebianCnf, shellSingleQuote(dumpPath))
	} else {
		script = fmt.Sprintf(`MYSQL_PWD="$MYSQL_PWD" mysqldump -h 127.0.0.1 -u root --all-databases --single-transaction > %s`, shellSingleQuote(dumpPath))
		env = []string{"MYSQL_PWD=" + resolvedAuth}
	}

	var estimatedSize int64
	if liveOutput != nil {
		estimatedSize, _ = b.nativeMySQLDatabaseSize(ctx, resolvedAuth)
	}
	stopProgress := b.startDumpProgressPoller(ctx, nativeMySQLContainer, dumpPath, estimatedSize, liveOutput)
	_, err := b.Runner.Run(ctx, sshx.Mutating, "sh", []string{"-c", script}, sshx.RunOptions{Env: env, Timeout: sshx.LongRunningTimeout})
	stopProgress()
	if err != nil {
		return DatabaseManifest{}, fmt.Errorf("mysqldump (native) for %s: %w", nativeMySQLContainer, err)
	}

	sha, err := b.sha256File(ctx, dumpPath)
	if err != nil {
		return DatabaseManifest{}, err
	}
	rowCounts, err := b.nativeMySQLRowCounts(ctx, resolvedAuth)
	if err != nil {
		return DatabaseManifest{}, err
	}
	return DatabaseManifest{Container: nativeMySQLContainer, SHA256: sha, RowCounts: rowCounts}, nil
}

func (b Backend) nativeMySQLQuery(ctx context.Context, resolvedAuth, query string) (string, error) {
	if resolvedAuth == "" {
		args := []string{"--defaults-file=" + nativeMySQLDebianCnf, "-N", "-B", "-e", query}
		result, err := b.Runner.Run(ctx, sshx.ReadOnly, "mysql", args, sshx.RunOptions{})
		if err != nil {
			return "", err
		}
		return result.Stdout, nil
	}

	script := fmt.Sprintf(`MYSQL_PWD="$MYSQL_PWD" mysql -N -B -h 127.0.0.1 -u root -e %s`, shellSingleQuote(query))
	result, err := b.Runner.Run(ctx, sshx.ReadOnly, "sh", []string{"-c", script}, sshx.RunOptions{
		Env: []string{"MYSQL_PWD=" + resolvedAuth},
	})
	if err != nil {
		return "", err
	}
	return result.Stdout, nil
}

func (b Backend) nativeMySQLRowCounts(ctx context.Context, resolvedAuth string) (map[string]int64, error) {
	const listQuery = "SELECT concat(table_schema,'.',table_name) FROM information_schema.tables " +
		"WHERE table_type='BASE TABLE' AND table_schema NOT IN ('mysql','information_schema','performance_schema','sys') ORDER BY 1"
	listOut, err := b.nativeMySQLQuery(ctx, resolvedAuth, listQuery)
	if err != nil {
		return nil, fmt.Errorf("list tables (native mysql): %w", err)
	}
	tables := splitNonEmptyLines(listOut)
	if len(tables) == 0 {
		return map[string]int64{}, nil
	}

	countOut, err := b.nativeMySQLQuery(ctx, resolvedAuth, mariaDBUnionCountQuery(tables))
	if err != nil {
		return nil, fmt.Errorf("count rows (native mysql): %w", err)
	}
	return parseCountLines(nativeMySQLContainer, countOut)
}

func (b Backend) nativeMySQLDatabaseSize(ctx context.Context, resolvedAuth string) (int64, error) {
	out, err := b.nativeMySQLQuery(ctx, resolvedAuth, mariaDBTableDataSizeQuery)
	if err != nil {
		return 0, fmt.Errorf("size of %s (native mysql): %w", nativeMySQLContainer, err)
	}
	return strconv.ParseInt(strings.TrimSpace(out), 10, 64)
}

// NativeMySQLSchemaSizes returns every real schema's own size on the
// native mysql/mariadb server (MariaDB's built-in system schemas
// excluded), name -> size in bytes — the native equivalent of
// MariaDBSchemaSizes, used by `fortified status`.
func (b Backend) NativeMySQLSchemaSizes(ctx context.Context, resolvedAuth string) (map[string]int64, error) {
	const query = "SELECT table_schema, sum(data_length+index_length) FROM information_schema.tables GROUP BY table_schema ORDER BY table_schema"
	out, err := b.nativeMySQLQuery(ctx, resolvedAuth, query)
	if err != nil {
		return nil, fmt.Errorf("schema sizes for %s (native mysql): %w", nativeMySQLContainer, err)
	}
	sizes := make(map[string]int64)
	for _, line := range splitNonEmptyLines(out) {
		name, sizeStr, ok := strings.Cut(line, "\t")
		if !ok || mariaDBSystemSchemas[name] {
			continue
		}
		size, err := strconv.ParseInt(strings.TrimSpace(sizeStr), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("schema sizes for %s (native mysql): parse size for %s: %w", nativeMySQLContainer, name, err)
		}
		sizes[name] = size
	}
	return sizes, nil
}
