package borg

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/danieltamas/fortified/internal/discover"
	"github.com/danieltamas/fortified/internal/sshx"
)

// FreeSpacePreflight fails before any dump runs if the target lacks
// enough free space (SPEC.md §4). Required space is
// lastRunTotalDumpSize × 1.5, or, when there's no prior run
// (lastRunTotalDumpSize == 0), the sum of each database's
// engine-reported size — conservative, since dumps compress.
// resolvedAuth maps container name to an already-resolved credential
// for databases discover couldn't auto-resolve auth for (config's
// auth_ref, resolved by the caller via internal/secrets — SPEC.md §3);
// a database absent from this map falls back to reading its own
// container env (the AuthResolved=true case).
func (b Backend) FreeSpacePreflight(ctx context.Context, workspaceDir string, databases []discover.DatabaseInstance, resolvedAuth map[string]string, lastRunTotalDumpSize int64) error {
	var required int64
	if lastRunTotalDumpSize > 0 {
		required = int64(float64(lastRunTotalDumpSize) * 1.5)
	} else {
		var err error
		required, err = b.estimateDatabaseSizes(ctx, databases, resolvedAuth)
		if err != nil {
			return fmt.Errorf("borg: estimate database sizes: %w", err)
		}
	}

	avail, err := b.availableSpace(ctx, filepath.Dir(workspaceDir))
	if err != nil {
		return fmt.Errorf("borg: check free space: %w", err)
	}
	if avail < required {
		return fmt.Errorf("borg: insufficient free space for staging at %s: need at least %d bytes, have %d", workspaceDir, required, avail)
	}
	return nil
}

func (b Backend) availableSpace(ctx context.Context, dir string) (int64, error) {
	result, err := b.Runner.Run(ctx, sshx.ReadOnly, "df", []string{"-B1", "--output=avail", dir}, sshx.RunOptions{})
	if err != nil {
		return 0, fmt.Errorf("df %s: %w", dir, err)
	}
	lines := splitNonEmptyLines(result.Stdout)
	if len(lines) < 2 {
		return 0, fmt.Errorf("unexpected df output for %s: %q", dir, result.Stdout)
	}
	avail, err := strconv.ParseInt(lines[len(lines)-1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse df output for %s: %w", dir, err)
	}
	return avail, nil
}

func (b Backend) estimateDatabaseSizes(ctx context.Context, databases []discover.DatabaseInstance, resolvedAuth map[string]string) (int64, error) {
	var total int64
	for _, db := range databases {
		var size int64
		var err error
		switch {
		case db.DumpStrategy == discover.DumpStrategyNative && db.Kind == "postgres":
			size, err = b.nativePostgresDatabaseSize(ctx, resolvedAuth[db.Container])
		case db.DumpStrategy == discover.DumpStrategyNative && db.Kind == "mariadb":
			size, err = b.nativeMySQLDatabaseSize(ctx, resolvedAuth[db.Container])
		case db.Kind == "postgres":
			size, err = b.postgresDatabaseSize(ctx, db.Container, resolvedAuth[db.Container], db.Username)
		case db.Kind == "mariadb":
			size, err = b.mariaDBDatabaseSize(ctx, db.Container, resolvedAuth[db.Container])
		case db.Kind == "cockroachdb":
			size, err = b.cockroachDatabaseSize(ctx, db.Container)
		default:
			err = fmt.Errorf("unsupported database kind %q for %s", db.Kind, db.Container)
		}
		if err != nil {
			return 0, err
		}
		total += size
	}
	return total, nil
}

func (b Backend) postgresDatabaseSize(ctx context.Context, container, resolvedAuth, username string) (int64, error) {
	const query = "SELECT coalesce(sum(pg_database_size(datname)),0) FROM pg_database"
	out, err := b.postgresQuery(ctx, container, resolvedAuth, username, "", query)
	if err != nil {
		return 0, fmt.Errorf("size of %s: %w", container, err)
	}
	return strconv.ParseInt(strings.TrimSpace(out), 10, 64)
}

func (b Backend) mariaDBDatabaseSize(ctx context.Context, container, resolvedAuth string) (int64, error) {
	password, err := b.mariaDBRootPassword(ctx, container, resolvedAuth)
	if err != nil {
		return 0, fmt.Errorf("resolve auth for %s: %w", container, err)
	}
	const query = "SELECT coalesce(sum(data_length+index_length),0) FROM information_schema.tables"
	out, err := b.mysqlQuery(ctx, container, password, query)
	if err != nil {
		return 0, fmt.Errorf("size of %s: %w", container, err)
	}
	return strconv.ParseInt(strings.TrimSpace(out), 10, 64)
}

// PostgresDatabaseSizes returns every real database's own size within
// container (template databases excluded — they're not user data),
// name -> size in bytes. Used by `fortified status` to show what's
// actually inside a "1 database instance" — a postgres container can
// itself hold several distinct databases.
func (b Backend) PostgresDatabaseSizes(ctx context.Context, container, resolvedAuth, username string) (map[string]int64, error) {
	const query = "SELECT datname, pg_database_size(datname) FROM pg_database WHERE NOT datistemplate ORDER BY datname"
	out, err := b.postgresQuery(ctx, container, resolvedAuth, username, "", query)
	if err != nil {
		return nil, fmt.Errorf("database sizes for %s: %w", container, err)
	}
	sizes := make(map[string]int64)
	for _, line := range splitNonEmptyLines(out) {
		name, sizeStr, ok := strings.Cut(line, "|")
		if !ok {
			continue
		}
		size, err := strconv.ParseInt(strings.TrimSpace(sizeStr), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("database sizes for %s: parse size for %s: %w", container, name, err)
		}
		sizes[name] = size
	}
	return sizes, nil
}

// mariaDBSystemSchemas are always present and never user data — never
// worth showing in a per-schema size breakdown.
var mariaDBSystemSchemas = map[string]bool{
	"information_schema": true, "performance_schema": true, "mysql": true, "sys": true,
}

// MariaDBSchemaSizes returns every real schema's own size within
// container (MariaDB's built-in system schemas excluded), name ->
// size in bytes — same reasoning as PostgresDatabaseSizes: one
// container can hold several distinct application schemas.
func (b Backend) MariaDBSchemaSizes(ctx context.Context, container, resolvedAuth string) (map[string]int64, error) {
	password, err := b.mariaDBRootPassword(ctx, container, resolvedAuth)
	if err != nil {
		return nil, fmt.Errorf("resolve auth for %s: %w", container, err)
	}
	const query = "SELECT table_schema, sum(data_length+index_length) FROM information_schema.tables GROUP BY table_schema ORDER BY table_schema"
	out, err := b.mysqlQuery(ctx, container, password, query)
	if err != nil {
		return nil, fmt.Errorf("schema sizes for %s: %w", container, err)
	}
	sizes := make(map[string]int64)
	for _, line := range splitNonEmptyLines(out) {
		name, sizeStr, ok := strings.Cut(line, "\t")
		if !ok || mariaDBSystemSchemas[name] {
			continue
		}
		size, err := strconv.ParseInt(strings.TrimSpace(sizeStr), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("schema sizes for %s: parse size for %s: %w", container, name, err)
		}
		sizes[name] = size
	}
	return sizes, nil
}
