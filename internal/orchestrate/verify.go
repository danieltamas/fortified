package orchestrate

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/danieltamas/fortified/internal/backend/borg"
	"github.com/danieltamas/fortified/internal/discover"
	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/state"
)

// verifyScratchDir is where Verify restores the latest archive on the
// target — separate from backup's own workspace dir so a verify run
// can never collide with a concurrently-locked backup (the two are
// mutually exclusive under state's per-server lock anyway, but a
// distinct name makes that true by construction, not just by policy).
//
// workspaceRoot mirrors backupWorkspaceDir's own anchoring (empty
// means the SSH login's own home directory) — found by cross-vendor
// review: restoring the whole archive (which includes every
// database's own dump, potentially the exact reason workspace_dir was
// configured in the first place) into a bare relative path would land
// back under the small disk workspace_dir exists to route around,
// failing verify for the same free-space reason backup no longer
// does.
func verifyScratchDir(serverID, workspaceRoot string) string {
	name := "fortified-verify-scratch-" + serverID
	if workspaceRoot == "" {
		return name
	}
	return strings.TrimSuffix(workspaceRoot, "/") + "/" + name
}

// throwawayContainerName is the disposable database container Verify
// loads a restored dump into — named after the container it's
// verifying so concurrent verifies of different databases (should
// that ever happen) can't collide.
func throwawayContainerName(container string) string {
	return "fortified-verify-" + container
}

// Verify restores the latest archive into a scratch location on the
// target, then proves restorability against the manifest Backup
// recorded: each dump's SHA-256 must match, then each dump is loaded
// into a throwaway container (same image as the source) and per-table
// row counts are compared against the manifest — concrete proof, not
// "extraction didn't error" (SPEC.md §5). A pass is recorded in state
// as the fact that unlocks enable-snapshots.
func Verify(ctx context.Context, d Deps) error {
	st, err := state.Load(d.StateDir, d.ServerID)
	if err != nil {
		return fmt.Errorf("verify: load state: %w", err)
	}
	if !st.Provider.RepoInitialized {
		return fmt.Errorf("verify: %s has not completed onboarding — run onboard first", d.ServerID)
	}
	if st.LastManifest == nil {
		return fmt.Errorf("verify: %s has no recorded backup manifest — run backup first", d.ServerID)
	}

	// GetDestination, never CreateIsolatedDestination — see backup.go's
	// identical comment: only onboard should ever bring a subaccount
	// into existence. Decryption uses the escrow-path passphrase (the
	// same reference Backup used, resolved fresh here) — never a copy
	// that might live on the target, since verifying with that would
	// prove nothing about surviving loss of the target itself
	// (SKILL.md's key custody rule, SPEC.md §5).
	_, repoPath, passphrase, err := confirmDestinationAndPassphrase(ctx, d, st)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}

	var archives []string
	if err := withProgress(d, "listing archives", func() error {
		var err error
		archives, err = d.Backend.ListArchives(ctx, repoPath, passphrase, automationKeyPath)
		return err
	}); err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	if len(archives) == 0 {
		return fmt.Errorf("verify: %s's repo has no archives yet — run backup first", d.ServerID)
	}
	latest := latestArchive(archives)

	// Verify's own checks (SHA-256, throwaway-container row counts,
	// below) only ever read files under workspaceDir — the one
	// directory backup staged every database's dump into. They never
	// touch the archive's other members (config's own raw `archive:`
	// paths — mail, bind mounts, whatever else a server backs up), so
	// restoring the *entire* archive here is pure waste: whole-repo
	// integrity already has its own, cheaper command (`fortified
	// check`'s `borg check`, which verifies chunk integrity over SSH
	// with no local extraction at all). Passing workspaceDir as
	// RestoreArchive's scoping path — the same paths ...string
	// mechanism `restore --db` already uses — extracts only the dumps,
	// so verify's disk footprint on the target scales with dump size,
	// not with however much raw file data the server also archives.
	//
	// Found live: host-2-example's verify ran 55 minutes into a
	// whole-archive `borg extract` before hitting ENOSPC, because its
	// archive's 31GB+ of raw mail/file data dwarfed its two database
	// dumps. Sizing the free-space preflight off just workspaceDir
	// (ArchivePathSize, not ArchiveInfo's whole-archive OriginalSize)
	// makes the ×1.5-buffered check match what extract is now actually
	// about to write.
	workspaceDir := backupWorkspaceDir(d.ServerID, d.Server.WorkspaceDir)
	var dumpsSize int64
	if err := withProgress(d, fmt.Sprintf("reading archive %s dump size", latest), func() error {
		var err error
		dumpsSize, err = d.Backend.ArchivePathSize(ctx, repoPath, borg.ArchiveID(latest), passphrase, automationKeyPath, workspaceDir)
		return err
	}); err != nil {
		return fmt.Errorf("verify: %w", err)
	}

	resolvedAuth, err := resolveAuthRefs(ctx, d)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}

	scratchDir := verifyScratchDir(d.ServerID, d.Server.WorkspaceDir)
	if err := d.Backend.FreeSpacePreflight(ctx, scratchDir, st.Databases, resolvedAuth, dumpsSize); err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	if _, err := d.Target.Run(ctx, sshx.Mutating, "mkdir", []string{"-p", scratchDir}, sshx.RunOptions{}); err != nil {
		return fmt.Errorf("verify: create scratch dir: %w", err)
	}
	defer func() {
		_, _ = d.Target.Run(ctx, sshx.Mutating, "rm", []string{"-rf", scratchDir}, sshx.RunOptions{})
	}()

	if err := withProgress(d, fmt.Sprintf("restoring archive %s", latest), func() error {
		return d.Backend.RestoreArchive(ctx, repoPath, borg.ArchiveID(latest), passphrase, automationKeyPath, scratchDir, workspaceDir)
	}); err != nil {
		return fmt.Errorf("verify: restore %s: %w", latest, err)
	}

	for _, dm := range st.LastManifest.Databases {
		container := dm.Container
		err := withProgress(d, fmt.Sprintf("verifying %s (checksum + row counts via a throwaway container)", container), func() error {
			return verifyDatabase(ctx, d, scratchDir, workspaceDir, dm, st.Databases, resolvedAuth)
		})
		if err != nil {
			return fmt.Errorf("verify: %s: %w", container, err)
		}
	}

	now := time.Now().UTC()
	st.Verify.EverPassed = true
	st.Timestamps.LastPassingVerify = &now
	if err := state.Save(d.StateDir, st); err != nil {
		return fmt.Errorf("verify: save state: %w", err)
	}
	return nil
}

// latestArchive picks the most recent of ListArchives' names —
// Backup names every archive with a UTC timestamp formatted so
// lexicographic order matches chronological order, so "latest" is
// simply the maximum string.
func latestArchive(archives []string) string {
	sorted := append([]string(nil), archives...)
	sort.Strings(sorted)
	return sorted[len(sorted)-1]
}

// verifyDatabase proves one database's restored dump matches its
// recorded baseline: SHA-256 first (cheap, catches most problems
// immediately), then a throwaway container of the same image loaded
// with the dump, with row counts compared per table.
func verifyDatabase(ctx context.Context, d Deps, scratchDir, workspaceDir string, dm state.DatabaseManifest,
	databases []discover.DatabaseInstance, resolvedAuth map[string]string) error {
	dbInstance := findDatabaseInstance(databases, dm.Container)
	if dbInstance == nil {
		return fmt.Errorf("no longer present in the last discover result — was it removed from the target since the last backup?")
	}

	dumpPath := scratchDir + "/" + workspaceDir + "/" + dm.Container + ".sql"
	sha, err := d.Backend.SHA256File(ctx, dumpPath)
	if err != nil {
		return fmt.Errorf("compute sha256 of restored dump: %w", err)
	}
	if sha != dm.SHA256 {
		return fmt.Errorf("restored dump sha256 = %s, manifest baseline = %s — the archive does not match what backup recorded", sha, dm.SHA256)
	}

	switch dbInstance.Kind {
	case "postgres":
		// verifyPostgres already never depends on the original's own
		// auth (its throwaway container sets POSTGRES_HOST_AUTH_METHOD=
		// trust unconditionally, regardless of Docker vs native) — the
		// only thing that had to change for native postgres was giving
		// it a real image, which discover now resolves live.
		return verifyPostgres(ctx, d, dbInstance.Image, dumpPath, dm)
	case "mariadb":
		if dbInstance.DumpStrategy == discover.DumpStrategyNative {
			// A native mariadb has no Docker container to read
			// MYSQL_ROOT_PASSWORD from at all — verifyMariaDB's
			// MariaDBRootPassword call would docker-inspect the
			// synthetic "mysql" container name, which isn't a real
			// container. The throwaway container's own credential
			// doesn't need to match the original (it's discarded right
			// after verify), so this path just generates a fresh one,
			// same as verifyPostgres already does unconditionally.
			return verifyNativeMariaDB(ctx, d, dbInstance.Image, dumpPath, dm)
		}
		return verifyMariaDB(ctx, d, dbInstance.Image, dumpPath, dm, resolvedAuth[dm.Container])
	case "cockroachdb":
		return verifyCockroachDB(ctx, d, dbInstance.Image, dumpPath, dm)
	default:
		return fmt.Errorf("unsupported database kind %q", dbInstance.Kind)
	}
}

func findDatabaseInstance(databases []discover.DatabaseInstance, container string) *discover.DatabaseInstance {
	for i := range databases {
		if databases[i].Container == container {
			return &databases[i]
		}
	}
	return nil
}

func verifyPostgres(ctx context.Context, d Deps, image, dumpPath string, dm state.DatabaseManifest) error {
	name := throwawayContainerName(dm.Container)
	env := []string{"POSTGRES_PASSWORD=fortified-verify", "POSTGRES_HOST_AUTH_METHOD=trust"}
	readyScript := fmt.Sprintf("docker exec -u postgres %s psql -c 'SELECT 1'", name)
	if err := startThrowawayContainer(ctx, d, image, name, env, readyScript); err != nil {
		return err
	}
	defer removeThrowawayContainer(ctx, d, name)

	// -v ON_ERROR_STOP=1: psql's default is to keep going past a failed
	// statement and still exit 0 — without this, a dump that's
	// genuinely incompatible with the throwaway image (or truncated)
	// can silently skip creating some tables while still looking like
	// a clean load, which is exactly the false-pass compareRowCounts
	// is otherwise exposed to below.
	//
	// The dump is piped through a filter dropping the two lines that
	// recreate the "postgres" role itself — found live: pg_dumpall
	// always includes CREATE ROLE postgres (dumping the whole cluster,
	// including built-in roles), but the throwaway container's own
	// bootstrap (POSTGRES_PASSWORD/POSTGRES_HOST_AUTH_METHOD) already
	// created that exact role, so loading it unfiltered fails outright
	// with "role postgres already exists" under ON_ERROR_STOP=1.
	// Verified live this is the correct fix and not a partial one:
	// adding pg_dumpall --clean --if-exists instead (the naive
	// standard fix) makes it WORSE — it then tries to DROP ROLE
	// postgres while the load is connected as that exact role, which
	// Postgres refuses ("current user cannot be dropped"). Every other
	// statement (databases, other roles, table data) loads unaffected
	// either way, so dropping just these two lines is sufficient.
	loadScript := fmt.Sprintf(
		"grep -vE '^(CREATE ROLE postgres;|ALTER ROLE postgres WITH)' %s | docker exec -i -u postgres %s psql -v ON_ERROR_STOP=1",
		shellSingleQuote(dumpPath), name)
	if _, err := d.Target.Run(ctx, sshx.Mutating, "sh", []string{"-c", loadScript}, sshx.RunOptions{}); err != nil {
		return fmt.Errorf("load restored dump into throwaway container: %w", err)
	}

	counts, err := d.Backend.RowCounts(ctx, "postgres", name, "")
	if err != nil {
		return fmt.Errorf("count rows in throwaway container: %w", err)
	}
	return compareRowCounts(dm, counts)
}

func verifyMariaDB(ctx context.Context, d Deps, image, dumpPath string, dm state.DatabaseManifest, resolvedAuth string) error {
	password, err := d.Backend.MariaDBRootPassword(ctx, dm.Container, resolvedAuth)
	if err != nil {
		return fmt.Errorf("resolve root password for the throwaway container: %w", err)
	}

	name := throwawayContainerName(dm.Container)
	// MYSQL_PWD (not just MYSQL_ROOT_PASSWORD) is deliberately also set
	// here — found live: readyScript below references $MYSQL_PWD, but
	// the container's own bootstrap only ever needs MYSQL_ROOT_PASSWORD,
	// so without this the readiness probe always authenticates with an
	// empty password instead of the real one. That empty-password probe
	// transiently succeeds during the official image's own temporary
	// pre-restart server (verified live: exit 0 for 1-2 consecutive
	// polls right before "Stopping temporary server" in its own logs),
	// which can satisfy startThrowawayContainer's 3-consecutive-successes
	// debounce on a false signal — reporting "ready" before the real,
	// password-enforced server has actually finished settling, which is
	// exactly the race that made the subsequent load intermittently fail
	// with "Access denied ... (using password: YES)" despite sending the
	// correct password.
	env := []string{"MYSQL_ROOT_PASSWORD=" + password, "MYSQL_PWD=" + password}
	readyScript := fmt.Sprintf(`docker exec -e MYSQL_PWD="$MYSQL_PWD" %s mysql -u root -e 'SELECT 1'`, name)
	if err := startThrowawayContainer(ctx, d, image, name, env, readyScript); err != nil {
		return err
	}
	defer removeThrowawayContainer(ctx, d, name)

	loadScript := fmt.Sprintf(`docker exec -e MYSQL_PWD="$MYSQL_PWD" -i %s mysql -u root < %s`, name, shellSingleQuote(dumpPath))
	if _, err := d.Target.Run(ctx, sshx.Mutating, "sh", []string{"-c", loadScript}, sshx.RunOptions{Env: []string{"MYSQL_PWD=" + password}}); err != nil {
		return fmt.Errorf("load restored dump into throwaway container: %w", err)
	}

	counts, err := d.Backend.RowCounts(ctx, "mariadb", name, password)
	if err != nil {
		return fmt.Errorf("count rows in throwaway container: %w", err)
	}
	return compareRowCounts(dm, counts)
}

// verifyNativeMariaDB mirrors verifyMariaDB for a native (non-Docker)
// original — see verifyDatabase's doc comment on why it can't reuse
// verifyMariaDB's own password-resolution step.
func verifyNativeMariaDB(ctx context.Context, d Deps, image, dumpPath string, dm state.DatabaseManifest) error {
	const throwawayPassword = "fortified-verify"
	name := throwawayContainerName(dm.Container)
	// See verifyMariaDB's identical comment on why MYSQL_PWD is set
	// here too, not just MYSQL_ROOT_PASSWORD.
	env := []string{"MYSQL_ROOT_PASSWORD=" + throwawayPassword, "MYSQL_PWD=" + throwawayPassword}
	readyScript := fmt.Sprintf(`docker exec -e MYSQL_PWD="$MYSQL_PWD" %s mysql -u root -e 'SELECT 1'`, name)
	if err := startThrowawayContainer(ctx, d, image, name, env, readyScript); err != nil {
		return err
	}
	defer removeThrowawayContainer(ctx, d, name)

	loadScript := fmt.Sprintf(`docker exec -e MYSQL_PWD="$MYSQL_PWD" -i %s mysql -u root < %s`, name, shellSingleQuote(dumpPath))
	if _, err := d.Target.Run(ctx, sshx.Mutating, "sh", []string{"-c", loadScript}, sshx.RunOptions{Env: []string{"MYSQL_PWD=" + throwawayPassword}}); err != nil {
		return fmt.Errorf("load restored dump into throwaway container: %w", err)
	}

	counts, err := d.Backend.RowCounts(ctx, "mariadb", name, throwawayPassword)
	if err != nil {
		return fmt.Errorf("count rows in throwaway container: %w", err)
	}
	return compareRowCounts(dm, counts)
}

// verifyCockroachDB loads the restored, self-contained dump (each
// database segment carries its own CREATE DATABASE/SET database
// preamble — see borg.Backend's dumpCockroachDB) into a throwaway
// single-node --insecure cluster, then re-derives row counts across
// every database it just recreated and compares. --insecure only:
// the only mode fortified supports (see cockroachInsecureReachable in
// internal/discover).
func verifyCockroachDB(ctx context.Context, d Deps, image, dumpPath string, dm state.DatabaseManifest) error {
	name := throwawayContainerName(dm.Container)
	readyScript := fmt.Sprintf("docker exec %s /cockroach/cockroach sql --insecure -e 'SELECT 1'", name)
	if err := startThrowawayContainer(ctx, d, image, name, nil, readyScript, "start", "--insecure"); err != nil {
		return err
	}
	defer removeThrowawayContainer(ctx, d, name)

	loadScript := fmt.Sprintf("docker exec -i %s /cockroach/cockroach sql --insecure < %s", name, shellSingleQuote(dumpPath))
	if _, err := d.Target.Run(ctx, sshx.Mutating, "sh", []string{"-c", loadScript}, sshx.RunOptions{}); err != nil {
		return fmt.Errorf("load restored dump into throwaway container: %w", err)
	}

	counts, err := d.Backend.RowCounts(ctx, "cockroachdb", name, "")
	if err != nil {
		return fmt.Errorf("count rows in throwaway container: %w", err)
	}
	return compareRowCounts(dm, counts)
}

// compareRowCounts distinguishes a table missing from the restored
// database entirely from one present with zero rows — both would
// otherwise read as "0" from a plain map index, silently passing a
// restore that dropped a table (e.g. a partially-failed SQL load).
func compareRowCounts(dm state.DatabaseManifest, got map[string]int64) error {
	for table, want := range dm.RowCounts {
		gotCount, ok := got[table]
		if !ok {
			return fmt.Errorf("table %s is missing from the restored database entirely (manifest baseline wants %d rows)", table, want)
		}
		if gotCount != want {
			return fmt.Errorf("row count for %s = %d, manifest baseline = %d", table, gotCount, want)
		}
	}
	return nil
}

// startThrowawayContainer starts a fresh, disposable container of
// image on the target and blocks until readyScript succeeds 3
// consecutive times — official Postgres/MariaDB images run a
// temporary internal server during first-time init before restarting
// as the real one, so a single successful probe can hit that
// transient instance right before the restart (observed live during
// Phase 4's integration tests; the same debounce is needed here).
//
// Both the run command and readyScript go through `sh -c` referencing
// "$VAR" for any secret rather than embedding literal values as argv
// words: a real value passed directly as a "docker run -e VAR=value"
// or "docker exec -e VAR=value" argument would be recorded verbatim
// by audit.Runner (it records args exactly as given), leaking a real
// database credential into the audit log — the same discipline
// dumpMariaDB already applies to the dump command itself.
//
// cmdArgs, if given, overrides the image's own default command —
// postgres/mariadb need none (env vars alone drive their init), but
// CockroachDB has no such env-var-driven mode and must be told
// explicitly to run as a single insecure node ("start", "--insecure").
func startThrowawayContainer(ctx context.Context, d Deps, image, name string, env []string, readyScript string, cmdArgs ...string) error {
	if image == "" {
		// An empty Image silently produces a malformed `docker run`
		// (missing its required IMAGE argument, since the format
		// string still has to fill that slot with something) — found
		// live: a native database's Image field is only ever
		// populated by `discover --refresh-databases`, so state saved
		// before that fix (or simply never refreshed since) reads as
		// "" here, and the resulting error was a confusing raw Docker
		// CLI usage message instead of pointing at the actual cause.
		return fmt.Errorf("no Image recorded for %s — run discover --refresh-databases to populate it, then retry verify", name)
	}
	runScript := fmt.Sprintf("docker run -d --name %s %s %s %s", name, envFlags(env), image, strings.Join(cmdArgs, " "))
	if _, err := d.Target.Run(ctx, sshx.Mutating, "sh", []string{"-c", runScript}, sshx.RunOptions{Env: env}); err != nil {
		return fmt.Errorf("start throwaway container %s: %w", name, err)
	}

	deadline := time.Now().Add(30 * time.Second)
	consecutiveSuccesses := 0
	for {
		if _, err := d.Target.Run(ctx, sshx.ReadOnly, "sh", []string{"-c", readyScript}, sshx.RunOptions{Env: env}); err == nil {
			consecutiveSuccesses++
			if consecutiveSuccesses >= 3 {
				return nil
			}
		} else {
			consecutiveSuccesses = 0
		}
		if time.Now().After(deadline) {
			removeThrowawayContainer(ctx, d, name)
			return fmt.Errorf("throwaway container %s never became stably ready", name)
		}
		select {
		case <-ctx.Done():
			removeThrowawayContainer(ctx, d, name)
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func removeThrowawayContainer(ctx context.Context, d Deps, name string) {
	_, _ = d.Target.Run(ctx, sshx.Mutating, "docker", []string{"rm", "-f", name}, sshx.RunOptions{})
}

// envFlags renders env's "VAR=value" pairs as "-e VAR=\"$VAR\"" docker
// flags — a reference to the shell variable Session.Run's env-prefix
// mechanism sets, never the literal value (see startThrowawayContainer's
// doc comment).
func envFlags(env []string) string {
	flags := make([]string, 0, len(env))
	for _, e := range env {
		name, _, _ := strings.Cut(e, "=")
		flags = append(flags, fmt.Sprintf(`-e %s="$%s"`, name, name))
	}
	return strings.Join(flags, " ")
}
