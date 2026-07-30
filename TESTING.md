# Testing fortified

No Go toolchain, borg, or database engines need to be installed on the
host machine — everything runs inside the `fortified-dev` Docker image
(`docker/Dockerfile.dev`) via `just`. The image talks to the host Docker
daemon through the mounted socket (docker-outside-of-docker), so
integration tests that spin up Postgres/MariaDB/CockroachDB containers
create real sibling containers on the host engine.

Build the image once, and after any `docker/Dockerfile.dev` edit:

```
just build-image
```

## Layer 1 — argv-level unit tests

Everywhere a command is executed (SSH, borg, docker exec, HTTP calls),
tests supply a `FakeRunner`/fake `http.RoundTripper` and assert the
*exact* argv or request constructed. No live access required.

```
just test
```

## Layer 2 — golden-file tests

Parser tests (`internal/discover`, `internal/config`) assert output
against committed fixtures under `testdata/`. Regenerate with:

```
just _run 'go test ./... -run TestGolden -update'
```

A dirty `git diff` after `-update` fails CI — golden files only change
when a human reviews the diff and commits it deliberately.

## Layer 3 — local integration tests

Tagged `integration`; require a real `borg` binary and the real `docker`
CLI against the host engine (both are present in `fortified-dev`):

```
just test-integration
```

Tool versions inside `fortified-dev` (pinned via the base image and apt,
see `docker/Dockerfile.dev`):

- Go: 1.26.x (`golang:1.26-bookworm`)
- borg: 1.2.4 (Debian bookworm's `borgbackup` package)
- docker CLI: 20.10.x (Debian bookworm's `docker.io` package) — talks to
  whatever engine version the host is actually running via the mounted
  socket; basic `ps`/`inspect`/`exec`/`run` are compatible across the
  version skew this implies.

Tests `t.Skip` with a clear message if `borg` or `docker` are absent;
the phase gate requires them to actually run, not just compile.

## Live tier

Anything touching a real Hetzner account or a real server
(`host-2-example`) is gated behind `FORTIFIED_LIVE_TEST=1` *and*
operator presence — never set by an agent, never run in CI.

## Everyday gate

```
just check
```

Runs `gofmt -l .`, `go vet ./...`, `golangci-lint run`, a static build,
and `go test ./...` — this must pass before every commit.
