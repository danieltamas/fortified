package borg

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/danieltamas/fortified/internal/sshx"
)

// dumpProgressPollInterval is how often startDumpProgressPoller checks
// a growing dump file's size — a package var, not a const, so tests
// can override it for a fast, deterministic run instead of waiting
// out a real interval.
var dumpProgressPollInterval = 5 * time.Second

// startDumpProgressPoller watches dumpPath's growing size on the
// target while a long-running pg_dumpall/mysqldump/cockroach dump
// produces no progress output of its own, writing a self-overwriting
// line to liveOutput every dumpProgressPollInterval — the same
// self-overwrite convention `borg create --progress` already uses on
// this same writer (internal/orchestrate.Deps.LiveOutput), so the two
// don't visually fight each other.
//
// Nil-safe: a nil liveOutput (no one watching) means this is a no-op,
// matching the "only pay for it when someone's listening" pattern
// CreateArchive's own --progress flag already follows. estimatedSize
// <= 0 means "unknown" — the line then reports bytes copied so far
// without a percentage, rather than a nonsensical "12.4 GB / 0 B".
//
// stop() cancels the poller and blocks until its goroutine has
// actually exited, so the caller's own next output (a dump's "done"
// boundary line, or the next database's own dumping) never
// interleaves with a straggling poll tick.
func (b Backend) startDumpProgressPoller(ctx context.Context, container, dumpPath string, estimatedSize int64, liveOutput io.Writer) (stop func()) {
	if liveOutput == nil {
		return func() {}
	}

	pollCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(dumpProgressPollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-pollCtx.Done():
				return
			case <-ticker.C:
				b.reportDumpProgress(pollCtx, container, dumpPath, estimatedSize, liveOutput)
			}
		}
	}()

	return func() {
		cancel()
		<-done
	}
}

// reportDumpProgress stats dumpPath once and writes one progress line
// — a stat failure (the dump file not created yet, the brief window
// before its `>` redirect takes effect, or the poll racing the dump's
// own completion/cleanup) reads as "0 bytes so far", never an error:
// this line exists purely to reassure the operator something is
// happening, not to detect a real fault (the dump command's own exit
// code is what actually surfaces a failure).
func (b Backend) reportDumpProgress(ctx context.Context, container, dumpPath string, estimatedSize int64, liveOutput io.Writer) {
	var size int64
	if result, err := b.Runner.Run(ctx, sshx.ReadOnly, "stat", []string{"-c%s", dumpPath}, sshx.RunOptions{}); err == nil {
		if n, parseErr := strconv.ParseInt(strings.TrimSpace(result.Stdout), 10, 64); parseErr == nil {
			size = n
		}
	}

	line := fmt.Sprintf("[%s] dumping... %s", container, humanBytes(size))
	if estimatedSize > 0 {
		pct := float64(size) / float64(estimatedSize) * 100
		if pct > 100 {
			pct = 100
		}
		line = fmt.Sprintf("[%s] dumping... %s / ~%s (%.0f%%)", container, humanBytes(size), humanBytes(estimatedSize), pct)
	}
	_, _ = fmt.Fprintf(liveOutput, "\r\x1b[K%s", line)
}

// humanBytes renders n as a human-readable size (decimal units,
// KB/MB/GB/...) — shared by the dump-progress poller and
// CockroachDB's own best-effort size reporting.
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
