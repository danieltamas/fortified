package borg

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
)

func TestHumanBytes(t *testing.T) {
	cases := map[int64]string{
		0:             "0 B",
		999:           "999 B",
		1000:          "1.0 KB",
		1500:          "1.5 KB",
		1_000_000:     "1.0 MB",
		1_200_000:     "1.2 MB",
		1_000_000_000: "1.0 GB",
	}
	for n, want := range cases {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", n, got, want)
		}
	}
}

// TestStartDumpProgressPollerIsNoOpWithoutLiveOutput proves the poller
// never touches the Runner at all when nobody's watching — matching
// CreateArchive's own "--progress only when someone's listening"
// pattern, and avoiding an unnecessary SSH round-trip on every backup.
func TestStartDumpProgressPollerIsNoOpWithoutLiveOutput(t *testing.T) {
	fake := &sshxtest.FakeRunner{}
	b := Backend{Runner: fake}

	stop := b.startDumpProgressPoller(context.Background(), "psql", "/work/psql.sql", 0, nil)
	time.Sleep(20 * time.Millisecond)
	stop()

	if len(fake.Calls) != 0 {
		t.Errorf("Calls = %v, want none when liveOutput is nil", fake.Calls)
	}
}

// TestStartDumpProgressPollerReportsGrowingSize proves the poller
// stats the dump file on a fast, overridden interval and writes a
// self-overwriting progress line reflecting the growing size and, when
// an estimate is known, a percentage.
func TestStartDumpProgressPollerReportsGrowingSize(t *testing.T) {
	original := dumpProgressPollInterval
	dumpProgressPollInterval = 5 * time.Millisecond
	defer func() { dumpProgressPollInterval = original }()

	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Result: sshx.Result{Stdout: "1000000\n"}},
		{Result: sshx.Result{Stdout: "2000000\n"}},
		{Result: sshx.Result{Stdout: "2000000\n"}},
	}}
	b := Backend{Runner: fake}

	var out strings.Builder
	stop := b.startDumpProgressPoller(context.Background(), "psql", "/work/psql.sql", 4_000_000, &out)
	deadline := time.Now().Add(2 * time.Second)
	for fake.CallCount() < 2 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	stop()

	if len(fake.Calls) < 2 {
		t.Fatalf("expected at least 2 poll ticks, got %d", len(fake.Calls))
	}
	for _, call := range fake.Calls {
		if call.Cmd != "stat" || len(call.Args) != 2 || call.Args[0] != "-c%s" || call.Args[1] != "/work/psql.sql" {
			t.Errorf("poll call = %+v, want stat -c%%s /work/psql.sql", call)
		}
	}

	written := out.String()
	if !strings.Contains(written, "[psql] dumping...") {
		t.Errorf("output = %q, want it to name the container", written)
	}
	if !strings.Contains(written, "\r\x1b[K") {
		t.Errorf("output = %q, want each line to self-overwrite via \\r\\x1b[K", written)
	}
	if !strings.Contains(written, "%") {
		t.Errorf("output = %q, want a percentage once an estimate is known", written)
	}
}

// TestStartDumpProgressPollerOmitsPercentageWithoutEstimate proves an
// unresolved size estimate (estimatedSize <= 0) degrades to reporting
// bytes copied so far, never a nonsensical "X / 0 B (Inf%)".
func TestStartDumpProgressPollerOmitsPercentageWithoutEstimate(t *testing.T) {
	original := dumpProgressPollInterval
	dumpProgressPollInterval = 5 * time.Millisecond
	defer func() { dumpProgressPollInterval = original }()

	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Result: sshx.Result{Stdout: "500\n"}},
	}}
	b := Backend{Runner: fake}

	var out strings.Builder
	stop := b.startDumpProgressPoller(context.Background(), "mysql", "/work/mysql.sql", 0, &out)
	deadline := time.Now().Add(2 * time.Second)
	for fake.CallCount() < 1 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	stop()

	written := out.String()
	if !strings.Contains(written, "dumping... 500 B") {
		t.Errorf("output = %q, want bytes-copied-so-far with no estimate", written)
	}
	if strings.Contains(written, "%") {
		t.Errorf("output = %q, want no percentage without a size estimate", written)
	}
}

// TestStartDumpProgressPollerTreatsStatFailureAsZero proves a stat
// failure (the dump file not created yet, the brief window before its
// `>` redirect takes effect) reads as "0 bytes so far", never an
// error surfaced to the operator — the dump command's own exit code is
// what actually detects a real failure.
func TestStartDumpProgressPollerTreatsStatFailureAsZero(t *testing.T) {
	original := dumpProgressPollInterval
	dumpProgressPollInterval = 5 * time.Millisecond
	defer func() { dumpProgressPollInterval = original }()

	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Err: context.DeadlineExceeded},
	}}
	b := Backend{Runner: fake}

	var out strings.Builder
	stop := b.startDumpProgressPoller(context.Background(), "psql", "/work/psql.sql", 0, &out)
	deadline := time.Now().Add(2 * time.Second)
	for fake.CallCount() < 1 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	stop()

	if !strings.Contains(out.String(), "dumping... 0 B") {
		t.Errorf("output = %q, want a stat failure to read as 0 bytes", out.String())
	}
}

// TestStartDumpProgressPollerStopBlocksUntilGoroutineExits proves stop()
// doesn't return until the poller goroutine has actually finished —
// otherwise a straggling tick could write to liveOutput after the
// caller has moved on to its own next output (e.g. the "done" boundary
// line), interleaving garbled text.
func TestStartDumpProgressPollerStopBlocksUntilGoroutineExits(t *testing.T) {
	original := dumpProgressPollInterval
	dumpProgressPollInterval = time.Millisecond
	defer func() { dumpProgressPollInterval = original }()

	fake := &sshxtest.FakeRunner{}
	b := Backend{Runner: fake}
	var out strings.Builder

	stop := b.startDumpProgressPoller(context.Background(), "psql", "/work/psql.sql", 0, &out)
	time.Sleep(20 * time.Millisecond)
	stop()

	callsAtStop := len(fake.Calls)
	time.Sleep(50 * time.Millisecond)
	if len(fake.Calls) != callsAtStop {
		t.Errorf("Calls grew from %d to %d after stop() returned — poller kept running", callsAtStop, len(fake.Calls))
	}
}
