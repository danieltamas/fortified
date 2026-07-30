// Package sshxtest provides FakeRunner, the shared test double every
// other package's Layer-1 argv tests are built on (SPEC.md §8).
package sshxtest

import (
	"context"
	"sync"

	"github.com/danieltamas/fortified/internal/sshx"
)

// Call is one recorded invocation: exact argv, env, stdin, and the
// declared class — this is what Layer-1 tests assert against, not
// just "contains borg".
type Call struct {
	Class sshx.Class
	Cmd   string
	Args  []string
	Env   []string
	Stdin string
}

// Response is a scripted reply to one Call, consumed in order.
type Response struct {
	Result sshx.Result
	Err    error
}

// FakeRunner records every call it receives and returns scripted
// Responses in order. A call beyond the scripted responses returns a
// zero Result and a nil error — most tests only care about argv, not
// output, unless they explicitly script a response.
//
// mu guards Calls/Responses: a background progress poller (borg's
// startDumpProgressPoller) now genuinely runs Run concurrently with
// whatever the test's main goroutine is doing, the same as it would
// against a real *sshx.Session — every other caller stays
// single-threaded and unaffected by the lock.
type FakeRunner struct {
	mu        sync.Mutex
	Calls     []Call
	Responses []Response
}

// Run implements sshx.Runner.
func (f *FakeRunner) Run(_ context.Context, class sshx.Class, cmd string, args []string, opts sshx.RunOptions) (sshx.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.Calls = append(f.Calls, Call{
		Class: class,
		Cmd:   cmd,
		Args:  append([]string{}, args...),
		Env:   append([]string{}, opts.Env...),
		Stdin: opts.Stdin,
	})

	if len(f.Responses) == 0 {
		return sshx.Result{}, nil
	}
	resp := f.Responses[0]
	f.Responses = f.Responses[1:]
	return resp.Result, resp.Err
}

// CallCount returns how many calls have been recorded so far,
// lock-protected — the one safe way to poll progress from a test's
// main goroutine while a background caller (e.g. borg's dump-progress
// poller) may still be calling Run concurrently. Reading the Calls
// field directly from another goroutine while Run is still in flight
// is a data race; once the concurrent caller has fully stopped (e.g.
// after a poller's stop() returns), reading Calls directly is fine
// again, same as any other single-threaded test.
func (f *FakeRunner) CallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.Calls)
}

var _ sshx.Runner = &FakeRunner{}
