package borg

import (
	"context"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
)

func TestCheckArgv(t *testing.T) {
	fake := &sshxtest.FakeRunner{}
	b := Backend{Runner: fake}

	if err := b.Check(context.Background(), "/repo/host-2-example", "pw", "/identity-key"); err != nil {
		t.Fatalf("Check: %v", err)
	}

	call := fake.Calls[0]
	if call.Cmd != "borg" || strings.Join(call.Args, "|") != "check|/repo/host-2-example" {
		t.Errorf("cmd/args = %q %v, want borg [check /repo/host-2-example]", call.Cmd, call.Args)
	}
	if call.Class != sshx.ReadOnly {
		t.Errorf("class = %v, want ReadOnly", call.Class)
	}
}

func TestCheckFailurePropagates(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{{Err: errBoom}}}
	b := Backend{Runner: fake}
	if err := b.Check(context.Background(), "/repo/x", "pw", "/identity-key"); err == nil {
		t.Fatal("expected Check to propagate the runner error")
	}
}
