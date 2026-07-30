package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// TestPruneAbortsByDefaultWithoutConfirmation proves prune refuses to
// proceed unless the operator explicitly types "yes" — a destructive,
// irreversible operation must default to abort, not default to
// proceed just because a key was supplied.
func TestPruneAbortsByDefaultWithoutConfirmation(t *testing.T) {
	cmd := newRootCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetIn(strings.NewReader("\n")) // empty line — not "yes"
	cmd.SetArgs([]string{"prune", "some-server", "--prune-key", "/tmp/does-not-matter"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "aborted") {
		t.Fatalf("Execute error = %v, want it to mention aborting", err)
	}
	if !strings.Contains(errOut.String(), "cannot be undone") {
		t.Errorf("stderr = %q, want a clear warning before the prompt", errOut.String())
	}
}

// TestPruneYesIMeanItSkipsThePrompt proves --yes-i-mean-it bypasses
// the confirmation entirely — proven indirectly: with no stdin
// available at all (which would make Scan() fail and abort if the
// prompt ran), the command must still get past confirmation and fail
// later, for an unrelated reason (no such config file).
func TestPruneYesIMeanItSkipsThePrompt(t *testing.T) {
	cmd := newRootCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetIn(strings.NewReader("")) // nothing to read — would abort if the prompt ran
	missingConfig := filepath.Join(t.TempDir(), "missing-fleet.yaml")
	cmd.SetArgs([]string{"prune", "some-server", "--prune-key", "/tmp/does-not-matter", "--yes-i-mean-it", "--config", missingConfig})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected an error (missing config), proving prune got past confirmation")
	}
	if strings.Contains(err.Error(), "aborted") {
		t.Fatalf("Execute error = %v, want a config-loading error, not an abort — --yes-i-mean-it must skip the prompt", err)
	}
}

// TestPruneTypingYesProceedsPastConfirmation mirrors the skip-prompt
// test but via the interactive path: typing exactly "yes" must let
// execution continue past confirmation, same as --yes-i-mean-it.
func TestPruneTypingYesProceedsPastConfirmation(t *testing.T) {
	cmd := newRootCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetIn(strings.NewReader("yes\n"))
	missingConfig := filepath.Join(t.TempDir(), "missing-fleet.yaml")
	cmd.SetArgs([]string{"prune", "some-server", "--prune-key", "/tmp/does-not-matter", "--config", missingConfig})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected an error (missing config), proving prune got past confirmation")
	}
	if strings.Contains(err.Error(), "aborted") {
		t.Fatalf("Execute error = %v, want a config-loading error, not an abort — typing \"yes\" must proceed", err)
	}
}

func TestPruneDryRunNeverPrompts(t *testing.T) {
	cmd := newRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetIn(strings.NewReader("")) // nothing to read — would fail if a prompt tried to read it
	cmd.SetArgs([]string{"prune", "some-server", "--prune-key", "/tmp/does-not-matter", "--dry-run"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out.String(), "[dry-run]") {
		t.Errorf("out = %q, want the dry-run plan line", out.String())
	}
}
