package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRootHelp(t *testing.T) {
	cmd := newRootCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute --help: %v", err)
	}

	got := buf.String()
	for _, want := range []string{"fortified", "--json", "version"} {
		if !strings.Contains(got, want) {
			t.Errorf("--help output missing %q, got:\n%s", want, got)
		}
	}
}

func TestVersionJSONFlag(t *testing.T) {
	cmd := newRootCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"--json", "version"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute version --json: %v", err)
	}

	if got := buf.String(); !strings.Contains(got, `"version": "dev"`) {
		t.Errorf("expected JSON version output, got %q", got)
	}
}

func TestVersionTableDefault(t *testing.T) {
	cmd := newRootCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"version"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute version: %v", err)
	}

	want := "VERSION\ndev\n"
	if got := buf.String(); got != want {
		t.Errorf("table output mismatch: got %q, want %q", got, want)
	}
}
