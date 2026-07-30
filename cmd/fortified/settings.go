package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/danieltamas/fortified/internal/config"
)

func newSettingsCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "settings",
		Short: "Open fleet.yaml (the scanned/onboarded fleet config) in your editor",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			editor := editorCommand()

			if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
				return fmt.Errorf("settings: create config directory: %w", err)
			}

			c := exec.CommandContext(cmd.Context(), editor, configPath) //nolint:gosec // editor comes from $VISUAL/$EDITOR/PATH, configPath from --config; both operator-controlled
			c.Stdin = cmd.InOrStdin()
			c.Stdout = cmd.OutOrStdout()
			c.Stderr = cmd.ErrOrStderr()
			if err := c.Run(); err != nil {
				return fmt.Errorf("settings: %s %s: %w", editor, configPath, err)
			}

			if _, err := config.Load(configPath); err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "settings: warning: %s does not currently load cleanly: %v\n", configPath, err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", defaultConfigPath(), "path to fleet.yaml")

	return cmd
}

// editorCommand picks the editor to open, following the same
// $VISUAL/$EDITOR convention as git and every other CLI that shells
// out to one. Falls back to nano rather than vi when neither is set —
// vi is POSIX-guaranteed but nano's keys (Ctrl+K to cut a line, no
// modes) are what an operator with no configured preference expects
// from an unfamiliar terminal editor.
func editorCommand() string {
	if v := os.Getenv("VISUAL"); v != "" {
		return v
	}
	if e := os.Getenv("EDITOR"); e != "" {
		return e
	}
	return "nano"
}
