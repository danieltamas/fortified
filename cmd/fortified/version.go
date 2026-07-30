package main

import (
	"github.com/spf13/cobra"

	"github.com/danieltamas/fortified/internal/report"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

type versionInfo struct {
	Version string `json:"version"`
}

func (v versionInfo) table() report.Table {
	return report.Table{Headers: []string{"VERSION"}, Rows: [][]string{{v.Version}}}
}

func newVersionCmd(jsonOutput *bool) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the fortified version",
		RunE: func(cmd *cobra.Command, args []string) error {
			info := versionInfo{Version: version}
			r := report.Reporter{JSON: *jsonOutput}
			return r.Render(cmd.OutOrStdout(), info, info.table)
		},
	}
}
