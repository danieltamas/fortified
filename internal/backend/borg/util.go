package borg

import "strings"

// splitNonEmptyLines splits s on newlines, dropping blank lines and
// surrounding whitespace on each — borg's line-oriented output
// (`list --short`, table dumps) is parsed with this everywhere.
func splitNonEmptyLines(s string) []string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
