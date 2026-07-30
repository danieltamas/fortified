package sshx

import "testing"

func TestShellQuoteIfNeeded(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"lsblk", "lsblk"},
		{"-J", "-J"},
		{"docker-compose*.yml", "'docker-compose*.yml'"},
		{"docker exec -u postgres psql pg_dumpall > /tmp/dump.sql", "'docker exec -u postgres psql pg_dumpall > /tmp/dump.sql'"},
		{"it's", `'it'\''s'`},
		{"", "''"},                 // an empty arg must round-trip as an empty word, not vanish when ssh joins args with spaces
		{"#staging", "'#staging'"}, // unquoted, the remote shell would treat this as a comment and truncate the command
	}
	for _, c := range cases {
		if got := shellQuoteIfNeeded(c.in); got != c.want {
			t.Errorf("shellQuoteIfNeeded(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
