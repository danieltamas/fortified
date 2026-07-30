package report

import (
	"bytes"
	"strings"
	"testing"
)

type serverStatus struct {
	Name       string `json:"name"`
	LastBackup string `json:"last_backup"`
}

func (s serverStatus) table() Table {
	return Table{
		Headers: []string{"NAME", "LAST_BACKUP"},
		Rows:    [][]string{{s.Name, s.LastBackup}},
	}
}

func TestRenderJSON(t *testing.T) {
	buf := &bytes.Buffer{}
	r := Reporter{JSON: true}
	s := serverStatus{Name: "host-2-example", LastBackup: "2026-07-17T02:00:00Z"}

	if err := r.Render(buf, s, s.table); err != nil {
		t.Fatalf("Render: %v", err)
	}

	got := buf.String()
	for _, want := range []string{`"name": "host-2-example"`, `"last_backup": "2026-07-17T02:00:00Z"`} {
		if !strings.Contains(got, want) {
			t.Errorf("JSON output missing %q, got:\n%s", want, got)
		}
	}
}

func TestRenderTable(t *testing.T) {
	buf := &bytes.Buffer{}
	r := Reporter{JSON: false}
	s := serverStatus{Name: "host-2-example", LastBackup: "2026-07-17T02:00:00Z"}

	if err := r.Render(buf, s, s.table); err != nil {
		t.Fatalf("Render: %v", err)
	}

	want := "NAME            LAST_BACKUP\n" +
		"host-2-example  2026-07-17T02:00:00Z\n"
	if got := buf.String(); got != want {
		t.Errorf("table mismatch:\ngot:  %q\nwant: %q", got, want)
	}
}

func TestRenderTableAlignsMultipleRows(t *testing.T) {
	buf := &bytes.Buffer{}
	r := Reporter{JSON: false}
	tbl := Table{
		Headers: []string{"NAME", "STATUS"},
		Rows: [][]string{
			{"host-2-example", "ok"},
			{"host-example-with-a-long-name", "unverified"},
		},
	}

	if err := r.Render(buf, nil, func() Table { return tbl }); err != nil {
		t.Fatalf("Render: %v", err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines (header + 2 rows), got %d: %v", len(lines), lines)
	}
	// The second column must start at the same offset on every line —
	// that's what "aligned" means, regardless of gap width.
	statusOffset := strings.Index(lines[0], "STATUS")
	if statusOffset < 0 {
		t.Fatalf("header line %q missing STATUS", lines[0])
	}
	for i, row := range tbl.Rows {
		line := lines[i+1]
		if len(line) < statusOffset || !strings.HasPrefix(line[statusOffset:], row[1]) {
			t.Errorf("row %q: STATUS column not aligned at offset %d, line was %q", row[0], statusOffset, line)
		}
	}
}

// TestWriteTableSeparatorRow proves a SeparatorRow entry renders as a
// dashed rule spanning every column's width plus the gaps between
// them, not as an empty data row — grouping rows within one table
// (e.g. one container's databases, then the next) without breaking
// column alignment the way starting a whole new table would.
func TestWriteTableSeparatorRow(t *testing.T) {
	buf := &bytes.Buffer{}
	tbl := Table{
		Headers: []string{"A", "BB"},
		Rows: [][]string{
			{"x", "y"},
			SeparatorRow,
			{"long-value", "z"},
		},
	}

	if err := WriteTable(buf, tbl); err != nil {
		t.Fatalf("WriteTable: %v", err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("expected 4 lines (header + row + separator + row), got %d: %v", len(lines), lines)
	}
	// Column widths: "long-value" (10) + gap(2) + "BB"/"z"/"y" (2) = 14.
	wantSeparator := strings.Repeat("-", 14)
	if lines[2] != wantSeparator {
		t.Errorf("separator line = %q, want %q", lines[2], wantSeparator)
	}
}

// TestWriteTableRightAlign proves a column marked RightAlign has its
// shorter values padded on the left, not the right — lining up digits
// in a size column the way NAME/PATH-style columns never need to.
func TestWriteTableRightAlign(t *testing.T) {
	buf := &bytes.Buffer{}
	tbl := Table{
		Headers:    []string{"PATH", "SIZE"},
		Rows:       [][]string{{"/home/example", "144.4 GB"}, {"/etc/nginx", "23.5 KB"}},
		RightAlign: []bool{false, true},
	}

	if err := WriteTable(buf, tbl); err != nil {
		t.Fatalf("WriteTable: %v", err)
	}

	// Column widths: PATH column 13 (len("/home/example")), SIZE
	// column 8 (len("144.4 GB")) — both header cells get padded to
	// those widths too, SIZE right-aligned like every row under it.
	want := "PATH               SIZE\n" +
		"/home/example  144.4 GB\n" +
		"/etc/nginx      23.5 KB\n"
	if got := buf.String(); got != want {
		t.Errorf("table mismatch:\ngot:  %q\nwant: %q", got, want)
	}
}

// TestWriteTableCanBeCalledSeveralTimes proves a command showing
// multiple distinct tables in one plain-table run (Reporter.Render
// only ever writes one) can just call WriteTable again for each one.
func TestWriteTableCanBeCalledSeveralTimes(t *testing.T) {
	buf := &bytes.Buffer{}
	first := Table{Headers: []string{"A"}, Rows: [][]string{{"1"}}}
	second := Table{Headers: []string{"B"}, Rows: [][]string{{"2"}}}

	if err := WriteTable(buf, first); err != nil {
		t.Fatalf("WriteTable(first): %v", err)
	}
	if err := WriteTable(buf, second); err != nil {
		t.Fatalf("WriteTable(second): %v", err)
	}

	want := "A\n1\nB\n2\n"
	if got := buf.String(); got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}

func TestRenderTableEmptyRows(t *testing.T) {
	buf := &bytes.Buffer{}
	r := Reporter{JSON: false}
	tbl := Table{Headers: []string{"NAME"}, Rows: nil}

	if err := r.Render(buf, nil, func() Table { return tbl }); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if got := buf.String(); got != "NAME\n" {
		t.Errorf("expected header-only output, got %q", got)
	}
}
