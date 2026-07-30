// Package report renders command output as either a table or JSON from
// the same underlying data, so every command's --json output stays in
// lockstep with its table output instead of drifting apart over time.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Table is the display form of a report: column headers and row cells,
// already formatted as strings.
type Table struct {
	Headers []string
	Rows    [][]string
	// RightAlign marks which columns should be right-aligned (e.g. a
	// size column, where digits should line up) — nil, or any entry
	// left false, means left-aligned exactly as before; every existing
	// caller leaves this unset.
	RightAlign []bool
}

// Reporter renders a value as JSON or as a table, depending on JSON.
// JSON field names come from the value's own struct tags and are part
// of the tool's contract (snake_case, per SPEC §5) — callers must tag
// their structs accordingly.
type Reporter struct {
	JSON bool
}

// Render writes data as indented JSON when r.JSON is set; otherwise it
// calls toTable to obtain the table form and writes that. toTable is a
// func, not a precomputed Table, so callers that only need JSON never
// pay for building a table representation.
func (r Reporter) Render(w io.Writer, data any, toTable func() Table) error {
	if r.JSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(data)
	}
	return WriteTable(w, toTable())
}

// SeparatorRow, used as a Table.Rows entry, renders as a full-width
// dashed rule instead of data cells — for grouping rows within a
// single table (e.g. one container's databases, then a rule, then the
// next container's) without breaking column alignment the way
// starting a whole new table would.
var SeparatorRow = []string{}

// WriteTable renders t directly, bypassing JSON/table branching — for
// a command that shows several distinct tables in one plain-table run
// (Reporter.Render only ever writes one), each additional one is
// written with this instead of round-tripping through Render.
func WriteTable(w io.Writer, t Table) error {
	widths := columnWidths(t)
	if err := writeRow(w, t.Headers, widths, t.RightAlign); err != nil {
		return err
	}
	for _, row := range t.Rows {
		if len(row) == 0 {
			if err := writeSeparator(w, widths); err != nil {
				return err
			}
			continue
		}
		if err := writeRow(w, row, widths, t.RightAlign); err != nil {
			return err
		}
	}
	return nil
}

func columnWidths(t Table) []int {
	widths := make([]int, len(t.Headers))
	for i, h := range t.Headers {
		widths[i] = len(h)
	}
	for _, row := range t.Rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}
	return widths
}

// writeSeparator prints a dashed line as wide as the table's columns
// and their gaps combined — matches writeRow's own "  " (2-space) gap
// convention exactly, so the rule lines up with the data above/below
// it rather than falling short or overrunning.
func writeSeparator(w io.Writer, widths []int) error {
	total := 0
	for i, width := range widths {
		total += width
		if i > 0 {
			total += 2
		}
	}
	_, err := fmt.Fprintln(w, strings.Repeat("-", total))
	return err
}

func writeRow(w io.Writer, cells []string, widths []int, rightAlign []bool) error {
	padded := make([]string, len(cells))
	for i, c := range cells {
		if i >= len(widths) {
			padded[i] = c
			continue
		}
		if i < len(rightAlign) && rightAlign[i] {
			padded[i] = fmt.Sprintf("%*s", widths[i], c)
		} else {
			padded[i] = fmt.Sprintf("%-*s", widths[i], c)
		}
	}
	_, err := fmt.Fprintln(w, strings.TrimRight(strings.Join(padded, "  "), " "))
	return err
}
