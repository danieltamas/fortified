package orchestrate

import (
	"time"
)

// withProgress reports label starting, runs fn, then reports it done
// (with elapsed time) or failed — the one place timing/formatting
// lives, so call sites just name the step instead of repeating this.
// It never changes fn's return value or affects control flow: with a
// nil Deps.Progress (every existing test), this is a plain pass-through.
func withProgress(d Deps, label string, fn func() error) error {
	d.reportProgress("%s...", label)
	start := time.Now()
	err := fn()
	elapsed := time.Since(start).Round(time.Millisecond)
	if err != nil {
		d.reportProgress("%s: failed (%s)", label, elapsed)
		return err
	}
	d.reportProgress("%s: done (%s)", label, elapsed)
	return nil
}
