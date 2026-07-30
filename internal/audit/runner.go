package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/danieltamas/fortified/internal/sshx"
)

// Runner wraps an sshx.Runner, recording one Entry per call to Writer.
// It never records opts.Env or opts.Stdin — only argv, class, exit
// code, a digest of stderr, and duration — so a resolved secret passed
// via the session environment can never end up in the audit log.
type Runner struct {
	Next         sshx.Runner
	Writer       *Writer
	Command      string
	InvocationID string
}

// Run implements sshx.Runner.
func (r Runner) Run(ctx context.Context, class sshx.Class, cmd string, args []string, opts sshx.RunOptions) (sshx.Result, error) {
	start := time.Now()
	result, runErr := r.Next.Run(ctx, class, cmd, args, opts)

	entry := Entry{
		Time:         start.UTC().Format(time.RFC3339Nano),
		Command:      r.Command,
		InvocationID: r.InvocationID,
		Class:        class.String(),
		Argv:         append([]string{cmd}, args...),
		ExitCode:     result.ExitCode,
		StderrDigest: digest(result.Stderr),
		DurationMS:   time.Since(start).Milliseconds(),
	}

	if writeErr := r.Writer.Append(entry); writeErr != nil {
		// An action whose audit record failed to land is not fully
		// recorded — surface that rather than let a caller believe a
		// mutating call was accounted for when it wasn't.
		return result, errors.Join(runErr, fmt.Errorf("audit: %w", writeErr))
	}
	return result, runErr
}

var _ sshx.Runner = Runner{}

// digest returns a short, non-reversible fingerprint of stderr — a
// clue for cross-referencing without persisting full (potentially
// noisy or oversized) subprocess output.
func digest(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:16]
}
