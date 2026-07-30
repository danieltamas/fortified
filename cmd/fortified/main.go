// Command fortified is a deterministic backup and disaster-recovery CLI
// for a fleet of self-hosted servers. See SPEC.md at the repo root for
// the full command reference and exit-code contract.
package main

import "os"

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
