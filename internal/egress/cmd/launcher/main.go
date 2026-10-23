//go:build linux && amd64

// Command launcher is the trusted pre-exec half of the egress boundary.
package main

import (
	"fmt"
	"github.com/relux-works/swarma-credential-broker/internal/egress"
	"os"
)

func main() {
	if egress.Bootstrap() != nil {
		fmt.Fprintln(os.Stderr, "egress launcher unavailable")
		os.Exit(125)
	}
}
