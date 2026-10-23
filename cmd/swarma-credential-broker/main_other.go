//go:build !linux

package main

import (
	"fmt"
	"io"
)

func run(_ []string, _ io.Writer, diagnostic io.Writer) int {
	fmt.Fprintln(diagnostic, "Linux is required for this profile")
	return 69
}
