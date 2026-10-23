//go:build linux

package authowner

import (
	"os/signal"
	"syscall"
)

func signalIgnore() { signal.Ignore(syscall.SIGTERM) }
