//go:build linux

package authowner

import (
	"io"
	"os"
	"testing"
)

// captureOwnerOutput observes this process's owner stdout/stderr. Vendor stdio
// remains on its private pipes; real unit stderr is independently required null.
func captureOwnerOutput(t *testing.T, fn func()) []byte {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal("output capture unavailable")
	}
	defer read.Close()
	defer write.Close()
	defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()
	captured := make(chan []byte, 1)
	go func() { b, _ := io.ReadAll(io.LimitReader(read, 1<<20+1)); captured <- b }()
	os.Stdout, os.Stderr = write, write
	fn()
	os.Stdout, os.Stderr = oldOut, oldErr
	write.Close()
	b := <-captured
	if len(b) > 1<<20 {
		t.Fatal("owner output exceeded capture bound")
	}
	return b
}
