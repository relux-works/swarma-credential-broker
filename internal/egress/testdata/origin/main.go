//go:build linux && amd64

// A synthetic origin fixture. It never accesses an account or credential store.
package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/relux-works/swarma-credential-broker/internal/egress"
	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) < 4 {
		os.Exit(125)
	}
	mode, status := os.Args[2], os.Args[3]
	if os.Args[1] == "bootstrap" {
		if mode == "pre-exec" {
			if _, err := unix.Write(9, make([]byte, 32)); err != nil {
				os.Exit(125)
			}
		}
		// Hold this thread so Bootstrap executes on a separate Go runtime thread.
		runtime.LockOSThread()
		go func() {
			runtime.LockOSThread()
			if unix.Gettid() == unix.Getpid() {
				os.Exit(125)
			}
			if _, err := unix.Write(6, []byte(strconv.Itoa(unix.Gettid()))); err != nil {
				os.Exit(125)
			}
			argv := []string{os.Args[0], "/proc/self/fd/4", "case", mode, status}
			if mode == "unexpected-exec" {
				argv[1] = "/proc/self/fd/7"
			}
			if mode == "wrong-argv" {
				argv = append(argv, "extra")
			}
			if mode == "oversized-argv" {
				argv = append(argv, strings.Repeat("x", 2049))
			}
			os.Args = argv
			if err := egress.Bootstrap(); err != nil {
				fmt.Fprintln(os.Stderr, "bootstrap:", err)
			}
			os.Exit(125)
		}()
		select {}
	}
	if os.Args[1] != "case" || len(os.Args) != 4 {
		os.Exit(125)
	}
	unix.CloseOnExec(9)
	if mode == "wrong-sender" {
		_, _ = unix.Read(8, make([]byte, 1))
		os.Exit(125)
	}
	b := make([]byte, 32)
	if n, err := unix.Read(9, b); err != nil || n != len(b) {
		os.Exit(125)
	}
	if mode == "later-exec" {
		if unix.Exec("/proc/self/fd/7", []string{"/proc/self/fd/7"}, []string{}) != nil {
			os.Exit(125)
		}
	}
	if mode != "pre-exec" && mode != "wrong-sender" {
		if mode == "malformed" {
			b = append(b, 0)
		}
		if _, err := unix.Write(9, b); err != nil {
			os.Exit(125)
		}
		if mode == "duplicate" || mode == "empty-duplicate" {
			if mode == "empty-duplicate" {
				b = []byte{}
			}
			_, _ = unix.Write(9, b)
		}
	}
	if mode == "descendant" {
		pid, _, errno := unix.RawSyscall(unix.SYS_CLONE, uintptr(unix.SIGCHLD), 0, 0)
		if errno != 0 {
			os.Exit(125)
		}
		if pid == 0 {
			for {
				unix.RawSyscall(unix.SYS_PAUSE, 0, 0, 0)
			}
		}
	}
	// Real notification traffic: permit socket creation, refuse an unlisted
	// loopback connect before the kernel can send. No external endpoint exists.
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		os.Exit(125)
	}
	err = unix.Connect(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}, Port: 9})
	unix.Close(fd)
	if err != unix.ECONNREFUSED {
		os.Exit(125)
	}
	n, err := strconv.Atoi(status)
	if err != nil {
		os.Exit(125)
	}
	os.Exit(n)
}
