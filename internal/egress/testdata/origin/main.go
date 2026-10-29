//go:build linux && amd64

// A synthetic origin fixture. It never accesses an account or credential store.
package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/relux-works/swarma-credential-broker/internal/egress"
	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) < 3 {
		os.Exit(125)
	}
	mode, status := os.Args[2], "0"
	if len(os.Args) > 3 {
		status = os.Args[3]
	}
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
			if !strings.HasPrefix(mode, "owner-close-") {
				if _, err := unix.Write(6, []byte(strconv.Itoa(unix.Gettid()))); err != nil {
					os.Exit(125)
				}
			}
			argv := []string{os.Args[0], "/proc/self/fd/4", "case", mode, status}
			if strings.HasPrefix(mode, "owner-") || strings.HasPrefix(mode, "planned-") {
				role := "qualification-owner"
				if strings.HasPrefix(mode, "planned-writer") {
					role = "qualification-writer"
				}
				argv = []string{os.Args[0], "/proc/self/fd/4", role, os.Getenv("OWNER_DIGEST")}
			}
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
	if os.Args[1] == "qualification-owner" || os.Args[1] == "qualification-writer" {
		mode = os.Getenv("OWNER_MODE")
		digest := os.Getenv("OWNER_DIGEST")
		if mode == "owner-noop" {
			os.Exit(0)
		}
		if mode == "owner-context" {
			digest = strings.Repeat("0", 64)
		}
		var err error
		if strings.HasSuffix(mode, "-wrong-domain") {
			err = egress.EnterOwnerRole(digest)
		} else if os.Args[1] == "qualification-writer" {
			err = egress.EnterWriterRole(digest)
		} else if mode == "owner-case" {
			err = egress.EnterCase()
		} else {
			err = egress.EnterOwnerRole(digest)
		}
		if err != nil {
			os.Exit(125)
		}
		if mode == "owner-close-clean" || mode == "owner-close-wait" {
			// Fixed secret-free close fixture: real framed startup/close, then
			// either normal exit or a read held until the supervisor cancels.
			startup := []byte(`{"Data":"lease","Error":"","ID":1,"Op":"startup"}`)
			var size [4]byte
			binary.BigEndian.PutUint32(size[:], uint32(len(startup)))
			if _, err := unix.Write(6, append(size[:], startup...)); err != nil {
				os.Exit(125)
			}
			input := os.NewFile(8, "fixture-input")
			if _, err := io.ReadFull(input, size[:]); err != nil || binary.BigEndian.Uint32(size[:]) > 4096 {
				os.Exit(125)
			}
			body := make([]byte, binary.BigEndian.Uint32(size[:]))
			var close struct {
				ID int
				Op string
			}
			if _, err := io.ReadFull(input, body); err != nil || json.Unmarshal(body, &close) != nil || close.ID != 1 || close.Op != "close" {
				os.Exit(125)
			}
			if mode == "owner-close-wait" {
				var extra [1]byte
				_, _ = input.Read(extra[:])
				os.Exit(1)
			}
			os.Exit(0)
		}
		if strings.HasPrefix(mode, "planned-") {
			if _, err := unix.Write(6, []byte("entered")); err != nil {
				os.Exit(125)
			}
			var b [1]byte
			_, _ = unix.Read(8, b[:])
			os.Exit(0)
		}
		if mode == "owner-exec" {
			_ = unix.Exec("/proc/self/fd/7", []string{"/proc/self/fd/7"}, []string{})
		}
		if mode == "owner-process" {
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
		os.Exit(0)
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
