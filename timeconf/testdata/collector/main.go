//go:build linux

// Command collector supplies synthetic clock reports only to package tests.
// It imports no provider or qualification code and is never a shipped command.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const tracking = "C0000201,192.0.2.1,3,1893553444.000000000,0.001,0.001,0.001,1.0,0.1,0.1,0.002,0.001,10.0,Normal\n"

func main() {
	if len(os.Args) < 3 || os.Args[1] != "-c" {
		os.Exit(11)
	}
	if os.Args[2] == "qualified-descendant" {
		time.Sleep(time.Minute)
		return
	}
	// Descriptor execution can use /proc/self/fd/3 as argv[0]. Resolve the
	// actual pinned inode to find this test's private scenario directory.
	path, err := os.Executable()
	if err != nil {
		os.Exit(11)
	}
	scenario, _ := os.ReadFile(filepath.Join(filepath.Dir(path), "scenario"))
	switch string(scenario) {
	case "arguments":
		fmt.Print(strings.Join(os.Args[1:], "|"))
	case "descriptor":
		_, err := unix.FcntlInt(200, unix.F_GETFD, 0)
		if err == nil {
			fmt.Print("present")
		} else if err == unix.EBADF {
			fmt.Print("closed")
		} else {
			os.Exit(9)
		}
	case "exit":
		os.Exit(9)
	case "timeout":
		time.Sleep(time.Hour)
	case "oversized":
		fmt.Print(strings.Repeat("x", 70000))
	case "stderr":
		fmt.Fprintln(os.Stderr, "unrecognized diagnostic")
	case "environment":
		if !reflect.DeepEqual(os.Environ(), []string{"LC_ALL=C", "LANG=C", "TZ=UTC"}) {
			os.Exit(10)
		}
		fmt.Print(tracking)
	case "qualified-fork":
		cmd := exec.Command(path, "-c", "qualified-descendant")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if cmd.Start() != nil {
			os.Exit(11)
		}
		if os.WriteFile(filepath.Join(filepath.Dir(path), "child.pid"), []byte(strconv.Itoa(cmd.Process.Pid)), 0600) != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			os.Exit(12)
		}
	default:
		fmt.Print(tracking)
	}
}
