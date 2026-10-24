//go:build linux

// This fixture contains no account or credential behavior. Settings and marker
// files belong exclusively to the test that copied the binary.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type settings struct{ Mode, Marker, Counter, PID string }

func main() {
	path, _ := os.Executable()
	raw, _ := os.ReadFile(path + ".json")
	var cfg settings
	json.Unmarshal(raw, &cfg)
	if len(os.Args) > 1 && os.Args[1] == "sleep-child" {
		os.WriteFile(cfg.PID, []byte(strconv.Itoa(os.Getpid())), 0600)
		fmt.Print("ready")
		time.Sleep(time.Hour)
		return
	}
	home := os.Getenv("HOME")
	entries, e := os.ReadDir(home)
	if e != nil || len(entries) != 0 || home != os.Getenv("CODEX_HOME") {
		os.Exit(3)
	}
	if cfg.Marker != "" {
		f, e := os.OpenFile(cfg.Marker, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if e != nil {
			panic(e)
		}
		fmt.Fprintln(f, home)
		f.Close()
	}
	args := strings.Join(os.Args[1:], " ")
	if args == "--version" {
		switch cfg.Mode {
		case "wrong":
			fmt.Print("codex-cli 0.162.0\n")
			return
		case "malformed":
			fmt.Print("codex-cli 0.163.0 extra\n")
			return
		case "oversized":
			fmt.Print(strings.Repeat("x", 1<<20))
			return
		case "stderr-oversized":
			fmt.Fprint(os.Stderr, strings.Repeat("x", 1<<20))
		case "sleep":
			time.Sleep(time.Hour)
		case "unix":
			fd, e := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
			if e != nil {
				panic(e)
			}
			defer unix.Close(fd)
			_ = unix.Connect(fd, &unix.SockaddrUnix{Name: "/unavailable-observer-fixture.sock"})
		case "external", "external-bad-fd":
			fd := -1
			if cfg.Mode == "external" {
				fd, e = unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK, 0)
				if e != nil {
					panic(e)
				}
				defer unix.Close(fd)
			}
			// The bad-FD control cannot emit traffic even with no boundary; the
			// normal case separately exercises an actual socket under confinement.
			_ = unix.Connect(fd, &unix.SockaddrInet4{Addr: [4]byte{192, 0, 2, 1}, Port: 9})
		case "leftover":
			c := exec.Command(path, "sleep-child")
			c.Env = os.Environ()
			r, w, e := os.Pipe()
			if e != nil {
				panic(e)
			}
			defer r.Close()
			c.Stdout = w
			if c.Start() != nil {
				os.Exit(4)
			}
			w.Close()
			var ready [1]byte
			if _, e = io.ReadFull(r, ready[:]); e != nil {
				os.Exit(4)
			}
		}
		fmt.Print("codex-cli 0.163.0\n")
		return
	}
	if args == "app-server --help" {
		fmt.Println("generate-json-schema")
		return
	}
	if args == "app-server generate-json-schema --help" {
		fmt.Println("--experimental --out <directory>")
		return
	}
	if len(os.Args) == 6 && os.Args[1] == "app-server" && os.Args[2] == "generate-json-schema" && os.Args[3] == "--experimental" && os.Args[4] == "--out" {
		dir := os.Args[5]
		if os.Mkdir(dir, 0700) != nil {
			os.Exit(5)
		}
		n := 0
		if cfg.Counter != "" {
			b, _ := os.ReadFile(cfg.Counter)
			n, _ = strconv.Atoi(string(b))
			n++
			os.WriteFile(cfg.Counter, []byte(strconv.Itoa(n)), 0600)
		}
		b := []byte(`{"b":2,"a":1}`)
		if n%2 == 0 {
			b = []byte("{\n  \"a\":1, \"b\":2\n}")
		}
		if cfg.Mode == "schema-drift" {
			b = []byte(fmt.Sprintf(`{"revision":%d}`, n))
		}
		if cfg.Mode == "schema-duplicate" {
			b = []byte(`{"a":1,"a":2}`)
		}
		if cfg.Mode == "schema-oversized" {
			b = []byte(`{"x":"` + strings.Repeat("x", 9<<20) + `"}`)
		}
		if cfg.Mode == "schema-link" {
			os.Symlink(cfg.Counter, filepath.Join(dir, "schema.json"))
			return
		}
		if os.WriteFile(filepath.Join(dir, "schema.json"), b, 0600) != nil {
			os.Exit(6)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "app-server" {
		s := bufio.NewScanner(os.Stdin)
		for s.Scan() {
			var req struct {
				ID     any    `json:"id"`
				Method string `json:"method"`
			}
			if json.Unmarshal(s.Bytes(), &req) != nil {
				os.Exit(7)
			}
			if req.ID == nil {
				continue
			}
			var result any = map[string]string{"userAgent": "fixture"}
			if req.Method == "model/list" {
				result = map[string]any{"data": []any{map[string]any{"model": "fixture-model", "supportedReasoningEfforts": []any{map[string]string{"reasoningEffort": "medium"}, map[string]string{"reasoningEffort": "low"}}}}, "nextCursor": nil}
				if cfg.Mode == "catalog-invalid" {
					result = map[string]any{"data": []any{}, "nextCursor": nil}
				}
			}
			b, _ := json.Marshal(map[string]any{"id": req.ID, "result": result})
			fmt.Println(string(b))
		}
		return
	}
	os.Exit(8)
}
