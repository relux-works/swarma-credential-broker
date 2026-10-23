//go:build linux

package timeconf

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}
func makeConfigDir(t *testing.T, path string) {
	t.Helper()
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
}
func directoryFixture(t *testing.T) (Policy, *runnerFixture, string, string, string, string) {
	t.Helper()
	root := protectedTemp(t)
	sources, conf, dhcp := filepath.Join(root, "sources"), filepath.Join(root, "conf"), filepath.Join(root, "dhcp")
	makeConfigDir(t, sources)
	makeConfigDir(t, conf)
	exe := filepath.Join(root, "chronyc-fixture")
	if err := os.WriteFile(exe, nil, 0500); err != nil {
		t.Fatal(err)
	}
	main := filepath.Join(root, "chrony.conf")
	writeConfig(t, main, "sourcedir "+sources+"\nsourcedir "+dhcp+"\nconfdir "+conf+"\nleapseclist /fixture/leap-seconds.list\n")
	writeConfig(t, filepath.Join(sources, "pool.sources"), "pool 192.0.2.1 nts iburst\n")
	writeConfig(t, filepath.Join(conf, "settings.conf"), "rtcsync\nmakestep 1.0 3\n")
	p := testPolicy()
	p.Chronyc = exe
	p.SourceFiles = []string{main}
	return p, &runnerFixture{output: []byte(goodCSV)}, root, sources, conf, dhcp
}
func directoryProvider(t *testing.T, p Policy, r *runnerFixture) *Provider {
	t.Helper()
	v, err := ParseTracking([]byte(goodCSV))
	if err != nil {
		t.Fatal(err)
	}
	clock := &fakeClock{point: ClockPoint{Now: v.Reference.Add(time.Second), Elapsed: time.Hour, Boot: "fixture-boot"}}
	provider, err := New(p, SystemCollector{Runner: r}, clock, nil)
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

// Claim: a host-shaped inventory with an absent DHCP directory and recursive
// configuration files trusts an in-tolerance selection found only in .sources.
// Named matching uses chronyd's original name with unchanged tracking identity.
func TestSourceDirectorySelection(t *testing.T) {
	for _, name := range []bool{false, true} {
		t.Run(map[bool]string{false: "address", true: "name"}[name], func(t *testing.T) {
			p, r, root, sources, conf, _ := directoryFixture(t)
			nested := filepath.Join(root, "nested")
			makeConfigDir(t, nested)
			writeConfig(t, filepath.Join(conf, "nested.conf"), "confdir "+nested+"\n")
			writeConfig(t, filepath.Join(nested, "settings.conf"), "maxupdateskew 100\n")
			if name {
				writeConfig(t, filepath.Join(sources, "pool.sources"), "pool time.example nts\n")
				r.named = []byte(strings.Replace(goodCSV, "192.0.2.1", "time.example", 1))
			}
			trusted(t, directoryProvider(t, p, r))
			e, err := (SystemCollector{Runner: r}).Collect(context.Background(), p)
			if err != nil || e.Sources.Count != 1 || !e.Sources.AllNTS {
				t.Fatal("source union mismatch", err)
			}
		})
	}
}

// Claim: unsafe or invalid effective directory inputs refuse before launching
// any command, with a trusted control before each independent fault. Ignored
// suffixes add no sources; sourcedir files accept only newline-terminated sources.
func TestSourceDirectoryFailures(t *testing.T) {
	cases := map[string]func(*testing.T, Policy, string, string, string){
		"non-nts": func(t *testing.T, p Policy, s, c, root string) {
			writeConfig(t, filepath.Join(s, "pool.sources"), "server 192.0.2.1 iburst\n")
		},
		"unsafe-directory": func(t *testing.T, p Policy, s, c, root string) {
			if os.Chmod(s, 0777) != nil {
				t.Fatal("chmod failed")
			}
		},
		"oversized-file": func(t *testing.T, p Policy, s, c, root string) {
			writeConfig(t, filepath.Join(s, "pool.sources"), strings.Repeat("#", p.MaxOutputBytes+1))
		},
		"unreadable-file": func(t *testing.T, p Policy, s, c, root string) {
			if os.Chmod(filepath.Join(s, "pool.sources"), 0000) != nil {
				t.Fatal("chmod failed")
			}
		},
		"writable-file": func(t *testing.T, p Policy, s, c, root string) {
			if os.Chmod(filepath.Join(s, "pool.sources"), 0666) != nil {
				t.Fatal("chmod failed")
			}
		},
		"file-symlink": func(t *testing.T, p Policy, s, c, root string) {
			if os.Symlink(filepath.Join(s, "pool.sources"), filepath.Join(s, "link.sources")) != nil {
				t.Fatal("symlink failed")
			}
		},
		"file-hardlink": func(t *testing.T, p Policy, s, c, root string) {
			if os.Link(filepath.Join(s, "pool.sources"), filepath.Join(s, "link.sources")) != nil {
				t.Fatal("hardlink failed")
			}
		},
		"directory-symlink": func(t *testing.T, p Policy, s, c, root string) {
			link := filepath.Join(root, "link")
			if os.Symlink(s, link) != nil {
				t.Fatal("symlink failed")
			}
			writeConfig(t, p.SourceFiles[0], "sourcedir "+link+"\n")
		},
		"directory-ancestor": func(t *testing.T, p Policy, s, c, root string) {
			if os.Chmod(root, 0777) != nil {
				t.Fatal("chmod failed")
			}
			t.Cleanup(func() { os.Chmod(root, 0700) })
		},
		"no-newline": func(t *testing.T, p Policy, s, c, root string) {
			writeConfig(t, filepath.Join(s, "pool.sources"), "server 192.0.2.1 nts")
		},
		"non-source-directive": func(t *testing.T, p Policy, s, c, root string) {
			writeConfig(t, filepath.Join(s, "pool.sources"), "rtcsync\nserver 192.0.2.1 nts\n")
		},
		"source-in-confdir": func(t *testing.T, p Policy, s, c, root string) {
			writeConfig(t, filepath.Join(c, "extra.conf"), "server 192.0.2.2\n")
		},
		"recursive-cycle": func(t *testing.T, p Policy, s, c, root string) {
			writeConfig(t, filepath.Join(c, "cycle.conf"), "confdir "+c+"\n")
		},
		"include": func(t *testing.T, p Policy, s, c, root string) {
			writeConfig(t, filepath.Join(c, "include.conf"), "include /fixture/other.conf\n")
		},
		"relative-directory": func(t *testing.T, p Policy, s, c, root string) {
			writeConfig(t, p.SourceFiles[0], "sourcedir relative\n")
		},
		"directory-as-file": func(t *testing.T, p Policy, s, c, root string) {
			makeConfigDir(t, filepath.Join(s, "directory.sources"))
		},
	}
	for name, fault := range cases {
		t.Run(name, func(t *testing.T) {
			p, r, root, s, c, _ := directoryFixture(t)
			trusted(t, directoryProvider(t, p, r))
			r.calls = nil
			fault(t, p, s, c, root)
			refused(t, directoryProvider(t, p, r))
			if len(r.calls) != 0 {
				t.Fatal("unsafe configuration reached collector command")
			}
		})
	}
	p, r, _, s, _, _ := directoryFixture(t)
	writeConfig(t, filepath.Join(s, "ignored.txt"), "server 192.0.2.2\n")
	trusted(t, directoryProvider(t, p, r))
}

// Claim: every sample rechecks directories, including DHCP directories that
// appear after a trusted sample. Non-NTS data keeps subsequent samples closed;
// replacing it with an NTS association permits the positive recovery control.
func TestSourceDirectoryDHCPReread(t *testing.T) {
	p, r, _, _, _, dhcp := directoryFixture(t)
	provider := directoryProvider(t, p, r)
	trusted(t, provider)
	makeConfigDir(t, dhcp)
	file := filepath.Join(dhcp, "lease.sources")
	writeConfig(t, file, "server 192.0.2.2 iburst\n")
	refused(t, provider)
	refused(t, provider)
	writeConfig(t, file, "server 192.0.2.2 nts\n")
	trusted(t, provider)
}

// Claim: each directory directive combines filenames lexicographically and
// selects the first directory for duplicate basenames, as chrony does. A later
// unique non-NTS file must still refuse; the shadowed file has no authority.
func TestSourceDirectoryOrderingAndPrecedence(t *testing.T) {
	for _, kind := range []string{"sourcedir", "confdir"} {
		t.Run(kind, func(t *testing.T) {
			p, r, _, first, second, _ := directoryFixture(t)
			suffix := ".sources"
			if kind == "confdir" {
				suffix = ".conf"
			}
			writeConfig(t, p.SourceFiles[0], kind+" "+first+" "+second+"\n")
			if err := os.Remove(filepath.Join(first, "pool.sources")); err != nil {
				t.Fatal(err)
			}
			writeConfig(t, filepath.Join(first, "z"+suffix), "server 192.0.2.1 nts\n")
			writeConfig(t, filepath.Join(second, "a"+suffix), "server 192.0.2.2 nts\n")
			writeConfig(t, filepath.Join(second, "z"+suffix), "server 192.0.2.3\n")
			e, err := (SystemCollector{Runner: r}).Collect(context.Background(), p)
			if err != nil || !reflect.DeepEqual(e.Sources.Entries, []string{"192.0.2.2", "192.0.2.1"}) {
				t.Fatal("directory precedence/order mismatch", err)
			}
			writeConfig(t, filepath.Join(second, "b"+suffix), "server 192.0.2.4\n")
			refused(t, directoryProvider(t, p, r))
		})
	}
}

// Claim: inventory work cannot grow past the file, directory, entry or aggregate
// byte budgets. Small neighboring inventories still pass the same reader.
func TestConfigurationExpansionBudgets(t *testing.T) {
	for _, counter := range []string{"files", "directories", "entries", "bytes"} {
		t.Run(counter, func(t *testing.T) {
			p, _, _, s, _, _ := directoryFixture(t)
			r := configReader{ctx: context.Background(), uid: uint32(os.Geteuid()), limit: p.MaxOutputBytes}
			switch counter {
			case "files":
				r.files = maxConfigFiles
			case "directories":
				r.directories = maxConfigDirectories
			case "entries":
				r.entries = maxConfigEntries
			case "bytes":
				r.bytes = maxConfigBytes
			}
			if _, err := r.file(p.SourceFiles[0], false, 0); err == nil {
				t.Fatal("exhausted budget accepted")
			}
			r = configReader{ctx: context.Background(), uid: uint32(os.Geteuid()), limit: p.MaxOutputBytes}
			if _, err := r.file(filepath.Join(s, "pool.sources"), true, 0); err != nil {
				t.Fatal("small control refused", err)
			}
		})
	}
}

// Claim: quoted prose in ignored comments cannot reject standard configuration;
// quotes/escapes in effective directives still refuse instead of changing tokens.
func TestConfigurationComments(t *testing.T) {
	for _, prefix := range []string{"#", "!", ";", "%"} {
		b := []byte(prefix + " ignored \"text\" and apostrophe's \\notes\nserver 192.0.2.1 nts # ignored \"text\"\n")
		if _, err := ParseSources(b); err != nil {
			t.Fatal("comment prose refused", err)
		}
	}
	for _, line := range []string{`server "192.0.2.1" nts`, `server '192.0.2.1' nts`, `server 192.0.2.1 nts\\`} {
		if _, err := ParseSources([]byte(line + "\n")); err == nil {
			t.Fatal("effective quoting/escape accepted")
		}
	}
}
