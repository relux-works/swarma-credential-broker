//go:build linux && amd64

package egress

import (
	"context"
	"encoding/binary"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Claim: FIONBIO changes a real descriptor's mode; a valid neighboring FIONREAD
// stays refused by this boundary even though the kernel could perform it.
func TestDescriptorModeIOCTL(t *testing.T) {
	t.Run("unrelated", func(t *testing.T) {
		r, out, err := runProbe(t, Policy{}, "ioctl-unrelated", "0")
		if err != nil || !strings.Contains(out, "errno=1\n") {
			t.Fatalf("unrelated ioctl: %v %s", err, out)
		}
		event(t, r, "ioctl", "other", "refuse")
	})
	t.Run("nonblocking", func(t *testing.T) {
		r, out, err := runProbe(t, Policy{}, "ioctl-nonblocking", "0")
		if err != nil || strings.TrimSpace(out) != "nonblocking" {
			t.Fatalf("descriptor mode: %v %s", err, out)
		}
		event(t, r, "ioctl", "descriptor", "allow")
	})
}

func closedProxy(t *testing.T) uint16 {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	if err = unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	a, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	return uint16(a.(*unix.SockaddrInet4).Port)
}

// Claim: wget honors the generated host exclusions and reaches an admitted HTTP
// fake; an equally reachable host-matching port stays refused by seccomp.
// This uses wget rather than Go's special-case loopback proxy bypass.
func TestLocalProxyClientProbe(t *testing.T) {
	var requests atomic.Int32
	l, port := tcp(t)
	s := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte("fixture"))
	})}
	go s.Serve(l)
	defer s.Close()
	env, err := ProxyEnvironment([]string{"HOME=" + t.TempDir(), "PATH=/usr/bin:/bin", "LANG=C"}, closedProxy(t), []uint16{port})
	if err != nil {
		t.Fatal(err)
	}
	for _, allowed := range []bool{false, true} {
		name := "disallowed-port"
		if allowed {
			name = "allowed-port"
		}
		t.Run(name, func(t *testing.T) {
			out, err := os.CreateTemp(t.TempDir(), "output")
			if err != nil {
				t.Fatal(err)
			}
			defer out.Close()
			p := Policy{}
			if allowed {
				p.Ports = []uint16{port}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			r, runErr := Run(ctx, Config{Launcher: launcher, Executable: "/usr/bin/wget", Args: []string{"-q", "--timeout=2", "--tries=1", "-O", "-", "http://127.0.0.1:" + strconv.Itoa(int(port)) + "/fixture"}, Env: env, Policy: p, Stdout: out, Stderr: out})
			b, err := os.ReadFile(out.Name())
			if err != nil {
				t.Fatal(err)
			}
			if allowed {
				if runErr != nil || string(b) != "fixture" || requests.Load() != 1 || r.Incomplete {
					t.Fatalf("allowed HTTP: %v output=%s requests=%d incomplete=%t", runErr, b, requests.Load(), r.Incomplete)
				}
				event(t, r, "connect", "loopback", "allow")
			} else {
				if runErr == nil || requests.Load() != 0 {
					t.Fatalf("disallowed HTTP: %v requests=%d", runErr, requests.Load())
				}
				event(t, r, "connect", "loopback", "refuse")
			}
			for _, e := range r.Events {
				if e.Syscall == "connect" && e.Port != port {
					t.Fatal("client used proxy instead of host exclusion")
				}
			}
		})
	}
}

// Claim: Go's ordinary UDP setup and DNS query reach a configured loopback
// resolver. Broadcast and TEST-NET resolvers are refused before any query.
func TestLocalDNSProbe(t *testing.T) {
	dns, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer dns.Close()
	var queries atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			b := make([]byte, 512)
			n, peer, err := dns.ReadFromUDP(b)
			if err != nil {
				return
			}
			b = b[:n]
			if n < 17 || binary.BigEndian.Uint16(b[4:6]) != 1 {
				continue
			}
			end := 12
			for end < n && b[end] != 0 {
				end += int(b[end]) + 1
			}
			end += 5
			if end > n || binary.BigEndian.Uint16(b[end-4:end-2]) != 1 {
				continue
			}
			queries.Add(1)
			reply := append([]byte(nil), b[:end]...)
			binary.BigEndian.PutUint16(reply[2:4], 0x8180)
			binary.BigEndian.PutUint16(reply[6:8], 1)
			for i := 8; i < 12; i++ {
				reply[i] = 0
			}
			reply = append(reply, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1)
			_, _ = dns.WriteToUDP(reply, peer)
		}
	}()
	defer func() { dns.Close(); <-done }()
	port := uint16(dns.LocalAddr().(*net.UDPAddr).Port)
	for _, host := range []string{"255.255.255.255", "192.0.2.1", "127.0.0.1"} {
		t.Run(host, func(t *testing.T) {
			before := queries.Load()
			r, out, err := runProbe(t, Policy{Ports: []uint16{port}}, "dns", net.JoinHostPort(host, strconv.Itoa(int(port))))
			if err != nil || r.Incomplete {
				t.Fatalf("resolver run: %v %s", err, out)
			}
			if host == "127.0.0.1" {
				if !strings.Contains(out, "resolved=127.0.0.1") || queries.Load() <= before {
					t.Fatalf("missing local answer: %s queries=%d", out, queries.Load())
				}
				event(t, r, "connect", "loopback", "allow")
				event(t, r, "setsockopt", "socket", "allow")
			} else {
				if !strings.Contains(out, "dns-errno=111") || queries.Load() != before {
					t.Fatalf("resolver was not refused: %s queries=%d", out, queries.Load())
				}
				event(t, r, "connect", "external", "refuse")
			}
		})
	}
}

// Claim: addressed broadcast DNS datagrams are refused at sendto/sendmsg even
// for an otherwise admitted port. SO_BROADCAST remains off in this probe so a
// narrowing mutant cannot emit a broadcast; allowed unicast controls are in
// TestLocalDNSProbe and TestDatagramPolicy.
func TestBroadcastSendRefused(t *testing.T) {
	for _, mode := range []string{"broadcast-sendto", "broadcast-sendmsg"} {
		t.Run(mode, func(t *testing.T) {
			r, out, err := runProbe(t, Policy{Ports: []uint16{53}}, mode, "53")
			if err != nil || !strings.Contains(out, "errno=111\n") || r.Incomplete {
				t.Fatalf("broadcast query: %v %s", err, out)
			}
			call := strings.TrimPrefix(mode, "broadcast-")
			event(t, r, call, "external", "refuse")
		})
	}
}
