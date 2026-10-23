//go:build linux && amd64

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

func compatibility(mode, arg string) bool {
	switch mode {
	case "ioctl-nonblocking", "ioctl-unrelated":
		var fds [2]int
		if err := unix.Pipe2(fds[:], unix.O_CLOEXEC); err != nil {
			panic(err)
		}
		defer unix.Close(fds[0])
		defer unix.Close(fds[1])
		if mode == "ioctl-nonblocking" {
			// FIONBIO changes descriptor mode without selecting a destination.
			err := unix.IoctlSetPointerInt(fds[0], 0x5421, 1)
			flags, flagErr := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFL, 0)
			if err != nil || flagErr != nil || flags&unix.O_NONBLOCK == 0 {
				fmt.Printf("nonblocking failed: %v %v\n", err, flagErr)
				os.Exit(3)
			}
			fmt.Println("nonblocking")
		} else {
			// A valid FIONREAD would succeed if the whole ioctl family were allowed.
			_, err := unix.IoctlGetInt(fds[0], unix.TIOCINQ)
			fmt.Printf("errno=%d\n", err)
		}
	case "dns":
		var refused atomic.Bool
		resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: time.Second}
			c, err := d.DialContext(ctx, "udp4", arg)
			if errors.Is(err, unix.ECONNREFUSED) {
				refused.Store(true)
			}
			return c, err
		}}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		ips, err := resolver.LookupIP(ctx, "ip4", "fixture.test")
		// net.DNSError may retain only text, so check the actual Dial error above.
		if err != nil && refused.Load() {
			fmt.Println("dns-errno=111")
		} else if err != nil || len(ips) != 1 || !ips[0].Equal(net.IPv4(127, 0, 0, 1)) {
			fmt.Printf("DNS failed: %v %v\n", err, ips)
			os.Exit(3)
		} else {
			fmt.Println("resolved=127.0.0.1")
		}
	case "broadcast-sendto", "broadcast-sendmsg":
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
		if err != nil {
			panic(err)
		}
		defer unix.Close(fd)
		// Leave broadcast disabled: even a mutated supervisor cannot emit this
		// packet. A continuation reaches the kernel's EACCES rather than EPERM
		// or the supervisor's expected ECONNREFUSED, and still fails the test.
		flag, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BROADCAST)
		if err != nil || flag != 0 {
			panic("broadcast safety control unavailable")
		}
		port, _ := strconv.Atoi(arg)
		dest := &unix.SockaddrInet4{Addr: [4]byte{255, 255, 255, 255}, Port: port}
		// A single fixture.test A query; no external resolver is used.
		query := []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'f', 'i', 'x', 't', 'u', 'r', 'e', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1}
		if mode == "broadcast-sendto" {
			err = unix.Sendto(fd, query, 0, dest)
		} else {
			err = unix.Sendmsg(fd, query, nil, dest, 0)
		}
		fmt.Printf("errno=%d\n", err)
	default:
		return false
	}
	return true
}
