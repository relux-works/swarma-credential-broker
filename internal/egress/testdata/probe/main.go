//go:build linux && amd64

// A synthetic network probe. Every destination is a caller-owned loopback
// endpoint or a documentation address. External TCP attempts have short bounds.
package main

import (
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"time"
	"unsafe"
)

func main() {
	if len(os.Args) < 3 {
		os.Exit(2)
	}
	if compatibility(os.Args[1], os.Args[2]) {
		return
	}
	mode := os.Args[1]
	port, _ := strconv.Atoi(os.Args[2])
	var err error
	if mode == "thread" || mode == "thread-closed" {
		runtime.LockOSThread()
		ch := make(chan error)
		go func() { runtime.LockOSThread(); ch <- connect(mode == "thread-closed", port) }()
		err = <-ch
	} else if mode == "grandchild" {
		c := exec.Command(os.Args[0], "external", os.Args[2])
		c.Env = []string{}
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		if c.Run() != nil {
			os.Exit(1)
		}
		return
	} else if mode == "unix" {
		fd, e := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
		if e != nil {
			panic(e)
		}
		defer unix.Close(fd)
		err = unix.Connect(fd, &unix.SockaddrUnix{Name: os.Args[2]})
	} else if mode == "fd" {
		b, _ := os.ReadFile("/proc/self/fd/4")
		fmt.Print(string(b))
		return
	} else if mode == "env" {
		fmt.Println(os.Getenv("EGRESS_CANARY"))
		return
	} else if mode == "sleep" {
		time.Sleep(time.Hour)
		return
	} else if mode == "check-fd" {
		_, e := unix.FcntlInt(uintptr(port), unix.F_GETFD, 0)
		if e == unix.EBADF {
			fmt.Println("closed")
		} else {
			fmt.Println("open")
		}
		return
	} else if mode == "clone-ns" || mode == "clone3-ns" {
		var r uintptr
		var e unix.Errno
		if mode == "clone-ns" {
			r, _, e = unix.RawSyscall(unix.SYS_CLONE, unix.CLONE_NEWNET|uintptr(unix.SIGCHLD), 0, 0)
		} else {
			a := [11]uint64{uint64(unix.CLONE_NEWNET), 0, 0, 0, uint64(unix.SIGCHLD)}
			r, _, e = unix.RawSyscall(unix.SYS_CLONE3, uintptr(unsafe.Pointer(&a)), 88, 0)
		}
		if e == 0 && r == 0 {
			unix.RawSyscall(unix.SYS_EXIT, 0, 0, 0)
		}
		if e != 0 {
			err = e
		}
	} else if mode == "sockopt" || mode == "sockopt-allowed" {
		fd, e := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
		if e != nil {
			panic(e)
		}
		defer unix.Close(fd)
		if mode == "sockopt-allowed" {
			err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 4096)
		} else {
			err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MULTICAST_IF, 0)
		}
	} else if mode == "syscall" || mode == "seal" {
		nr := port
		_, _, e := unix.Syscall6(uintptr(nr), 0, 0, 0, 0, 0, 0)
		if e != 0 {
			err = e
		}
	} else if mode == "uring" {
		_, _, e := unix.Syscall(unix.SYS_IO_URING_SETUP, 1, 0, 0)
		if e != 0 {
			err = e
		}
	} else if mode == "packet" || mode == "raw" {
		family, kind := unix.AF_PACKET, unix.SOCK_DGRAM
		if mode == "raw" {
			family, kind = unix.AF_INET, unix.SOCK_RAW
		}
		fd, e := unix.Socket(family, kind, 0)
		if fd >= 0 {
			unix.Close(fd)
		}
		if e != nil {
			err = e
		}
	} else if mode == "sendto" || mode == "sendmsg" || mode == "sendmmsg" || mode == "udp-allowed" || mode == "udp-closed" || mode == "msg-allowed" || mode == "mmsg-allowed" || mode == "msg-control" {
		fd, e := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
		if e != nil {
			panic(e)
		}
		defer unix.Close(fd)
		a := &unix.SockaddrInet4{Port: port, Addr: [4]byte{192, 0, 2, 1}}
		if mode == "udp-allowed" || mode == "udp-closed" || mode == "msg-allowed" || mode == "mmsg-allowed" || mode == "msg-control" {
			a.Addr = [4]byte{127, 0, 0, 1}
		}
		if mode == "sendmsg" || mode == "msg-allowed" || mode == "msg-control" {
			var oob []byte
			if mode == "msg-control" {
				oob = make([]byte, unix.CmsgSpace(4))
				h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
				h.Level = unix.IPPROTO_IP
				h.Type = unix.IP_TTL
				h.SetLen(unix.CmsgLen(4))
				binary.LittleEndian.PutUint32(oob[unix.CmsgLen(0):], 64)
			}
			err = unix.Sendmsg(fd, []byte("fixture"), oob, a, 0)
		} else if mode == "sendmmsg" || mode == "mmsg-allowed" {
			sa := unix.RawSockaddrInet4{Family: unix.AF_INET, Port: uint16(port>>8) | uint16(port&255)<<8, Addr: a.Addr}
			b := []byte("fixture")
			io := unix.Iovec{Base: &b[0], Len: uint64(len(b))}
			message := struct {
				Header unix.Msghdr
				Len    uint32
				Pad    uint32
			}{Header: unix.Msghdr{Name: (*byte)(unsafe.Pointer(&sa)), Namelen: 16, Iov: &io, Iovlen: 1}}
			_, _, e := unix.Syscall6(unix.SYS_SENDMMSG, uintptr(fd), uintptr(unsafe.Pointer(&message)), 1, 0, 0, 0)
			if e != 0 {
				err = e
			}
		} else {
			err = unix.Sendto(fd, []byte("fixture"), 0, a)
		}
	} else if mode == "v6" || mode == "mapped" {
		fd, e := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM|unix.SOCK_NONBLOCK, 0)
		if e != nil {
			panic(e)
		}
		defer unix.Close(fd)
		a := &unix.SockaddrInet6{Port: port, Addr: [16]byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}
		if mode == "mapped" {
			a.Addr = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192, 0, 2, 1}
		}
		err = unix.Connect(fd, a)
	} else {
		err = connect(mode == "allowed" || mode == "closed", port)
	}
	if err == nil {
		fmt.Println("allowed")
		return
	}
	fmt.Printf("errno=%d\n", err)
	if err != unix.ECONNREFUSED && err != unix.EAFNOSUPPORT && err != unix.EPERM {
		os.Exit(3)
	}
}
func connect(loop bool, port int) error {
	fd, e := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK, 0)
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	a := &unix.SockaddrInet4{Port: port, Addr: [4]byte{192, 0, 2, 1}}
	if loop {
		a.Addr = [4]byte{127, 0, 0, 1}
	}
	e = unix.Connect(fd, a)
	if e != unix.EINPROGRESS {
		return e
	}
	p := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
	_, _ = unix.Poll(p, 150)
	n, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
	if err != nil {
		return err
	}
	if n == 0 && p[0].Revents != 0 {
		return nil
	}
	if n != 0 {
		return unix.Errno(n)
	}
	return unix.ETIMEDOUT
}
