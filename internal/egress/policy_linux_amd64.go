//go:build linux && amd64

package egress

import (
	"encoding/binary"
	"golang.org/x/sys/unix"
	"path/filepath"
	"strings"
	"unsafe"
)

type notification struct {
	ID    uint64
	PID   uint32
	Flags uint32
	NR    int32
	Arch  uint32
	IP    uint64
	Args  [6]uint64
}
type response struct {
	ID    uint64
	Value int64
	Error int32
	Flags uint32
}
type decision struct {
	family int
	class  string
	port   uint16
	errno  unix.Errno
}

func refusal() decision { return decision{class: "other", errno: unix.ECONNREFUSED} }
func ioctl(fd int, op uintptr, p unsafe.Pointer) error {
	_, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), op, uintptr(p))
	if e != 0 {
		return e
	}
	return nil
}
func valid(fd int, id uint64) bool {
	return ioctl(fd, unix.SECCOMP_IOCTL_NOTIF_ID_VALID, unsafe.Pointer(&id)) == nil
}
func memory(fd int, n notification, addr uint64, size int) ([]byte, error) {
	if size < 0 || size > 4096 || addr == 0 || addr+uint64(size) < addr || !valid(fd, n.ID) {
		return nil, ErrUnavailable
	}
	b := make([]byte, size)
	if size == 0 {
		return b, nil
	}
	local := unix.Iovec{Base: &b[0], Len: uint64(size)}
	got, err := unix.ProcessVMReadv(int(n.PID), []unix.Iovec{local}, []unix.RemoteIovec{{Base: uintptr(addr), Len: size}}, 0)
	if err != nil || got != size || !valid(fd, n.ID) {
		return nil, ErrUnavailable
	}
	return b, nil
}
func (p Policy) address(fd int, n notification, addr, length uint64) decision {
	d := refusal()
	if length < 2 || length > 128 {
		return d
	}
	b, err := memory(fd, n, addr, int(length))
	if err != nil {
		return d
	}
	d.family = int(binary.LittleEndian.Uint16(b))
	d.class = "external"
	switch d.family {
	case unix.AF_INET:
		if len(b) != 16 {
			return d
		}
		d.port = binary.BigEndian.Uint16(b[2:4])
		if b[4] == 127 {
			d.class = "loopback"
		}
	case unix.AF_INET6:
		if len(b) != 28 {
			return d
		}
		d.port = binary.BigEndian.Uint16(b[2:4])
		a := b[8:24]
		loop := true
		for _, v := range a[:15] {
			if v != 0 {
				loop = false
			}
		}
		loop = loop && a[15] == 1
		mapped := true
		for _, v := range a[:10] {
			if v != 0 {
				mapped = false
			}
		}
		mapped = mapped && a[10] == 255 && a[11] == 255
		if loop || (mapped && a[12] == 127) {
			d.class = "loopback"
		}
	case unix.AF_UNIX:
		d.class = "unix"
		if len(b) < 3 || b[2] == 0 {
			return d
		}
		path := string(b[2:])
		if i := strings.IndexByte(path, 0); i >= 0 {
			for _, v := range []byte(path[i:]) {
				if v != 0 {
					return d
				}
			}
			path = path[:i]
		}
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return d
		}
		for _, allowed := range p.UnixPaths {
			if allowed == path {
				d.errno = 0
			}
		}
		return d
	default:
		return d
	}
	if d.class == "loopback" {
		for _, port := range p.Ports {
			if d.port == port {
				d.errno = 0
			}
		}
	}
	return d
}
func (p Policy) message(fd int, n notification, addr uint64) decision {
	b, err := memory(fd, n, addr, 56)
	if err != nil {
		return refusal()
	}
	name := binary.LittleEndian.Uint64(b[:8])
	length := uint64(binary.LittleEndian.Uint32(b[8:12]))
	d := decision{class: "connected"}
	if name != 0 || length != 0 {
		d = p.address(fd, n, name, length)
	}
	// Ancillary routing headers/options may select a destination outside msg_name.
	// Refuse all candidate control data; the trusted bootstrap transfers its
	// listener before the final TSYNC and never passes this candidate check.
	if d.errno == 0 && binary.LittleEndian.Uint64(b[40:48]) != 0 {
		d.errno = unix.EPERM
	}
	return d
}
func (p Policy) decide(fd int, n notification) decision {
	a := n.Args
	switch n.NR {
	case unix.SYS_SOCKET, unix.SYS_SOCKETPAIR:
		d := decision{family: int(a[0]), class: "socket", errno: unix.EAFNOSUPPORT}
		kind := a[1] &^ uint64(unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC)
		protocolOK := a[2] == 0 || (kind == unix.SOCK_STREAM && a[2] == unix.IPPROTO_TCP) || (kind == unix.SOCK_DGRAM && a[2] == unix.IPPROTO_UDP)
		if a[0] == unix.AF_UNIX {
			protocolOK = a[2] == 0
		}
		if protocolOK && (kind == unix.SOCK_STREAM || kind == unix.SOCK_DGRAM || (a[0] == unix.AF_UNIX && kind == unix.SOCK_SEQPACKET)) && (a[0] == unix.AF_UNIX || (n.NR == unix.SYS_SOCKET && (a[0] == unix.AF_INET || a[0] == unix.AF_INET6))) {
			d.errno = 0
		}
		return d
	case unix.SYS_CONNECT:
		return p.address(fd, n, a[1], a[2])
	case unix.SYS_SENDTO:
		if a[4] == 0 && a[5] == 0 {
			return decision{class: "connected"}
		}
		return p.address(fd, n, a[4], a[5])
	case unix.SYS_SENDMSG:
		return p.message(fd, n, a[1])
	case unix.SYS_SENDMMSG:
		if a[2] == 0 || a[2] > 64 {
			return refusal()
		}
		var result decision
		for i := uint64(0); i < a[2]; i++ {
			d := p.message(fd, n, a[1]+i*64)
			if d.errno != 0 {
				return d
			}
			if i == 0 {
				result = d
			} else if result.family != d.family || result.class != d.class || result.port != d.port {
				result = decision{class: "mixed"}
			}
		}
		return result
	case unix.SYS_IOCTL:
		// FIONBIO only changes descriptor nonblocking mode. Keep all other
		// device/interface controls, including FIONREAD, refused.
		if a[1] == 0x5421 {
			return decision{class: "descriptor"}
		}
	case unix.SYS_SETSOCKOPT:
		// No multicast membership, transparent routing, repair or protocol-specific
		// connect options. These listed knobs cannot create a new destination.
		if (a[1] == unix.SOL_SOCKET && (a[2] == unix.SO_REUSEADDR || a[2] == unix.SO_REUSEPORT || a[2] == unix.SO_KEEPALIVE || a[2] == unix.SO_SNDBUF || a[2] == unix.SO_RCVBUF || a[2] == unix.SO_BROADCAST)) ||
			(a[1] == unix.IPPROTO_TCP && (a[2] == unix.TCP_NODELAY || a[2] == unix.TCP_KEEPIDLE || a[2] == unix.TCP_KEEPINTVL || a[2] == unix.TCP_KEEPCNT || a[2] == unix.TCP_USER_TIMEOUT)) ||
			(a[1] == unix.IPPROTO_IPV6 && a[2] == unix.IPV6_V6ONLY) {
			return decision{class: "socket"}
		}
	case unix.SYS_CLONE:
		if a[0]&namespaceFlags == 0 {
			return decision{class: "process"}
		}
	case unix.SYS_CLONE3:
		if a[1] >= 64 && a[1] <= 4096 {
			b, err := memory(fd, n, a[0], 8)
			if err == nil && binary.LittleEndian.Uint64(b)&namespaceFlags == 0 {
				return decision{class: "process"}
			}
		}
	}
	return decision{class: "other", errno: unix.EPERM}
}
