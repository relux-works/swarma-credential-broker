//go:build linux && amd64

package egress

import (
	"golang.org/x/sys/unix"
	"runtime"
	"unsafe"
)

const namespaceFlags = unix.CLONE_NEWCGROUP | unix.CLONE_NEWIPC | unix.CLONE_NEWNET | unix.CLONE_NEWNS | unix.CLONE_NEWPID | unix.CLONE_NEWUSER | unix.CLONE_NEWUTS | unix.CLONE_NEWTIME | unix.CLONE_UNTRACED

var names = map[int32]string{
	unix.SYS_SOCKET: "socket", unix.SYS_SOCKETPAIR: "socketpair", unix.SYS_CONNECT: "connect",
	unix.SYS_SENDTO: "sendto", unix.SYS_SENDMSG: "sendmsg", unix.SYS_SENDMMSG: "sendmmsg",
	unix.SYS_CLONE: "clone", unix.SYS_CLONE3: "clone3",
	unix.SYS_IO_URING_SETUP: "io_uring_setup", unix.SYS_IO_URING_ENTER: "io_uring_enter", unix.SYS_IO_URING_REGISTER: "io_uring_register",
	unix.SYS_BPF: "bpf", unix.SYS_PTRACE: "ptrace", unix.SYS_PROCESS_VM_WRITEV: "process_vm_writev", unix.SYS_UNSHARE: "unshare", unix.SYS_SETNS: "setns",
	unix.SYS_PIDFD_GETFD: "pidfd_getfd", unix.SYS_RECVMSG: "recvmsg", unix.SYS_RECVMMSG: "recvmmsg",
	unix.SYS_IOCTL: "ioctl", unix.SYS_SETSOCKOPT: "setsockopt",
	unix.SYS_SETSID: "setsid", unix.SYS_SETPGID: "setpgid",
	unix.SYS_BIND: "bind", unix.SYS_LISTEN: "listen", unix.SYS_ACCEPT: "accept", unix.SYS_ACCEPT4: "accept4",
}

func stmt(code uint16, k uint32) unix.SockFilter { return unix.SockFilter{Code: code, K: k} }
func jump(k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: k, Jt: jt, Jf: jf}
}

func notifyFilter() []unix.SockFilter {
	f := []unix.SockFilter{
		stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 4), jump(unix.AUDIT_ARCH_X86_64, 1, 0), stmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_KILL_PROCESS),
		stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 0),
		{Code: unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, K: 0x40000000, Jf: 1}, stmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_KILL_PROCESS),
	}
	// All listed calls are supervised, including denials, to retain bounded evidence.
	for nr := range names {
		f = append(f, jump(uint32(nr), 0, 1), stmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_USER_NOTIF))
	}
	return append(f, stmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ALLOW))
}

// The final TSYNC carries the installer's entire listener-bearing filter tree
// onto every bootstrap thread. Seal filter changes before untrusted exec.
func sealFilter() []unix.SockFilter {
	return []unix.SockFilter{
		stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 0), jump(unix.SYS_SECCOMP, 0, 1), stmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM)),
		jump(unix.SYS_PRCTL, 0, 3), stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 16), jump(unix.PR_SET_SECCOMP, 0, 1), stmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM)),
		stmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ALLOW),
	}
}

func install(f []unix.SockFilter, flags uintptr) (int, error) {
	p := unix.SockFprog{Len: uint16(len(f)), Filter: &f[0]}
	r, _, e := unix.RawSyscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, flags, uintptr(unsafe.Pointer(&p)))
	runtime.KeepAlive(f)
	if e != 0 {
		return -1, e
	}
	return int(r), nil
}
