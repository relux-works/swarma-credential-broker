import ctypes
import errno
import os
import socket
import sys


class ArgumentComparison(ctypes.Structure):
    _fields_ = [
        ("arg", ctypes.c_uint),
        ("op", ctypes.c_uint),
        ("datum_a", ctypes.c_uint64),
        ("datum_b", ctypes.c_uint64),
    ]


def restrict_network():
    library = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    library.seccomp_init.argtypes = [ctypes.c_uint32]
    library.seccomp_init.restype = ctypes.c_void_p
    library.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    library.seccomp_syscall_resolve_name.restype = ctypes.c_int
    library.seccomp_rule_add_array.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint,
        ctypes.POINTER(ArgumentComparison),
    ]
    library.seccomp_rule_add_array.restype = ctypes.c_int
    library.seccomp_load.argtypes = [ctypes.c_void_p]
    library.seccomp_load.restype = ctypes.c_int
    library.seccomp_release.argtypes = [ctypes.c_void_p]
    context = library.seccomp_init(0x7FFF0000)
    if not context:
        raise RuntimeError("seccomp_init failed")
    try:
        refusal = 0x00050000 | errno.EPERM
        comparison = ArgumentComparison(0, 1, socket.AF_UNIX, 0)
        syscall = library.seccomp_syscall_resolve_name(b"socket")
        if syscall < 0:
            raise RuntimeError("socket syscall unavailable")
        result = library.seccomp_rule_add_array(context, refusal, syscall, 1, ctypes.byref(comparison))
        if result != 0:
            raise RuntimeError(f"socket seccomp rule failed: {result}")
        for name in (b"io_uring_setup", b"io_uring_enter", b"io_uring_register", b"socketcall"):
            syscall = library.seccomp_syscall_resolve_name(name)
            if syscall >= 0:
                result = library.seccomp_rule_add_array(context, refusal, syscall, 0, None)
                if result != 0:
                    raise RuntimeError(f"{name.decode()} rule failed: {result}")
        result = library.seccomp_load(context)
        if result != 0:
            raise RuntimeError(f"seccomp_load failed: {result}")
    finally:
        library.seccomp_release(context)


def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: socket_only.py EXECUTABLE [ARG ...]")
    os.closerange(3, 1048576)
    restrict_network()
    os.execv(sys.argv[1], sys.argv[1:])


if __name__ == "__main__":
    main()
