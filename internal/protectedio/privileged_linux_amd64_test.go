//go:build privileged && linux && amd64

package protectedio

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const privilegedOwner = 42001
const privilegedGroup = 42002
const privilegedOther = 42003

type privilegedObservation struct {
	TID      int
	Device   uint64
	Inode    uint64
	Size     int64
	Control  bool
	Refused  bool
	Callback bool
}

func privilegedRequire(test *testing.T, err error) {
	test.Helper()
	if err != nil {
		test.Fatalf("privileged fixture setup: %v", err)
	}
}

func privilegedFile(test *testing.T, path, contents string, owner, group int, mode fs.FileMode) FilePolicy {
	test.Helper()
	privilegedRequire(test, os.WriteFile(path, []byte(contents), 0600))
	privilegedRequire(test, os.Chown(path, owner, group))
	privilegedRequire(test, os.Chmod(path, mode))
	return FilePolicy{UID: uint32(owner), GID: uint32(group), Mode: mode, Links: 1, MaxBytes: int64(len(contents))}
}

func privilegedDirectory(test *testing.T, path string, owner, group int, mode fs.FileMode) {
	test.Helper()
	privilegedRequire(test, os.MkdirAll(path, 0700))
	privilegedRequire(test, os.Chown(path, owner, group))
	privilegedRequire(test, os.Chmod(path, mode))
}

func privilegedRead(path string, policy FilePolicy) bool {
	metadata, contents, err := (Reader{}).Read(context.Background(), path, policy)
	return err == nil && string(contents) == "inert" && metadata.UID == policy.UID && metadata.GID == policy.GID && metadata.Size == 5
}

func privilegedRefused(path string, policy FilePolicy) bool {
	metadata, contents, err := (Reader{}).Read(context.Background(), path, policy)
	return errors.Is(err, ErrProtection) && metadata == (Identity{}) && contents == nil
}

func privilegedFixture(test *testing.T, scenario string) privilegedObservation {
	test.Helper()
	var result privilegedObservation
	switch scenario {
	case "owner", "other-write", "group-write", "sticky", "setgid", "setuid":
		policy := privilegedFile(test, "/record", "inert", privilegedOwner, privilegedGroup, 0640)
		result.Control = privilegedRead("/record", policy)
		modes := map[string]fs.FileMode{"other-write": 0757, "group-write": 0775, "sticky": 0755 | fs.ModeSticky, "setgid": 0755 | fs.ModeSetgid, "setuid": 0755 | fs.ModeSetuid}
		if scenario == "owner" {
			privilegedRequire(test, os.Chown("/", privilegedOther, 0))
		} else {
			privilegedRequire(test, os.Chmod("/", modes[scenario]))
		}
		observed, err := os.Stat("/")
		privilegedRequire(test, err)
		stat := observed.Sys().(*syscall.Stat_t)
		if scenario == "owner" && stat.Uid != privilegedOther || scenario != "owner" && observed.Mode() != fs.ModeDir|modes[scenario] {
			test.Fatal("privileged root inode precondition missing")
		}
		result.Refused = privilegedRefused("/record", policy)
	case "policy-owner":
		privilegedDirectory(test, "/policy", privilegedOwner, privilegedGroup, 0750)
		policy := privilegedFile(test, "/policy/record", "inert", privilegedOwner, privilegedGroup, 0640)
		result.Control = privilegedRead("/policy/record", policy)
		privilegedRequire(test, os.Chown("/policy", privilegedOther, privilegedGroup))
		result.Refused = privilegedRefused("/policy/record", policy)
	case "gate-parent-owner", "gate-parent-group", "gate-ancestor-owner", "window-parent-owner", "window-parent-group", "window-ancestor-owner", "gate-leaf-owner", "gate-leaf-group":
		privilegedDirectory(test, "/locks", privilegedOwner, privilegedGroup, 0750)
		privilegedDirectory(test, "/locks/parent", privilegedOwner, privilegedGroup, 0750)
		policy := privilegedFile(test, "/locks/parent/lock", "", privilegedOwner, privilegedGroup, 0640)
		gate, err := NewConfigGate(context.Background(), "/locks/parent/lock", policy)
		if err == nil && gate != nil {
			called := false
			err = gate.WithRead(context.Background(), func(context.Context) error { called = true; return nil })
			result.Control = err == nil && called
		}
		target, owner, group := "/locks/parent", privilegedOwner, privilegedGroup
		switch scenario {
		case "gate-parent-owner", "window-parent-owner":
			owner = privilegedOther
		case "gate-parent-group", "window-parent-group":
			group = privilegedOther
		case "gate-ancestor-owner", "window-ancestor-owner":
			target, owner = "/locks", privilegedOther
		case "gate-leaf-owner":
			target, owner = "/locks/parent/lock", privilegedOther
		case "gate-leaf-group":
			target, group = "/locks/parent/lock", privilegedOther
		}
		privilegedRequire(test, os.Chown(target, owner, group))
		if len(scenario) >= 7 && scenario[:7] == "window-" {
			if gate != nil {
				err = gate.WithRead(context.Background(), func(context.Context) error { result.Callback = true; return nil })
				result.Refused = errors.Is(err, ErrProtection) && !result.Callback
			}
		} else {
			gate, err = NewConfigGate(context.Background(), "/locks/parent/lock", policy)
			result.Refused = errors.Is(err, ErrProtection) && gate == nil
		}
	default:
		test.Fatalf("unknown privileged fixture %q", scenario)
	}
	return result
}

func privilegedProcess(test *testing.T, scenario string) privilegedObservation {
	test.Helper()
	if os.Geteuid() != 0 {
		test.Fatal("privileged fixtures require actual root; no skip is permitted")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestPrivilegedChild$", "-test.timeout=10s")
	command.Env = append(os.Environ(), "PROTECTEDIO_PRIVILEGED_SCENARIO="+scenario, "PROTECTEDIO_PRIVILEGED_ROOT="+test.TempDir())
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS}
	reader, writer, err := os.Pipe()
	privilegedRequire(test, err)
	defer reader.Close()
	defer writer.Close()
	command.ExtraFiles = []*os.File{writer}
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	privilegedRequire(test, command.Start())
	pid := command.Process.Pid
	test.Logf("privileged fixture child pid=%d scenario=%s", pid, scenario)
	waited := false
	defer func() {
		if !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	privilegedRequire(test, writer.Close())
	decoder := json.NewDecoder(reader)
	var result privilegedObservation
	if scenario == "read-fault" || scenario == "negative-size" {
		var target privilegedObservation
		privilegedRequire(test, decoder.Decode(&target))
		if !target.Control || target.Size != 5 || target.Inode == 0 {
			test.Fatal("privileged fault valid control or target identity missing")
		}
		privilegedTrace(test, target, scenario)
	}
	decodeErr := decoder.Decode(&result)
	waitErr := command.Wait()
	waited = true
	if decodeErr != nil || waitErr != nil || ctx.Err() != nil {
		test.Fatalf("privileged fixture infrastructure failed: decode=%v wait=%v context=%v: %s", decodeErr, waitErr, ctx.Err(), output.String())
	}
	return result
}

// Claim: each unsafe actual root owner or single forbidden mode bit refuses with zero results beside an accepted safe-root read.
func TestPrivilegedActualRoot(test *testing.T) {
	for _, scenario := range []string{"owner", "other-write", "group-write", "sticky", "setgid", "setuid"} {
		test.Run(scenario, func(test *testing.T) {
			result := privilegedProcess(test, scenario)
			if !result.Control {
				test.Fatal("privileged root valid control refused")
			}
			if !result.Refused {
				test.Fatal("ASSERT_PRIVILEGED_ROOT: unsafe actual root admitted or partial result")
			}
		})
	}
}

// Claim: a non-process-owned policy ancestor and leaf admit a read, while a third-party ancestor refuses without partial results.
func TestPrivilegedPolicyOwner(test *testing.T) {
	result := privilegedProcess(test, "policy-owner")
	if !result.Control {
		test.Fatal("ASSERT_PRIVILEGED_POLICY: separately owned valid read refused")
	}
	if !result.Refused {
		test.Fatal("ASSERT_PRIVILEGED_POLICY: third-party ancestor admitted or partial result")
	}
}

// Claim: distinct lock owner/group controls construct and enter a gate; mismatched parent, ancestor or leaf ownership refuses with no callback.
func TestPrivilegedGateOwners(test *testing.T) {
	for _, scenario := range []string{"gate-parent-owner", "gate-parent-group", "gate-ancestor-owner", "window-parent-owner", "window-parent-group", "window-ancestor-owner", "gate-leaf-owner", "gate-leaf-group"} {
		test.Run(scenario, func(test *testing.T) {
			result := privilegedProcess(test, scenario)
			if !result.Control {
				test.Fatal("ASSERT_PRIVILEGED_GATE: separately owned/grouped valid gate refused")
			}
			if !result.Refused || result.Callback {
				test.Fatal("ASSERT_PRIVILEGED_GATE: mismatched hierarchy admitted or callback invoked")
			}
		})
	}
}

// Claim: a non-EOF read error after exactly the saved byte count refuses without partial results beside an uninjected full read.
func TestPrivilegedReadFault(test *testing.T) {
	result := privilegedProcess(test, "read-fault")
	if !result.Control || !result.Refused {
		test.Fatal("ASSERT_PRIVILEGED_READ: equal-size non-EOF read error admitted or partial result")
	}
}

// Claim: a stable negative leaf stat size refuses openFile before reading beside the same descriptor's positive-size valid control.
func TestPrivilegedNegativeSize(test *testing.T) {
	result := privilegedProcess(test, "negative-size")
	if !result.Control || !result.Refused {
		test.Fatal("ASSERT_PRIVILEGED_SIZE: negative saved size admitted by openFile")
	}
}

// Claim: the fixture child changes only a private tmpfs root; fault children trace only their pinned test thread and owned inert inode.
func TestPrivilegedChild(test *testing.T) {
	scenario := os.Getenv("PROTECTEDIO_PRIVILEGED_SCENARIO")
	root := os.Getenv("PROTECTEDIO_PRIVILEGED_ROOT")
	if os.Geteuid() != 0 || scenario == "" || !filepath.IsAbs(root) || root == "/" {
		test.Fatal("privileged child requires root and an explicit isolated fixture root")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	privilegedRequire(test, unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""))
	privilegedRequire(test, unix.Mount("tmpfs", root, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0755,size=1m"))
	privilegedRequire(test, unix.Chroot(root))
	privilegedRequire(test, os.Chdir("/"))
	privilegedRequire(test, os.Chmod("/", 0755))
	output := os.NewFile(3, "privileged-result")
	defer output.Close()
	encoder := json.NewEncoder(output)
	if scenario != "read-fault" && scenario != "negative-size" {
		privilegedRequire(test, encoder.Encode(privilegedFixture(test, scenario)))
		return
	}
	policy := privilegedFile(test, "/record", "inert", privilegedOwner, privilegedGroup, 0640)
	var stat unix.Stat_t
	privilegedRequire(test, unix.Stat("/record", &stat))
	result := privilegedObservation{TID: unix.Gettid(), Device: uint64(stat.Dev), Inode: stat.Ino, Size: stat.Size, Control: privilegedRead("/record", policy)}
	privilegedRequire(test, encoder.Encode(result))
	_, _, errno := unix.RawSyscall6(unix.SYS_PTRACE, unix.PTRACE_TRACEME, 0, 0, 0, 0, 0)
	if errno != 0 {
		test.Fatalf("privileged fault traceme: %v", errno)
	}
	privilegedRequire(test, unix.Tgkill(os.Getpid(), unix.Gettid(), unix.SIGSTOP))
	if scenario == "read-fault" {
		result.Refused = privilegedRefused("/record", policy)
	} else {
		opened, err := openFile(context.Background(), "/record", policy)
		result.Refused = errors.Is(err, ErrProtection) && opened == nil
		if opened != nil {
			opened.close()
		}
	}
	privilegedRequire(test, encoder.Encode(result))
}

func privilegedTrace(test *testing.T, target privilegedObservation, scenario string) {
	test.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var status unix.WaitStatus
	_, err := unix.Wait4(target.TID, &status, unix.WALL, nil)
	privilegedRequire(test, err)
	if !status.Stopped() || status.StopSignal() != unix.SIGSTOP {
		test.Fatalf("privileged trace initial stop: %v", status)
	}
	privilegedRequire(test, unix.PtraceSetOptions(target.TID, unix.PTRACE_O_TRACESYSGOOD|unix.PTRACE_O_EXITKILL))
	var number, first, second, third uint64
	leafFD := uint64(^uint64(0))
	readBytes, injections := int64(0), 0
	signal := 0
	for {
		privilegedRequire(test, unix.PtraceSyscall(target.TID, signal))
		_, err = unix.Wait4(target.TID, &status, unix.WALL, nil)
		privilegedRequire(test, err)
		if !status.Stopped() {
			test.Fatalf("privileged trace ended before completion: %v", status)
		}
		signal = 0
		if status.StopSignal() != unix.SIGTRAP|0x80 {
			signal = int(status.StopSignal())
			continue
		}
		var info [88]byte
		_, _, errno := unix.RawSyscall6(unix.SYS_PTRACE, unix.PTRACE_GET_SYSCALL_INFO, uintptr(target.TID), uintptr(len(info)), uintptr(unsafe.Pointer(&info[0])), 0, 0)
		if errno != 0 {
			test.Fatalf("privileged syscall info: %v", errno)
		}
		switch info[0] {
		case unix.PTRACE_SYSCALL_INFO_ENTRY:
			number = binary.LittleEndian.Uint64(info[24:32])
			first = binary.LittleEndian.Uint64(info[32:40])
			second = binary.LittleEndian.Uint64(info[40:48])
			third = binary.LittleEndian.Uint64(info[48:56])
			if number == unix.SYS_WRITE && first == 3 {
				privilegedRequire(test, unix.PtraceDetach(target.TID))
				if injections == 0 || scenario == "read-fault" && (injections != 1 || readBytes != target.Size) {
					test.Fatalf("privileged fault not applied to intended target: injections=%d bytes=%d size=%d", injections, readBytes, target.Size)
				}
				test.Logf("fault instrument scenario=%s injections=%d read_bytes=%d saved_size=%d", scenario, injections, readBytes, target.Size)
				return
			}
		case unix.PTRACE_SYSCALL_INFO_EXIT:
			returned := int64(binary.LittleEndian.Uint64(info[24:32]))
			if returned == 0 && (number == unix.SYS_FSTAT || number == unix.SYS_NEWFSTATAT) {
				address := second
				if number == unix.SYS_NEWFSTATAT {
					address = third
				}
				var stat unix.Stat_t
				buffer := make([]byte, int(unsafe.Sizeof(stat)))
				count, err := unix.PtracePeekData(target.TID, uintptr(address), buffer)
				privilegedRequire(test, err)
				if count != len(buffer) {
					test.Fatal("privileged short stat observation")
				}
				device := binary.LittleEndian.Uint64(buffer[unsafe.Offsetof(stat.Dev):])
				inode := binary.LittleEndian.Uint64(buffer[unsafe.Offsetof(stat.Ino):])
				if device == target.Device && inode == target.Inode {
					if number == unix.SYS_FSTAT {
						leafFD = first
					}
					if scenario == "negative-size" {
						binary.LittleEndian.PutUint64(buffer[unsafe.Offsetof(stat.Size):], ^uint64(0))
						count, err = unix.PtracePokeData(target.TID, uintptr(address), buffer)
						privilegedRequire(test, err)
						if count != len(buffer) {
							test.Fatal("privileged short stat injection")
						}
						injections++
					}
				}
			}
			if scenario == "read-fault" && number == unix.SYS_READ && first == leafFD {
				if returned > 0 {
					readBytes += returned
				} else if returned == 0 && readBytes == target.Size && injections == 0 {
					var registers unix.PtraceRegs
					privilegedRequire(test, unix.PtraceGetRegs(target.TID, &registers))
					registers.Rax = ^uint64(unix.EIO - 1)
					privilegedRequire(test, unix.PtraceSetRegs(target.TID, &registers))
					injections++
				}
			}
		default:
			test.Fatalf("privileged unexpected syscall stop %d", info[0])
		}
	}
}
