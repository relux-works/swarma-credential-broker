//go:build linux && amd64

package egress

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The creator is stopped at a real clone event while another, already running
// thread exits the group. The newborn's trace stop must not depend on receiving
// the creator's clone event again. All waits/signals select this owned child.
func TestOriginExitBeforeCloneRegistration(t *testing.T) {
	originCloneExit(t, false, false, "")
}

func TestOriginCloneEventSurvivesGroupExit(t *testing.T) {
	originCloneExit(t, true, false, "")
}

func TestOriginCreationRejectsProcess(t *testing.T) {
	originCloneExit(t, false, true, "")
}

// Pipes force exit_group after the actual CLONE peek, either before the
// production event read or after that read and before production consumption.
// The stolen control consumes the same task's terminal status first.
func TestOriginStopTerminalTransition(t *testing.T) {
	for _, stage := range []string{"event-read", "stop-consume", "stolen-nonleader"} {
		t.Run(stage, func(t *testing.T) { originCloneExit(t, false, false, stage) })
	}
}

func originCloneExit(t *testing.T, delayedResume, process bool, transition string) {
	t.Helper()
	image := t.TempDir() + "/clone-exit"
	build := exec.Command("gcc", "-O0", "-pthread", "-o", image, "testdata/clone-exit.c")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("native clone fixture unavailable: %v: %s", err, out)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	creatorR, creatorW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer creatorR.Close()
	defer creatorW.Close()
	exitR, exitW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer exitR.Close()
	defer exitW.Close()
	readyR, readyW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readyR.Close()
	defer readyW.Close()
	readyFD := int(readyR.Fd())
	if err = unix.SetNonblock(readyFD, true); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(image)
	if process {
		cmd.Args = append(cmd.Args, "process")
	}
	cmd.Env = []string{"HOME=" + t.TempDir(), "TMPDIR=" + t.TempDir()}
	cmd.ExtraFiles = []*os.File{creatorR, exitR, readyW}
	fd := -1
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true, Setpgid: true, PidFD: &fd}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Release()
	w := originOwner{pid: cmd.Process.Pid, fd: fd, tasks: map[int]bool{cmd.Process.Pid: true}, strict: true}
	joined := false
	defer func() {
		if !joined {
			if _, err := w.reapStopped(); err != nil {
				t.Error("owned cleanup", err)
			}
		}
		if fd >= 0 {
			unix.Close(fd)
		}
	}()
	if fd < 0 {
		t.Fatal("owned pidfd unavailable")
	}
	var initial unix.WaitStatus
	if p, e := unix.Wait4(w.pid, &initial, unix.WALL, nil); e != nil || p != w.pid || !initial.Stopped() {
		t.Fatal("initial exec stop", p, initial, e)
	}
	options := unix.PTRACE_O_TRACECLONE | unix.PTRACE_O_TRACEFORK | unix.PTRACE_O_EXITKILL
	if transition == "" {
		options |= unix.PTRACE_O_TRACEEXIT
	}
	if err = unix.PtraceSetOptions(w.pid, options); err != nil {
		t.Fatal(err)
	}
	if err = w.resume(w.pid, initial); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	ready := false
	seen := map[int]bool{}
	for !ready && time.Now().Before(deadline) {
		var b [1]byte
		if n, e := unix.Read(readyFD, b[:]); e == nil && n == 1 {
			ready = true
			break
		}
		p, s, done, e := w.next()
		if e != nil || done {
			t.Fatal("startup trace", p, s, done, e)
		}
		if p != 0 {
			seen[p] = true
			if e = w.resume(p, s); e != nil {
				t.Fatal(e)
			}
		} else {
			time.Sleep(time.Millisecond)
		}
	}
	if !ready {
		t.Fatal("child readiness deadline")
	}
	creatorThread := 0
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", w.pid))
	if err != nil || len(entries) != 2 {
		t.Fatal("native creator inventory", len(entries), err)
	}
	for _, entry := range entries {
		p, e := strconv.Atoi(entry.Name())
		if e != nil {
			t.Fatal(e)
		}
		if p != w.pid {
			creatorThread = p
		}
	}
	for !seen[creatorThread] && time.Now().Before(deadline) {
		p, s, done, e := w.next()
		if e != nil || done {
			t.Fatal("creator entry", p, s, done, e)
		}
		if p != 0 {
			seen[p] = true
			if e = w.resume(p, s); e != nil {
				t.Fatal(e)
			}
		} else {
			time.Sleep(time.Millisecond)
		}
	}
	if !seen[creatorThread] {
		t.Fatal("creator initial stop not drained")
	}
	if _, err = creatorW.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if process {
		for time.Now().Before(deadline) {
			p, s, done, e := w.next()
			if e != nil {
				if !errors.Is(e, ErrUnavailable) {
					t.Fatal("wrong process refusal", e)
				}
				child := 0
				for tid := range w.tasks {
					if tid != w.pid && tid != creatorThread {
						child = tid
					}
				}
				if child == 0 || originThread(child, w.pid) {
					t.Fatal("refused process lost cleanup custody", child)
				}
				if _, e = w.reapStopped(); e != nil {
					t.Fatal("refused process cleanup", e)
				}
				joined = true
				for _, pid := range []int{child, w.pid} {
					var status unix.WaitStatus
					if _, e = unix.Wait4(pid, &status, unix.WNOHANG|unix.WALL, nil); e != unix.ECHILD {
						t.Fatal("refused owned process left waitable", pid, e)
					}
				}
				t.Log("distinct process refused and every owned process reaped")
				return
			}
			if done {
				t.Fatal("distinct process acquired terminal success")
			}
			if p != 0 {
				if e = w.resume(p, s); e != nil {
					t.Fatal(e)
				}
			} else {
				time.Sleep(time.Millisecond)
			}
		}
		t.Fatal("no actual process refusal within bound")
	}
	newborn := 0
	creator := 0
	var creation unix.WaitStatus
	var creationPeek unix.Siginfo
	for time.Now().Before(deadline) {
		var p int
		var s unix.WaitStatus
		var done bool
		var e error
		if delayedResume {
			p, s, done, e = w.next()
		} else {
			// Peek without giving next/resume the event: group exit must erase
			// the creator's stop before the supervisor can register its child.
			var si unix.Siginfo
			e = unix.Waitid(unix.P_PID, creatorThread, &si, unix.WSTOPPED|unix.WNOHANG|unix.WNOWAIT|unix.WALL, nil)
			b := (*[128]byte)(unsafe.Pointer(&si))
			creationPeek = si
			if si.Code != 0 {
				p = creatorThread
				s = unix.WaitStatus(binary.LittleEndian.Uint32(b[24:28])<<8 | 0x7f)
			}
		}
		if e != nil || done {
			t.Fatal("creator trace", p, s, done, e)
		}
		if s.TrapCause() == unix.PTRACE_EVENT_CLONE {
			n, e := unix.PtraceGetEventMsg(p)
			if e != nil || n == 0 || !originThread(int(n), w.pid) {
				t.Fatal("actual newborn thread", n, e)
			}
			newborn = int(n)
			creator, creation = p, s
			_, known := w.tasks[newborn]
			t.Logf("creator tid=%d held at CLONE; newborn tid=%d registered=%v", p, newborn, known)
			break // Deliberately do not register/resume the creator's event.
		}
		if p != 0 {
			seen[p] = true
			if e = w.resume(p, s); e != nil {
				t.Fatal(e)
			}
		} else {
			time.Sleep(time.Millisecond)
		}
	}
	if newborn == 0 {
		t.Fatal("no actual clone within bound")
	}
	if transition == "stop-consume" || transition == "stolen-nonleader" {
		b, e := w.captureBirth(creator, creation)
		if e != nil || b.pid != newborn || !b.thread {
			t.Fatal("pinned production birth", b, e)
		}
		w.births = map[int]originBirth{creator: b}
		w.tasks[newborn] = false
	}
	if _, err = exitW.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	{
		changed := false
		for time.Now().Before(deadline) {
			var si unix.Siginfo
			err := unix.Waitid(unix.P_PID, creator, &si, unix.WEXITED|unix.WSTOPPED|unix.WNOHANG|unix.WNOWAIT|unix.WALL, nil)
			if err != nil {
				t.Fatal("creator replacement wait", err)
			}
			b := (*[128]byte)(unsafe.Pointer(&si))
			status := binary.LittleEndian.Uint32(b[24:28])
			if si.Code != 0 && (si.Code != 4 || status != uint32(creation)>>8) {
				changed = true
				t.Logf("creator CLONE replaced by group exit: code=%d status=%#x", si.Code, status)
				break
			}
			time.Sleep(time.Millisecond)
		}
		if !changed {
			t.Fatal("group exit did not replace creator's consumed stop")
		}
		if delayedResume {
			if err = w.resume(creator, creation); err != nil {
				t.Fatal("lost already observed clone identity after group exit", err)
			}
		}
	}
	if transition != "" {
		var p int
		var s unix.WaitStatus
		var done bool
		var e error
		if transition == "event-read" {
			// This invokes the real GETEVENTMSG on the obsolete CLONE stop.
			if _, e = unix.PtraceGetEventMsg(creator); e != unix.ESRCH {
				t.Fatal("exit did not overtake event read", e)
			}
			p, s, done, e = w.observedTask(creator, creationPeek)
		} else {
			// The original stop-only consume fails on this exact owned task,
			// while leaving its terminal status available to the repaired path.
			var old unix.Siginfo
			if e := unix.Waitid(unix.P_PID, creator, &old, unix.WSTOPPED|unix.WNOHANG|unix.WALL, nil); e != unix.ECHILD {
				t.Fatal("original stop-only operation did not produce ECHILD", e)
			}
			if transition == "stolen-nonleader" {
				var stolen unix.WaitStatus
				if n, e := unix.Wait4(creator, &stolen, unix.WNOHANG|unix.WALL, nil); e != nil || n != creator || !stolen.Exited() {
					t.Fatal("no actual stolen terminal status", n, stolen, e)
				}
			}
			p, s, done, e = w.consumeTask(creator)
		}
		if transition == "stolen-nonleader" {
			if e != unix.ECHILD || done || p != -1 && p != 0 {
				t.Fatal("stolen task was accepted", p, s, done, e)
			}
			// This task supplied a genuine initial stop during startup. The
			// normal inventory/peek path must refuse its theft as well, even
			// if the leader's terminal state is already observable.
			if !w.seen[creator] {
				t.Fatal("negative control lacks a previously observed creator")
			}
			refused := false
			for step := 0; step < 128 && time.Now().Before(deadline); {
				p, s, done, e := w.next()
				if e == unix.ECHILD && !done {
					refused = true
					break
				}
				if e != nil || done {
					t.Fatal("normal next hid stolen task behind terminal leader", p, done, e)
				}
				if p == 0 {
					// Wait only for this forced group exit's actual status;
					// the fixed deadline also bounds idle observations.
					time.Sleep(time.Millisecond)
					continue
				}
				step++
				if p == newborn {
					seen[newborn] = true
				}
				if e = w.resume(p, s); e != nil {
					t.Fatal(e)
				}
			}
			if !refused {
				t.Fatal("stolen task not refused within bounded event drain")
			}
			w.forgetTask(creator)
			t.Log("actual nonleader terminal status stolen: ECHILD retained")
		} else {
			if e != nil || p != creator || !s.Exited() || s.ExitStatus() != 0 || done {
				t.Fatal("owned stop-to-terminal transition lost", p, s, done, e)
			}
			if err = w.resume(p, s); err != nil {
				t.Fatal(err)
			}
			t.Logf("forced %s: same creator terminal consumed, leader unconsumed", transition)
		}
		// Inventory must recover a newborn even when the creator's event read
		// was overtaken and therefore supplied no usable creation identity.
	}
	observed := seen[newborn]
	for time.Now().Before(deadline) {
		p, s, done, e := w.next()
		if e != nil {
			t.Fatal("exit trace", e)
		}
		if p == newborn {
			observed = true
			t.Logf("newborn tid=%d actual stop=%#x drained", p, int(s))
		}
		if done {
			if !observed {
				t.Fatal("terminal leader hid unregistered newborn")
			}
			if err = cmd.Wait(); err != nil {
				t.Fatal("terminal owned wait", err)
			}
			joined = true
			if cmd.ProcessState == nil || !cmd.ProcessState.Exited() || cmd.ProcessState.ExitCode() != 0 {
				t.Fatal("lost actual terminal zero exit")
			}
			return
		}
		if p != 0 {
			if e = w.resume(p, s); e != nil {
				t.Fatal(e)
			}
		} else {
			time.Sleep(time.Millisecond)
		}
	}
	var si unix.Siginfo
	e := unix.Waitid(unix.P_PID, newborn, &si, unix.WSTOPPED|unix.WNOHANG|unix.WNOWAIT|unix.WALL, nil)
	b := (*[128]byte)(unsafe.Pointer(&si))
	t.Fatalf("owned group not joined before fixed deadline: newborn_observed=%v pending_tid=%d code=%d wait=%v known=%v", observed, binary.LittleEndian.Uint32(b[16:20]), si.Code, e, w.tasks)
}
