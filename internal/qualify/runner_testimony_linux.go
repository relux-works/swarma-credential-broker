//go:build linux

package qualify

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/egress"
	"github.com/relux-works/swarma-credential-broker/internal/runner"
	"golang.org/x/sys/unix"
)

// RunnerTestimony is a single private exchange bound to one traced case.
// Its result grants no row credit, effect proof or Command-call observation.
type RunnerTestimony struct {
	origin        *egress.RunnerOrigin
	uid           uint32
	parent, child *os.File
	channel       *os.File
	directory     string
	used          atomic.Bool
	nonce         [32]byte
}

func NewRunnerTestimony(origin *egress.RunnerOrigin, uid uint32, root string) (*RunnerTestimony, error) {
	if origin == nil {
		return nil, egress.ErrRunnerOriginUnavailable
	}
	dir, e := os.MkdirTemp(root, "testimony-")
	if e != nil {
		return nil, egress.ErrRunnerOriginUnavailable
	}
	p := &RunnerTestimony{origin: origin, uid: uid, directory: dir}
	fd, e := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if e == nil {
		p.parent = os.NewFile(uintptr(fd), "testimony-listener")
	}
	path := filepath.Join(dir, "channel")
	if e != nil || unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PASSCRED, 1) != nil || unix.Bind(fd, &unix.SockaddrUnix{Name: path}) != nil || unix.Listen(fd, 1) != nil {
		p.Close()
		return nil, egress.ErrRunnerOriginUnavailable
	}
	var w *os.File
	p.child, w, e = os.Pipe()
	if e == nil {
		_, e = w.WriteString(path)
		w.Close()
	}
	if e != nil {
		p.Close()
		return nil, egress.ErrRunnerOriginUnavailable
	}
	return p, nil
}

// Child is a bounded private address pipe installed as FD4 by TraceRunner.
// The case connects before Command and closes its socket after ACK. root must
// support a short private Unix pathname; no existing origin gains socket FDs.
func (p *RunnerTestimony) Child() *os.File { return p.child }
func (p *RunnerTestimony) Close() {
	for _, f := range []*os.File{p.parent, p.child, p.channel} {
		if f != nil {
			f.Close()
		}
	}
	os.RemoveAll(p.directory)
}
func (p *RunnerTestimony) connection(ctx context.Context) (int, error) {
	for p.channel == nil && testimonyLive(ctx) && !p.origin.Facts().Joined {
		fd, _, e := unix.Accept4(int(p.parent.Fd()), unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK)
		if e == nil {
			p.channel = os.NewFile(uintptr(fd), "testimony-channel")
			break
		}
		if e != unix.EAGAIN && e != unix.EINTR {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if p.channel == nil {
		return -1, egress.ErrRunnerOriginUnavailable
	}
	return int(p.channel.Fd()), nil
}

// Exchange accepts readiness, sends a fresh nonce, accepts one answer, then
// requires endpoint closure after ACK. Both case frames need kernel credentials.
// The caller must separately join TraceRunner and validate effects before credit.
func (p *RunnerTestimony) Exchange(ctx context.Context) (runner.Outcome, error) {
	if !p.used.CompareAndSwap(false, true) {
		return runner.Outcome{}, egress.ErrRunnerOriginUnavailable
	}
	defer p.Close()
	for p.origin.Facts().PID == 0 {
		if !testimonyLive(ctx) {
			return runner.Outcome{}, egress.ErrRunnerOriginUnavailable
		}
		time.Sleep(time.Millisecond)
	}
	p.child.Close()
	fd, e := p.connection(ctx)
	if e != nil {
		return runner.Outcome{}, e
	}
	b, cred, e := testimonyRecv(ctx, fd)
	if e != nil || !bytes.Equal(b, []byte{'R'}) || !p.sender(cred) {
		return runner.Outcome{}, egress.ErrRunnerOriginUnavailable
	}
	if _, e = rand.Read(p.nonce[:]); e != nil || testimonySend(ctx, fd, append([]byte{'C'}, p.nonce[:]...)) != nil {
		return runner.Outcome{}, egress.ErrRunnerOriginUnavailable
	}
	b, cred, e = testimonyRecv(ctx, fd)
	if e != nil || len(b) != 35 || b[0] != 'A' || !p.sender(cred) || !bytes.Equal(b[1:33], p.nonce[:]) {
		return runner.Outcome{}, egress.ErrRunnerOriginUnavailable
	}
	out := runner.Outcome{Status: int(b[33]), Kind: runner.OutcomeKind(b[34])}
	if !testimonyOutcome(out) || testimonySend(ctx, fd, []byte{'K'}) != nil {
		return runner.Outcome{}, egress.ErrRunnerOriginUnavailable
	}
	if _, _, e = testimonyRecv(ctx, fd); e != io.EOF {
		return runner.Outcome{}, egress.ErrRunnerOriginUnavailable
	}
	return out, nil
}

func (p *RunnerTestimony) sender(c *unix.Ucred) bool {
	return c != nil && c.Uid == p.uid && p.origin.Live(int(c.Pid))
}

// RunnerTestimonyCommand is the measured dispatcher call, not a receipt hook.
// FD4 is a private address pipe, closed before any Command child is launched. There
// is no deferred send: an escaping panic or early return cannot send readiness.
func RunnerTestimonyCommand(ctx context.Context, args []string, streams runner.IO, d runner.Dependencies) (runner.Outcome, error) {
	if unix.SetNonblock(4, true) != nil {
		return runner.Outcome{}, egress.ErrRunnerOriginUnavailable
	}
	f := os.NewFile(4, "testimony-context")
	end, ok := ctx.Deadline()
	if !ok || f.SetReadDeadline(end) != nil {
		f.Close()
		return runner.Outcome{}, egress.ErrRunnerOriginUnavailable
	}
	b, e := io.ReadAll(io.LimitReader(f, 108))
	f.Close()
	if e != nil || len(b) == 0 || len(b) > 107 || !testimonyLive(ctx) {
		return runner.Outcome{}, egress.ErrRunnerOriginUnavailable
	}
	fd, e := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if e != nil {
		return runner.Outcome{}, egress.ErrRunnerOriginUnavailable
	}
	defer unix.Close(fd)
	if unix.Connect(fd, &unix.SockaddrUnix{Name: string(b)}) != nil {
		return runner.Outcome{}, egress.ErrRunnerOriginUnavailable
	}
	out := runner.CommandWithOutcome(ctx, args, streams, d)
	if !testimonyOutcome(out) || testimonySend(ctx, fd, []byte{'R'}) != nil {
		return runner.Outcome{}, egress.ErrRunnerOriginUnavailable
	}
	b, _, e = testimonyRecv(ctx, fd)
	if e != nil || len(b) != 33 || b[0] != 'C' {
		return runner.Outcome{}, egress.ErrRunnerOriginUnavailable
	}
	answer := append(append([]byte{'A'}, b[1:]...), byte(out.Status), byte(out.Kind))
	if testimonySend(ctx, fd, answer) != nil {
		return runner.Outcome{}, egress.ErrRunnerOriginUnavailable
	}
	b, _, e = testimonyRecv(ctx, fd)
	if e != nil || !bytes.Equal(b, []byte{'K'}) {
		return runner.Outcome{}, egress.ErrRunnerOriginUnavailable
	}
	return out, nil
}

func testimonyOutcome(o runner.Outcome) bool {
	switch o.Kind {
	case runner.OutcomeSuccess:
		return o.Status == 0
	case runner.OutcomeSourceConflict:
		return o.Status == 69
	case runner.OutcomeFailure:
		return o.Status == 1 || o.Status == 64 || o.Status == 69 || o.Status == 75 || o.Status == 124 || o.Status == 130
	}
	return false
}

func testimonyLive(ctx context.Context) bool {
	end, ok := ctx.Deadline()
	return ok && ctx.Err() == nil && time.Now().Before(end)
}

func testimonySend(ctx context.Context, fd int, b []byte) error {
	if !testimonyLive(ctx) || unix.Sendmsg(fd, b, nil, nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL) != nil {
		return egress.ErrRunnerOriginUnavailable
	}
	return nil
}

func testimonyRecv(ctx context.Context, fd int) ([]byte, *unix.Ucred, error) {
	for testimonyLive(ctx) {
		b := make([]byte, 64)
		control := make([]byte, unix.CmsgSpace(unix.SizeofUcred)+unix.CmsgSpace(32))
		n, size, flags, _, e := unix.Recvmsg(fd, b, control, unix.MSG_DONTWAIT|unix.MSG_CMSG_CLOEXEC)
		if e == unix.EAGAIN || e == unix.EINTR {
			time.Sleep(time.Millisecond)
			continue
		}
		messages, parseErr := unix.ParseSocketControlMessage(control[:size])
		var cred *unix.Ucred
		bad := false
		for _, m := range messages {
			if m.Header.Level == unix.SOL_SOCKET && m.Header.Type == unix.SCM_CREDENTIALS && cred == nil {
				cred, parseErr = unix.ParseUnixCredentials(&m)
			} else {
				bad = true
				if rights, re := unix.ParseUnixRights(&m); re == nil {
					for _, f := range rights {
						unix.Close(f)
					}
				}
			}
		}
		if e != nil || parseErr != nil || bad || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || !testimonyLive(ctx) {
			return nil, nil, egress.ErrRunnerOriginUnavailable
		}
		if n == 0 {
			if size == 0 {
				return nil, nil, io.EOF
			}
			return nil, nil, egress.ErrRunnerOriginUnavailable
		}
		return b[:n], cred, nil
	}
	return nil, nil, egress.ErrRunnerOriginUnavailable
}
