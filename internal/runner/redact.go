package runner

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"time"
	"unicode/utf8"
)

type textStream struct {
	out     io.Writer
	secrets [][]byte
	pending []byte
}

func (s *textStream) addSecret(token []byte) {
	s.secrets = append(s.secrets, bytes.Clone(token))
	// rejected_sha256 uses lowercase hex; protect its uppercase spelling too.
	hash := []byte(digest(token))
	s.secrets = append(s.secrets, hash, bytes.ToUpper(hash))
}
func (s *textStream) redact(b []byte) []byte {
	out := bytes.Clone(b)
	for _, secret := range s.secrets {
		if len(secret) > 0 {
			next := bytes.ReplaceAll(out, secret, []byte("[redacted]"))
			clear(out)
			out = next
		}
	}
	return out
}
func (s *textStream) write(text string, flush bool) error {
	s.pending = append(s.pending, []byte(text)...)
	clean := s.redact(s.pending)
	clear(s.pending)
	s.pending = clean
	hold := 0
	if !flush {
		for _, secret := range s.secrets {
			if len(secret) > hold {
				hold = len(secret)
			}
		}
		if hold > 0 {
			hold--
		}
	}
	n := len(s.pending) - hold
	if n < 0 {
		n = 0
	}
	for n > 0 && !utf8.Valid(s.pending[:n]) {
		n--
	}
	if n > 0 {
		if _, err := s.out.Write(s.pending[:n]); err != nil {
			return err
		}
		copy(s.pending, s.pending[n:])
		clear(s.pending[len(s.pending)-n:])
		s.pending = s.pending[:len(s.pending)-n]
	}
	return nil
}
func (s *textStream) erase() {
	clear(s.pending)
	for _, x := range s.secrets {
		clear(x)
	}
	s.secrets = nil
	s.pending = nil
}

// executionOutputStop is issued only when contextWriter observes its own
// execution context stopping the write. Underlying writer errors never receive
// this marker, even when they wrap a context error from an independent source.
type executionOutputStop struct{ cause error }

func (e *executionOutputStop) Error() string { return "execution output stopped" }
func (e *executionOutputStop) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// File-backed streams honor cancellation even when a consumer stops reading.
// Embedders supplying other io.Writers must provide bounded Write calls.
type contextWriter struct {
	ctx context.Context
	out io.Writer
}

func (w contextWriter) Write(b []byte) (int, error) {
	state, _ := w.ctx.Value(observationKey{}).(*statusRecord)
	if state != nil {
		state.outputStop = stopNone
	}
	stopped := func(cause error) error {
		if state != nil {
			switch cause {
			case context.DeadlineExceeded:
				state.outputStop = stopDeadline
			case context.Canceled:
				state.outputStop = stopInterrupt
			}
		}
		return &executionOutputStop{cause}
	}
	if err := w.ctx.Err(); err != nil {
		return 0, stopped(err)
	}
	if f, ok := w.out.(*os.File); ok {
		deadline, has := w.ctx.Deadline()
		if has {
			f.SetWriteDeadline(deadline)
		}
		stop := wakeOnCancel(w.ctx, func() { f.SetWriteDeadline(time.Now()) })
		defer func() {
			stop()
			// The caller retains this descriptor; do not leave a cancelled
			// deadline installed on its next use.
			f.SetWriteDeadline(time.Time{})
		}()
		n, err := f.Write(b)
		// Only a poll deadline induced by this context is cancellation.
		// EPIPE and other real output failures retain their own cause even
		// if cancellation arrives at the same time.
		if errors.Is(err, os.ErrDeadlineExceeded) {
			if cause := w.ctx.Err(); cause != nil {
				return n, stopped(cause)
			}
			// The descriptor deadline can fire just before the context timer
			// publishes Err; the same expired deadline still caused this I/O.
			if has && !time.Now().Before(deadline) {
				return n, stopped(context.DeadlineExceeded)
			}
		}
		return n, err
	}
	return w.out.Write(b)
}
