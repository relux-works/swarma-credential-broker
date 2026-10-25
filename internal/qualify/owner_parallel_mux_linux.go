//go:build linux

package qualify

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

type parallelFrame struct {
	Seq, ID                  int
	Context, Kind, Op, Error string
	Data                     json.RawMessage
}
type parallelWait struct {
	op     string
	answer chan parallelFrame
}

// One reader and serialized writer per direction. RPC IDs are distinct from
// frame sequence and commands; each waiter validates both method and ID.
type parallelMux struct {
	ctx                       context.Context
	r, w                      *os.File
	context                   string
	parent                    bool
	writeMu, mu               sync.Mutex
	reads, writes, next, last int
	pending                   map[int]parallelWait
	outstanding               map[int]string
	events                    chan parallelFrame
	done                      chan struct{}
	err                       error
}

func newParallelMux(ctx context.Context, ch *ownerChannel, digest string, parent bool) *parallelMux {
	m := &parallelMux{ctx: ctx, r: ch.r, w: ch.w, context: digest, parent: parent, pending: map[int]parallelWait{}, outstanding: map[int]string{}, events: make(chan parallelFrame, 64), done: make(chan struct{})}
	go m.readLoop()
	return m
}
func (m *parallelMux) write(f parallelFrame) error {
	m.mu.Lock()
	if m.err != nil {
		e := m.err
		m.mu.Unlock()
		return e
	}
	if m.reads+m.writes >= 512 {
		m.mu.Unlock()
		return errors.New("parallel frame budget")
	}
	m.writes++
	f.Seq = m.writes
	m.mu.Unlock()
	f.Context = m.context
	b, e := wire.Encode(f)
	if e != nil || len(b) > 4096 {
		return errors.New("parallel frame encoding")
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(b)))
	if _, e = m.w.Write(h[:]); e != nil {
		return e
	}
	_, e = m.w.Write(b)
	return e
}
func (m *parallelMux) send(kind, op string, id int, v any, failure error) error {
	f := parallelFrame{Kind: kind, Op: op, ID: id}
	if v != nil {
		b, e := wire.Encode(v)
		if e != nil {
			return e
		}
		f.Data = b
	}
	if failure != nil {
		f.Error = failure.Error()
	}
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	return m.write(f)
}
func (m *parallelMux) call(op string, v, result any) error {
	if e := m.ctx.Err(); e != nil {
		return e
	}
	b, e := wire.Encode(v)
	if e != nil {
		return e
	}
	m.writeMu.Lock()
	m.mu.Lock()
	m.next++
	id := m.next
	if id > 128 || len(m.pending) >= 8 {
		m.mu.Unlock()
		m.writeMu.Unlock()
		return errors.New("parallel RPC budget")
	}
	ch := make(chan parallelFrame, 1)
	m.pending[id] = parallelWait{op, ch}
	m.mu.Unlock()
	e = m.write(parallelFrame{Kind: "rpc", Op: op, ID: id, Data: b})
	m.writeMu.Unlock()
	if e != nil {
		return e
	}
	select {
	case f := <-ch:
		if e := m.ctx.Err(); e != nil {
			return e
		}
		if f.Op != op || f.ID != id {
			return errors.New("parallel reply binding")
		}
		if f.Error != "" {
			return errors.New(f.Error)
		}
		if result != nil {
			return wire.Decode(f.Data, result)
		}
		return nil
	case <-m.done:
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.err
	case <-m.ctx.Done():
		return m.ctx.Err()
	}
}
func (m *parallelMux) command(op string, v any) (int, error) {
	b, e := wire.Encode(v)
	if e != nil {
		return 0, e
	}
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	m.mu.Lock()
	m.next++
	id := m.next
	m.mu.Unlock()
	if id > 16 {
		return 0, errors.New("parallel command budget")
	}
	return id, m.write(parallelFrame{Kind: "command", Op: op, ID: id, Data: b})
}
func (m *parallelMux) replyTo(f parallelFrame, v any, e error) error {
	m.mu.Lock()
	op, ok := m.outstanding[f.ID]
	if ok {
		delete(m.outstanding, f.ID)
	}
	m.mu.Unlock()
	if !ok || op != f.Op {
		return errors.New("parallel reply replay")
	}
	return m.send("reply", f.Op, f.ID, v, e)
}
func (m *parallelMux) accept(f parallelFrame) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if f.Seq != m.reads+1 || f.Context != m.context || m.reads+m.writes >= 512 {
		return errors.New("parallel sequence/context/budget")
	}
	m.reads++
	if f.Kind == "reply" {
		waiter, ok := m.pending[f.ID]
		if !ok || waiter.op != f.Op {
			return errors.New("parallel unknown/duplicate reply")
		}
		delete(m.pending, f.ID)
		waiter.answer <- f
		return nil
	}
	allowed := f.Kind == "command" && !m.parent || m.parent && (f.Kind == "rpc" || f.Kind == "notice")
	if !allowed || f.Error != "" && f.Kind != "notice" {
		return errors.New("parallel direction/kind")
	}
	if f.Kind == "rpc" || f.Kind == "command" {
		if f.ID != m.last+1 {
			return errors.New("parallel request order")
		}
		m.last = f.ID
		if f.Kind == "rpc" {
			if len(m.outstanding) >= 8 {
				return errors.New("parallel outstanding budget")
			}
			m.outstanding[f.ID] = f.Op
		}
	}
	select {
	case m.events <- f:
		return nil
	case <-m.ctx.Done():
		return m.ctx.Err()
	}
}
func (m *parallelMux) readLoop() {
	var failure error
	defer func() { m.mu.Lock(); m.err = failure; m.mu.Unlock(); close(m.done) }()
	for {
		var h [4]byte
		if _, failure = io.ReadFull(m.r, h[:]); failure != nil {
			return
		}
		n := binary.BigEndian.Uint32(h[:])
		if n == 0 || n > 4096 {
			failure = errors.New("parallel frame length")
			return
		}
		b := make([]byte, n)
		if _, failure = io.ReadFull(m.r, b); failure != nil {
			return
		}
		var f parallelFrame
		if failure = wire.Decode(b, &f); failure != nil {
			return
		}
		if failure = m.accept(f); failure != nil {
			return
		}
	}
}
func (m *parallelMux) nextFrame() (parallelFrame, error) {
	select {
	case f := <-m.events:
		return f, nil
	default:
	}
	select {
	case f := <-m.events:
		return f, nil
	case <-m.done:
		select {
		case f := <-m.events:
			return f, nil
		default:
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		return parallelFrame{}, m.err
	case <-m.ctx.Done():
		return parallelFrame{}, m.ctx.Err()
	}
}
func (m *parallelMux) frames() int { m.mu.Lock(); defer m.mu.Unlock(); return m.reads + m.writes }
func (m *parallelMux) close()      { m.r.Close(); m.w.Close(); <-m.done }
