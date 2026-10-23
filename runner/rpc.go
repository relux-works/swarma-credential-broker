package runner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
	"time"
	"unicode/utf8"
)

const maxRPC = 4 << 20

type message struct {
	ID       json.RawMessage `json:"id,omitempty"`
	Method   string          `json:"method,omitempty"`
	Params   json.RawMessage `json:"params,omitempty"`
	Result   json.RawMessage `json:"result,omitempty"`
	Error    json.RawMessage `json:"error,omitempty"`
	received time.Time
}
type incoming struct {
	msg message
	err error
}
type rpc struct {
	in       *os.File
	messages chan incoming
	closed   chan struct{}
	next     int
	queue    []message
}

func newRPC(p *process) *rpc {
	r := &rpc{in: p.in, messages: make(chan incoming, 32), closed: make(chan struct{})}
	go func() {
		defer close(r.messages)
		scanner := bufio.NewScanner(p.out)
		scanner.Buffer(make([]byte, 4096), maxRPC)
		for scanner.Scan() {
			raw := scanner.Bytes()
			var m message
			if !utf8.Valid(raw) || json.Unmarshal(raw, &m) != nil {
				select {
				case r.messages <- incoming{err: errors.New("invalid rpc")}:
				case <-r.closed:
				}
				return
			}
			m.received = time.Now()
			select {
			case r.messages <- incoming{msg: m}:
			case <-r.closed:
				return
			}
		}
		select {
		case r.messages <- incoming{err: io.EOF}:
		case <-r.closed:
		}
	}()
	return r
}
func (r *rpc) send(ctx context.Context, v any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	defer clear(data)
	data = append(data, '\n')
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(time.Second)
	}
	if err = r.in.SetWriteDeadline(deadline); err != nil {
		return err
	}
	_, err = r.in.Write(data)
	return err
}
func (r *rpc) notify(ctx context.Context, method string, params any) error {
	return r.send(ctx, map[string]any{"method": method, "params": params})
}
func (r *rpc) request(ctx context.Context, method string, params any) (json.RawMessage, error) {
	r.next++
	id := json.RawMessage(strconv.Itoa(r.next))
	return id, r.send(ctx, map[string]any{"id": id, "method": method, "params": params})
}
func (r *rpc) receive(ctx context.Context) (message, error) {
	select {
	case <-ctx.Done():
		return message{}, ctx.Err()
	case v, ok := <-r.messages:
		if !ok {
			return message{}, io.EOF
		}
		return v.msg, v.err
	}
}
func (r *rpc) call(ctx context.Context, method string, params any, callback func(message) error) (json.RawMessage, error) {
	id, err := r.request(ctx, method, params)
	if err != nil {
		return nil, err
	}
	for {
		m, err := r.receive(ctx)
		if err != nil {
			return nil, err
		}
		if m.Method != "" {
			if len(m.ID) > 0 {
				if err = callback(m); err != nil {
					return nil, err
				}
			} else {
				if len(r.queue) >= 1024 {
					return nil, errors.New("event overflow")
				}
				r.queue = append(r.queue, m)
			}
			continue
		}
		if !bytes.Equal(m.ID, id) || len(m.Error) > 0 || len(m.Result) == 0 {
			return nil, errors.New("rpc refused")
		}
		return m.Result, nil
	}
}
