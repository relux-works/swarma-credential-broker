//go:build linux && broker_lab

package labtimev0

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type Start struct {
	path         string
	raw          []byte
	pins         StartPins
	owner, group uint32
}

func (start *Start) Context() Context {
	if start == nil {
		return Context{}
	}
	return start.pins.Context
}

func (start *Start) Generation() uint64 {
	if start == nil {
		return 0
	}
	return start.pins.Generation
}

func (start *Start) Heads() Heads {
	if start == nil {
		return Heads{}
	}
	return start.pins.Heads
}

func (start *Start) DecisionDigest() string {
	if start == nil {
		return ""
	}
	return start.pins.DecisionDigest
}

func (start *Start) RefusalFloors() []time.Time {
	if start == nil {
		return nil
	}
	return append([]time.Time(nil), start.pins.RefusalFloors...)
}

func (start *Start) Current(ctx context.Context) error {
	if start == nil || len(start.raw) == 0 {
		return ErrClosed
	}
	raw, err := readFence(ctx, start.path, start.owner, start.group)
	if err != nil || !bytes.Equal(raw, start.raw) {
		return ErrClosed
	}
	return nil
}

func fenceLocation(path, home string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !filepath.IsAbs(home) || filepath.Clean(home) != home || home == "/" {
		return false
	}
	return path != home && !strings.HasPrefix(path, home+"/") && !strings.HasPrefix(home, filepath.Dir(path)+"/") && filepath.Dir(path) != home
}

func readFence(ctx context.Context, path string, owner, group uint32) ([]byte, error) {
	if ctx.Err() != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, ErrClosed
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrClosed
	}
	directory := os.NewFile(uintptr(fd), "lab-fence-ancestor")
	defer func() { directory.Close() }()
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, part := range parts[:len(parts)-1] {
		var stat unix.Stat_t
		if unix.Fstat(int(directory.Fd()), &stat) != nil || stat.Mode&07022 != 0 || stat.Uid != 0 && stat.Uid != owner {
			return nil, ErrClosed
		}
		next, err := unix.Openat(int(directory.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, ErrClosed
		}
		directory.Close()
		directory = os.NewFile(uintptr(next), "lab-fence-ancestor")
	}
	var parent unix.Stat_t
	if unix.Fstat(int(directory.Fd()), &parent) != nil || parent.Mode&07022 != 0 || parent.Uid != 0 && parent.Uid != owner {
		return nil, ErrClosed
	}
	leaf, err := unix.Openat(int(directory.Fd()), parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrClosed
	}
	file := os.NewFile(uintptr(leaf), "lab-fence")
	defer file.Close()
	var before, after unix.Stat_t
	if unix.Fstat(leaf, &before) != nil || before.Mode != unix.S_IFREG|0644 || before.Uid != owner || before.Gid != group || before.Nlink != 1 || before.Size < 1 || before.Size > 65536 {
		return nil, ErrClosed
	}
	raw, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || int64(len(raw)) != before.Size || unix.Fstat(leaf, &after) != nil || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim || ctx.Err() != nil {
		return nil, ErrClosed
	}
	return raw, nil
}

func LoadStart(ctx context.Context, path, home string, decisionRaw, approvalRaw []byte, previous *Fence, pins StartPins) (*Start, error) {
	return loadStart(ctx, path, home, decisionRaw, approvalRaw, previous, pins, 0, 0)
}

func loadStart(ctx context.Context, path, home string, decisionRaw, approvalRaw []byte, previous *Fence, pins StartPins, owner, group uint32) (*Start, error) {
	if !fenceLocation(path, home) {
		return nil, ErrClosed
	}
	raw, err := readFence(ctx, path, owner, group)
	var fence Fence
	if err != nil || Decode(raw, &fence) != nil || !fence.Consumed {
		return nil, ErrClosed
	}
	fence.Consumed = false
	unconsumed, err := Encode(fence)
	if err != nil || CheckStart(decisionRaw, approvalRaw, unconsumed, previous, pins) != nil {
		return nil, ErrClosed
	}
	pins.RefusalFloors = append([]time.Time(nil), pins.RefusalFloors...)
	return &Start{path, append([]byte(nil), raw...), pins, owner, group}, nil
}

func ConsumeStartFence(ctx context.Context, path, home string, decisionRaw, approvalRaw []byte, previous *Fence, pins StartPins) error {
	if os.Geteuid() != 0 {
		return ErrClosed
	}
	return consumeStartFence(ctx, path, home, decisionRaw, approvalRaw, previous, pins, 0, 0)
}

func consumeStartFence(ctx context.Context, path, home string, decisionRaw, approvalRaw []byte, previous *Fence, pins StartPins, owner, group uint32) error {
	if !fenceLocation(path, home) {
		return ErrClosed
	}
	directory, err := os.OpenFile(filepath.Dir(path), os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrClosed
	}
	defer directory.Close()
	if unix.Flock(int(directory.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return ErrClosed
	}
	defer unix.Flock(int(directory.Fd()), unix.LOCK_UN)
	raw, err := readFence(ctx, path, owner, group)
	if err != nil || CheckStart(decisionRaw, approvalRaw, raw, previous, pins) != nil || ctx.Err() != nil {
		return ErrClosed
	}
	var fence Fence
	if Decode(raw, &fence) != nil {
		return ErrClosed
	}
	fence.Consumed = true
	next, err := Encode(fence)
	if err != nil {
		return ErrClosed
	}
	name := filepath.Base(path) + ".consuming"
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return ErrClosed
	}
	file := os.NewFile(uintptr(fd), "lab-start-fence")
	written, writeErr := file.Write(next)
	if writeErr == nil && written == len(next) {
		writeErr = file.Chmod(0644)
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil || written != len(next) || ctx.Err() != nil {
		return ErrClosed
	}
	if unix.Renameat(int(directory.Fd()), name, int(directory.Fd()), filepath.Base(path)) != nil || directory.Sync() != nil || ctx.Err() != nil {
		return ErrClosed
	}
	return nil
}
