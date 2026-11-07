//go:build linux

package demo

import (
	"context"
	"os"
	"strings"
	"sync"
)

// Admission is an immutable-lifetime snapshot. Root must keep this demo roster
// and launch records immutable until the broker stops; online maintenance is not
// supported. A roster failure or failure of an already pinned launch latches
// refusal for this instance; an unadmitted caller cannot pin a missing launch.
// The mutex orders local delivery and repeated snapshot checks, not root writes.
type Admission struct {
	mu        sync.Mutex
	failed    bool
	rosterSHA string
	launches  map[string]LaunchRecord
}

func NewAdmission() *Admission { return &Admission{launches: map[string]LaunchRecord{}} }

func (a *Admission) Peer(ctx context.Context, uid uint32) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failed || ctx.Err() != nil || uid < 30000 || uid > 30019 {
		return ErrRefused
	}
	raw, e := readRoot(RosterPath, 0644, 128*1024)
	if e != nil {
		a.failed = true
		return ErrRefused
	}
	r, e := DecodeRoster(raw)
	if e != nil {
		a.failed = true
		return e
	}
	currentBoot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil || strings.TrimSpace(string(currentBoot)) != r.BootID {
		a.failed = true
		return ErrRefused
	}
	sum := Hash(raw)
	if a.rosterSHA != "" && sum != a.rosterSHA {
		a.failed = true
		return ErrRefused
	}
	a.rosterSHA = sum
	if !FixedExecutorApproved(r) {
		return ErrRefused
	}
	for _, row := range r.Accounts {
		if row.UID == uid {
			_, e = r.Principal(uid, LaunchRecord{UID: uid, Generation: row.Generation, BootID: r.BootID})
			return e
		}
	}
	return ErrRefused
}
func (a *Admission) check(ctx context.Context, uid uint32, digest string) error {
	if a.failed || ctx.Err() != nil || !hash.MatchString(digest) {
		return ErrRefused
	}
	raw, e := readRoot(RosterPath, 0644, 128*1024)
	if e != nil {
		a.failed = true
		return ErrRefused
	}
	r, e := DecodeRoster(raw)
	if e != nil {
		a.failed = true
		return e
	}
	currentBoot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil || strings.TrimSpace(string(currentBoot)) != r.BootID {
		a.failed = true
		return ErrRefused
	}
	sum := Hash(raw)
	if a.rosterSHA != "" && sum != a.rosterSHA {
		a.failed = true
		return ErrRefused
	}
	a.rosterSHA = sum
	if !FixedExecutorApproved(r) {
		return ErrRefused
	}
	dir, e := openRooted(LaunchDirectory, true)
	if e != nil {
		return ErrRefused
	}
	defer dir.Close()
	info, e := dir.Stat()
	if e != nil || info.Mode().Perm()&0022 != 0 {
		return ErrRefused
	}
	entries, e := dir.ReadDir(257)
	if e != nil && len(entries) == 0 {
		return ErrRefused
	}
	if len(entries) > 256 {
		return ErrRefused
	}
	var selected LaunchRecord
	matches := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".json") {
			return ErrRefused
		}
		id := strings.TrimSuffix(name, ".json")
		rec, e := ReadLaunch(id)
		if e != nil {
			return ErrRefused
		}
		if rec.UID == uid && rec.PlanSHA256 == digest {
			selected = rec
			matches++
		}
	}
	if matches != 1 {
		return ErrRefused
	}
	if _, e = r.Principal(uid, selected); e != nil {
		return e
	}
	key := digest
	if old, ok := a.launches[key]; ok && old != selected {
		a.failed = true
		return ErrRefused
	}
	a.launches[key] = selected
	return nil
}
func (a *Admission) Check(ctx context.Context, uid uint32, digest string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, pinned := a.launches[digest]
	err := a.check(ctx, uid, digest)
	if err != nil && pinned && ctx.Err() == nil {
		a.failed = true
	}
	return err
}
func (a *Admission) Publish(ctx context.Context, uid uint32, digest string, write func(context.Context) error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if e := a.check(ctx, uid, digest); e != nil {
		if _, pinned := a.launches[digest]; pinned && ctx.Err() == nil {
			a.failed = true
		}
		return e
	}
	return write(ctx)
}
