//go:build linux

package runner

import "testing"

// Claim: only a successful completed open for the selected path and same TID
// acknowledges the injection, including real strace unfinished/resumed records.
func TestProcTraceOpenCompletion(t *testing.T) {
	type traceEvent struct {
		tid  int
		line string
		want bool
	}
	for _, fixture := range []struct {
		name  string
		lines []traceEvent
	}{
		{"complete", []traceEvent{
			{101, `101 openat(AT_FDCWD, "/proc/202/stat", O_RDONLY|O_CLOEXEC) = 8`, true},
			{101, `101 openat(AT_FDCWD, "/proc/202/stat", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)`, false},
			{101, `101 openat(AT_FDCWD, "/proc/202/stat-extra", O_RDONLY|O_CLOEXEC) = 8`, false},
		}},
		{"split", []traceEvent{
			{101, `101 openat(AT_FDCWD, "/proc/202/stat", O_RDONLY|O_CLOEXEC <unfinished ...>`, false},
			{102, `102 --- SIGURG {si_signo=SIGURG} ---`, false},
			{102, `102 <... openat resumed>)           = 9`, false},
			{101, `101 <... openat resumed>)           = 8`, true},
			{101, `101 <... openat resumed>)           = 8`, false},
		}},
		{"failed-split", []traceEvent{
			{101, `101 openat(AT_FDCWD, "/proc/202/stat", O_RDONLY|O_CLOEXEC <unfinished ...>`, false},
			{101, `101 <... openat resumed>) = -1 ESRCH (No such process)`, false},
			{101, `101 <... openat resumed>) = 8`, false},
		}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			unfinished := procTraceOpens{}
			for index, event := range fixture.lines {
				if got := unfinished.opened(event.tid, event.line, "/proc/202/stat"); got != event.want {
					t.Fatalf("event %d completed open=%t, want %t: %s", index, got, event.want, event.line)
				}
			}
			if len(unfinished) != 0 {
				t.Fatal("completed records left stale open evidence", unfinished)
			}
		})
	}
}
