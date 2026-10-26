package egress

import (
	"errors"
	"os"
	"sync/atomic"
)

var ErrRunnerOriginUnavailable = errors.New("runner origin unavailable")

// RunnerOrigin binds one direct child to retained audited bytes and exact argv.
// It proves process identity and wait ownership, not entry, Command invocation,
// post-return testimony, descendant absence or qualification credit. The caller
// owns Image and keeps it open and immutable through TraceRunner's return.
type RunnerOrigin struct {
	image                                     *os.File
	digest                                    string
	argv                                      []string
	pid                                       atomic.Int64
	used, verified, joined, invalid, terminal atomic.Bool
}

type RunnerOriginFacts struct {
	PID              int
	Verified, Joined bool
}

func (o *RunnerOrigin) Facts() RunnerOriginFacts {
	return RunnerOriginFacts{int(o.pid.Load()), o.verified.Load() && !o.invalid.Load(), o.joined.Load()}
}

// Live only identifies the verified direct process while its origin is live.
func (o *RunnerOrigin) Live(pid int) bool {
	f := o.Facts()
	return f.PID == pid && f.Verified && !f.Joined && !o.terminal.Load()
}

// RunnerTraceConfig launches the retained Image as descriptor 3, followed by
// ExtraFiles at 4+. Args excludes argv[0], which is /proc/self/fd/3. Env must be
// explicit. No network policy is installed around trusted runner setup; the
// runner retains responsibility for its own nested supervisor and confinement.
type RunnerTraceConfig struct {
	Origin                *RunnerOrigin
	Args, Env             []string
	Dir                   string
	Stdin, Stdout, Stderr *os.File
	ExtraFiles            []*os.File
	Started               func(int)
	Waited                func(*os.ProcessState)
}

// RunnerTraceResult retains the actual sole consuming wait separately from
// origin errors. A verified, joined exit 17 is a real status, not an unavailable
// origin. Children counts detached processes observed at initial stops, not a proof of
// descendant absence. Their subtrees belong to the runner's own containment.
type RunnerTraceResult struct {
	State             *os.ProcessState
	Threads, Children uint64
}
