package egress

import (
	"os"
	"sync/atomic"
)

// CaseOrigin is a single-use qualification endpoint created by NewCaseOrigin.
// Its socket is never accepted through the caller's generic ExtraFiles list.
// It authenticates a dispatcher entry, not a function call within that image.
type CaseOrigin struct {
	image, parent, child      *os.File
	ready                     func() error
	ownerContext              string
	writer                    bool
	termination               *TerminationController
	pid                       atomic.Int64
	verified, entered         atomic.Bool
	joined, invalid, terminal atomic.Bool
	nonleader, used           atomic.Bool
}

// OriginFacts are parent observations, not child-supplied lifecycle claims.
type OriginFacts struct{ Verified, Entered, Joined, Nonleader bool }

func (o *CaseOrigin) Facts() OriginFacts {
	return OriginFacts{o.verified.Load() && !o.invalid.Load(), o.entered.Load() && !o.invalid.Load(), o.joined.Load(), o.nonleader.Load()}
}

// Live admits only this still-running, independently verified case process.
func (o *CaseOrigin) Live(pid int) bool {
	f := o.Facts()
	return o.pid.Load() == int64(pid) && f.Verified && f.Entered && !f.Joined && !o.terminal.Load()
}

func (o *CaseOrigin) Close() error {
	o.invalid.Store(true)
	return closeOriginFiles(o.parent, o.child)
}

func closeOriginFiles(files ...*os.File) (err error) {
	for _, f := range files {
		if f != nil {
			if e := f.Close(); e != nil && err == nil {
				err = e
			}
		}
	}
	return
}
