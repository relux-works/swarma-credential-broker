//go:build linux

package demo

import (
	"io"
	"os"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// Plan is the fixed demo executor's closed intake, not a general launcher plan.
// It cannot select accounts, executables, homes, credentials or arbitrary argv.
// Its exact byte digest must independently appear in the root launch record.
type Plan struct {
	ExecutionID     string `json:"execution_id"`
	Prompt          string `json:"prompt"`
	Model           string `json:"model"`
	ReasoningEffort string `json:"reasoning_effort"`
}

func ReadPlan(f *os.File) (Plan, string, error) {
	var p Plan
	if f == nil {
		return p, "", ErrRefused
	}
	fd := int(f.Fd())
	flags, e := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if e != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
		return p, "", ErrRefused
	}
	var st unix.Stat_t
	seals, e := unix.FcntlInt(f.Fd(), unix.F_GET_SEALS, 0)
	required := unix.F_SEAL_SEAL | unix.F_SEAL_WRITE | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW
	offset, seek := unix.Seek(fd, 0, io.SeekCurrent)
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size <= 0 || st.Size > PlanMax || e != nil || seals&required != required || seek != nil || offset != 0 {
		return p, "", ErrRefused
	}
	// Exactly one bounded pass; never seek back, decode base64 again or reread FD3.
	b, e := io.ReadAll(io.LimitReader(f, PlanMax+1))
	defer clear(b)
	if e != nil || int64(len(b)) != st.Size || len(b) > PlanMax || decodeClosed(b, &p) != nil || !Identifier(p.ExecutionID) || p.Prompt == "" || !utf8.ValidString(p.Prompt) || p.Model == "" || p.ReasoningEffort == "" {
		return Plan{}, "", ErrRefused
	}
	return p, Hash(b), nil
}
func MatchPlan(p Plan, digest string, r LaunchRecord, uid uint32) error {
	if !Identifier(p.ExecutionID) || r.ExecutionID != p.ExecutionID || r.UID != uid || r.PlanSHA256 != digest || !hash.MatchString(digest) {
		return ErrRefused
	}
	return nil
}
