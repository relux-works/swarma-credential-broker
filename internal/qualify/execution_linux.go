//go:build linux

package qualify

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/qualification"
)

// Diagnostics are closed phase codes, never helper output, paths or identities.
type rowDiagnostic string

type rowExecution struct {
	Launched   bool          `json:"launched"`
	Handshake  bool          `json:"identity_handshake"`
	Started    bool          `json:"case_started"`
	Completed  bool          `json:"case_completed"`
	Joined     bool          `json:"helper_joined"`
	HelperExit int           `json:"helper_exit"`
	WorkerExit int           `json:"worker_exit"`
	CaseExit   int           `json:"case_exit"`
	Diagnostic rowDiagnostic `json:"diagnostic,omitempty"`
}

type rowExecutionRecord struct {
	ID        string       `json:"id"`
	Side      string       `json:"side"`
	Execution rowExecution `json:"execution"`
}

func workerDiagnostic(d rowDiagnostic) bool {
	switch d {
	case "", "case_not_started", "case_status_unavailable", "observation_invalid":
		return true
	}
	return false
}

func newRowExecution() rowExecution {
	return rowExecution{HelperExit: -1, WorkerExit: -1, CaseExit: -1}
}

func (d driver) recordExecution(id, side string, e rowExecution) {
	if d.executions != nil {
		*d.executions = append(*d.executions, rowExecutionRecord{id, side, e})
	}
}

func (e rowExecution) credit(peer bool) bool {
	return e.Launched && (!peer || e.Handshake) && e.Started && e.Completed && e.Joined && e.CaseExit >= 0 && e.CaseExit <= 255 && e.CaseExit == e.WorkerExit
}

func pendingRowControl() qualification.Control {
	return qualification.Control{Verdict: "pending", ExitCode: -1, Command: []string{}, Artifacts: []string{}, BoundNS: int64(30 * time.Second)}
}

func executionControl(id, side string, e rowExecution, elapsed time.Duration) qualification.Control {
	control := pendingRowControl()
	if !e.credit(id == "peer-denied") || elapsed <= 0 || elapsed > 30*time.Second {
		return control
	}
	control.Verdict, control.Executed, control.ExitCode = "failed", true, e.CaseExit
	control.Command, control.DurationNS = qualification.CaseCommand(id, side), int64(elapsed)
	return control
}

// Wait state is independent of observation/bootstrap errors. No status is
// inferred from a generic error, and a launch failure has no wait state.
func (e *rowExecution) waited(state *os.ProcessState) {
	if state != nil {
		e.Joined = true
		e.HelperExit = state.ExitCode()
	}
}

func launchDiagnostic(err error) rowDiagnostic {
	switch {
	case errors.Is(err, exec.ErrNotFound):
		return "launcher_lookup_failed"
	case errors.Is(err, os.ErrNotExist):
		return "launcher_not_found"
	case errors.Is(err, os.ErrPermission):
		return "launcher_not_executable"
	default:
		return "launcher_unavailable"
	}
}

// FD9 is separate from the context, candidate and lease phase descriptors.
// Only entry into the canonical case writes this byte; launcher Start cannot.
func signalCaseStart() error {
	f := os.NewFile(9, "case-start")
	if f == nil {
		return qualification.ErrUnavailable
	}
	_, e := f.Write([]byte{'c'})
	return errors.Join(e, f.Close())
}

func readCaseStart(r, w *os.File) bool {
	w.Close()
	b, e := io.ReadAll(io.LimitReader(r, 2))
	return e == nil && len(b) == 1 && b[0] == 'c'
}

func withCaseStart(files []*os.File, padding, started *os.File) []*os.File {
	for len(files) < 5 { // boundary candidate slots start at FD4
		files = append(files, padding)
	}
	return append(files, started)
}
