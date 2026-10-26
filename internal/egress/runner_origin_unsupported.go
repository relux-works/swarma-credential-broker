//go:build !linux || !amd64

package egress

import (
	"context"
	"os"
)

func NewRunnerOrigin(*os.File, string, []string) (*RunnerOrigin, error) {
	return nil, ErrRunnerOriginUnavailable
}
func TraceRunner(context.Context, RunnerTraceConfig) (RunnerTraceResult, error) {
	return RunnerTraceResult{}, ErrRunnerOriginUnavailable
}
