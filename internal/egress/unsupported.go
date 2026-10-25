//go:build !linux || !amd64

package egress

import (
	"context"
	"os"
)

// Unsupported platforms fail closed; no alternate network mechanism is selected.
func Run(context.Context, Config) (Report, error) { return Report{Incomplete: true}, ErrUnavailable }
func Bootstrap() error                            { return ErrUnavailable }

func NewCaseOrigin(*os.File, func() error) (*CaseOrigin, error) { return nil, ErrUnavailable }
func EnterCase() error                                          { return ErrUnavailable }

func NewOwnerOrigin(*os.File, string) (*CaseOrigin, error) { return nil, ErrUnavailable }
func EnterOwnerRole(string) error                          { return ErrUnavailable }
func NewCrashOwnerOrigin(*os.File, string) (*CaseOrigin, *TerminationController, error) {
	return nil, nil, ErrUnavailable
}
func NewWriterOrigin(*os.File, string) (*CaseOrigin, *TerminationController, error) {
	return nil, nil, ErrUnavailable
}
func EnterWriterRole(string) error { return ErrUnavailable }
