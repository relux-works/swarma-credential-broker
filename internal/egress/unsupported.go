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
