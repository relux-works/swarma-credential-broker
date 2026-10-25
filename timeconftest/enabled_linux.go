//go:build linux && timeconf_fixture

// Package timeconftest supplies codec and settlement controls for consumer tests.
// Import it only from tagged _test.go files, never from application code.
package timeconftest

import "github.com/relux-works/swarma-credential-broker/timeconf"

type FixtureConsumer = timeconf.FixtureConsumer

func New(root string) (*FixtureConsumer, error) { return timeconf.NewFixtureConsumer(root) }
func VerifyReceipt(raw []byte, expected timeconf.Enrollment) (timeconf.Receipt, error) {
	return timeconf.VerifyFixtureReceipt(raw, expected)
}
