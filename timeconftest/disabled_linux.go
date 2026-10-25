//go:build linux && !swarma_timeconf_fixture

// Package timeconftest refuses fixture selection without the explicit test tag.
package timeconftest

import (
	"context"
	"time"

	"github.com/relux-works/swarma-credential-broker/timeconf"
)

type FixtureConsumer struct{}

func inactive() error                      { return &timeconf.ActivationRefusal{Reason: "fixture_tag_required"} }
func New(string) (*FixtureConsumer, error) { return nil, inactive() }
func (*FixtureConsumer) ConsumeBeforePin(context.Context, timeconf.ConsumptionRequest) ([]byte, error) {
	return nil, &timeconf.ActivationRefusal{Reason: "fixture_unselected"}
}
func (*FixtureConsumer) Enrollment() timeconf.Enrollment { return timeconf.Enrollment{} }
func (*FixtureConsumer) Policy() timeconf.Policy         { return timeconf.Policy{} }
func (*FixtureConsumer) Advance(time.Duration) error {
	return &timeconf.ActivationRefusal{Reason: "fixture_unselected"}
}
func (*FixtureConsumer) LoseNextReply() {}
func (*FixtureConsumer) HighWater() (timeconf.Nanoseconds, error) {
	return "", &timeconf.ActivationRefusal{Reason: "fixture_unselected"}
}
func VerifyReceipt([]byte, timeconf.Enrollment) (timeconf.Receipt, error) {
	return timeconf.Receipt{}, inactive()
}
