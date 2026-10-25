//go:build linux && swarma_timeconf_fixture

package timeconftest

import "github.com/relux-works/swarma-credential-broker/timeconf"

type Handoff = timeconf.FixtureHandoff
type ReferenceUseStore = timeconf.ReferenceUseStore

func NewHandoffProvider(root string) (*FixtureConsumer, error) {
	return timeconf.NewFixtureHandoffProvider(root)
}
func PrepareHandoff(raw []byte, originals [][]byte, e timeconf.WindowExpected, p int64) (timeconf.PreparedHandoff, error) {
	return timeconf.PrepareFixtureHandoff(raw, originals, e, p)
}
func NewUseStore(epoch string, windows ...timeconf.UseKey) *ReferenceUseStore {
	return timeconf.NewReferenceUseStore(epoch, windows...)
}
