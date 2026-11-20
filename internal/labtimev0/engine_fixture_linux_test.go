//go:build linux && broker_lab

package labtimev0

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/timeconf"
)

const fixtureBoot = "11111111-1111-4111-8111-111111111111"

type settlementFixture struct {
	consumer      *Consumer
	enrollment    Enrollment
	policy        Policy
	root          string
	now           time.Time
	collection    localCollection
	collectErr    error
	before, after ClockPoint
	readCount     int
	head          WitnessHead
}

func protectedTemp(test *testing.T) string {
	test.Helper()
	root := test.TempDir()
	if os.Chmod(root, 0700) != nil {
		test.Fatal("protected fixture")
	}
	return root
}

func testPolicy() Policy {
	return Policy{Source: NTSAuthData, Chronyc: "/usr/bin/chronyc", SourceFiles: []string{"/etc/chrony/chrony.conf"}, MaxSyncAge: time.Minute, MaxUncertainty: timeconf.PlatformMaxUncertainty, MaxOffset: 10 * time.Millisecond, MaxRootDistance: 20 * time.Millisecond, AuthorityWindow: 30 * time.Second, StepTolerance: 100 * time.Millisecond, Timeout: time.Second, MaxOutputBytes: 4096, Resync: "operator"}
}

func newSettlementFixture(test *testing.T) *settlementFixture {
	test.Helper()
	fixture := &settlementFixture{root: protectedTemp(test), policy: testPolicy()}
	digest := sum([]byte("fixture-enrollment"))
	fixture.enrollment = Enrollment{Authority: timeconf.AuthorityFact{ID: LabAuthority, Version: "1", TrustRootDigest: digest, QualificationDigest: digest}, Adapter: timeconf.AdapterFact{Revision: strings.Repeat("a", 40), CollectorEntry: "timeconf.CollectorEntry", ImageDigest: digest, ChronycDigest: digest, ClosureDigest: digest}, Policy: timeconf.PolicyFact{SharedDigest: digest, ServiceDigest: "none", EffectiveDigest: ""}, Scope: timeconf.ScopeFact{Machine: "machine", Consumer: "consumer", Purpose: "test", ContinuityScope: "clock"}, Store: "continuity"}
	fixture.enrollment.Policy.EffectiveDigest, _ = timeconf.EffectivePolicyDigest(fixture.policy, digest, "none")
	var err error
	fixture.consumer, err = timeconf.NewConsumer(fixture.enrollment, fixture.policy, fixture.root)
	if err != nil {
		test.Fatal(err)
	}
	fixture.setTime(211, fixtureBoot)
	fixture.seed(test, 140, 140, fixtureBoot)
	return fixture
}

func (fixture *settlementFixture) Read(context.Context) (ClockPoint, error) {
	fixture.readCount++
	if fixture.readCount%2 == 1 {
		return fixture.before, nil
	}
	return fixture.after, nil
}

func (fixture *settlementFixture) collect(context.Context, Policy) (localCollection, error) {
	return fixture.collection, fixture.collectErr
}

func (fixture *settlementFixture) setTime(seconds int64, boot string) {
	fixture.now = time.Unix(seconds, 0).UTC()
	fixture.before = ClockPoint{Now: fixture.now, Elapsed: time.Duration(seconds) * time.Second, Boot: boot}
	fixture.after = fixture.before
	fixture.readCount = 0
	evidence := timeconf.Evidence{Tracking: timeconf.Tracking{ReferenceID: "C0000201", Address: "192.0.2.1", Stratum: 3, Reference: fixture.now.Add(-time.Second), Leap: "Normal", UpdateInterval: 10}, Sources: timeconf.Sources{Count: 1, AllNTS: true, Entries: []string{"192.0.2.1"}}, Authentication: Authentication{Addresses: map[string]bool{"192.0.2.1": true}}}
	fixture.collection = localCollection{Evidence: evidence, Originals: [][]byte{[]byte("fixture original source report")}, Terminal: true, Drained: true}
}

func (fixture *settlementFixture) seed(test *testing.T, watermark, wall int64, boot string) {
	test.Helper()
	ns := func(seconds int64) timeconf.Nanoseconds {
		return timeconf.Nanoseconds(strconv.FormatInt(seconds*int64(time.Second), 10))
	}
	record := settlement{Version: "qualified-time/settlement/1", Binding: fixture.consumer.LabStore().LabBinding(), Generation: "0", Previous: "none", HighWater: ns(watermark), Last: savedClock{Boot: boot, Wall: ns(wall), Elapsed: ns(wall), Reference: ns(wall - 1)}, Hold: savedClock{Wall: "0", Elapsed: "0", Reference: "0"}}
	raw, _ := canonical(record)
	fixture.head = WitnessHead{Generation: 0, RecordDigest: sum(raw)}
	if os.WriteFile(filepath.Join(fixture.root, objectName("record-", sum(raw))), raw, 0600) != nil || os.WriteFile(filepath.Join(fixture.root, "current"), witnessBytes(fixture.head), 0600) != nil {
		test.Fatal("seed")
	}
}

func (fixture *settlementFixture) request(challenge string) ConsumptionRequest {
	return ConsumptionRequest{Deadline: time.Now().Add(400 * time.Millisecond), Expected: fixture.enrollment, OperationDigest: sum([]byte("operation")), Challenge: challenge, JournalFloor: 140 * int64(time.Second)}
}
