//go:build linux && broker_lab

package labv0

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	labcontract "github.com/relux-works/swarma-credential-broker/contracts/lab-v0"
	"github.com/relux-works/swarma-credential-broker/internal/service"
	"github.com/relux-works/swarma-credential-broker/internal/store"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

type labFixture struct {
	a         *Account
	records   *store.Account
	disk      *store.Store
	root      string
	now       time.Time
	facts     projectionFacts
	broker    *service.Broker
	authority *fixtureAuthority
	fault     *string
}

func fixtureRecord(test *testing.T, format string) map[string]any {
	test.Helper()
	filename := "../../contracts/lab-v0/fixtures.json"
	if format == recoveryFormat {
		filename = "../../contracts/lab-v0/recovery-fixtures.json"
	}
	raw, err := os.ReadFile(filename)
	if err != nil {
		test.Fatal(err)
	}
	var fixtures struct {
		Cases []struct {
			Surface string         `json:"surface"`
			Valid   map[string]any `json:"valid"`
		} `json:"cases"`
	}
	if json.Unmarshal(raw, &fixtures) != nil {
		test.Fatal("fixture decode")
	}
	for _, candidate := range fixtures.Cases {
		if candidate.Surface == format {
			result, err := object(candidate.Valid)
			if err != nil {
				test.Fatal(err)
			}
			return result
		}
	}
	test.Fatal("fixture missing")
	return nil
}

func newLabFixture(test *testing.T, bootstrap bool) *labFixture {
	test.Helper()
	fixture := &labFixture{root: filepath.Join(test.TempDir(), "state"), now: time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC), fault: new(string)}
	journal := fixtureRecord(test, recoveryFormat)["external"].(map[string]any)
	context := journal["context"].(map[string]any)
	disk, err := store.OpenLab(fixture.root, context["installation_id"].(string), uint32(os.Geteuid()), true, func(stage string) error {
		if stage == *fixture.fault {
			*fixture.fault = ""
			return errors.New("injected durability uncertainty")
		}
		return nil
	})
	if err != nil {
		test.Fatal(err)
	}
	fixture.disk = disk
	test.Cleanup(func() { disk.Close() })
	fixture.records, err = disk.Account(accountLabel, true)
	if err != nil {
		test.Fatal(err)
	}
	authority := fixtureRecord(test, "swarma-broker-lab-authority/1")
	fixture.facts = projectionFacts{gateway: authority["gateway"].(map[string]any), caller: authority["worker"].(map[string]any), authorityUntil: fixture.now.Add(time.Hour), callerUntil: fixture.now.Add(time.Hour), timeUntil: fixture.now.Add(time.Hour), qualificationUntil: fixture.now.Add(time.Hour), lifetime: 900 * time.Second, version: "fixture-version"}
	fixture.a, err = newAccount(fixture.records, context, func(state wire.ServiceState, previous map[string]any) (map[string]any, error) {
		return fixture.facts.project(state, previous)
	})
	if err != nil {
		test.Fatal(err)
	}
	if bootstrap {
		custody := fixtureRecord(test, "swarma-broker-lab-custody/1")
		custody["material"] = "ssh-placeholder"
		metadata := fixtureRecord(test, "swarma-broker-lab-account/1")
		metadata["service_journal_head"] = journal["head"]
		if err := fixture.a.bootstrap(custody, metadata, journal, fixture.now); err != nil {
			test.Fatal(err)
		}
	}
	fixture.authority = &fixtureAuthority{fixture: fixture, confirmed: true, available: true}
	return fixture
}

type fixtureAuthority struct {
	fixture              *labFixture
	confirmed, available bool
}

func (authority *fixtureAuthority) WithIdentity(ctx context.Context, fn func(service.View) error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return fn(authority)
}
func (authority *fixtureAuthority) WithCurrent(ctx context.Context, fn func(service.View) error) error {
	if !authority.available {
		return wire.Refuse("revocation_state_unavailable")
	}
	return authority.WithIdentity(ctx, fn)
}
func (authority *fixtureAuthority) Principal(uid uint32) (service.Principal, error) {
	if uid == 0 {
		return service.Principal{UID: 0, Role: "operator", Generation: "root"}, nil
	}
	gateway := authority.fixture.facts.gateway
	if uid != uint32(gateway["uid"].(int64)) {
		return service.Principal{}, wire.Refuse("role_not_permitted")
	}
	return service.Principal{UID: uid, Role: "service", Generation: gateway["generation"].(string), Service: "credential-gateway"}, nil
}
func (authority *fixtureAuthority) Service(binding wire.ServiceBinding) error {
	gateway := authority.fixture.facts.gateway
	if binding.UID != uint32(gateway["uid"].(int64)) || binding.Generation != gateway["generation"] || binding.Kind != service.LabKind {
		return wire.Refuse("service_binding_mismatch")
	}
	return nil
}
func (authority *fixtureAuthority) Caller(_ wire.ServiceBinding, caller wire.ServiceCaller) (time.Time, string, error) {
	facts := authority.fixture.facts
	if caller.UID != uint32(facts.caller["uid"].(int64)) || caller.Generation != facts.caller["generation"] || caller.LaunchID != facts.caller["execution_id"] {
		return time.Time{}, "", wire.Refuse("lease_not_authorised")
	}
	until := facts.callerUntil
	for _, bound := range []time.Time{facts.authorityUntil, facts.timeUntil, facts.qualificationUntil} {
		if bound.Before(until) {
			until = bound
		}
	}
	return until, "fixture-binding", nil
}
func (authority *fixtureAuthority) Owner(uid uint32, account string) bool {
	return uid == 0 && account == accountLabel
}
func (authority *fixtureAuthority) OperatorAct(principal service.Principal, _ string, _ json.RawMessage) bool {
	return principal.UID == 0 && authority.confirmed
}
func (authority *fixtureAuthority) Event(json.RawMessage) bool { return false }
func (authority *fixtureAuthority) Sequence() json.RawMessage  { return json.RawMessage(`1`) }

func (fixture *labFixture) start(test *testing.T) {
	test.Helper()
	broker, err := service.NewLabWithLifetime(fixture.authority, map[string]service.Account{accountLabel: fixture.a}, func() time.Time { return fixture.now }, fixture.facts.lifetime)
	if err != nil {
		test.Fatal(err)
	}
	fixture.broker = broker
}
func (fixture *labFixture) call(test *testing.T, uid uint32, method string, arguments any) (any, error) {
	test.Helper()
	raw, err := wire.Encode(arguments)
	if err != nil {
		test.Fatal(err)
	}
	principal, err := fixture.broker.Open(context.Background(), uid)
	if err != nil {
		return nil, err
	}
	var result any
	err = fixture.broker.Call(context.Background(), principal, method, raw, func(value any) error { result = value; return nil })
	return result, err
}
func (fixture *labFixture) bind(test *testing.T) {
	test.Helper()
	_, err := fixture.call(test, 0, "service.bind", wire.ServiceBind{OperationID: strings.Repeat("a", 32), ServiceBinding: wire.ServiceBinding{Service: "credential-gateway", UID: 4101, Generation: fixture.facts.gateway["generation"].(string), Account: accountLabel, Kind: service.LabKind, PolicyDigest: fixture.facts.gateway["plan_sha256"].(string)}})
	if err != nil {
		test.Fatal(err)
	}
}
func (fixture *labFixture) request(operation string) wire.ServiceRequest {
	return wire.ServiceRequest{OperationID: operation, ServiceCaller: wire.ServiceCaller{Account: accountLabel, UID: 4102, Generation: fixture.facts.caller["generation"].(string), LaunchID: fixture.facts.caller["execution_id"].(string)}}
}

// Claim: a committed fresh account starts the existing engine, while missing, orphaned and production-family stores cannot bootstrap or become an empty controller.
func TestLabCommittedBootstrapAndCrossRead(test *testing.T) {
	valid := newLabFixture(test, true)
	valid.start(test)
	if _, err := valid.a.Snapshot(); err != nil {
		test.Fatal(err)
	}
	missing := newLabFixture(test, false)
	if _, err := missing.a.LoadServiceState(); !errors.Is(err, ErrUnknown) {
		test.Fatal("missing state adopted")
	}
	if err := missing.records.Append("owner-orphan.json", map[string]any{"installation_id": missing.a.installation, "revision": 1}); err != nil {
		test.Fatal(err)
	}
	custody := fixtureRecord(test, "swarma-broker-lab-custody/1")
	custody["material"] = "ssh-placeholder"
	metadata := fixtureRecord(test, "swarma-broker-lab-account/1")
	journal := fixtureRecord(test, recoveryFormat)["external"].(map[string]any)
	metadata["service_journal_head"] = journal["head"]
	if err := missing.a.bootstrap(custody, metadata, journal, missing.now); !errors.Is(err, ErrUnknown) {
		test.Fatal("orphan adopted")
	}
	for _, direction := range []string{"lab-to-production", "production-to-lab"} {
		test.Run(direction, func(test *testing.T) {
			path := filepath.Join(test.TempDir(), "cross")
			var disk *store.Store
			var err error
			if direction == "lab-to-production" {
				disk, err = store.OpenLab(path, "cross", uint32(os.Geteuid()), true, nil)
			} else {
				disk, err = store.Open(path, "cross", uint32(os.Geteuid()), true, nil)
			}
			if err != nil {
				test.Fatal(err)
			}
			disk.Close()
			if direction == "lab-to-production" {
				disk, err = store.Open(path, "cross", uint32(os.Geteuid()), false, nil)
			} else {
				disk, err = store.OpenLab(path, "cross", uint32(os.Geteuid()), false, nil)
			}
			if err == nil {
				disk.Close()
				test.Fatal("foreign store adopted")
			}
		})
	}
}

// Claim: private recovery is lossless across issue/two renewals/restart and contradicting arguments refuse without a second effect or latest-deadline substitution.
func TestLabRecoveryHistoricalReplay(test *testing.T) {
	fixture := newLabFixture(test, true)
	fixture.start(test)
	fixture.bind(test)
	request := fixture.request(strings.Repeat("b", 32))
	result, err := fixture.call(test, 4101, "service.lease.request", request)
	if err != nil {
		test.Fatal(err)
	}
	original := result.(wire.ServiceLease)
	for _, digit := range []string{"c", "d"} {
		fixture.now = fixture.now.Add(time.Second)
		result, err = fixture.call(test, 4101, "service.lease.renew", wire.ServiceRenew{OperationID: strings.Repeat(digit, 32), ServiceLeaseID: wire.ServiceLeaseID{LeaseID: original.LeaseID}})
		if err != nil {
			test.Fatal(err)
		}
		if result.(wire.ServiceLease).AuthorizedUntil == original.AuthorizedUntil {
			test.Fatal("renewal control not distinct")
		}
	}
	before, err := fixture.a.LoadServiceState()
	if err != nil {
		test.Fatal(err)
	}
	fixture.start(test)
	result, err = fixture.call(test, 4101, "service.lease.request", request)
	if err != nil {
		test.Fatal(err)
	}
	if result.(wire.ServiceLease).AuthorizedUntil != original.AuthorizedUntil {
		test.Fatal("historical replay widened")
	}
	request.LaunchID = "contradictory"
	if _, err = fixture.call(test, 4101, "service.lease.request", request); err == nil || err.Error() != "service_operation_conflict" {
		test.Fatalf("contradictory replay: %v", err)
	}
	after, _ := fixture.a.LoadServiceState()
	if len(after.Operations) != len(before.Operations) {
		test.Fatal("duplicate effect")
	}
	raw, err := fixture.records.Read(stateName)
	if err != nil {
		test.Fatal(err)
	}
	if bytes.Contains(raw, []byte("ssh-placeholder")) {
		test.Fatal("material in recovery")
	}
	for _, envelope := range []bool{false, true} {
		snapshot, err := fixture.a.Snapshot()
		if err != nil {
			test.Fatal(err)
		}
		if envelope {
			snapshot = raw
		}
		if _, err := labcontract.Read(journalFormat, snapshot); (err == nil) == envelope {
			test.Fatal("private/public cross-read")
		}
	}
}

// Claim: a rename-uncertain hold hides the candidate projection and material until identical recovery confirms it; a different hold ID cannot resolve UNKNOWN.
func TestLabHoldUnknownAtomicJoin(test *testing.T) {
	fixture := newLabFixture(test, true)
	fixture.start(test)
	fixture.bind(test)
	result, err := fixture.call(test, 4101, "service.lease.request", fixture.request(strings.Repeat("b", 32)))
	if err != nil {
		test.Fatal(err)
	}
	lease := result.(wire.ServiceLease)
	hold := wire.ServiceHold{OperationID: strings.Repeat("c", 32), LeaseID: lease.LeaseID, Account: accountLabel, Reason: "leak_match"}
	*fixture.fault = "rename"
	if _, err = fixture.call(test, 4101, "account.hold", hold); err == nil || err.Error() != "account_hold_unknown" {
		test.Fatalf("hold uncertainty: %v", err)
	}
	if _, err = fixture.a.Snapshot(); !errors.Is(err, ErrUnknown) {
		test.Fatal("uncertain projection escaped")
	}
	other := hold
	other.OperationID = strings.Repeat("d", 32)
	if _, err = fixture.call(test, 4101, "account.hold", other); err == nil {
		test.Fatal("different ID resolved unknown")
	}
	if _, err = fixture.call(test, 4101, "account.hold", hold); err != nil {
		test.Fatalf("same-ID reconciliation: %v", err)
	}
	snapshot, err := fixture.a.Snapshot()
	if err != nil {
		test.Fatal(err)
	}
	public, _ := wire.Parse(snapshot)
	if public["held"] != true {
		test.Fatal("hold lost")
	}
	if _, err = fixture.call(test, 4101, "service.lease.request", fixture.request(strings.Repeat("e", 32))); err == nil {
		test.Fatal("held material reopened")
	}
}

// Claim: the pure reserve gate admits its valid control and refuses missing count, byte or reconciliation-revision capacity; native-plan admission is not claimed.
func TestLabFiniteNarrowingReserve(test *testing.T) {
	fixture := newLabFixture(test, true)
	state, err := fixture.a.LoadServiceState()
	if err != nil {
		test.Fatal(err)
	}
	journal := fixtureRecord(test, recoveryFormat)["external"].(map[string]any)
	if !reserveFits(state, journal, 1000) {
		test.Fatal("valid reserve refused")
	}
	for _, change := range []string{"count", "reserve", "private-bytes", "public-bytes", "revision"} {
		test.Run(change, func(test *testing.T) {
			candidate := state
			external, _ := object(journal)
			size := 1000
			switch change {
			case "count":
				external["operation_limit"] = int64(7)
			case "reserve":
				external["narrowing_reserve"] = int64(1)
			case "private-bytes":
				size = 524288
			case "public-bytes":
				external["entries"] = make([]any, 65536)
			case "revision":
				candidate.Revision = 9007199254740989
			}
			if reserveFits(candidate, external, size) {
				test.Fatal("lost narrowing reserve admitted")
			}
		})
	}
}

// Claim: a released lease retains its exact inclusive hold endpoint across a later issue and restart, and one nanosecond after that endpoint refuses.
func TestLabReleaseHoldBoundary(test *testing.T) {
	for _, late := range []bool{false, true} {
		test.Run(fmt.Sprint("late=", late), func(test *testing.T) {
			fixture := newLabFixture(test, true)
			fixture.start(test)
			fixture.bind(test)
			result, err := fixture.call(test, 4101, "service.lease.request", fixture.request(strings.Repeat("b", 32)))
			if err != nil {
				test.Fatal(err)
			}
			lease := result.(wire.ServiceLease)
			fixture.now = fixture.now.Add(time.Second)
			releasedAt := fixture.now
			if _, err = fixture.call(test, 4101, "service.lease.release", wire.ServiceLeaseID{LeaseID: lease.LeaseID}); err != nil {
				test.Fatal(err)
			}
			fixture.now = fixture.now.Add(time.Second)
			if _, err = fixture.call(test, 4101, "service.lease.request", fixture.request(strings.Repeat("c", 32))); err != nil {
				test.Fatal(err)
			}
			fixture.start(test)
			fixture.now = releasedAt.Add(fixture.facts.lifetime)
			if late {
				fixture.now = fixture.now.Add(time.Nanosecond)
			}
			_, err = fixture.call(test, 4101, "account.hold", wire.ServiceHold{OperationID: strings.Repeat("d", 32), LeaseID: lease.LeaseID, Account: accountLabel, Reason: "leak_match"})
			if !late && err != nil {
				test.Fatal("inclusive control refused:", err)
			}
			if late && (err == nil || err.Error() != "lease_not_active") {
				test.Fatalf("late hold wrong refusal: %v", err)
			}
		})
	}
}

// Claim: exact-root lift admits but wrong-ID/nonowner lift refuses, old leases remain revoked, and unbinding closes the registered engine connection; no native socket timing is claimed.
func TestLabLiftAndUnbindContainment(test *testing.T) {
	fixture := newLabFixture(test, true)
	fixture.start(test)
	fixture.bind(test)
	result, err := fixture.call(test, 4101, "service.lease.request", fixture.request(strings.Repeat("b", 32)))
	if err != nil {
		test.Fatal(err)
	}
	lease := result.(wire.ServiceLease)
	result, err = fixture.call(test, 4101, "account.hold", wire.ServiceHold{OperationID: strings.Repeat("c", 32), LeaseID: lease.LeaseID, Account: accountLabel, Reason: "leak_match"})
	if err != nil {
		test.Fatal(err)
	}
	holdID := result.(map[string]any)["hold_id"].(string)
	lift := wire.ServiceLift{OperationID: strings.Repeat("d", 32), HoldID: "wrong", Account: accountLabel}
	if _, err = fixture.call(test, 0, "account.hold.lift", lift); err == nil || err.Error() != "account_hold_not_found" {
		test.Fatalf("wrong hold lift: %v", err)
	}
	lift.HoldID = holdID
	if _, err = fixture.call(test, 4101, "account.hold.lift", lift); err == nil || err.Error() != "role_not_permitted" {
		test.Fatalf("nonowner lift: %v", err)
	}
	if _, err = fixture.call(test, 0, "account.hold.lift", lift); err != nil {
		test.Fatal(err)
	}
	if _, err = fixture.call(test, 4101, "service.lease.renew", wire.ServiceRenew{OperationID: strings.Repeat("e", 32), ServiceLeaseID: wire.ServiceLeaseID{LeaseID: lease.LeaseID}}); err == nil || err.Error() != "lease_not_active" {
		test.Fatalf("old lease resurrected: %v", err)
	}
	if _, err = fixture.call(test, 4101, "service.lease.request", fixture.request(strings.Repeat("f", 32))); err != nil {
		test.Fatal("fresh post-lift control:", err)
	}
	principal, err := fixture.broker.Open(context.Background(), 4101)
	if err != nil {
		test.Fatal(err)
	}
	closed := false
	cleanup, err := fixture.broker.RegisterConnection(context.Background(), principal, func() { closed = true })
	if err != nil {
		test.Fatal(err)
	}
	defer cleanup()
	state, err := fixture.a.LoadServiceState()
	if err != nil {
		test.Fatal(err)
	}
	if _, err = fixture.call(test, 0, "service.unbind", wire.ServiceUnbind{OperationID: strings.Repeat("1", 32), BindingID: state.Bindings[0].ID}); err != nil {
		test.Fatal(err)
	}
	if !closed {
		test.Fatal("unbind left registered connection open")
	}
	if _, err = fixture.call(test, 4101, "service.lease.request", fixture.request(strings.Repeat("2", 32))); err == nil {
		test.Fatal("unbound material reopened")
	}
}

// Claim: a valid whole recovery image admits but digest, revision, canonical truncation and operation/optional-field mismatches cannot be read as committed state.
func TestLabRecoveryJoinTampering(test *testing.T) {
	fixture := newLabFixture(test, true)
	fixture.start(test)
	fixture.bind(test)
	if _, err := fixture.call(test, 4101, "service.lease.request", fixture.request(strings.Repeat("b", 32))); err != nil {
		test.Fatal(err)
	}
	raw, err := fixture.records.Read(stateName)
	if err != nil {
		test.Fatal(err)
	}
	if _, _, err = readRecovery(raw, fixture.a.installation); err != nil {
		test.Fatal(err)
	}
	for _, change := range []string{"digest", "revision", "truncated", "operation", "optional", "caller", "renewal"} {
		test.Run(change, func(test *testing.T) {
			envelope, err := wire.Parse(raw)
			if err != nil {
				test.Fatal(err)
			}
			switch change {
			case "digest":
				envelope["external_sha256"] = "sha256:" + strings.Repeat("0", 64)
			case "revision":
				envelope["previous_revision"] = int64(0)
			case "operation":
				envelope["state"].(map[string]any)["operations"].([]any)[0].(map[string]any)["operation_id"] = strings.Repeat("3", 32)
			case "optional":
				binding := envelope["state"].(map[string]any)["bindings"].([]any)[0].(map[string]any)
				binding["removed_at"] = []any{fixture.now.Format(time.RFC3339Nano), fixture.now.Format(time.RFC3339Nano)}
			case "caller":
				envelope["external"].(map[string]any)["bindings"].([]any)[0].(map[string]any)["caller"].(map[string]any)["generation"] = "foreign"
			case "renewal":
				envelope["external"].(map[string]any)["leases"].([]any)[0].(map[string]any)["renew_operation_ids"] = []any{strings.Repeat("4", 32)}
			}
			if change == "caller" || change == "renewal" {
				external := envelope["external"].(map[string]any)
				sealJournal(external)
				envelope["external_sha256"] = digest(external)
			}
			candidate, err := wire.Encode(envelope)
			if err != nil {
				test.Fatal(err)
			}
			if change == "truncated" {
				candidate = candidate[:len(candidate)-1]
			}
			expected := map[string]string{"digest": "recovery_join", "revision": "recovery_join", "truncated": "canonical", "operation": "recovery_operation_id", "optional": "recovery_optional", "caller": "recovery_caller_join", "renewal": "recovery_renew_join"}[change]
			if _, _, err := readRecovery(candidate, fixture.a.installation); err == nil || err.Error() != expected {
				test.Fatalf("mismatched/partial join admitted or wrong gate: %v", err)
			}
		})
	}
}

// Claim: a stale revision cannot overwrite a confirmed successor and a changed bootstrap operation budget is refused without committing a new snapshot.
func TestLabRecoveryCASAndImmutableBudget(test *testing.T) {
	fixture := newLabFixture(test, true)
	fixture.start(test)
	state, err := fixture.a.LoadServiceState()
	if err != nil {
		test.Fatal(err)
	}
	state.Revision++
	if err := fixture.a.StoreServiceState(state); err != nil {
		test.Fatal("valid CAS:", err)
	}
	before, err := fixture.records.Read(stateName)
	if err != nil {
		test.Fatal(err)
	}
	if err := fixture.a.StoreServiceState(state); !errors.Is(err, ErrUnknown) {
		test.Fatal("stale revision admitted")
	}
	after, err := fixture.records.Read(stateName)
	if err != nil || !bytes.Equal(before, after) {
		test.Fatal("stale write changed committed state")
	}
	fixture.start(test)
	project := fixture.a.project
	fixture.a.project = func(state wire.ServiceState, previous map[string]any) (map[string]any, error) {
		candidate, err := project(state, previous)
		if err == nil {
			candidate["operation_limit"] = int64(31)
			sealJournal(candidate)
		}
		return candidate, err
	}
	if _, err := fixture.call(test, 0, "service.bind", wire.ServiceBind{OperationID: strings.Repeat("a", 32), ServiceBinding: wire.ServiceBinding{Service: "credential-gateway", UID: 4101, Generation: fixture.facts.gateway["generation"].(string), Account: accountLabel, Kind: service.LabKind, PolicyDigest: fixture.facts.gateway["plan_sha256"].(string)}}); err == nil {
		test.Fatal("operation budget retargeted")
	}
	state, err = fixture.a.LoadServiceState()
	if err != nil {
		test.Fatal(err)
	}
	if len(state.Operations) != 0 {
		test.Fatal("refused budget committed effect")
	}
}

// Claim: the tagged engine retains the 1..900 ceiling and earliest bound, while 0/901 and an old replay exceeding newly narrowed authority refuse.
func TestLabLifetimeAndEarlierDeadline(test *testing.T) {
	for _, seconds := range []int{0, 1, 900, 901} {
		test.Run(fmt.Sprint("lifetime=", seconds), func(test *testing.T) {
			fixture := newLabFixture(test, true)
			fixture.facts.lifetime = time.Duration(seconds) * time.Second
			broker, err := service.NewLabWithLifetime(fixture.authority, map[string]service.Account{accountLabel: fixture.a}, func() time.Time { return fixture.now }, fixture.facts.lifetime)
			if seconds == 0 || seconds == 901 {
				if err == nil {
					test.Fatal("invalid ceiling admitted")
				}
				return
			}
			if err != nil {
				test.Fatal(err)
			}
			fixture.broker = broker
			fixture.bind(test)
			result, err := fixture.call(test, 4101, "service.lease.request", fixture.request(strings.Repeat("b", 32)))
			if err != nil {
				test.Fatal(err)
			}
			if result.(wire.ServiceLease).AuthorizedUntil != fixture.now.Add(fixture.facts.lifetime).Format(time.RFC3339Nano) {
				test.Fatal("ceiling not exact")
			}
		})
	}
	for _, earlier := range []string{"authority", "caller", "time", "qualification"} {
		test.Run(earlier, func(test *testing.T) {
			fixture := newLabFixture(test, true)
			bound := fixture.now.Add(10*time.Second + time.Nanosecond)
			switch earlier {
			case "authority":
				fixture.facts.authorityUntil = bound
			case "caller":
				fixture.facts.callerUntil = bound
			case "time":
				fixture.facts.timeUntil = bound
			case "qualification":
				fixture.facts.qualificationUntil = bound
			}
			fixture.start(test)
			fixture.bind(test)
			request := fixture.request(strings.Repeat("b", 32))
			result, err := fixture.call(test, 4101, "service.lease.request", request)
			if err != nil {
				test.Fatal(err)
			}
			if result.(wire.ServiceLease).AuthorizedUntil != bound.Format(time.RFC3339Nano) {
				test.Fatal("earlier deadline ignored")
			}
			fixture.facts.authorityUntil = fixture.now.Add(time.Second)
			if _, err = fixture.call(test, 4101, "service.lease.request", request); err == nil || err.Error() != "lease_not_authorised" {
				test.Fatalf("narrowed replay: %v", err)
			}
		})
	}
}
