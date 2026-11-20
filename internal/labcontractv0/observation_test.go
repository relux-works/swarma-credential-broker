package labcontractv0

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const observationRequest = "swarma-broker-lab-observation-request/1"
const observationResponse = "swarma-broker-lab-observation-response/1"

func nativeIDOracle(value any) bool {
	text, ok := value.(string)
	if !ok || len(text) < 1 || len(text) > 64 {
		return false
	}
	for offset, char := range []byte(text) {
		alpha := char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9'
		if !alpha && (offset == 0 || !strings.ContainsRune("._-", rune(char))) {
			return false
		}
	}
	return true
}

func nativeExecutorOracle(value any) bool {
	text, ok := value.(string)
	if !ok || len(text) < 1 || len(text) > 32 {
		return false
	}
	for offset, char := range []byte(text) {
		alpha := char >= 'a' && char <= 'z' || char >= '0' && char <= '9'
		if !alpha && (offset == 0 || char != '-') {
			return false
		}
	}
	return true
}

func nativeTextMutations(kind string) []grammarMutation {
	maximum, seed, oracle := 64, "a.B_9", nativeIDOracle
	if kind == "native-executor" {
		maximum, seed, oracle = 32, "ab-09", nativeExecutorOracle
	}
	var result []grammarMutation
	for _, text := range []string{"a", "A", "0", seed, strings.Repeat("a", maximum)} {
		for _, mutation := range append(literalMutations(text), wrongTypes(text)...) {
			mutation.Name = text + "/" + mutation.Name
			mutation.Admit = oracle(mutation.Value)
			result = append(result, mutation)
		}
	}
	for _, count := range []int{0, 1, 2, maximum - 1, maximum, maximum + 1} {
		text := strings.Repeat("x", count)
		result = append(result, grammarMutation{fmt.Sprintf("native-length-%d", count), text, count >= 1 && count <= maximum})
	}
	for _, offset := range []int{0, 2, 4} {
		for value := 0; value < 256; value++ {
			text := []byte(seed)
			text[offset] = byte(value)
			result = append(result, grammarMutation{fmt.Sprintf("native-byte-%d-%d", offset, value), string(text), oracle(string(text))})
		}
	}
	for _, text := range []string{"a/", "a\x00", "é", "aK", "aı", "aſ", "a．b", "a_b", "A.B-9"} {
		result = append(result, grammarMutation{"native-confusable-" + text, text, oracle(text)})
	}
	return result
}

type observationFixture struct {
	Request      map[string]any `json:"request"`
	Response     map[string]any `json:"response"`
	Invalidation map[string]any `json:"invalidation"`
	Stop         map[string]any `json:"stop"`
	Expected     map[string]any `json:"expected"`
}

func observationControl(test *testing.T) observationFixture {
	test.Helper()
	var fixture observationFixture
	decodeContract(test, "observation-fixtures.json", &fixture)
	fixture.Request = normalizedBounded(test, fixture.Request)
	fixture.Response = normalizedBounded(test, fixture.Response)
	fixture.Invalidation = normalizedBounded(test, fixture.Invalidation)
	fixture.Stop = normalizedBounded(test, fixture.Stop)
	fixture.Expected = normalizedBounded(test, fixture.Expected)
	return fixture
}

func observationAdmission(test *testing.T, fixture observationFixture, nativeLocked bool) string {
	test.Helper()
	return observationJoinAdmission(test, fixture, nativeLocked, false)
}

func observationJoinAdmission(test *testing.T, fixture observationFixture, nativeLocked, narrowing bool) string {
	test.Helper()
	set, _ := loadContracts(test)
	for format, record := range map[string]map[string]any{observationRequest: fixture.Request, observationResponse: fixture.Response} {
		if checkRecord(canonicalObject(test, record), boundedShape(set, format), set) != nil {
			return "shape"
		}
	}
	if !nativeLocked {
		return "native_lock"
	}
	request, response, expected := fixture.Request, fixture.Response, fixture.Expected
	start := response["start"].(map[string]any)
	manager := response["manager"].(map[string]any)
	store := response["store"].(map[string]any)
	if response["operation_id"] != request["operation_id"] || response["start_id"] != request["start_id"] || start["operation_id"] != request["operation_id"] || start["start_id"] != request["start_id"] {
		return "request_join"
	}
	if !reflect.DeepEqual(manager, expected["manager"]) {
		return "manager"
	}
	if store["generation"] != expected["store_generation"] {
		return "store_generation"
	}
	if !reflect.DeepEqual(store["manager_head"], expected["manager_head"]) {
		return "manager_head"
	}
	if store["generation_current"] != true {
		return "currentness"
	}
	if response["complete"] != true {
		return "completeness"
	}
	if response["sequence_generation"] != store["generation"] {
		return "sequence_generation"
	}
	if response["sequence"].(int64) <= expected["sequence_high_water"].(int64) {
		return "sequence"
	}
	observed := response["observed_monotonic_ms"].(int64)
	before, after := expected["before_monotonic_ms"].(int64), expected["after_monotonic_ms"].(int64)
	if before > observed || observed > after || after < before || after-before >= 250 {
		return "interval"
	}
	pins := cloneObject(test, start)
	delete(pins, "phase")
	if !reflect.DeepEqual(normalizedBounded(test, pins), expected["start"]) {
		return "start_join"
	}
	if start["phase"] != "admitted" && !narrowing {
		return "start_phase"
	}
	if len(response["stops"].([]any)) != 0 && !narrowing {
		return "stop"
	}
	receipts, debits, invalidations := response["receipts"].([]any), response["debits"].([]any), response["invalidations"].([]any)
	if len(receipts) != 1 {
		return "receipt_count"
	}
	if len(debits) != 1 {
		return "debit_count"
	}
	if len(invalidations) != 0 && !narrowing {
		return "invalidation"
	}
	receipt, debit := receipts[0].(map[string]any), debits[0].(map[string]any)
	for _, field := range []string{"execution_id", "epoch", "pid", "start_time", "boot_id"} {
		if receipt[field] != debit[field] {
			return "incarnation"
		}
	}
	if receipt["execution_id"] != request["start_id"] || receipt["epoch"] != start["epoch"] || receipt["boot_id"] != manager["boot_id"] || debit["generation"] != start["generation"] {
		return "incarnation"
	}
	if start["uid"].(int64) > 4294967294 || receipt["pid"].(int64) > 4194304 || receipt["session_id"].(int64) > 4194304 {
		return "native_bounds"
	}
	for _, value := range invalidations {
		invalidation := value.(map[string]any)
		if invalidation["generation"] != start["generation"] || invalidation["execution_id"] != request["start_id"] || invalidation["boot_id"] != manager["boot_id"] {
			return "invalidation_join"
		}
	}
	for _, value := range response["stops"].([]any) {
		stop := value.(map[string]any)
		if stop["generation"] != start["generation"] || stop["start_id"] != request["start_id"] {
			return "stop_join"
		}
	}
	if debit["committed_ms"].(int64) > observed {
		return "debit_time"
	}
	if store["debits_head"].(map[string]any)["sequence"].(int64) < int64(len(debits)) {
		return "proof_heads"
	}
	return "valid"
}

type observationTransport struct {
	ClientUID, DaemonUID, ServerUID, SocketOwnerUID               int64
	TrustedServer, ProtectedPath, NativeLock, WriteEOF, Ancillary bool
	RequestBytes, ResponseBytes, Requests, Responses, ElapsedMS   int64
	InFlight, LockHoldMS, NativeWaitMS, CooldownMS                int64
}

func validObservationTransport() observationTransport {
	return observationTransport{ClientUID: 4001, DaemonUID: 4001, ServerUID: 0, SocketOwnerUID: 0, TrustedServer: true, ProtectedPath: true, NativeLock: true, WriteEOF: true, RequestBytes: 4096, ResponseBytes: 65536, Requests: 1, Responses: 1, ElapsedMS: 249, InFlight: 1, LockHoldMS: 24, NativeWaitMS: 25, CooldownMS: 250}
}

func observationTransportAdmission(input observationTransport) string {
	if input.DaemonUID < 1 || input.DaemonUID > 4294967294 || input.ClientUID != input.DaemonUID {
		return "client_peer"
	}
	if input.ServerUID != 0 || input.SocketOwnerUID != 0 || !input.TrustedServer || !input.ProtectedPath {
		return "server_peer"
	}
	if verdict := observationLoad(input); verdict != "valid" {
		return verdict
	}
	if input.RequestBytes < 1 || input.RequestBytes > 4096 || input.ResponseBytes < 1 || input.ResponseBytes > 65536 {
		return "frame_size"
	}
	if input.Requests != 1 || input.Responses != 1 || !input.WriteEOF || input.Ancillary {
		return "one_frame"
	}
	if input.ElapsedMS < 0 || input.ElapsedMS >= 250 {
		return "deadline"
	}
	if !input.NativeLock {
		return "native_lock"
	}
	return "valid"
}

type observationPublication struct {
	Floor     int64
	Published bool
}

func publishObservation(test *testing.T, state *observationPublication, first, final observationFixture, transport observationTransport, elapsed int64, fresh, cas bool) string {
	test.Helper()
	if observationTransportAdmission(transport) != "valid" {
		return "unknown_transport"
	}
	if observationAdmission(test, first, true) != "valid" || observationAdmission(test, final, true) != "valid" {
		return "unknown_observation"
	}
	if !fresh || final.Expected["before_monotonic_ms"].(int64)-first.Expected["after_monotonic_ms"].(int64) < 250 {
		return "unknown_freshness"
	}
	sequence := final.Response["sequence"].(int64)
	if first.Response["sequence"].(int64) <= state.Floor || sequence <= first.Response["sequence"].(int64) || sequence <= state.Floor {
		return "unknown_sequence"
	}
	old, newer := cloneObject(test, first.Response), cloneObject(test, final.Response)
	for _, record := range []map[string]any{old, newer} {
		delete(record, "sequence")
		delete(record, "observed_monotonic_ms")
	}
	if !reflect.DeepEqual(old, newer) {
		return "unknown_snapshot"
	}
	before := final.Expected["before_monotonic_ms"].(int64)
	if elapsed < final.Expected["after_monotonic_ms"].(int64) || elapsed-before >= 250 {
		return "unknown_deadline"
	}
	if !cas {
		return "unknown_commit"
	}
	state.Floor, state.Published = sequence, true
	return "published"
}

// Claim: every complete request/receipt/debit/proof join admits beside each independently changed, absent or invalidated UNKNOWN control; these are reference facts, not native observations.
func TestLabObservationJoinPairs(test *testing.T) {
	run := func(name, wanted string, change func(*observationFixture)) {
		test.Run(name, func(test *testing.T) {
			control := observationControl(test)
			if got := observationAdmission(test, control, true); got != "valid" {
				test.Fatalf("valid join: %s", got)
			}
			change(&control)
			if got := observationAdmission(test, control, true); got != wanted {
				test.Fatalf("join verdict: got %s want %s", got, wanted)
			}
		})
	}
	for _, field := range []string{"operation_id", "start_id"} {
		run("response-"+field, "request_join", func(fixture *observationFixture) { fixture.Response[field] = "fixture-other" })
		run("start-"+field, "request_join", func(fixture *observationFixture) { fixture.Response["start"].(map[string]any)[field] = "fixture-other" })
	}
	for _, field := range []string{"identity", "executable_sha256", "instance_id", "boot_id"} {
		run("manager-"+field, "manager", func(fixture *observationFixture) {
			manager := fixture.Response["manager"].(map[string]any)
			switch field {
			case "identity":
				manager[field] = "fixture-other"
			case "executable_sha256":
				manager[field] = "sha256:" + strings.Repeat("0", 64)
			case "instance_id":
				manager[field] = strings.Repeat("d", 32)
			case "boot_id":
				manager[field] = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
			}
		})
	}
	run("store-generation", "store_generation", func(fixture *observationFixture) {
		fixture.Response["store"].(map[string]any)["generation"] = strings.Repeat("d", 32)
	})
	for _, field := range []string{"sequence", "sha256"} {
		run("manager-head-"+field, "manager_head", func(fixture *observationFixture) {
			head := fixture.Response["store"].(map[string]any)["manager_head"].(map[string]any)
			if field == "sequence" {
				head[field] = int64(4)
			} else {
				head[field] = "sha256:" + strings.Repeat("0", 64)
			}
		})
	}
	run("stale-generation", "currentness", func(fixture *observationFixture) {
		fixture.Response["store"].(map[string]any)["generation_current"] = false
	})
	run("partial", "completeness", func(fixture *observationFixture) { fixture.Response["complete"] = false })
	for _, value := range []int64{6, 7} {
		run(fmt.Sprintf("sequence-%d", value), "sequence", func(fixture *observationFixture) { fixture.Response["sequence"] = value })
	}
	for _, value := range []int64{2098, 2102} {
		run(fmt.Sprintf("observed-%d", value), "interval", func(fixture *observationFixture) { fixture.Response["observed_monotonic_ms"] = value })
	}
	for _, value := range []int64{250, 251} {
		run(fmt.Sprintf("interval-%d", value), "interval", func(fixture *observationFixture) {
			fixture.Expected["after_monotonic_ms"] = fixture.Expected["before_monotonic_ms"].(int64) + value
		})
	}
	for _, field := range []string{"owner", "generation", "epoch", "uid", "executor", "plan_sha256", "profile_id", "profile_sha256"} {
		run("start-pin-"+field, "start_join", func(fixture *observationFixture) {
			start := fixture.Response["start"].(map[string]any)
			switch field {
			case "epoch", "uid":
				start[field] = start[field].(int64) + 1
			case "generation":
				start[field] = strings.Repeat("d", 32)
			case "plan_sha256", "profile_sha256":
				start[field] = "sha256:" + strings.Repeat("0", 64)
			case "phase":
				start[field] = "terminal"
			default:
				start[field] = "fixture-other"
			}
		})
	}
	for _, field := range []string{"receipts", "debits"} {
		wanted := "receipt_count"
		if field == "debits" {
			wanted = "debit_count"
		}
		for _, count := range []int{0, 2} {
			run(fmt.Sprintf("%s-count-%d", field, count), wanted, func(fixture *observationFixture) {
				original := fixture.Response[field].([]any)[0]
				items := []any{}
				for index := 0; index < count; index++ {
					items = append(items, original)
				}
				fixture.Response[field] = items
			})
		}
	}
	run("invalidation", "invalidation", func(fixture *observationFixture) { fixture.Response["invalidations"] = []any{fixture.Invalidation} })
	for _, side := range []string{"receipts", "debits"} {
		for _, field := range []string{"execution_id", "epoch", "pid", "start_time", "boot_id"} {
			run(side+"-"+field, "incarnation", func(fixture *observationFixture) {
				record := fixture.Response[side].([]any)[0].(map[string]any)
				switch field {
				case "execution_id":
					record[field] = "fixture-other"
				case "boot_id":
					record[field] = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
				default:
					record[field] = record[field].(int64) + 1
				}
			})
		}
	}
	for _, field := range []string{"execution_id", "epoch", "boot_id"} {
		run("both-incarnations-"+field, "incarnation", func(fixture *observationFixture) {
			for _, side := range []string{"receipts", "debits"} {
				record := fixture.Response[side].([]any)[0].(map[string]any)
				switch field {
				case "execution_id":
					record[field] = "fixture-other"
				case "epoch":
					record[field] = int64(2)
				case "boot_id":
					record[field] = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
				}
			}
		})
	}
	run("debit-generation", "incarnation", func(fixture *observationFixture) {
		fixture.Response["debits"].([]any)[0].(map[string]any)["generation"] = strings.Repeat("d", 32)
	})
	run("uid-overflow", "native_bounds", func(fixture *observationFixture) {
		fixture.Response["start"].(map[string]any)["uid"] = int64(4294967295)
		fixture.Expected["start"].(map[string]any)["uid"] = int64(4294967295)
	})
	for _, field := range []string{"pid", "session_id"} {
		run(field+"-overflow", "native_bounds", func(fixture *observationFixture) {
			fixture.Response["receipts"].([]any)[0].(map[string]any)[field] = int64(4194305)
			if field == "pid" {
				fixture.Response["debits"].([]any)[0].(map[string]any)[field] = int64(4194305)
			}
		})
	}
	run("debit-future", "debit_time", func(fixture *observationFixture) {
		fixture.Response["debits"].([]any)[0].(map[string]any)["committed_ms"] = int64(2101)
	})
	run("debit-proof-count", "proof_heads", func(fixture *observationFixture) {
		fixture.Response["store"].(map[string]any)["debits_head"].(map[string]any)["sequence"] = int64(0)
	})
	run("missing-byte", "shape", func(fixture *observationFixture) { delete(fixture.Response, "complete") })
	run("request-path", "shape", func(fixture *observationFixture) { fixture.Request["path"] = "fixture-selector" })
}

// Claim: the native shared lock is mandatory even for otherwise complete authenticated-looking bytes.
func TestLabObservationLockPair(test *testing.T) {
	fixture := observationControl(test)
	if got := observationAdmission(test, fixture, true); got != "valid" {
		test.Fatal(got)
	}
	if got := observationAdmission(test, fixture, false); got != "native_lock" {
		test.Fatalf("lock verdict: %s", got)
	}
}

// Claim: transport rejects every foreign/root client, either/both role swaps, invalid frame boundary, extra connection frame, timeout or absent native lock beside the exact daemon/root-manager control.
func TestLabObservationTransportPairs(test *testing.T) {
	run := func(name, wanted string, change func(*observationTransport)) {
		test.Run(name, func(test *testing.T) {
			input := validObservationTransport()
			if got := observationTransportAdmission(input); got != "valid" {
				test.Fatalf("valid transport: %s", got)
			}
			change(&input)
			if got := observationTransportAdmission(input); got != wanted {
				test.Fatalf("transport verdict: got %s want %s", got, wanted)
			}
		})
	}
	for _, uid := range []int64{-1, 0, 1, 4000, 4002, 4003, 4294967295} {
		run(fmt.Sprintf("client-%d", uid), "client_peer", func(input *observationTransport) { input.ClientUID = uid })
	}
	run("daemon-root-binding", "client_peer", func(input *observationTransport) { input.ClientUID = 0; input.DaemonUID = 0 })
	run("daemon-upper-bound", "client_peer", func(input *observationTransport) { input.ClientUID = 4294967295; input.DaemonUID = 4294967295 })
	for _, which := range []string{"client", "server", "both"} {
		wanted := "client_peer"
		if which == "server" {
			wanted = "server_peer"
		}
		run("role-swap-"+which, wanted, func(input *observationTransport) {
			if which != "server" {
				input.ClientUID = 0
			}
			if which != "client" {
				input.ServerUID = 4001
			}
		})
	}
	for _, field := range []string{"server", "owner", "identity", "path"} {
		run(field, "server_peer", func(input *observationTransport) {
			switch field {
			case "server":
				input.ServerUID = 4002
			case "owner":
				input.SocketOwnerUID = 4001
			case "identity":
				input.TrustedServer = false
			case "path":
				input.ProtectedPath = false
			}
		})
	}
	for _, field := range []string{"request", "response"} {
		maximum := int64(4096)
		if field == "response" {
			maximum = 65536
		}
		for _, value := range []int64{0, maximum + 1} {
			run(fmt.Sprintf("%s-%d", field, value), "frame_size", func(input *observationTransport) {
				if field == "request" {
					input.RequestBytes = value
				} else {
					input.ResponseBytes = value
				}
			})
		}
		for _, value := range []int64{1, 2, maximum - 1, maximum} {
			input := validObservationTransport()
			if field == "request" {
				input.RequestBytes = value
			} else {
				input.ResponseBytes = value
			}
			if got := observationTransportAdmission(input); got != "valid" {
				test.Fatalf("valid size %s/%d: %s", field, value, got)
			}
		}
	}
	for _, field := range []string{"requests", "responses"} {
		for _, value := range []int64{0, 2} {
			run(fmt.Sprintf("%s-%d", field, value), "one_frame", func(input *observationTransport) {
				if field == "requests" {
					input.Requests = value
				} else {
					input.Responses = value
				}
			})
		}
	}
	run("no-eof", "one_frame", func(input *observationTransport) { input.WriteEOF = false })
	run("ancillary", "one_frame", func(input *observationTransport) { input.Ancillary = true })
	for _, value := range []int64{-1, 250, 251} {
		run(fmt.Sprintf("elapsed-%d", value), "deadline", func(input *observationTransport) { input.ElapsedMS = value })
	}
	for _, value := range []int64{0, 1, 248, 249} {
		input := validObservationTransport()
		input.ElapsedMS = value
		if observationTransportAdmission(input) != "valid" {
			test.Fatal("valid deadline refused")
		}
	}
	run("lock", "native_lock", func(input *observationTransport) { input.NativeLock = false })
}

// Claim: native numeric join bounds and closed transport bounds accept each inside edge beside the intended outside refusal, without implying a real process incarnation.
func TestLabObservationNativeBoundaries(test *testing.T) {
	for _, field := range []string{"uid", "pid", "session_id"} {
		maximum := int64(4194304)
		if field == "uid" {
			maximum = 4294967294
		}
		for _, value := range []int64{0, 1, 2, maximum - 1, maximum, maximum + 1} {
			test.Run(fmt.Sprintf("%s-%d", field, value), func(test *testing.T) {
				fixture := observationControl(test)
				if observationAdmission(test, fixture, true) != "valid" {
					test.Fatal("valid control refused")
				}
				if field == "uid" {
					fixture.Response["start"].(map[string]any)[field] = value
					fixture.Expected["start"].(map[string]any)[field] = value
				} else {
					fixture.Response["receipts"].([]any)[0].(map[string]any)[field] = value
					if field == "pid" {
						fixture.Response["debits"].([]any)[0].(map[string]any)[field] = value
					}
				}
				want := "valid"
				if value == 0 {
					want = "shape"
				}
				if value > maximum {
					want = "native_bounds"
				}
				if got := observationAdmission(test, fixture, true); got != want {
					test.Fatalf("native bound: got %s want %s", got, want)
				}
			})
		}
	}
	for _, value := range []int64{0, 1, 2099, 2100, 2101} {
		fixture := observationControl(test)
		fixture.Response["debits"].([]any)[0].(map[string]any)["committed_ms"] = value
		want := "valid"
		if value > 2100 {
			want = "debit_time"
		}
		if got := observationAdmission(test, fixture, true); got != want {
			test.Fatalf("commit bound: %s", got)
		}
	}
}

func freshObservationPair(test *testing.T) (observationFixture, observationFixture) {
	first, final := observationControl(test), observationControl(test)
	final.Response["sequence"] = int64(9)
	final.Response["observed_monotonic_ms"] = int64(2352)
	final.Expected["before_monotonic_ms"], final.Expected["after_monotonic_ms"] = int64(2351), int64(2353)
	return first, final
}

// Claim: a new complete observation is mandatory immediately before atomic publication; mismatches, replay, partials, timeouts and failed CAS leave floor and publication unchanged.
func TestLabObservationPublicationPairs(test *testing.T) {
	names := []string{"fresh", "reused", "sequence", "floor", "initial-floor", "generation", "manager", "prefix", "receipt", "debit", "invalidation", "partial", "timeout", "delayed", "clock-regression", "cas", "transport", "reordered-time"}
	for _, name := range names {
		test.Run(name, func(test *testing.T) {
			first, final := freshObservationPair(test)
			state := observationPublication{Floor: 7}
			if got := publishObservation(test, &state, first, final, validObservationTransport(), 2353, true, true); got != "published" || !state.Published || state.Floor != 9 {
				test.Fatalf("valid publication: %s", got)
			}
			first, final = freshObservationPair(test)
			state = observationPublication{Floor: 7}
			original := state
			transport := validObservationTransport()
			elapsed := int64(2353)
			fresh, cas := true, true
			want := "unknown_observation"
			switch name {
			case "fresh", "reused":
				fresh = false
				want = "unknown_freshness"
			case "sequence":
				final.Response["sequence"] = int64(8)
				want = "unknown_sequence"
			case "initial-floor":
				state.Floor = 8
				original = state
				want = "unknown_sequence"
			case "floor":
				state.Floor = 9
				original = state
				want = "unknown_sequence"
			case "generation":
				final.Response["store"].(map[string]any)["generation_current"] = false
			case "manager":
				final.Response["manager"].(map[string]any)["instance_id"] = strings.Repeat("d", 32)
			case "prefix":
				final.Response["store"].(map[string]any)["effects_sha256"] = "sha256:" + strings.Repeat("0", 64)
				want = "unknown_snapshot"
			case "receipt":
				final.Response["receipts"].([]any)[0].(map[string]any)["session_id"] = int64(4322)
				want = "unknown_snapshot"
			case "debit":
				final.Response["debits"].([]any)[0].(map[string]any)["committed_ms"] = int64(2001)
				want = "unknown_snapshot"
			case "invalidation":
				final.Response["invalidations"] = []any{final.Invalidation}
			case "partial":
				final.Response["complete"] = false
			case "timeout":
				transport.ElapsedMS = 250
				want = "unknown_transport"
			case "delayed":
				elapsed = 2601
				want = "unknown_deadline"
			case "clock-regression":
				elapsed = 2102
				want = "unknown_deadline"
			case "cas":
				cas = false
				want = "unknown_commit"
			case "reordered-time":
				final.Expected["before_monotonic_ms"], final.Expected["after_monotonic_ms"] = int64(2099), int64(2101)
				final.Response["observed_monotonic_ms"] = int64(2100)
				want = "unknown_freshness"
			case "transport":
				transport.ClientUID = 0
				want = "unknown_transport"
			}
			if got := publishObservation(test, &state, first, final, transport, elapsed, fresh, cas); got != want {
				test.Fatalf("publication verdict: got %s want %s", got, want)
			}
			if state != original {
				test.Fatal("UNKNOWN changed publication or high-water")
			}
		})
	}
}

func reserveObservationSequence(current int64, durable, installed bool) (int64, string) {
	if !installed || !durable || current < 1 || current >= 9007199254740991 {
		return current, "unknown"
	}
	return current + 1, "reserved"
}

// Claim: sequence reservation has no missing-store/restart default, requires durable confirmation and refuses exhaustion before any response is modeled.
func TestLabObservationSequencePairs(test *testing.T) {
	for _, current := range []int64{0, 1, 2, 9007199254740990, 9007199254740991} {
		for _, durable := range []bool{false, true} {
			for _, installed := range []bool{false, true} {
				if next, status := reserveObservationSequence(7, true, true); next != 8 || status != "reserved" {
					test.Fatal("valid sequence refused")
				}
				next, status := reserveObservationSequence(current, durable, installed)
				admit := current >= 1 && current < 9007199254740991 && durable && installed
				if (status == "reserved") != admit || !admit && next != current || admit && next != current+1 {
					test.Fatalf("sequence reservation: %d/%v/%v -> %d/%s", current, durable, installed, next, status)
				}
			}
		}
	}
}
