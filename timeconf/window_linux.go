//go:build linux

package timeconf

// VerifyWindow checks only privately owned preparation and independently held
// values. There is no production preparer: nil/zero preparation refuses. The
// tagged preparer is synthetic, not a provenance or native qualification backend.
// No clock, callback, identity allocation, I/O, consumption or state mutation is
// reachable from this function. A candidate is never permission to dispatch.
//
//go:noinline
func VerifyWindow(prepared PreparedHandoff, expected WindowExpected, local LockedWindowState, m FinalCapture) (WindowCandidate, error) {
	zero := WindowCandidate{}
	a := prepared.anchor
	if a == nil {
		return zero, &ActivationRefusal{Reason: "handoff_unqualified"}
	}
	if len(a.originals) < 5 || len(a.originals) > 63 {
		return zero, handoffRefusal("original_missing")
	}
	for _, original := range a.originals {
		if len(original) == 0 {
			return zero, handoffRefusal("original_missing")
		}
	}
	f := a.facts
	if expected.Operation != a.expected.Operation || expected.Operation != f.Scope.OperationDigest || local.Intent.Operation != expected.Operation {
		return zero, handoffRefusal("operation")
	}
	if expected.Enrollment != a.expected.Enrollment || local.Intent.Enrollment != expected.Enrollment {
		return zero, handoffRefusal("consumer")
	}
	if expected.Deadline.Boot != a.expected.Deadline.Boot || m.Boot != expected.Deadline.Boot || m.Boot != f.Clock.Boot || m.Clock != "CLOCK_BOOTTIME" {
		return zero, handoffRefusal("boot")
	}
	if expected.Deadline != a.expected.Deadline || local.Intent.Deadline != expected.Deadline {
		return zero, handoffRefusal("deadline_binding")
	}
	if expected.Window != a.expected.Window || local.Intent.Window != expected.Window || expected.TransitionVersion != a.expected.TransitionVersion || local.Intent.TransitionVersion != expected.TransitionVersion {
		return zero, handoffRefusal("window")
	}
	if expected.Run != a.expected.Run || local.Intent.Run != expected.Run {
		return zero, handoffRefusal("run")
	}
	if expected.Epoch == "" || expected.Epoch != a.expected.Epoch || local.Intent.Epoch != expected.Epoch || local.Epoch != expected.Epoch {
		return zero, handoffRefusal("epoch")
	}
	if expected.Challenge != a.expected.Challenge || local.Intent.Challenge != expected.Challenge {
		return zero, handoffRefusal("binding")
	}
	if expected.Budget != a.expected.Budget || local.Intent.Budget != expected.Budget {
		return zero, handoffRefusal("reserve")
	}
	if !local.Current {
		return zero, handoffRefusal("continuity")
	}
	if !local.Unused {
		return zero, handoffRefusal("replay")
	}
	if !windowUnsigned(string(local.Revision)) {
		return zero, handoffRefusal("binding")
	}
	if expected != a.expected || local.Intent != expected {
		return zero, handoffRefusal("binding")
	}
	// Private immutable preparation pins the original settled uncertainty. The
	// provider has already charged reserve; never add it again or advance O.
	s, ok := windowInteger(string(f.Clock.ObservedNS))
	if !ok {
		return zero, handoffRefusal("overflow")
	}
	d, ok := windowInteger(string(expected.Deadline.AbsoluteNS))
	if !ok {
		return zero, handoffRefusal("overflow")
	}
	start, ok := windowInteger(string(expected.Deadline.StartNS))
	if !ok {
		return zero, handoffRefusal("overflow")
	}
	originalBudget, ok := windowInteger(string(expected.Deadline.OriginalBudgetNS))
	if !ok {
		return zero, handoffRefusal("overflow")
	}
	t, ok := windowInteger(string(expected.Budget.TotalDelayNS))
	if !ok {
		return zero, handoffRefusal("overflow")
	}
	work, ok := windowInteger(string(expected.Budget.FinalWorkMaxNS))
	if !ok {
		return zero, handoffRefusal("overflow")
	}
	epsilon, ok := windowInteger(string(expected.Budget.ErrorNS))
	if !ok {
		return zero, handoffRefusal("overflow")
	}
	reserve, ok := windowInteger(string(expected.Budget.ReservedUncertaintyNS))
	if !ok {
		return zero, handoffRefusal("overflow")
	}
	if s < 0 || start < 0 || start > s || originalBudget <= 0 || t <= 0 || work <= 0 || epsilon < 0 || reserve < 0 || m.NS < a.prelock || a.prelock < s {
		return zero, handoffRefusal("reserve")
	}
	end, ok := windowAdd(start, originalBudget)
	if !ok {
		return zero, handoffRefusal("overflow")
	}
	if d <= start || d > end {
		return zero, handoffRefusal("deadline_binding")
	}
	span, ok := windowAdd(work, epsilon)
	if !ok {
		return zero, handoffRefusal("overflow")
	}
	endpoint, ok := windowAdd(m.NS, span)
	if !ok {
		return zero, handoffRefusal("overflow")
	}
	if endpoint >= d {
		return zero, handoffRefusal("deadline")
	}
	used, ok := windowAdd(m.NS-s, span)
	if !ok {
		return zero, handoffRefusal("overflow")
	}
	if used > t || reserve < t {
		return zero, handoffRefusal("reserve")
	}
	o, ok := windowInteger(string(f.Observed))
	if !ok {
		return zero, handoffRefusal("overflow")
	}
	delta, ok := windowInteger(string(f.Uncertainty))
	if !ok {
		return zero, handoffRefusal("overflow")
	}
	authority, ok := windowInteger(string(f.AuthorityUntil))
	if !ok {
		return zero, handoffRefusal("overflow")
	}
	w, ok := windowInteger(string(f.Continuity.PriorHighWater))
	if !ok {
		return zero, handoffRefusal("overflow")
	}
	j, ok := windowInteger(string(f.Continuity.JournalFloor))
	if !ok {
		return zero, handoffRefusal("overflow")
	}
	if delta < reserve || delta > expected.UncertaintyCapNS || expected.UncertaintyCapNS > 1500000000 || expected.UncertaintyCapNS < 0 {
		return zero, handoffRefusal("reserve")
	}
	lower, ok := windowAdd(o, -delta)
	if !ok {
		return zero, handoffRefusal("overflow")
	}
	upper, ok := windowAdd(o, delta)
	if !ok {
		return zero, handoffRefusal("overflow")
	}
	if j != expected.JournalFloorNS || lower <= w || lower <= j || lower <= local.FloorNS {
		return zero, handoffRefusal("interval")
	}
	if upper >= authority || upper >= local.ExpiryNS {
		return zero, handoffRefusal("authority")
	}
	key := UseKey{f.Scope.Consumer, f.Continuity.Store, expected.Operation, expected.Window}
	return WindowCandidate{key: key, commitment: a.commitment, revision: local.Revision, epoch: local.Epoch, transitionVersion: expected.TransitionVersion, run: expected.Run}, nil
}

// These bounded scalar helpers avoid parsing, reflection or dynamic dispatch
// through a general codec in the pure call graph.
func windowAdd(a, b int64) (int64, bool) {
	const hi = int64(1<<63 - 1)
	const lo = -hi - 1
	if b > 0 && a > hi-b || b < 0 && a < lo-b {
		return 0, false
	}
	return a + b, true
}
func windowInteger(s string) (int64, bool) {
	if len(s) == 0 || len(s) > 20 {
		return 0, false
	}
	negative := s[0] == '-'
	i := 0
	if negative {
		i++
	}
	if i == len(s) || s[i] == '0' && (negative || i+1 != len(s)) {
		return 0, false
	}
	var n uint64
	limit := uint64(1<<63 - 1)
	if negative {
		limit++
	}
	for ; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		d := uint64(s[i] - '0')
		if n > (limit-d)/10 {
			return 0, false
		}
		n = n*10 + d
	}
	if negative {
		return -int64(n), true
	}
	return int64(n), true
}
func windowUnsigned(s string) bool {
	if len(s) == 0 || len(s) > 20 || len(s) > 1 && s[0] == '0' {
		return false
	}
	var n uint64
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
		d := uint64(s[i] - '0')
		if n > (^uint64(0)-d)/10 {
			return false
		}
		n = n*10 + d
	}
	return true
}
