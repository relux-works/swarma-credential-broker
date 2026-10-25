//go:build linux

package qualify

import (
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// One connection carries at most 65 outstanding operations. The real server
// correlates their replies; no child reports queue depth or refresh counters.
func leaseProtocolExchange(in rowInput) (string, []rowEnvelope, error) {
	phase, ack := os.NewFile(7, "lease-phase"), os.NewFile(8, "lease-ack")
	if phase == nil || ack == nil {
		return "", nil, qualification.ErrUnavailable
	}
	defer phase.Close()
	defer ack.Close()
	for _, f := range []*os.File{phase, ack} {
		s, e := f.Stat()
		if e != nil || s.Mode()&os.ModeNamedPipe == 0 {
			return "", nil, qualification.ErrUnavailable
		}
	}
	checkpoint := func(b byte) error {
		if _, e := phase.Write([]byte{b}); e != nil {
			return e
		}
		var one [1]byte
		if _, e := io.ReadFull(ack, one[:]); e != nil || one[0] != 'a' {
			return qualification.ErrUnavailable
		}
		return nil
	}
	c, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: in.Socket, Net: "unix"})
	if e != nil {
		return "", nil, e
	}
	defer c.Close()
	if e = c.SetDeadline(time.Now().Add(25 * time.Second)); e != nil {
		return "", nil, e
	}
	send := func(method, id string, value any) error {
		b, e := wire.Encode(value)
		if e != nil {
			return e
		}
		return wire.Write(c, wire.Request{Method: method, ID: id, Params: b})
	}
	if e = send("hello", "fixture-hello", wire.Hello{Versions: []int{1}, Profile: wire.Profile}); e != nil {
		return "", nil, e
	}
	b, e := wire.Read(c)
	if e != nil {
		return "", nil, e
	}
	hello, e := decodeRowEnvelope(b, in.ID, "positive", in.Policy.Generation)
	if e != nil {
		return "", nil, e
	}
	facts := []rowEnvelope{hello}
	count := leaseRowCount(in)
	grants := make([]wire.LeaseResult, count)
	a := in.Policy.Accounts[0]
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("request-%d", i)
		request := wire.LeaseRequest{Harness: "codex_cli", Profile: a.Profiles[0], Account: a.Label, Channel: "external-token", Binding: in.Policy.Binding(in.Peer, a, a.Profiles[0]), Network: []byte("null"), LaunchID: fmt.Sprintf("synthetic-launch-%d", i), Executor: wire.Executor{Version: "fixture", Capabilities: []string{"credential-injection/1"}}}
		if e = send("lease.request", id, request); e != nil {
			return "", nil, e
		}
		b, e = wire.Read(c)
		if e != nil {
			return "", nil, e
		}
		grant, f, e := decodeAdmissionGrant(b, id, in)
		if e != nil {
			return "", nil, e
		}
		grants[i] = grant
		facts = append(facts, f)
	}
	if e = checkpoint('g'); e != nil {
		return "", nil, e
	}
	renew := func(i int) error {
		digest := lease.Digest(grants[i].Payload.AccessToken)
		if in.ID == "renew-unknown-digest" && in.Side == "negative" {
			digest = strings.Repeat("0", 64)
			if digest == lease.Digest(grants[i].Payload.AccessToken) {
				return qualification.ErrUnavailable
			}
		}
		return send("lease.renew", fmt.Sprintf("renew-%d", i), wire.Renew{LeaseID: grants[i].LeaseID, RejectedSHA256: digest})
	}
	n := count
	if in.ID == "queue-full" {
		n = 63
		if in.Side == "negative" {
			n = 64
		}
	}
	for i := 0; i < n; i++ {
		if e = renew(i); e != nil {
			return "", nil, e
		}
	}
	if in.ID != "renew-unknown-digest" {
		if e = checkpoint('h'); e != nil {
			return "", nil, e
		}
		if in.ID == "queue-full" {
			if e = renew(n); e != nil {
				return "", nil, e
			}
			n++
			if e = checkpoint('i'); e != nil {
				return "", nil, e
			}
		}
	}
	seen := map[string]bool{}
	current := ""
	for i := 0; i < n; i++ {
		b, e = wire.Read(c)
		if e != nil {
			return "", nil, e
		}
		var identity struct {
			ID     string `json:"request_id"`
			Result any    `json:"result,omitempty"`
			Error  any    `json:"error,omitempty"`
		}
		if wire.Decode(b, &identity) != nil || seen[identity.ID] || !strings.HasPrefix(identity.ID, "renew-") {
			return "", nil, qualification.ErrUnavailable
		}
		index, e := strconv.Atoi(strings.TrimPrefix(identity.ID, "renew-"))
		if e != nil || index < 0 || index >= n || identity.ID != fmt.Sprintf("renew-%d", index) {
			return "", nil, qualification.ErrUnavailable
		}
		seen[identity.ID] = true
		refused := in.Side == "negative" && (in.ID == "renew-unknown-digest" || in.ID == "queue-full" && index == 64)
		if refused {
			f, e := decodeAdmissionError(b, in.ID, identity.ID)
			if e != nil {
				return "", nil, qualification.ErrUnavailable
			}
			facts = append(facts, f)
		} else {
			renewed, f, e := decodeAdmissionGrant(b, identity.ID, in)
			if e != nil || renewed.LeaseID != grants[index].LeaseID || renewed.AuthorizedUntil != grants[index].AuthorizedUntil || renewed.TokenExpiresAt != grants[index].TokenExpiresAt {
				return "", nil, qualification.ErrUnavailable
			}
			digest := lease.Digest(renewed.Payload.AccessToken)
			if digest == lease.Digest(grants[index].Payload.AccessToken) || current != "" && digest != current {
				return "", nil, qualification.ErrUnavailable
			}
			current = digest
			renewed.Payload.AccessToken = ""
			facts = append(facts, f)
		}
	}
	if in.ID == "renew-unknown-digest" {
		if e = checkpoint('i'); e != nil {
			return "", nil, e
		}
	}
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("release-%d", i)
		if e = send("lease.release", id, wire.Release{LeaseID: grants[i].LeaseID}); e != nil {
			return "", nil, e
		}
		b, e = wire.Read(c)
		if e != nil {
			return "", nil, e
		}
		f, e := decodeAdmissionRelease(b, id, grants[i].LeaseID)
		if e != nil {
			return "", nil, e
		}
		facts = append(facts, f)
		grants[i].Payload.AccessToken = ""
	}
	result := rowPositive(in.ID)
	if in.Side == "negative" {
		result = rowRefusal(in.ID)
	}
	return result, facts, nil
}

func validLeaseProtocolEnvelopes(o rowObservation, generation uint64) bool {
	in := rowInput{ID: o.ID, Side: o.Side}
	count := leaseRowCount(in)
	renews := count
	if o.ID == "queue-full" && o.Side == "positive" {
		renews = 64
	}
	if len(o.Envelopes) != 1+count+renews+count || !validRowEnvelope(o.Envelopes[0], o.ID, "positive", generation) {
		return false
	}
	grants := make([]rowLease, count)
	unique := map[string]bool{}
	for i := 0; i < count; i++ {
		f := o.Envelopes[1+i]
		if !validAdmissionGrant(f, fmt.Sprintf("request-%d", i)) || unique[f.Lease.ID] {
			return false
		}
		grants[i] = *f.Lease
		unique[f.Lease.ID] = true
	}
	seen := map[string]bool{}
	for _, f := range o.Envelopes[1+count : 1+count+renews] {
		if f.RequestID == nil || seen[*f.RequestID] || !strings.HasPrefix(*f.RequestID, "renew-") {
			return false
		}
		i, e := strconv.Atoi(strings.TrimPrefix(*f.RequestID, "renew-"))
		if e != nil || i < 0 || i >= renews || *f.RequestID != fmt.Sprintf("renew-%d", i) {
			return false
		}
		seen[*f.RequestID] = true
		refused := o.Side == "negative" && (o.ID == "renew-unknown-digest" || o.ID == "queue-full" && i == 64)
		if refused {
			if !validAdmissionError(f, o.ID, *f.RequestID) {
				return false
			}
		} else if !validAdmissionGrant(f, *f.RequestID) || !reflect.DeepEqual(*f.Lease, grants[i]) {
			return false
		}
	}
	for i, f := range o.Envelopes[1+count+renews:] {
		if !validAdmissionRelease(f, fmt.Sprintf("release-%d", i), grants[i].ID) {
			return false
		}
	}
	return true
}
func validLeaseProtocolEffects(o rowObservation) bool {
	f := o.LeaseProtocol
	if f == nil || o.Admission != nil || o.Runner != nil || o.Peer != nil || !f.GuardVerified || !f.StateVerified || f.AuthorityRefusals != 0 {
		return false
	}
	count := leaseRowCount(rowInput{ID: o.ID, Side: o.Side})
	success := count
	peak, refresh, gen, methods := count, 1, uint64(2), 3*count
	if o.ID == "queue-full" {
		peak, success = 64, 64
		if o.Side == "positive" {
			methods--
		}
	}
	if o.ID == "renew-unknown-digest" {
		peak, refresh = 0, 0
		if o.Side == "negative" {
			success, gen = 0, 1
		}
	}
	if f.Leases != count || f.Requests != count || f.Methods != methods || f.PeakPending != peak || f.Refreshes != refresh || f.Writers != refresh || f.Generation != gen || f.Snapshots != 2*count+2*success {
		return false
	}
	start, e := time.Parse(time.RFC3339Nano, f.StartedAt)
	if e != nil {
		return false
	}
	for _, fact := range o.Envelopes {
		if fact.Kind == "lease" && (fact.Lease.Until != start.Add(30*time.Second).Truncate(time.Second).Format(time.RFC3339) || fact.Lease.Expires != start.Add(time.Minute).Truncate(time.Second).Format(time.RFC3339)) {
			return false
		}
	}
	return true
}
