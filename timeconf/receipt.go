package timeconf

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"regexp"
	"strconv"
)

// ReceiptVersion identifies the closed provider codec, not a consumer journal codec.
const ReceiptVersion = "qualified-time/1"
const receiptLimit = 65536

// Nanoseconds and Generation preserve the contract's decimal-string wire form.
// DecodeReceipt checks canonical encodings and arithmetic before returning them.
type Nanoseconds string
type Generation string

type AuthorityFact struct {
	ID                  string `json:"id"`
	Version             string `json:"version"`
	TrustRootDigest     string `json:"trust_root_digest"`
	QualificationDigest string `json:"qualification_digest"`
}
type EvidenceFact struct {
	Qualified      bool        `json:"qualified"`
	Source         Source      `json:"source"`
	NTSConfig      bool        `json:"nts_config"`
	NTSAssociation string      `json:"nts_association"`
	Reference      Nanoseconds `json:"reference"`
	Digest         string      `json:"digest"`
}
type AdapterFact struct {
	Revision       string `json:"revision"`
	CollectorEntry string `json:"collector_entry"`
	ImageDigest    string `json:"image_digest"`
	ChronycDigest  string `json:"chronyc_digest"`
	ClosureDigest  string `json:"closure_digest"`
}
type PolicyFact struct {
	SharedDigest    string `json:"shared_digest"`
	ServiceDigest   string `json:"service_digest"`
	EffectiveDigest string `json:"effective_digest"`
}
type ScopeFact struct {
	Machine         string `json:"machine"`
	Consumer        string `json:"consumer"`
	Purpose         string `json:"purpose"`
	ContinuityScope string `json:"continuity_scope"`
	OperationDigest string `json:"operation_digest"`
}
type SampleFact struct {
	ID         string     `json:"id"`
	Challenge  string     `json:"challenge"`
	Generation Generation `json:"generation"`
	Fresh      bool       `json:"fresh"`
}
type ClockFact struct {
	Boot       string      `json:"boot"`
	Wall       string      `json:"wall"`
	Monotonic  string      `json:"monotonic"`
	BeforeNS   Nanoseconds `json:"before_ns"`
	ObservedNS Nanoseconds `json:"observed_ns"`
}
type ContinuityFact struct {
	Store          string      `json:"store"`
	Generation     Generation  `json:"generation"`
	RecordDigest   string      `json:"record_digest"`
	WitnessDigest  string      `json:"witness_digest"`
	PriorHighWater Nanoseconds `json:"prior_high_water"`
	HighWater      Nanoseconds `json:"high_water"`
	JournalFloor   Nanoseconds `json:"journal_floor"`
	PriorBoot      string      `json:"prior_boot"`
	Transition     string      `json:"transition"`
	Held           bool        `json:"held"`
}

// Facts are the eleven provider facts. No field authenticates itself; consumers
// must validate the retained closure and protected enrollment independently.
type Facts struct {
	Authority      AuthorityFact  `json:"authority"`
	Evidence       EvidenceFact   `json:"evidence"`
	Adapter        AdapterFact    `json:"adapter"`
	Policy         PolicyFact     `json:"policy"`
	Scope          ScopeFact      `json:"scope"`
	Sample         SampleFact     `json:"sample"`
	Clock          ClockFact      `json:"clock"`
	Observed       Nanoseconds    `json:"observed"`
	Uncertainty    Nanoseconds    `json:"uncertainty"`
	AuthorityUntil Nanoseconds    `json:"authority_until"`
	Continuity     ContinuityFact `json:"continuity"`
}
type Receipt struct {
	Version string `json:"version"`
	Facts   Facts  `json:"facts"`
}

var (
	idPattern         = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	randomPattern     = regexp.MustCompile(`^[0-9a-f]{32}$`)
	bootPattern       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	revisionPattern   = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
	integerPattern    = regexp.MustCompile(`^(0|-?[1-9][0-9]*)$`)
	generationPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
)

func ns(v int64) Nanoseconds  { return Nanoseconds(strconv.FormatInt(v, 10)) }
func gen(v uint64) Generation { return Generation(strconv.FormatUint(v, 10)) }
func integer(v Nanoseconds) (int64, error) {
	if !integerPattern.MatchString(string(v)) {
		return 0, ErrUnavailable
	}
	n, e := strconv.ParseInt(string(v), 10, 64)
	if e != nil {
		return 0, ErrUnavailable
	}
	return n, nil
}
func generation(v Generation) (uint64, error) {
	if !generationPattern.MatchString(string(v)) {
		return 0, ErrUnavailable
	}
	n, e := strconv.ParseUint(string(v), 10, 64)
	if e != nil {
		return 0, ErrUnavailable
	}
	return n, nil
}
func bootValid(v string) bool {
	return bootPattern.MatchString(v) && v != "00000000-0000-0000-0000-000000000000"
}
func sum(b []byte) string { v := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(v[:]) }
func canonical(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, ErrUnavailable
	}
	var m any
	if json.Unmarshal(b, &m) != nil {
		return nil, ErrUnavailable
	}
	// Every number in these records is a string. Maps give ASCII member ordering.
	return json.Marshal(m)
}
func boundedJSON(b []byte, max int) bool {
	if len(b) == 0 || len(b) > max {
		return false
	}
	depth := 0
	quoted, escape := false, false
	for _, c := range b {
		if quoted {
			if escape {
				escape = false
			} else if c == '\\' {
				escape = true
			} else if c == '"' {
				quoted = false
			}
			continue
		}
		if c == '"' {
			quoted = true
		}
		if c == '{' || c == '[' {
			depth++
			if depth > 16 {
				return false
			}
		}
		if c == '}' || c == ']' {
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0 && !quoted
}
func strictRecord(b []byte, v any, max int) error {
	if !boundedJSON(b, max) || json.Unmarshal(b, v) != nil {
		return ErrUnavailable
	}
	c, e := canonical(v)
	if e != nil || !bytes.Equal(c, b) {
		return ErrUnavailable
	}
	return nil
}

// EncodeReceipt checks the closed representations and internal interval rules.
// It conveys no authentication, qualification or permission to cache a verdict.
func EncodeReceipt(r Receipt) ([]byte, error) {
	if r.validate() != nil {
		return nil, ErrUnavailable
	}
	b, e := canonical(r)
	if e != nil || len(b) > receiptLimit {
		return nil, ErrUnavailable
	}
	return b, nil
}

// DecodeReceipt rejects noncanonical bytes, including unknown/duplicate/null or
// missing members. It is a codec, not the enrolled owner's authenticity validator.
func DecodeReceipt(b []byte) (Receipt, error) {
	var r Receipt
	if strictRecord(b, &r, receiptLimit) != nil || r.validate() != nil {
		return Receipt{}, ErrUnavailable
	}
	return r, nil
}
func (r Receipt) validate() error {
	f := r.Facts
	for _, id := range []string{f.Authority.ID, f.Authority.Version, f.Scope.Machine, f.Scope.Consumer, f.Scope.Purpose, f.Scope.ContinuityScope, f.Continuity.Store} {
		if !idPattern.MatchString(id) {
			return ErrUnavailable
		}
	}
	if len(f.Authority.Version) > 32 {
		return ErrUnavailable
	}
	for _, d := range []string{f.Authority.TrustRootDigest, f.Authority.QualificationDigest, f.Adapter.ImageDigest, f.Adapter.ChronycDigest, f.Adapter.ClosureDigest, f.Policy.SharedDigest, f.Policy.EffectiveDigest, f.Scope.OperationDigest, f.Evidence.Digest, f.Continuity.RecordDigest, f.Continuity.WitnessDigest} {
		if !digestPattern.MatchString(d) {
			return ErrUnavailable
		}
	}
	if f.Policy.ServiceDigest != "none" && !digestPattern.MatchString(f.Policy.ServiceDigest) {
		return ErrUnavailable
	}
	if r.Version != ReceiptVersion || !revisionPattern.MatchString(f.Adapter.Revision) || f.Adapter.CollectorEntry != "timeconf.CollectorEntry" || !f.Evidence.Qualified || !f.Evidence.NTSConfig || !f.Sample.Fresh || f.Continuity.Held {
		return ErrUnavailable
	}
	if f.Evidence.Source != NTSConfig && f.Evidence.Source != NTSAuthData {
		return ErrUnavailable
	}
	if f.Evidence.NTSAssociation != "verified" && f.Evidence.NTSAssociation != "unproven" || f.Evidence.Source == NTSAuthData && f.Evidence.NTSAssociation != "verified" {
		return ErrUnavailable
	}
	if !randomPattern.MatchString(f.Sample.ID) || !randomPattern.MatchString(f.Sample.Challenge) || !bootValid(f.Clock.Boot) || !bootValid(f.Continuity.PriorBoot) || f.Clock.Wall != "CLOCK_REALTIME/UTC" || f.Clock.Monotonic != "CLOCK_BOOTTIME" {
		return ErrUnavailable
	}
	if f.Continuity.Transition != "same-boot" && f.Continuity.Transition != "qualified-reboot" || (f.Clock.Boot == f.Continuity.PriorBoot) != (f.Continuity.Transition == "same-boot") {
		return ErrUnavailable
	}
	g, e := generation(f.Sample.Generation)
	if e != nil || g == 0 || f.Sample.Generation != f.Continuity.Generation {
		return ErrUnavailable
	}
	vals := []Nanoseconds{f.Observed, f.Uncertainty, f.AuthorityUntil, f.Clock.BeforeNS, f.Clock.ObservedNS, f.Evidence.Reference, f.Continuity.PriorHighWater, f.Continuity.HighWater, f.Continuity.JournalFloor}
	n := make([]int64, len(vals))
	for i, v := range vals {
		var e error
		n[i], e = integer(v)
		if e != nil {
			return ErrUnavailable
		}
	}
	o, d, a, before, after, ref, w, u, j := n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7], n[8]
	if d < 0 || d > int64(PlatformMaxUncertainty) || before < 0 || after < before || o > math.MaxInt64-d || o < math.MinInt64+d {
		return ErrUnavailable
	}
	if o-d <= max(w, j) || u != o+d || u >= a || ref > o || o > math.MaxInt64-int64(PlatformAuthorityWindow) || ref > math.MaxInt64-int64(PlatformMaxSyncAge) || a > min(o+int64(PlatformAuthorityWindow), ref+int64(PlatformMaxSyncAge)) {
		return ErrUnavailable
	}
	return nil
}

// ExecutorOperationDigest hashes bytes already validated by the executor's
// owning CCJ-1 codec. This helper does not implement or accept a Scope adapter.
func ExecutorOperationDigest(ccj []byte) (string, error) {
	if len(ccj) == 0 || len(ccj) > receiptLimit || bytes.ContainsAny(ccj, "\r\n") {
		return "", ErrUnavailable
	}
	return sum(append([]byte("qualified-time/executor-scope/1\x00"), ccj...)), nil
}

// NativeOperationDigest hashes an enrolled profile and its owning codec's
// canonical public identity bytes. Selecting or validating that codec is the
// enrollment owner's responsibility; no secret input belongs in this binding.
func NativeOperationDigest(profile string, identity []byte) (string, error) {
	if !idPattern.MatchString(profile) || len(identity) == 0 || len(identity) > receiptLimit {
		return "", ErrUnavailable
	}
	b := []byte("qualified-time/consumer-operation/1\x00")
	b = binary.BigEndian.AppendUint32(b, uint32(len(profile)))
	b = append(b, profile...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(identity)))
	b = append(b, identity...)
	return sum(b), nil
}
