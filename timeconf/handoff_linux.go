//go:build linux

package timeconf

import (
	"bytes"
	"encoding/json"
	"io"
)

const HandoffVersion = "qualified-time/handoff/1"
const HandoffProfile = "retained-anchor/1"
const WitnessPlaceholderVersion = "unavailable/1"
const handoffLimit = 131072
const handoffMetadataLimit = 16384
const handoffClosureLimit = 8 << 20

// HandoffRefusal contains only a fixed internal reason, never input contents.
type HandoffRefusal struct{ Code string }

func (r *HandoffRefusal) Error() string { return "qualified_time_handoff_refused: " + r.Code }
func (*HandoffRefusal) Unwrap() error   { return ErrUnavailable }
func handoffRefusal(code string) error  { return &HandoffRefusal{Code: code} }

// WindowIdentity names an originally authorized phase/slot. The enrolled profile
// maps native owner/action/phase identities without truncation; Sequence is not
// a retry counter. Neither field depends on H, a challenge or a run.
type WindowIdentity struct {
	Profile  string     `json:"profile"`
	Sequence Generation `json:"sequence"`
}

type HandoffDeadline struct {
	Boot             string      `json:"boot"`
	Clock            string      `json:"clock"`
	StartNS          Nanoseconds `json:"start_ns"`
	AbsoluteNS       Nanoseconds `json:"absolute_ns"`
	OriginalUTCNS    Nanoseconds `json:"original_utc_ns"`
	OriginalBudgetNS Nanoseconds `json:"original_budget_ns"`
	MappingDigest    string      `json:"mapping_digest"`
}

// HandoffBudget is bound before settlement. TotalDelayNS is T from s through
// completion, FinalWorkMaxNS is f, and ErrorNS is epsilon, already included in T.
type HandoffBudget struct {
	QualificationDigest   string      `json:"qualification_digest"`
	TotalDelayNS          Nanoseconds `json:"total_delay_ns"`
	FinalWorkMaxNS        Nanoseconds `json:"final_work_max_ns"`
	ErrorNS               Nanoseconds `json:"error_ns"`
	ReservedUncertaintyNS Nanoseconds `json:"reserved_uncertainty_ns"`
}

type HandoffReference struct {
	SHA256 string     `json:"sha256"`
	Size   Generation `json:"size"`
}
type HandoffObject struct {
	Role   string     `json:"role"`
	SHA256 string     `json:"sha256"`
	Size   Generation `json:"size"`
}

// WitnessMaterial deliberately has no backend proof members. Its decoder is
// closed and versioned; ValidateHandoffWitness always refuses authentication.
// A future backend requires its own reviewed format, not new optional fields.
type WitnessMaterial struct {
	Version string `json:"version"`
}

func ValidateHandoffWitness(WitnessMaterial) error {
	return &ActivationRefusal{Reason: "witness_unavailable"}
}

type HandoffMetadata struct {
	Profile           string           `json:"profile"`
	ID                string           `json:"id"`
	ConsumerRun       string           `json:"consumer_run"`
	Window            WindowIdentity   `json:"window"`
	TransitionVersion string           `json:"transition_version"`
	Deadline          HandoffDeadline  `json:"deadline"`
	Budget            HandoffBudget    `json:"budget"`
	ReceiptRef        HandoffReference `json:"receipt_ref"`
	ClosureDigest     string           `json:"closure_digest"`
	ValidatorDigest   string           `json:"validator_digest"`
	Witness           WitnessMaterial  `json:"witness"`
}

// Handoff is structural data, not authenticated preparation or use authority.
// Exact originals travel separately, never through lazy readers or descriptors.
type Handoff struct {
	Version string          `json:"version"`
	Receipt Receipt         `json:"receipt"`
	Handoff HandoffMetadata `json:"handoff"`
	Objects []HandoffObject `json:"objects"`
}

func DecodeHandoff(raw []byte) (Handoff, error) {
	// Bound arrays before the typed decoder can allocate descriptor slices.
	if !boundedJSON(raw, handoffLimit) {
		return Handoff{}, handoffRefusal("encoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	arrays, count := 0, 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return Handoff{}, handoffRefusal("encoding")
		}
		if d, ok := token.(json.Delim); ok {
			switch d {
			case '[':
				arrays++
			case ']':
				arrays--
			case '{':
				if arrays > 0 {
					count++
					if count > 63 {
						return Handoff{}, handoffRefusal("limit")
					}
				}
			}
		}
	}
	var h Handoff
	if strictRecord(raw, &h, handoffLimit) != nil {
		return Handoff{}, handoffRefusal("encoding")
	}
	if err := h.validate(); err != nil {
		return Handoff{}, err
	}
	return h, nil
}
func EncodeHandoff(h Handoff) ([]byte, error) {
	if err := h.validate(); err != nil {
		return nil, err
	}
	b, err := canonical(h)
	if err != nil || len(b) > handoffLimit {
		return nil, handoffRefusal("limit")
	}
	return b, nil
}
func HandoffCommitment(raw []byte) (string, error) {
	if _, err := DecodeHandoff(raw); err != nil {
		return "", err
	}
	return sum(append([]byte("qualified-time/handoff-commitment/1\x00"), raw...)), nil
}
func (h Handoff) validate() error {
	m := h.Handoff
	if h.Version != HandoffVersion || m.Profile != HandoffProfile || m.Witness.Version != WitnessPlaceholderVersion {
		return handoffRefusal("encoding")
	}
	if !randomPattern.MatchString(m.ID) || !randomPattern.MatchString(m.ConsumerRun) || !idPattern.MatchString(m.Window.Profile) || !idPattern.MatchString(m.TransitionVersion) {
		return handoffRefusal("encoding")
	}
	if _, err := generation(m.Window.Sequence); err != nil {
		return handoffRefusal("encoding")
	}
	for _, d := range []string{m.ClosureDigest, m.ValidatorDigest, m.Budget.QualificationDigest, m.Deadline.MappingDigest} {
		if !digestPattern.MatchString(d) {
			return handoffRefusal("encoding")
		}
	}
	if !bootValid(m.Deadline.Boot) || m.Deadline.Clock != "CLOCK_BOOTTIME" {
		return handoffRefusal("boot")
	}
	for _, n := range []Nanoseconds{m.Deadline.StartNS, m.Deadline.AbsoluteNS, m.Deadline.OriginalBudgetNS, m.Budget.TotalDelayNS, m.Budget.FinalWorkMaxNS, m.Budget.ErrorNS, m.Budget.ReservedUncertaintyNS} {
		if v, err := integer(n); err != nil || v < 0 {
			return handoffRefusal("encoding")
		}
	}
	if _, err := integer(m.Deadline.OriginalUTCNS); err != nil {
		return handoffRefusal("encoding")
	}
	receipt, err := EncodeReceipt(h.Receipt)
	if err != nil {
		return handoffRefusal("encoding")
	}
	if m.ReceiptRef != (HandoffReference{sum(receipt), gen(uint64(len(receipt)))}) {
		return handoffRefusal("original_mismatch")
	}
	metadata, _ := canonical(m)
	if len(metadata) > handoffMetadataLimit || len(h.Objects) < 5 || len(h.Objects) > 63 {
		return handoffRefusal("limit")
	}
	fixed := []string{"receipt", "settlement", "evidence-manifest", "witness"}
	seen := map[string]bool{}
	total := uint64(0)
	for i, o := range h.Objects {
		role := "source"
		if i < len(fixed) {
			role = fixed[i]
		} else if o.Role == "history-settlement" || o.Role == "history-receipt" || o.Role == "history-source" {
			role = o.Role
		}
		n, e := generation(o.Size)
		if o.Role != role || !digestPattern.MatchString(o.SHA256) || e != nil || n == 0 || n > handoffClosureLimit || seen[o.SHA256] {
			return handoffRefusal("original_mismatch")
		}
		seen[o.SHA256] = true
		total += n
		if total > handoffClosureLimit {
			return handoffRefusal("limit")
		}
	}
	manifest, _ := canonical(h.Objects)
	if m.ClosureDigest != sum(manifest) || h.Objects[0].SHA256 != sum(receipt) || h.Objects[0].Size != gen(uint64(len(receipt))) {
		return handoffRefusal("original_mismatch")
	}
	b, _ := canonical(h)
	if len(b) > handoffLimit || total+uint64(len(b)) > handoffClosureLimit {
		return handoffRefusal("limit")
	}
	return nil
}

// CheckHandoffOriginals reconstructs the exact settled receipt and compares every
// bounded copied original. It does not authenticate descriptor custody or the
// independent witness, and cannot construct a PreparedHandoff.
func CheckHandoffOriginals(h Handoff, originals [][]byte) error {
	if err := h.validate(); err != nil {
		return err
	}
	if len(originals) != len(h.Objects) {
		return handoffRefusal("original_missing")
	}
	for i, ref := range h.Objects {
		if len(originals[i]) == 0 {
			return handoffRefusal("original_missing")
		}
		if ref.Size != gen(uint64(len(originals[i]))) || ref.SHA256 != sum(originals[i]) {
			return handoffRefusal("original_mismatch")
		}
	}
	want, _ := EncodeReceipt(h.Receipt)
	if !bytes.Equal(want, originals[0]) {
		return handoffRefusal("original_mismatch")
	}
	var record settlement
	if strictRecord(originals[1], &record, handoffClosureLimit) != nil {
		return handoffRefusal("original_mismatch")
	}
	g, _ := generation(h.Receipt.Facts.Continuity.Generation)
	if record.Generation != gen(g) || record.Version != "qualified-time/settlement/1" {
		return handoffRefusal("continuity")
	}
	r, err := settledReceipt(record, WitnessHead{g, h.Objects[1].SHA256})
	if err != nil {
		return handoffRefusal("continuity")
	}
	rebuilt, err := EncodeReceipt(r)
	if err != nil || !bytes.Equal(rebuilt, want) {
		return handoffRefusal("original_mismatch")
	}
	manifest, _ := canonical(record.Originals)
	if !bytes.Equal(manifest, originals[2]) || len(record.Originals) > len(originals)-4 {
		return handoffRefusal("original_mismatch")
	}
	for i, ref := range record.Originals {
		if ref.Digest != h.Objects[i+4].SHA256 || ref.Size != h.Objects[i+4].Size {
			return handoffRefusal("original_mismatch")
		}
	}
	var w WitnessMaterial
	if strictRecord(originals[3], &w, handoffMetadataLimit) != nil || w != h.Handoff.Witness {
		return handoffRefusal("encoding")
	}
	return checkHandoffHistory(h, originals, record, g)
}

func checkHandoffHistory(h Handoff, originals [][]byte, walk settlement, g uint64) error {
	byDigest := make(map[string]int, len(h.Objects))
	used := map[int]bool{0: true, 1: true, 2: true, 3: true}
	for i, ref := range h.Objects {
		byDigest[ref.SHA256] = i
	}
	for depth := 0; ; depth++ {
		if depth >= 16 {
			return handoffRefusal("limit")
		}
		for _, ref := range walk.Originals {
			i, ok := byDigest[ref.Digest]
			if !ok || i < 4 || h.Objects[i].Size != ref.Size || (h.Objects[i].Role != "source" && h.Objects[i].Role != "history-source") {
				return handoffRefusal("original_missing")
			}
			used[i] = true
		}
		if g == 0 {
			if walk.Previous != "none" {
				return handoffRefusal("continuity")
			}
			break
		}
		i, ok := byDigest[walk.Previous]
		if !ok || used[i] || h.Objects[i].Role != "history-settlement" {
			return handoffRefusal("continuity")
		}
		used[i] = true
		var ancestor settlement
		if strictRecord(originals[i], &ancestor, handoffClosureLimit) != nil || ancestor.Version != "qualified-time/settlement/1" || ancestor.Binding != walk.Binding || ancestor.Generation != gen(g-1) {
			return handoffRefusal("continuity")
		}
		if ancestor.Facts != nil {
			r, err := settledReceipt(ancestor, WitnessHead{g - 1, h.Objects[i].SHA256})
			if err != nil {
				return handoffRefusal("continuity")
			}
			b, err := EncodeReceipt(r)
			if err != nil {
				return handoffRefusal("continuity")
			}
			j, found := byDigest[sum(b)]
			if !found || h.Objects[j].Role != "history-receipt" || !bytes.Equal(originals[j], b) {
				return handoffRefusal("original_missing")
			}
			used[j] = true
		}
		walk = ancestor
		g--
	}
	if len(used) != len(originals) {
		return handoffRefusal("original_mismatch")
	}
	return nil
}

// Retained copies are private and have no public constructor. Decoding, hashing
// or implementing OriginalReader cannot produce this type's live anchor.
type PreparedHandoff struct{ anchor *handoffAnchor }
type handoffAnchor struct {
	metadata   HandoffMetadata
	facts      Facts
	commitment string
	expected   WindowExpected
	prelock    int64
	originals  []string // Immutable owned copies of the entire bounded closure.
}
