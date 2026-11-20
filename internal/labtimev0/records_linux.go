//go:build linux && broker_lab

package labtimev0

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

var ErrClosed = errors.New("lab_time_closed")

const (
	DecisionFormat   = "swarma-broker-lab-owner-decision/1"
	ApprovalFormat   = "swarma-broker-lab-off-vm-approval/1"
	FenceFormat      = "swarma-broker-lab-start-fence/1"
	FloorFormat      = "swarma-broker-lab-consumer-high-water/1"
	CheckpointFormat = "swarma-broker-lab-time-checkpoint/1"
	AmendmentDigest  = "sha256:efcc345793d7e21ce7d967da29b1c6234421def3d4848dd3f03bc92d63aeab85"
	APIDigest        = "sha256:ba65951a3f4644442c44dca5059d860baf1347b1c9f3afa4d4d1597963b7252f"
	JoinsDigest      = "sha256:bd86fe4864546880068058ef574a15cdb4e6640b33dce079907348d53cbf8928"
)

type Context struct {
	Account      string `json:"account" lab:"id"`
	Installation string `json:"installation_id" lab:"id"`
	Machine      string `json:"machine_id" lab:"uuid"`
	Expires      string `json:"qualification_expires_at" lab:"time"`
	Revision     string `json:"qualification_revision" lab:"id"`
	VM           string `json:"vm_identity_digest" lab:"digest"`
}

type Head struct {
	Sequence uint64 `json:"sequence" lab:"uint"`
	SHA256   string `json:"sha256" lab:"digest"`
}

type Heads struct {
	Authority  Head `json:"authority"`
	Floor      Head `json:"floor"`
	Manager    Head `json:"manager"`
	Revocation Head `json:"revocation"`
	Service    Head `json:"service"`
	Time       Head `json:"time"`
}

type Approval struct {
	At      string `json:"approved_at" lab:"time"`
	SHA256  string `json:"approved_sha256" lab:"digest"`
	Channel string `json:"channel" lab:"=owner-terminal"`
	Expires string `json:"expires_at" lab:"time"`
	Record  string `json:"record_id" lab:"id"`
}

type OwnerRole struct {
	Accepted bool   `json:"accepted"`
	Role     string `json:"role" lab:"repository|time-contract|user-manager"`
}

type Decision struct {
	Amendment string      `json:"amendment_sha256" lab:"digest"`
	API       string      `json:"api_exception_sha256" lab:"digest"`
	Approval  Approval    `json:"approval"`
	Context   Context     `json:"context"`
	ID        string      `json:"decision_id" lab:"id"`
	Direction string      `json:"direction" lab:"=lab-path-B"`
	Format    string      `json:"format" lab:"=swarma-broker-lab-owner-decision/1"`
	Joins     string      `json:"joins_sha256" lab:"digest"`
	Recorded  string      `json:"recorded_at" lab:"time"`
	Residual  bool        `json:"residual_accepted"`
	Roles     []OwnerRole `json:"roles"`
}

type OffVM struct {
	Access     string   `json:"access_attestation_sha256" lab:"digest"`
	Approval   Approval `json:"approval"`
	Context    Context  `json:"context"`
	Format     string   `json:"format" lab:"=swarma-broker-lab-off-vm-approval/1"`
	Heads      Heads    `json:"heads"`
	Invocation string   `json:"invocation_sha256" lab:"digest"`
	Now        string   `json:"off_vm_now" lab:"time"`
	Release    string   `json:"release_set_sha256" lab:"digest"`
	Generation uint64   `json:"start_generation" lab:"positive"`
}

type Fence struct {
	Consumed       bool    `json:"consumed"`
	Context        Context `json:"context"`
	Format         string  `json:"format" lab:"=swarma-broker-lab-start-fence/1"`
	Heads          Heads   `json:"heads"`
	ApprovalDigest string  `json:"off_vm_approval_sha256" lab:"digest"`
	Generation     uint64  `json:"start_generation" lab:"positive"`
	State          string  `json:"state" lab:"fresh|orderly-stop"`
}

type Floor struct {
	Context    Context  `json:"context"`
	Format     string   `json:"format" lab:"=swarma-broker-lab-consumer-high-water/1"`
	Holds      []string `json:"hold_ids" lab:"id"`
	Manager    Head     `json:"manager_prefix"`
	Persisted  bool     `json:"persisted_before_release"`
	Previous   Head     `json:"previous_prefix"`
	Checkpoint string   `json:"time_checkpoint_sha256" lab:"digest"`
	Watermark  string   `json:"watermark" lab:"time"`
}

type Checkpoint struct {
	Boot      string   `json:"boot_id" lab:"uuid"`
	Context   Context  `json:"context"`
	Format    string   `json:"format" lab:"=swarma-broker-lab-time-checkpoint/1"`
	Incident  string   `json:"incident" lab:"none|held|burned"`
	Monotonic uint64   `json:"monotonic_nanoseconds" lab:"uint"`
	Inventory string   `json:"nts_inventory_sha256" lab:"digest"`
	Previous  Head     `json:"previous"`
	Scope     string   `json:"scope_id" lab:"id"`
	Settled   bool     `json:"settled"`
	Holds     []string `json:"sticky_holds" lab:"id"`
	Lower     string   `json:"trusted_lower" lab:"time"`
	Upper     string   `json:"trusted_upper" lab:"time"`
	Watermark string   `json:"watermark" lab:"time"`
}

var patterns = map[string]*regexp.Regexp{
	"id":     regexp.MustCompile(`^[\x21-\x7e]{1,128}$`),
	"uuid":   regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
	"digest": regexp.MustCompile(`^sha256:[0-9a-f]{64}$`),
}

func Digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func Encode(value any) ([]byte, error) {
	raw, err := wire.Encode(value)
	if err != nil {
		return nil, ErrClosed
	}
	return raw, nil
}

func Decode(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > 65536 {
		return ErrClosed
	}
	switch target.(type) {
	case *Decision, *OffVM, *Fence, *Floor, *Checkpoint:
	default:
		return ErrClosed
	}
	object, err := wire.Parse(raw)
	if err != nil || shape(object, reflect.TypeOf(target).Elem(), "") != nil {
		return ErrClosed
	}
	if wire.Decode(raw, target) != nil {
		return ErrClosed
	}
	return nil
}

func shape(value any, kind reflect.Type, grammar string) error {
	switch kind.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok || len(object) != kind.NumField() {
			return ErrClosed
		}
		for index := 0; index < kind.NumField(); index++ {
			field := kind.Field(index)
			member, found := object[field.Tag.Get("json")]
			if !found || shape(member, field.Type, field.Tag.Get("lab")) != nil {
				return ErrClosed
			}
		}
	case reflect.Slice:
		items, ok := value.([]any)
		if !ok || len(items) > 256 {
			return ErrClosed
		}
		for _, item := range items {
			if shape(item, kind.Elem(), grammar) != nil {
				return ErrClosed
			}
		}
	case reflect.Bool:
		if _, ok := value.(bool); !ok {
			return ErrClosed
		}
	case reflect.Uint64:
		number, ok := value.(int64)
		if !ok || number < 0 || number > 9007199254740991 || grammar == "positive" && number == 0 {
			return ErrClosed
		}
	case reflect.String:
		text, ok := value.(string)
		if !ok {
			return ErrClosed
		}
		switch {
		case strings.HasPrefix(grammar, "="):
			if text != grammar[1:] {
				return ErrClosed
			}
		case strings.Contains(grammar, "|"):
			if !slices.Contains(strings.Split(grammar, "|"), text) {
				return ErrClosed
			}
		case grammar == "time":
			parsed, err := time.Parse(time.RFC3339Nano, text)
			if err != nil || !parsed.After(time.Unix(0, 0)) || parsed.UTC().Format(time.RFC3339Nano) != text {
				return ErrClosed
			}
		default:
			pattern := patterns[grammar]
			if pattern == nil || !pattern.MatchString(text) {
				return ErrClosed
			}
		}
	default:
		return ErrClosed
	}
	return nil
}

func ApprovalTarget(raw []byte) (string, error) {
	object, err := wire.Parse(raw)
	if err != nil {
		return "", ErrClosed
	}
	delete(object, "approval")
	image, err := Encode(map[string]any{"domain": "swarma-broker-lab-approval-target/1", "record": object})
	if err != nil {
		return "", err
	}
	return Digest(image), nil
}

func approved(raw []byte, approval Approval, now time.Time) bool {
	target, err := ApprovalTarget(raw)
	return err == nil && target == approval.SHA256 && !now.Before(instant(approval.At)) && now.Before(instant(approval.Expires))
}

func instant(value string) time.Time { parsed, _ := time.Parse(time.RFC3339Nano, value); return parsed }

func canonicalCopy(value any, target any) error {
	raw, err := Encode(value)
	if err != nil {
		return err
	}
	return Decode(raw, target)
}
