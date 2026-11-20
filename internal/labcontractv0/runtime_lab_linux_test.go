//go:build linux && broker_lab

package labcontractv0

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	labcontract "github.com/relux-works/swarma-credential-broker/contracts/lab-v0"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

func runtimeRead(format string, raw []byte) error {
	if format == recoveryFormat {
		_, err := labcontract.ReadRecovery(raw)
		return err
	}
	_, err := labcontract.Read(format, raw)
	return err
}

// Claim: the tagged runtime shape reader accepts each C0 own-format control and refuses the same exported top/nested closure negatives; private recovery cannot use its external entry point.
func TestLabRuntimeSurfacePairs(test *testing.T) {
	set, fixtures := loadContracts(test)
	for position, shape := range set.Surfaces {
		test.Run(shape.Format, func(test *testing.T) {
			fixture := fixtures[position]
			if err := runtimeRead(shape.Format, canonicalObject(test, fixture.Valid)); err != nil {
				test.Fatal("own-format control:", err)
			}
			for _, negative := range append([]mapRecord{{fixture.Negative}}, nestedRecords(fixture.NestedNegatives)...) {
				if err := runtimeRead(shape.Format, canonicalObject(test, negative.value)); err == nil || !strings.Contains(err.Error(), "field_set") {
					test.Fatalf("closure refusal: %v", err)
				}
			}
			if shape.Format == recoveryFormat {
				if _, err := labcontract.Read(recoveryFormat, canonicalObject(test, fixture.Valid)); err == nil || err.Error() != "private_recovery" {
					test.Fatal("private recovery exposed")
				}
			}
		})
	}
}

type mapRecord struct{ value map[string]any }

func nestedRecords(negatives []nestedNegative) []mapRecord {
	result := make([]mapRecord, len(negatives))
	for position, negative := range negatives {
		result[position] = mapRecord{negative.Record}
	}
	return result
}

// Claim: the actual tagged reader applies C0 scalar/type/array operators at every populated grammar path, including all private replay alternatives; this tests shape, not semantic authority.
func TestLabRuntimeCataloguePairs(test *testing.T) {
	set, _ := loadContracts(test)
	for _, shape := range set.Surfaces {
		test.Run(shape.Format, func(test *testing.T) {
			control := map[string]any{}
			for name, grammar := range shape.Fields {
				control[name] = grammarSample(grammar, set)
			}
			if err := runtimeRead(shape.Format, canonicalObject(test, control)); err != nil {
				test.Fatal("runtime grammar control:", err)
			}
			for _, visit := range fixtureFields(control, shape, set) {
				mutations := wrongTypes(visit.Value)
				if strings.HasPrefix(visit.Type, "[]") {
					for _, count := range []int{0, 1, 257} {
						items := make([]any, count)
						for position := range items {
							items[position] = grammarSample(visit.Type[2:], set)
						}
						mutations = append(mutations, grammarMutation{Name: fmt.Sprintf("count-%d", count), Value: items, Admit: count <= 256})
					}
				} else if !strings.HasPrefix(visit.Type, "@") {
					mutations = append(mutations, scalarMutations(visit.Type)...)
				}
				for _, mutation := range mutations {
					test.Run(fmt.Sprint(visit.Path, "/", mutation.Name), func(test *testing.T) {
						if err := runtimeRead(shape.Format, canonicalObject(test, control)); err != nil {
							test.Fatal("valid control refused:", err)
						}
						changed := cloneObject(test, control)
						putPath(changed, visit.Path, mutation.Value)
						raw, encodeErr := wire.Encode(changed)
						if encodeErr != nil {
							if mutation.Admit {
								test.Fatalf("admitted mutation is not encodable: %v", encodeErr)
							}
							var err error
							raw, err = json.Marshal(changed)
							if err != nil {
								test.Fatal(err)
							}
						}
						admit := mutation.Admit && len(raw) <= shape.MaxBytes
						if err := runtimeRead(shape.Format, raw); (err == nil) != admit {
							test.Fatalf("runtime catalogue verdict: admit=%v error=%v", admit, err)
						}
					})
				}
			}
		})
	}
}
