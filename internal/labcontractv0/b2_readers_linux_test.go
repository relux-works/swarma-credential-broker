//go:build linux && broker_lab

package labcontractv0

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/labtimev0"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

func b2Target(format string) any {
	switch format {
	case labtimev0.DecisionFormat:
		return &labtimev0.Decision{}
	case labtimev0.ApprovalFormat:
		return &labtimev0.OffVM{}
	case labtimev0.FenceFormat:
		return &labtimev0.Fence{}
	case labtimev0.FloorFormat:
		return &labtimev0.Floor{}
	case labtimev0.CheckpointFormat:
		return &labtimev0.Checkpoint{}
	default:
		return nil
	}
}

// Claim: actual B2 codecs accept frozen C0 bytes and reject each published adjacent closure negative without changing production readers.
func TestLabB2FrozenSurfacePairs(test *testing.T) {
	set, fixtures := loadContracts(test)
	for index, shape := range set.Surfaces {
		if b2Target(shape.Format) == nil {
			continue
		}
		fixture := fixtures[index]
		test.Run(shape.Format, func(test *testing.T) {
			control := canonicalObject(test, fixture.Valid)
			if err := labtimev0.Decode(control, b2Target(shape.Format)); err != nil {
				test.Fatal(err)
			}
			if err := labtimev0.Decode(canonicalObject(test, fixture.Negative), b2Target(shape.Format)); err == nil {
				test.Fatal("unknown member accepted")
			}
			for _, negative := range fixture.NestedNegatives {
				if err := labtimev0.Decode(control, b2Target(shape.Format)); err != nil {
					test.Fatal(err)
				}
				if err := labtimev0.Decode(canonicalObject(test, negative.Record), b2Target(shape.Format)); err == nil {
					test.Fatal("nested closure accepted", negative.Path)
				}
			}
		})
	}
}

// Claim: every instantiated B2 field obeys the frozen C0 scalar, wrong-kind, array and label operators in the actual consuming codec.
func TestLabB2CatalogueGrammarPairs(test *testing.T) {
	set, fixtures := loadContracts(test)
	for index, shape := range set.Surfaces {
		if b2Target(shape.Format) == nil {
			continue
		}
		object, err := wire.Parse(canonicalObject(test, fixtures[index].Valid))
		if err != nil {
			test.Fatal(err)
		}
		for _, field := range fixtureFields(object, shape, set) {
			test.Run(fmt.Sprint(shape.Format, "/", field.Path), func(test *testing.T) {
				control := cloneObject(test, fixtures[index].Valid)
				value := grammarSample(field.Type, set)
				putPath(control, field.Path, value)
				mutations := wrongTypes(value)
				if strings.HasPrefix(field.Type, "[]") {
					if !strings.HasPrefix(field.Type[2:], "@") {
						for _, mutation := range scalarMutations(field.Type[2:]) {
							mutation.Value = []any{mutation.Value}
							mutations = append(mutations, mutation)
						}
					}
					for _, count := range []int{0, 1, 255, 256, 257} {
						items := make([]any, count)
						for position := range items {
							items[position] = grammarSample(field.Type[2:], set)
						}
						mutations = append(mutations, grammarMutation{fmt.Sprint("count-", count), items, count <= 256})
					}
				} else if !strings.HasPrefix(field.Type, "@") {
					mutations = append(mutations, scalarMutations(field.Type)...)
				}
				for _, mutation := range mutations {
					if err := labtimev0.Decode(canonicalObject(test, control), b2Target(shape.Format)); err != nil {
						test.Fatal("valid control", err)
					}
					candidate := cloneObject(test, control)
					putPath(candidate, field.Path, mutation.Value)
					raw, encodeErr := wire.Encode(candidate)
					if encodeErr != nil {
						raw, encodeErr = json.Marshal(candidate)
						if encodeErr != nil {
							test.Fatal("operator fixture", mutation.Name, encodeErr)
						}
					}
					if (labtimev0.Decode(raw, b2Target(shape.Format)) == nil) != mutation.Admit {
						test.Fatal("operator", mutation.Name, "admit", mutation.Admit)
					}
				}
				parent := pathValue(object, field.Path[:len(field.Path)-1])
				name, member := field.Path[len(field.Path)-1].(string)
				if !member {
					return
				}
				if _, ok := parent.(map[string]any); !ok {
					return
				}
				for _, mutation := range labelCases(name) {
					if mutation.Admit {
						continue
					}
					candidate := cloneObject(test, fixtures[index].Valid)
					parent := pathValue(candidate, field.Path[:len(field.Path)-1]).(map[string]any)
					parent[mutation.Value.(string)] = parent[name]
					delete(parent, name)
					if labtimev0.Decode(canonicalObject(test, fixtures[index].Valid), b2Target(shape.Format)) != nil {
						test.Fatal("valid label control")
					}
					if labtimev0.Decode(canonicalObject(test, candidate), b2Target(shape.Format)) == nil {
						test.Fatal("label alias", mutation.Name)
					}
				}
			})
		}
	}
}
