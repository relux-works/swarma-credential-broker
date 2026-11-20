package labcontractv0

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

type grammarMutation struct {
	Name  string
	Value any
	Admit bool
}

func literalMutations(text string) []grammarMutation {
	result := []grammarMutation{{"literal-valid", text, true}, {"literal-empty", "", false}, {"literal-suffix", text + "x", false}, {"literal-prefix", "x" + text, false}}
	for name, changed := range map[string]string{"whole-upper": strings.ToUpper(text), "whole-lower": strings.ToLower(text), "whole-flip": flipASCII(text)} {
		if changed != text {
			result = append(result, grammarMutation{name, changed, false})
		}
	}
	for index, pair := range [][2]string{{"\"", "\""}, {"[", "]"}, {"{", "}"}, {"(", ")"}, {" ", " "}, {"\t", "\t"}, {"\r\n", "\r\n"}, {"'", "'"}, {"\v", "\v"}, {"\f", "\f"}} {
		result = append(result, grammarMutation{fmt.Sprintf("wrapper-%d", index), pair[0] + text + pair[1], false})
		result = append(result, grammarMutation{fmt.Sprintf("leading-wrapper-%d", index), pair[0] + text, false}, grammarMutation{fmt.Sprintf("trailing-wrapper-%d", index), text + pair[1], false})
	}
	for offset, char := range []byte(text) {
		replacement := byte('x')
		if char == replacement {
			replacement = 'y'
		}
		result = append(result, grammarMutation{fmt.Sprintf("literal-%d-altered", offset), text[:offset] + string(replacement) + text[offset+1:], false}, grammarMutation{fmt.Sprintf("literal-%d-removed", offset), text[:offset] + text[offset+1:], false})
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' {
			result = append(result, grammarMutation{fmt.Sprintf("case-%d", offset), text[:offset] + string(char^32) + text[offset+1:], false})
		}
		if strings.ContainsRune(separatorAlphabet, rune(char)) {
			result = append(result, separatorMutations(text, offset)...)
		}
	}
	return result
}

const separatorAlphabet = "TZ_,.-:/;= ?&()[]{}\\\"\t\r\n"

func flipASCII(text string) string {
	result := []byte(text)
	for index, char := range result {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' {
			result[index] = char ^ 32
		}
	}
	return string(result)
}

func separatorMutations(text string, offset int) []grammarMutation {
	char := text[offset : offset+1]
	result := []grammarMutation{}
	for index, replacement := range append([]string{"", char + char, " " + char + " ", "\t" + char + "\t", "\r\n" + char + "\r\n"}, strings.Split(separatorAlphabet, "")...) {
		if replacement != char {
			result = append(result, grammarMutation{fmt.Sprintf("separator-%d-op-%d", offset, index), text[:offset] + replacement + text[offset+1:], false})
		}
	}
	return result
}

func hexMutations(kind string) []grammarMutation {
	prefix, groups := "", []int{32}
	switch kind {
	case "digest":
		prefix, groups = "sha256:", []int{64}
	case "commit":
		groups = []int{40}
	case "uuid":
		groups = []int{8, 4, 4, 4, 12}
	}
	parts := make([]string, len(groups))
	for index, count := range groups {
		parts[index] = strings.Repeat("a", count)
	}
	valid := prefix + strings.Join(parts, "-")
	result := []grammarMutation{{"hex-valid", valid, true}}
	for _, mutation := range literalMutations(valid) {
		if !mutation.Admit {
			result = append(result, mutation)
		}
	}
	if kind == "uuid" {
		result = append(result, grammarMutation{"uuid-urn-prefix", "urn:uuid:" + valid, false})
	}
	if prefix != "" {
		for _, mutation := range literalMutations(prefix) {
			if !mutation.Admit {
				result = append(result, grammarMutation{"prefix-" + mutation.Name, mutation.Value.(string) + strings.Join(parts, "-"), false})
			}
		}
	}
	for group, count := range groups {
		for _, char := range []byte{'0', '9', 'a', 'f', '/', ':', '`', 'g', 'A'} {
			changed := slices.Clone(parts)
			changed[group] = strings.Repeat(string(char), count)
			result = append(result, grammarMutation{fmt.Sprintf("group-%d-alphabet-%d", group, char), prefix + strings.Join(changed, "-"), strings.ContainsRune("09af", rune(char))})
		}
		for _, delta := range []int{-1, 1} {
			changed := slices.Clone(parts)
			changed[group] = strings.Repeat("a", count+delta)
			result = append(result, grammarMutation{fmt.Sprintf("group-%d-length-%d", group, delta), prefix + strings.Join(changed, "-"), false})
		}
	}
	for offset, char := range []byte(valid[len(prefix):]) {
		if char != '-' {
			continue
		}
		offset += len(prefix)
		for _, separator := range []string{"", "_", ".", "a", "--"} {
			result = append(result, grammarMutation{fmt.Sprintf("separator-%d-%q", offset, separator), valid[:offset] + separator + valid[offset+1:], false})
		}
		shifted := []byte(valid)
		shifted[offset], shifted[offset+1] = shifted[offset+1], shifted[offset]
		result = append(result, grammarMutation{fmt.Sprintf("separator-%d-shift", offset), string(shifted), false})
	}
	return result
}

func scalarMutations(kind string) []grammarMutation {
	if strings.HasPrefix(kind, "=") || strings.Contains(kind, "|") {
		members := []string{strings.TrimPrefix(kind, "=")}
		if strings.Contains(kind, "|") {
			members = strings.Split(kind, "|")
		}
		var result []grammarMutation
		for member, text := range members {
			for _, mutation := range literalMutations(text) {
				mutation.Name = fmt.Sprintf("member-%d-%s", member, mutation.Name)
				mutation.Admit = slices.Contains(members, mutation.Value.(string))
				result = append(result, mutation)
			}
		}
		return result
	}
	if slices.Contains([]string{"digest", "operation", "commit", "uuid"}, kind) {
		return hexMutations(kind)
	}
	if kind == "id" || kind == "material" {
		maximum := 128
		if kind == "material" {
			maximum = 4096
		}
		var result []grammarMutation
		for _, count := range []int{0, 1, 2, maximum - 1, maximum, maximum + 1} {
			result = append(result, grammarMutation{fmt.Sprintf("length-%d", count), strings.Repeat("x", count), count >= 1 && count <= maximum})
		}
		for _, char := range []byte{0x20, 0x21, 0x22, 0x7d, 0x7e, 0x7f} {
			result = append(result, grammarMutation{fmt.Sprintf("ascii-%d", char), string(char), char >= 0x21 && char <= 0x7e})
		}
		return append(result, grammarMutation{"non-ascii", "é", false})
	}
	bounds := map[string][2]int64{"uint": {0, 9007199254740991}, "positive": {1, 9007199254740991}, "root": {0, 0}, "lifetime": {1, 900}, "alignment": {0, 2}, "exit": {0, 255}, "poll": {250, 250}, "capture-timeout": {300, 300}}
	if bound, exists := bounds[kind]; exists {
		var result []grammarMutation
		for _, value := range []int64{bound[0] - 1, bound[0], bound[0] + 1, bound[1] - 1, bound[1], bound[1] + 1} {
			result = append(result, grammarMutation{fmt.Sprintf("integer-%d", value), value, value >= bound[0] && value <= bound[1]})
		}
		return append(result, grammarMutation{"fractional-number", float64(1.5), false})
	}
	if kind == "bool" {
		return []grammarMutation{{"false", false, true}, {"true", true, true}}
	}
	if kind == "time" {
		result := []grammarMutation{{"epoch-minus-one-ns", "1969-12-31T23:59:59.999999999Z", false}, {"epoch", "1970-01-01T00:00:00Z", false}, {"epoch-plus-one-ns", "1970-01-01T00:00:00.000000001Z", true}, {"epoch-plus-two-ns", "1970-01-01T00:00:00.000000002Z", true}, {"maximum-minus-one-ns", "9999-12-31T23:59:59.999999998Z", true}, {"maximum", "9999-12-31T23:59:59.999999999Z", true}, {"maximum-plus-one-ns", "10000-01-01T00:00:00Z", false}, {"offset", "2027-01-01T00:00:00+00:00", false}, {"redundant-fraction", "2027-01-01T00:00:00.000Z", false}}
		for _, mutation := range timeCanonicalMutations() {
			result = append(result, mutation)
		}
		text := "2027-01-01T00:00:00.123456789Z"
		result = append(result, grammarMutation{"time-valid", text, true})
		for _, mutation := range literalMutations(text) {
			name := mutation.Name
			if strings.HasPrefix(name, "separator-") || strings.HasPrefix(name, "case-") || strings.HasPrefix(name, "whole-") || strings.Contains(name, "wrapper-") || name == "literal-prefix" || name == "literal-suffix" || strings.HasPrefix(name, "literal-") && (strings.Contains(name, "removed") || strings.Contains(name, "altered")) && strings.ContainsAny(string(textOffset(text, name)), "-T:.Z") {
				result = append(result, mutation)
			}
		}
		for _, positions := range [][3]int{{5, 7, 12}, {8, 10, 31}, {11, 13, 23}, {14, 16, 59}, {17, 19, 59}} {
			for _, value := range []int{-1, 0, 1, positions[2] - 1, positions[2], positions[2] + 1} {
				changed := text[:positions[0]] + fmt.Sprintf("%02d", value) + text[positions[1]:]
				result = append(result, grammarMutation{fmt.Sprintf("component-%d-%d", positions[0], value), changed, value >= 0 && value <= positions[2] && ((positions[0] != 5 && positions[0] != 8) || value >= 1)})
			}
		}
		for _, digits := range []int{0, 1, 8, 9, 10} {
			fraction := ""
			if digits != 0 {
				fraction = "." + strings.Repeat("1", digits)
			}
			result = append(result, grammarMutation{fmt.Sprintf("fraction-count-%d", digits), "2027-01-01T00:00:00" + fraction + "Z", digits <= 9})
		}
		return result
	}
	panic("uncovered grammar: " + kind)
}

func textOffset(text, name string) byte {
	var offset int
	if _, err := fmt.Sscanf(name, "literal-%d-", &offset); err != nil {
		panic(err)
	}
	return text[offset]
}

func jsonKind(value any) string {
	switch value.(type) {
	case nil:
		return "null"
	case bool:
		return "bool"
	case int64, float64:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		panic("unknown JSON type")
	}
}

func wrongTypes(control any) []grammarMutation {
	values := []any{nil, false, int64(1), "PUBLIC-TYPE", []any{}, map[string]any{}}
	var result []grammarMutation
	for _, value := range values {
		if jsonKind(value) != jsonKind(control) {
			result = append(result, grammarMutation{"type-" + jsonKind(value), value, false})
		}
	}
	return result
}

func grammarSample(kind string, set contractSet) any {
	if strings.HasPrefix(kind, "[]") {
		return []any{grammarSample(kind[2:], set)}
	}
	if strings.HasPrefix(kind, "@") {
		object := map[string]any{}
		for name, child := range set.Structures[kind[1:]].Fields {
			object[name] = grammarSample(child, set)
		}
		return object
	}
	for _, mutation := range scalarMutations(kind) {
		if mutation.Admit {
			return mutation.Value
		}
	}
	panic("missing grammar control")
}

// Claim: every encountered field and empty-array element grammar gets null/all wrong JSON kinds, both bound sides, and all literal/group/separator/case mutations beside accepted controls, independently of frame size and seals.
func TestLabGeneratedGrammarPairs(test *testing.T) {
	set, fixtures := loadContracts(test)
	seen := map[string]bool{}
	for position, shape := range set.Surfaces {
		object, err := wire.Parse(canonicalObject(test, fixtures[position].Valid))
		if err != nil {
			test.Fatal(err)
		}
		for _, field := range fixtureFields(object, shape, set) {
			test.Run(fmt.Sprint(shape.Format, "/", field.Path), func(test *testing.T) {
				kinds := []string{field.Type}
				if strings.HasPrefix(field.Type, "[]") {
					kinds = append(kinds, field.Type[2:])
				}
				for _, kind := range kinds {
					control := grammarSample(kind, set)
					cases := wrongTypes(control)
					if strings.HasPrefix(kind, "[]") {
						for _, count := range []int{0, 1, 255, 256, 257} {
							items := make([]any, count)
							for index := range items {
								items[index] = grammarSample(kind[2:], set)
							}
							cases = append(cases, grammarMutation{fmt.Sprintf("count-%d", count), items, count <= 256})
						}
					} else if !strings.HasPrefix(kind, "@") {
						cases = append(cases, scalarMutations(kind)...)
					}
					for _, mutation := range cases {
						test.Run(kind+"/"+mutation.Name, func(test *testing.T) {
							if err := checkValue(control, kind, set); err != nil {
								test.Fatalf("generated valid control refused: %v", err)
							}
							err := checkValue(mutation.Value, kind, set)
							if (err == nil) != mutation.Admit {
								test.Fatalf("generated grammar verdict %s/%s: admit=%v error=%v", kind, mutation.Name, mutation.Admit, err)
							}
						})
					}
					if !seen[kind] {
						seen[kind] = true
						names := make([]string, len(cases))
						for index, mutation := range cases {
							names[index] = mutation.Name
						}
						test.Logf("GENERATED-RULE %s => %s", kind, strings.Join(names, ", "))
					}
				}
			})
		}
	}
}

func wireBodyVisits(value any, path []any) []fieldVisit {
	visits := []fieldVisit{{Path: path, Value: value}}
	switch object := value.(type) {
	case map[string]any:
		for name, child := range object {
			visits = append(visits, wireBodyVisits(child, append(slices.Clone(path), name))...)
		}
	case []any:
		for index, child := range object {
			visits = append(visits, wireBodyVisits(child, append(slices.Clone(path), index))...)
		}
	}
	return visits
}

func cloneWire(test *testing.T, fixture wireFixture) wireFixture {
	test.Helper()
	data, err := json.Marshal(fixture)
	if err != nil {
		test.Fatal(err)
	}
	var result wireFixture
	if err := json.Unmarshal(data, &result); err != nil {
		test.Fatal(err)
	}
	return result
}

// Claim: every measured body occurrence rejects null/all wrong JSON kinds; fixed strings, counts and values reject mechanically altered variants beside the unchanged admitted request, without constraining unretained sentinel text.
func TestLabGeneratedWirePairs(test *testing.T) {
	var fixtures struct {
		Cases []wireFixture `json:"cases"`
	}
	decodeContract(test, "wire-fixtures.json", &fixtures)
	var observed struct {
		Requests []struct {
			Headers map[string]any `json:"headers"`
			Shape   struct {
				Paths []string `json:"paths"`
			} `json:"body_shape"`
		} `json:"requests"`
	}
	decodeContract(test, "probe/observed.json", &observed)
	paths := map[string]bool{}
	for _, path := range observed.Requests[1].Shape.Paths {
		paths[path] = true
	}
	beta := observed.Requests[1].Headers["anthropic-beta"].(string)
	valid := fixtures.Cases[0]
	for _, field := range wireBodyVisits(valid.Request.Body, nil) {
		if len(field.Path) == 0 {
			continue
		}
		cases := wrongTypes(field.Value)
		switch value := field.Value.(type) {
		case string:
			last := field.Path[len(field.Path)-1]
			if last != "text" && last != "user_id" && last != "previous_message_id" {
				cases = append(cases, literalMutations(value)...)
			} else {
				for index, content := range []string{"", "PUBLIC-OTHER", "é", strings.ToLower(value), strings.ToUpper(value)} {
					cases = append(cases, grammarMutation{fmt.Sprintf("open-string-%d", index), content, true})
				}
			}
		case []any:
			for _, count := range []int{len(value) - 1, len(value), len(value) + 1} {
				if count < 0 {
					continue
				}
				items := make([]any, count)
				for index := range items {
					if len(value) > 0 {
						items[index] = value[index%len(value)]
					} else {
						items[index] = "PUBLIC-TOOL"
					}
				}
				cases = append(cases, grammarMutation{fmt.Sprintf("count-%d", count), items, count == len(value)})
			}
		case float64:
			for _, delta := range []float64{-1, 0, 1} {
				cases = append(cases, grammarMutation{fmt.Sprint("number-", delta), value + delta, delta == 0})
			}
		case bool:
			cases = append(cases, grammarMutation{"opposite", !value, false})
		}
		for _, mutation := range cases {
			test.Run(fmt.Sprint(field.Path, "/", mutation.Name), func(test *testing.T) {
				if !wireAdmitted(valid, beta, paths) {
					test.Fatal("generated wire valid control refused")
				}
				changed := cloneWire(test, valid)
				putPath(changed.Request.Body, field.Path, mutation.Value)
				reason := wireRefusal(changed, beta, paths)
				expected := ""
				if !mutation.Admit {
					expected = wireValueRefusal(field.Value, mutation.Value, field.Path)
				}
				if reason != expected {
					test.Fatalf("generated wire verdict: admit=%v reason=%s want=%s", mutation.Admit, reason, expected)
				}
			})
		}
		names := make([]string, len(cases))
		for index, mutation := range cases {
			names[index] = mutation.Name
		}
		test.Logf("GENERATED-WIRE %v => %s", field.Path, strings.Join(names, ", "))
	}
}

// Claim: fixed envelope/header spellings and each beta token reject per-byte/case/separator variants; HTTP header-name case and beta order remain valid controls.
func TestLabGeneratedWireEnvelopePairs(test *testing.T) {
	var fixtures struct {
		Cases []wireFixture `json:"cases"`
	}
	decodeContract(test, "wire-fixtures.json", &fixtures)
	var observed struct {
		Requests []struct {
			Headers map[string]any `json:"headers"`
			Shape   struct {
				Paths []string `json:"paths"`
			} `json:"body_shape"`
		} `json:"requests"`
	}
	decodeContract(test, "probe/observed.json", &observed)
	paths := map[string]bool{}
	for _, path := range observed.Requests[1].Shape.Paths {
		paths[path] = true
	}
	beta := observed.Requests[1].Headers["anthropic-beta"].(string)
	for _, valid := range fixtures.Cases {
		if !valid.Admit {
			continue
		}
		test.Run(valid.Name, func(test *testing.T) {
			fields := map[string]string{"method": valid.Request.Method, "path": valid.Request.Path, "source_scheme": valid.Request.SourceScheme}
			for name, value := range fields {
				for _, mutation := range literalMutations(value) {
					test.Run(name+"/"+mutation.Name, func(test *testing.T) {
						if !wireAdmitted(valid, beta, paths) {
							test.Fatal("generated wire valid control refused")
						}
						changed := cloneWire(test, valid)
						switch name {
						case "method":
							changed.Request.Method = mutation.Value.(string)
						case "path":
							changed.Request.Path = mutation.Value.(string)
						case "source_scheme":
							changed.Request.SourceScheme = mutation.Value.(string)
						}
						if wireAdmitted(changed, beta, paths) != mutation.Admit {
							test.Fatalf("generated envelope verdict: admit=%v", mutation.Admit)
						}
					})
				}
			}
			for index, header := range valid.Request.Headers {
				for _, mutation := range literalMutations(header[0]) {
					test.Run(fmt.Sprintf("header-name-%d/%s", index, mutation.Name), func(test *testing.T) {
						if !wireAdmitted(valid, beta, paths) {
							test.Fatal("generated wire valid control refused")
						}
						changed := cloneWire(test, valid)
						changed.Request.Headers[index][0] = mutation.Value.(string)
						if wireAdmitted(changed, beta, paths) != strings.EqualFold(mutation.Value.(string), header[0]) {
							test.Fatal("generated header name verdict")
						}
					})
				}
				members := []string{header[1]}
				if header[0] == "anthropic-beta" {
					members = strings.Split(header[1], ",")
				}
				for member, value := range members {
					for _, mutation := range literalMutations(value) {
						test.Run(fmt.Sprintf("%s/member-%d/%s", header[0], member, mutation.Name), func(test *testing.T) {
							if !wireAdmitted(valid, beta, paths) {
								test.Fatal("generated wire valid control refused")
							}
							changed := cloneWire(test, valid)
							items := slices.Clone(members)
							items[member] = mutation.Value.(string)
							changed.Request.Headers[index][1] = strings.Join(items, ",")
							admit := mutation.Admit
							if header[0] == "anthropic-beta" {
								admit = strings.Trim(mutation.Value.(string), " \t\r\n") == value
							}
							if wireAdmitted(changed, beta, paths) != admit {
								test.Fatalf("generated header verdict: admit=%v", admit)
							}
						})
					}
				}
				changed := cloneWire(test, valid)
				changed.Request.Headers[index][0] = strings.ToUpper(header[0])
				if !wireAdmitted(changed, beta, paths) {
					test.Fatal("case-insensitive header name refused")
				}
			}
			for _, count := range []int{len(valid.Request.Headers) - 1, len(valid.Request.Headers), len(valid.Request.Headers) + 1} {
				test.Run(fmt.Sprintf("header-count-%d", count), func(test *testing.T) {
					if !wireAdmitted(valid, beta, paths) {
						test.Fatal("generated wire valid control refused")
					}
					changed := cloneWire(test, valid)
					if count <= len(changed.Request.Headers) {
						changed.Request.Headers = changed.Request.Headers[:count]
					} else {
						changed.Request.Headers = append(changed.Request.Headers, changed.Request.Headers[0])
					}
					if wireAdmitted(changed, beta, paths) != (count == len(valid.Request.Headers)) {
						test.Fatal("generated header count verdict")
					}
				})
			}
			if valid.Request.Method == "GET" {
				for _, profile := range fixtures.Cases {
					if !profile.Admit {
						continue
					}
					for _, header := range profile.Request.Headers {
						if header[0] == "user-agent" {
							continue
						}
						test.Run("extra-known-header-"+header[0], func(test *testing.T) {
							if !wireAdmitted(valid, beta, paths) {
								test.Fatal("generated wire valid control refused")
							}
							changed := cloneWire(test, valid)
							changed.Request.Headers = append(changed.Request.Headers, header)
							if wireAdmitted(changed, beta, paths) {
								test.Fatal("generated GET header cardinality verdict")
							}
						})
					}
				}
				changed := cloneWire(test, valid)
				changed.Request.Body = map[string]any{"PUBLIC-EXTRA": true}
				if !wireAdmitted(valid, beta, paths) || wireAdmitted(changed, beta, paths) {
					test.Fatal("generated GET body closure verdict")
				}
			}
		})
	}

}

// Claim: closed records with stale approval/journal seals reach the composed seal refusal, while the corresponding original records pass.
func TestLabComposedSealPairs(test *testing.T) {
	set, fixtures := loadContracts(test)
	for position, fixture := range fixtures {
		shape := set.Surfaces[position]
		for _, name := range []string{"approval", "owner_approval", "head"} {
			member, exists := fixture.Valid[name].(map[string]any)
			if !exists {
				continue
			}
			field := "approved_sha256"
			refusal := "approval_seal"
			if name == "head" {
				field, refusal = "sha256", "journal_seal"
			}
			if _, exists := member[field]; !exists {
				continue
			}
			test.Run(fixture.Surface+"/"+name, func(test *testing.T) {
				if err := checkSealedRecord(canonicalObject(test, fixture.Valid), shape, set); err != nil {
					test.Fatalf("composed valid seal refused: %v", err)
				}
				changed := cloneObject(test, fixture.Valid)
				changed[name].(map[string]any)[field] = "sha256:" + strings.Repeat("0", 64)
				if err := checkSealedRecord(canonicalObject(test, changed), shape, set); err == nil || err.Error() != refusal {
					test.Fatalf("composed stale seal wrong refusal: %v", err)
				}
			})
		}
	}
}

// Claim: every root/nested member name is closed and case-sensitive; every member gets missing/null and per-byte/label/separator replacements beside the complete shape, without a second seal gate.
func TestLabGeneratedClosedFieldPairs(test *testing.T) {
	set, fixtures := loadContracts(test)
	shapes := maps.Clone(set.Structures)
	controls := map[string]map[string]any{}
	for name := range set.Structures {
		controls[name] = grammarSample("@"+name, set).(map[string]any)
	}
	for position, shape := range set.Surfaces {
		shapes[shape.Format] = shape
		control, err := wire.Parse(canonicalObject(test, fixtures[position].Valid))
		if err != nil {
			test.Fatal(err)
		}
		controls[shape.Format] = control
	}
	for name, shape := range shapes {
		test.Run(name, func(test *testing.T) {
			control := controls[name]
			test.Run("unknown-extra", func(test *testing.T) {
				if err := checkFields(control, shape, set); err != nil {
					test.Fatalf("closed valid control refused: %v", err)
				}
				changed := maps.Clone(control)
				changed["PUBLIC-EXTRA"] = true
				if err := checkFields(changed, shape, set); err == nil || err.Error() != "field_set" {
					test.Fatalf("generated closed-field extra wrong refusal: %v", err)
				}
			})
			for field := range shape.Fields {
				mutations := labelCases(field)
				mutations = append(mutations, grammarMutation{"missing", nil, false}, grammarMutation{"null", nil, false})
				for _, mutation := range mutations {
					test.Run(field+"/"+mutation.Name, func(test *testing.T) {
						if err := checkFields(control, shape, set); err != nil {
							test.Fatalf("closed valid control refused: %v", err)
						}
						changed := maps.Clone(control)
						switch mutation.Name {
						case "missing":
							delete(changed, field)
						case "null":
							changed[field] = nil
						default:
							delete(changed, field)
							changed[mutation.Value.(string)] = control[field]
						}
						err := checkFields(changed, shape, set)
						if mutation.Admit && err != nil || !mutation.Admit && (err == nil || !strings.HasPrefix(err.Error(), "field_set")) {
							test.Fatalf("generated closed-field verdict: admit=%v error=%v", mutation.Admit, err)
						}
					})
				}
			}
		})
	}
}
