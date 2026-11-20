package labcontractv0

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

func wireBodyClosure(value any, prefix string, paths map[string]bool) error {
	fields := map[string]bool{}
	lead := prefix
	if lead != "" {
		lead += "."
	}
	for path := range paths {
		if strings.HasPrefix(path, lead) {
			suffix := strings.TrimPrefix(path, lead)
			if suffix != "" && !strings.ContainsAny(suffix, ".[]") {
				fields[suffix] = true
			}
		}
	}
	if len(fields) > 0 {
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("body_fields")
		}
		for name := range object {
			if !fields[name] {
				return fmt.Errorf("body_fields")
			}
		}
		for name := range fields {
			_, present := object[name]
			if !present && !(strings.HasSuffix(prefix, "cache_control") && name == "scope") {
				return fmt.Errorf("body_fields")
			}
		}
		for name, child := range object {
			if err := wireBodyClosure(child, lead+name, paths); err != nil {
				return err
			}
		}
		return nil
	}
	array := false
	for path := range paths {
		if strings.HasPrefix(path, prefix+"[].") {
			array = true
		}
	}
	if array {
		items, ok := value.([]any)
		if !ok {
			return fmt.Errorf("body_fields")
		}
		for _, item := range items {
			if err := wireBodyClosure(item, prefix+"[]", paths); err != nil {
				return err
			}
		}
	} else {
		switch value.(type) {
		case map[string]any, []any:
			if prefix != "tools" {
				return fmt.Errorf("body_fields")
			}
		}
	}
	return nil
}

func timeCanonicalMutations() []grammarMutation {
	base := "2027-01-01T00:00:00"
	result := []grammarMutation{}
	for count := 1; count <= 10; count++ {
		result = append(result, grammarMutation{fmt.Sprintf("all-zero-fraction-%d", count), base + "." + strings.Repeat("0", count) + "Z", false})
		if count <= 9 {
			digits := strings.Repeat("1", count)
			result = append(result, grammarMutation{fmt.Sprintf("nonzero-fraction-%d-valid", count), base + "." + digits + "Z", true}, grammarMutation{fmt.Sprintf("nonzero-fraction-%d-trailing-zero", count), base + "." + digits + "0Z", false})
			if count > 1 {
				result = append(result, grammarMutation{fmt.Sprintf("fraction-leading-zero-%d-valid", count), base + "." + strings.Repeat("0", count-1) + "1Z", true}, grammarMutation{fmt.Sprintf("fraction-leading-zero-%d-redundant", count), base + "." + strings.Repeat("0", count-1) + "10Z", false})
			}
		}
	}
	for _, value := range []string{base + ".120Z", base + ".100000000Z", base + ".000000010Z", "02027-01-01T00:00:00Z", "+2027-01-01T00:00:00Z", "-2027-01-01T00:00:00Z", base + ".1e1Z", base + ".1E+1Z", base + ".+1Z", base + ".-1Z"} {
		result = append(result, grammarMutation{fmt.Sprintf("canonical-%q", value), value, false})
	}
	for _, marker := range []string{"e", "E"} {
		for _, sign := range []string{"", "+", "-"} {
			result = append(result, grammarMutation{"fraction-exponent-" + marker + fmt.Sprintf("%q", sign), base + ".1" + marker + sign + "1Z", false})
		}
	}
	for _, offset := range []int{4, 7, 10, 13, 16, 19, 29} {
		for _, mutation := range separatorMutations(base+".123456789Z", offset) {
			result = append(result, mutation)
		}
	}
	return result
}

func wireControls(test *testing.T) (wireFixture, string, map[string]bool) {
	test.Helper()
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
	return fixtures.Cases[0], observed.Requests[1].Headers["anthropic-beta"].(string), paths
}

func labelCases(name string) []grammarMutation {
	cases := literalMutations(name)
	cases = append(cases, grammarMutation{"unicode-fullwidth", strings.Map(func(char rune) rune {
		if char >= '!' && char <= '~' {
			return char + 0xfee0
		}
		return char
	}, name), false}, grammarMutation{"unicode-combining", name + "\u0301", false})
	return cases
}

// Claim: all wire objects have exact case-sensitive member names and nesting; missing, renamed and extra aliases refuse at body_fields, not later value checks.
func TestLabGeneratedWireClosurePairs(test *testing.T) {
	valid, beta, paths := wireControls(test)
	for _, field := range wireBodyVisits(valid.Request.Body, nil) {
		object, ok := field.Value.(map[string]any)
		if !ok {
			continue
		}
		test.Run(fmt.Sprint(field.Path), func(test *testing.T) {
			for name := range object {
				for _, mutation := range labelCases(name) {
					for _, mode := range []string{"rename", "extra"} {
						if mutation.Admit && mode == "extra" {
							continue
						}
						test.Run(name+"/"+mode+"/"+mutation.Name, func(test *testing.T) {
							if reason := wireRefusal(valid, beta, paths); reason != "" {
								test.Fatalf("wire closure control: %s", reason)
							}
							changed := cloneWire(test, valid)
							target := pathValue(changed.Request.Body, field.Path).(map[string]any)
							if mode == "rename" {
								delete(target, name)
							}
							target[mutation.Value.(string)] = object[name]
							reason := wireRefusal(changed, beta, paths)
							if mutation.Admit && reason != "" || !mutation.Admit && reason != "body_fields" {
								test.Fatalf("wire closure verdict: admit=%v reason=%s", mutation.Admit, reason)
							}
						})
					}
				}
				test.Run(name+"/missing", func(test *testing.T) {
					if wireRefusal(valid, beta, paths) != "" {
						test.Fatal("wire closure control")
					}
					changed := cloneWire(test, valid)
					target := pathValue(changed.Request.Body, field.Path).(map[string]any)
					delete(target, name)
					reason := wireRefusal(changed, beta, paths)
					if reason != "body_fields" && !(name == "scope" && reason == "body_value") {
						test.Fatalf("missing member refusal: %s", reason)
					}
				})
			}
			for _, label := range []string{"PUBLIC-EXTRA", "thinking.type", "metadata.user_id", "output_config.effort", "messages[].role", "system[].text", "context_management.edits[].keep"} {
				test.Run("plain-or-path-alias/"+label, func(test *testing.T) {
					if wireRefusal(valid, beta, paths) != "" {
						test.Fatal("wire closure control")
					}
					changed := cloneWire(test, valid)
					pathValue(changed.Request.Body, field.Path).(map[string]any)[label] = "PUBLIC-EXTRA"
					if reason := wireRefusal(changed, beta, paths); reason != "body_fields" {
						test.Fatalf("alias closure refusal: %s", reason)
					}
				})
			}
			test.Run("wrong-nesting", func(test *testing.T) {
				if wireRefusal(valid, beta, paths) != "" {
					test.Fatal("wire closure control")
				}
				changed := cloneWire(test, valid)
				if len(field.Path) == 0 {
					changed.Request.Body = map[string]any{"PUBLIC-WRAPPER": changed.Request.Body}
				} else {
					putPath(changed.Request.Body, field.Path, map[string]any{"PUBLIC-WRAPPER": object})
				}
				if reason := wireRefusal(changed, beta, paths); reason != "body_fields" {
					test.Fatalf("nesting refusal: %s", reason)
				}
			})
		})
	}
}

// Claim: all ten beta-list separators receive every separator operator; order and SP/HTAB OWS remain admitted, missing/duplicate/foreign delimiters refuse at beta.
func TestLabGeneratedBetaSeparatorPairs(test *testing.T) {
	valid, beta, paths := wireControls(test)
	index := -1
	for position, header := range valid.Request.Headers {
		if header[0] == "anthropic-beta" {
			index = position
		}
	}
	if index < 0 {
		test.Fatal("missing beta control")
	}
	cases := []grammarMutation{}
	for offset, char := range []byte(beta) {
		if char == ',' {
			cases = append(cases, separatorMutations(beta, offset)...)
		}
	}
	for position := range cases {
		changed := cases[position].Value.(string)
		cases[position].Admit = strings.ReplaceAll(strings.ReplaceAll(changed, " ", ""), "\t", "") == beta
	}
	tokens := strings.Split(beta, ",")
	slices.Reverse(tokens)
	cases = append(cases, grammarMutation{"beta-reversed", strings.Join(tokens, ","), true})
	for _, mutation := range cases {
		test.Run(mutation.Name, func(test *testing.T) {
			if wireRefusal(valid, beta, paths) != "" {
				test.Fatal("beta control refused")
			}
			changed := cloneWire(test, valid)
			changed.Request.Headers[index][1] = mutation.Value.(string)
			reason := wireRefusal(changed, beta, paths)
			if mutation.Admit && reason != "" || !mutation.Admit && reason != "beta" {
				test.Fatalf("beta separator verdict: admit=%v reason=%s", mutation.Admit, reason)
			}
		})
	}
}

func readUniqueJSON(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var read func() (any, error)
	read = func() (any, error) {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{':
				object := map[string]any{}
				for decoder.More() {
					key, err := decoder.Token()
					if err != nil {
						return nil, err
					}
					name, ok := key.(string)
					if !ok {
						return nil, fmt.Errorf("json")
					}
					if _, exists := object[name]; exists {
						return nil, fmt.Errorf("duplicate")
					}
					value, err := read()
					if err != nil {
						return nil, err
					}
					object[name] = value
				}
				end, err := decoder.Token()
				if err != nil || end != json.Delim('}') {
					return nil, fmt.Errorf("json")
				}
				return object, nil
			case '[':
				items := []any{}
				for decoder.More() {
					value, err := read()
					if err != nil {
						return nil, err
					}
					items = append(items, value)
				}
				end, err := decoder.Token()
				if err != nil || end != json.Delim(']') {
					return nil, fmt.Errorf("json")
				}
				return items, nil
			}
			return nil, fmt.Errorf("json")
		}
		return token, nil
	}
	value, err := read()
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("json")
	}
	return value, nil
}

func duplicateMember(test *testing.T, object map[string]any, name string) []byte {
	test.Helper()
	body := canonicalObject(test, object)
	key, _ := json.Marshal(name)
	value, _ := json.Marshal(object[name])
	return append(append(append([]byte{'{'}, key...), append([]byte{':'}, value...)...), append([]byte{','}, body[1:]...)...)
}

// Claim: every root/nested record and wire object member rejects duplicate bytes at the parser, beside a unique valid control; record aliases and wrong nesting reject at field_set before seals.
func TestLabGeneratedObjectBytePairs(test *testing.T) {
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
		control := controls[name]
		test.Run(name, func(test *testing.T) {
			for _, mutation := range wrongTypes(control) {
				test.Run(mutation.Name, func(test *testing.T) {
					if _, err := wire.Parse(canonicalObject(test, control)); err != nil {
						test.Fatal(err)
					}
					data, err := json.Marshal(mutation.Value)
					if err != nil {
						test.Fatal(err)
					}
					if _, err := wire.Parse(data); err != wire.ErrMalformed {
						test.Fatalf("object type parser refusal: %v", err)
					}
				})
			}
			for member := range shape.Fields {
				test.Run(member+"/duplicate", func(test *testing.T) {
					if _, err := wire.Parse(canonicalObject(test, control)); err != nil {
						test.Fatal(err)
					}
					if _, err := wire.Parse(duplicateMember(test, control, member)); err != wire.ErrMalformed {
						test.Fatalf("duplicate parser refusal: %v", err)
					}
				})
				for _, mutation := range labelCases(member) {
					if mutation.Admit {
						continue
					}
					test.Run(member+"/extra/"+mutation.Name, func(test *testing.T) {
						if err := checkFields(control, shape, set); err != nil {
							test.Fatal(err)
						}
						changed := maps.Clone(control)
						changed[mutation.Value.(string)] = control[member]
						if err := checkFields(changed, shape, set); err == nil || err.Error() != "field_set" {
							test.Fatalf("extra alias refusal: %v", err)
						}
					})
				}
			}
			test.Run("wrong-nesting", func(test *testing.T) {
				if err := checkFields(control, shape, set); err != nil {
					test.Fatal(err)
				}
				if err := checkFields(map[string]any{"PUBLIC-WRAPPER": control}, shape, set); err == nil || err.Error() != "field_set" {
					test.Fatalf("nesting refusal: %v", err)
				}
			})
		})
	}
	valid, _, _ := wireControls(test)
	for _, field := range wireBodyVisits(valid.Request.Body, nil) {
		object, ok := field.Value.(map[string]any)
		if !ok {
			continue
		}
		for member := range object {
			test.Run(fmt.Sprint("wire/", field.Path, "/", member), func(test *testing.T) {
				if _, err := readUniqueJSON(canonicalObject(test, object)); err != nil {
					test.Fatal(err)
				}
				if _, err := readUniqueJSON(duplicateMember(test, object, member)); err == nil || err.Error() != "duplicate" {
					test.Fatalf("wire duplicate refusal: %v", err)
				}
			})
		}
	}
}

// Claim: each integer grammar's lexical alternatives fail CCJ canonical admission, while both in-range bound controls survive; this does not impose CCJ spelling on HTTP bodies.
func TestLabGeneratedNumberLexemePairs(test *testing.T) {
	set, _ := loadContracts(test)
	bounds := map[string][2]int64{"uint": {0, 9007199254740991}, "positive": {1, 9007199254740991}, "root": {0, 0}, "lifetime": {1, 900}, "alignment": {0, 2}, "exit": {0, 255}, "poll": {250, 250}, "capture-timeout": {300, 300}}
	for kind, bound := range bounds {
		for _, number := range []int64{0, 1, bound[0], bound[1]} {
			text := strconv.FormatInt(number, 10)
			cases := map[string]string{"leading-zero": "0" + text, "redundant-zero": "00" + text, "positive-sign": "+" + text, "negative-sign": "-" + text, "fraction": "" + text + ".0", "exponent": text + "e0", "positive-exponent": text + "E+0", "negative-exponent": text + "e-0"}
			for _, marker := range []string{"e", "E"} {
				for _, sign := range []string{"", "+", "-"} {
					for _, exponent := range []string{"0", "00", "1"} {
						cases["exponent-"+marker+"-"+fmt.Sprintf("%q", sign)+"-"+exponent] = text + marker + sign + exponent
					}
				}
			}
			cases["fraction-two-zeroes"] = text + ".00"
			cases["fraction-nonzero"] = text + ".5"
			for name, lexeme := range cases {
				test.Run(kind+"/"+text+"/"+name, func(test *testing.T) {
					controlNumber := number
					if number < bound[0] || number > bound[1] {
						controlNumber = bound[0]
					}
					valid, err := wire.Parse([]byte(`{"number":` + strconv.FormatInt(controlNumber, 10) + `}`))
					if err != nil || checkValue(valid["number"], kind, set) != nil {
						test.Fatal("number canonical control")
					}
					changed, err := wire.Parse([]byte(`{"number":` + lexeme + `}`))
					if err == nil && (name != "negative-sign" || checkValue(changed["number"], kind, set) == nil) {
						test.Fatalf("number lexeme refusal: %s", lexeme)
					}
				})
			}
		}
	}
}

// Claim: every owner role must be present once and accepted, and residual consent is independently required, beside all-role consent.
func TestLabGeneratedOwnerSetPairs(test *testing.T) {
	set, fixtures := loadContracts(test)
	for position, shape := range set.Surfaces {
		if shape.Format != "swarma-broker-lab-owner-decision/1" {
			continue
		}
		valid, err := wire.Parse(canonicalObject(test, fixtures[position].Valid))
		if err != nil {
			test.Fatal(err)
		}
		for index, item := range valid["roles"].([]any) {
			name := item.(map[string]any)["role"].(string)
			cases := []string{"unaccepted", "missing", "extra", "unknown", "repository", "time-contract", "user-manager"}
			for _, mutation := range cases {
				if mutation == name {
					continue
				}
				test.Run(name+"/"+mutation, func(test *testing.T) {
					if !ownersAccepted(valid) {
						test.Fatal("owner valid control")
					}
					changed, err := wire.Parse(canonicalObject(test, fixtures[position].Valid))
					if err != nil {
						test.Fatal(err)
					}
					roles := changed["roles"].([]any)
					switch mutation {
					case "unaccepted":
						roles[index].(map[string]any)["accepted"] = false
					case "missing":
						changed["roles"] = append(slices.Clone(roles[:index]), roles[index+1:]...)
					case "extra":
						changed["roles"] = append(roles, roles[index])
					case "unknown":
						roles[index].(map[string]any)["role"] = "PUBLIC-UNKNOWN"
					default:
						roles[index].(map[string]any)["role"] = mutation
					}
					if ownersAccepted(changed) {
						test.Fatal("owner set violation admitted")
					}
				})
			}
		}
		test.Run("residual-unaccepted", func(test *testing.T) {
			if !ownersAccepted(valid) {
				test.Fatal("owner valid control")
			}
			changed := maps.Clone(valid)
			changed["residual_accepted"] = false
			if ownersAccepted(changed) {
				test.Fatal("residual consent omitted")
			}
		})
		return
	}
	test.Fatal("missing owner fixture")
}

// Claim: an independent compositional pass attacks interactions absent from the unary catalogue; each forbidden combination still refuses beside the unchanged request.
func TestLabIndependentAdversarialPairs(test *testing.T) {
	valid, beta, paths := wireControls(test)
	cases := []struct {
		Name   string
		Step   string
		Mutate func(*wireFixture)
	}{
		{"two-global-caches", "body_value", func(changed *wireFixture) {
			systems := changed.Request.Body["system"].([]any)
			for _, item := range systems {
				item.(map[string]any)["cache_control"].(map[string]any)["scope"] = "global"
			}
		}},
		{"no-global-cache", "body_fields", func(changed *wireFixture) {
			for _, item := range changed.Request.Body["system"].([]any) {
				delete(item.(map[string]any)["cache_control"].(map[string]any), "scope")
			}
		}},
		{"per-instance-system-transplant", "body_fields", func(changed *wireFixture) {
			systems := changed.Request.Body["system"].([]any)
			delete(systems[0].(map[string]any), "text")
			systems[1].(map[string]any)["system[].text"] = "PUBLIC-OTHER"
		}},
		{"thinking-cross-slot-values", "body_value", func(changed *wireFixture) {
			thinking := changed.Request.Body["thinking"].(map[string]any)
			thinking["type"], thinking["display"] = thinking["display"], thinking["type"]
		}},
		{"two-effort-slots-outside-profile", "body_value", func(changed *wireFixture) {
			changed.Request.Body["output_config"].(map[string]any)["effort"] = "high"
			changed.Request.Body["messages"].([]any)[0].(map[string]any)["output_config"].(map[string]any)["effort"] = "high"
		}},
		{"system-and-content-discriminator-swap", "body_value", func(changed *wireFixture) {
			changed.Request.Body["system"].([]any)[0].(map[string]any)["type"] = "user"
			changed.Request.Body["messages"].([]any)[0].(map[string]any)["role"] = "text"
		}},
		{"compensated-beta-cardinality", "beta", func(changed *wireFixture) {
			for index, header := range changed.Request.Headers {
				if header[0] == "anthropic-beta" {
					tokens := strings.Split(header[1], ",")
					tokens[len(tokens)-1] = tokens[0]
					changed.Request.Headers[index][1] = strings.Join(tokens, ",")
				}
			}
		}},
		{"oauth-with-complete-api-beta-set", "beta", func(changed *wireFixture) {
			for index, header := range changed.Request.Headers {
				if header[0] == "anthropic-beta" {
					changed.Request.Headers[index][1] = header[1] + ",oauth-2025-04-20"
				}
			}
		}},
		{"equal-count-header-cross-slot-swap", "envelope", func(changed *wireFixture) {
			headers := changed.Request.Headers
			headers[0][1], headers[1][1] = headers[1][1], headers[0][1]
		}},
		{"two-cache-ttls-equal-and-foreign", "body_fields", func(changed *wireFixture) {
			for _, item := range changed.Request.Body["system"].([]any) {
				item.(map[string]any)["cache_control"].(map[string]any)["ttl"] = "1h"
			}
		}},
		{"tools-and-edits-object-transplant", "body_fields", func(changed *wireFixture) {
			management := changed.Request.Body["context_management"].(map[string]any)
			changed.Request.Body["tools"], management["edits"] = management["edits"], changed.Request.Body["tools"]
		}},
		{"metadata-diagnostics-key-transplant", "body_fields", func(changed *wireFixture) {
			changed.Request.Body["metadata"], changed.Request.Body["diagnostics"] = changed.Request.Body["diagnostics"], changed.Request.Body["metadata"]
		}},
	}
	for _, mutation := range cases {
		test.Run(mutation.Name, func(test *testing.T) {
			if wireRefusal(valid, beta, paths) != "" {
				test.Fatal("adversarial control refused")
			}
			changed := cloneWire(test, valid)
			mutation.Mutate(&changed)
			if reason := wireRefusal(changed, beta, paths); reason != mutation.Step {
				test.Fatalf("adversarial intended refusal: got %s want %s", reason, mutation.Step)
			}
		})
	}
}

// Claim: envelope scalars and header cells reject null and every non-string JSON type, without treating a decoder error as a body-gate refusal.
func TestLabGeneratedWireJSONTypePairs(test *testing.T) {
	valid, beta, paths := wireControls(test)
	original, _ := json.Marshal(valid)
	var object map[string]any
	if err := json.Unmarshal(original, &object); err != nil {
		test.Fatal(err)
	}
	pathsToValues := [][]any{{"request", "body"}, {"request", "method"}, {"request", "path"}, {"request", "source_scheme"}}
	headers := object["request"].(map[string]any)["headers"].([]any)
	for index := range headers {
		for side := 0; side < 2; side++ {
			pathsToValues = append(pathsToValues, []any{"request", "headers", index, side})
		}
	}
	for _, path := range pathsToValues {
		for _, mutation := range wrongTypes(pathValue(object, path)) {
			test.Run(fmt.Sprint(path, "/", mutation.Name), func(test *testing.T) {
				var control wireFixture
				if err := json.Unmarshal(original, &control); err != nil || !wireAdmitted(control, beta, paths) {
					test.Fatal("typed wire control")
				}
				var changed map[string]any
				if err := json.Unmarshal(original, &changed); err != nil {
					test.Fatal(err)
				}
				putPath(changed, path, mutation.Value)
				encoded, _ := json.Marshal(changed)
				var candidate wireFixture
				err := json.Unmarshal(encoded, &candidate)
				if err == nil && wireAdmitted(candidate, beta, paths) {
					test.Fatal("wrong JSON wire scalar admitted")
				}
			})
		}
	}
}

func wireValueRefusal(control, candidate any, path []any) string {
	if path[len(path)-1] == "tools" {
		return "body_value"
	}
	switch typed := control.(type) {
	case map[string]any:
		return "body_fields"
	case []any:
		items, ok := candidate.([]any)
		if !ok || len(items) < len(typed) {
			return "body_fields"
		}
	}
	switch candidate.(type) {
	case map[string]any, []any:
		if jsonKind(control) != jsonKind(candidate) {
			return "body_fields"
		}
	}
	return "body_value"
}

// Claim: canonical bytes admit the exact object, but leading/trailing/interior whitespace and redundant ASCII escapes refuse at the CCJ round-trip gate, even when decoded values agree.
func TestLabGeneratedCanonicalBytePairs(test *testing.T) {
	set, fixtures := loadContracts(test)
	for position, shape := range set.Surfaces {
		control := canonicalObject(test, fixtures[position].Valid)
		cases := map[string][]byte{
			"leading-space":        append([]byte{' '}, control...),
			"trailing-space":       append(slices.Clone(control), ' '),
			"trailing-newline":     append(slices.Clone(control), '\n'),
			"interior-space":       append([]byte{'{', ' '}, control[1:]...),
			"redundant-key-escape": bytes.Replace(control, []byte(`"format"`), []byte(`"\u0066ormat"`), 1),
		}
		for name, data := range cases {
			test.Run(shape.Format+"/"+name, func(test *testing.T) {
				if _, err := wire.Parse(control); err != nil {
					test.Fatal(err)
				}
				var before, after any
				if err := json.Unmarshal(control, &before); err != nil {
					test.Fatal(err)
				}
				if err := json.Unmarshal(data, &after); err != nil {
					test.Fatal(err)
				}
				left, _ := json.Marshal(before)
				right, _ := json.Marshal(after)
				if !bytes.Equal(left, right) {
					test.Fatal("canonical witness changed value")
				}
				if _, err := wire.Parse(data); err != wire.ErrMalformed {
					test.Fatalf("canonical bytes refusal: %v", err)
				}
			})
		}
	}
}

func asciiHeaderCaseEqual(candidate, measured string) bool {
	if len(candidate) != len(measured) {
		return false
	}
	for index := range measured {
		if candidate[index] != measured[index] && !(measured[index] >= 'a' && measured[index] <= 'z' && candidate[index] == measured[index]-('a'-'A')) {
			return false
		}
	}
	return true
}

func headerNameCases(name string) []grammarMutation {
	cases := labelCases(name)
	for offset := 0; offset <= len(name); offset++ {
		for value := 0; value <= 255; value++ {
			inserted := name[:offset] + string([]byte{byte(value)}) + name[offset:]
			cases = append(cases, grammarMutation{fmt.Sprintf("byte-%d-insert-%02x", offset, value), inserted, false})
			if offset < len(name) {
				replaced := name[:offset] + string([]byte{byte(value)}) + name[offset+1:]
				cases = append(cases, grammarMutation{fmt.Sprintf("byte-%d-replace-%02x", offset, value), replaced, asciiHeaderCaseEqual(replaced, name)})
			}
		}
		if offset < len(name) {
			for position, alias := range map[byte][]string{'i': {"\u0131", "\u0130"}, 'k': {"\u212a"}, 's': {"\u017f"}}[name[offset]] {
				cases = append(cases, grammarMutation{fmt.Sprintf("unicode-alias-%d-%d", offset, position), name[:offset] + alias + name[offset+1:], false})
			}
		}
	}
	return cases
}

// Claim: the header-name primitive accepts exactly nonempty ASCII tchar tokens and folds only ASCII letters, independently of the measured-name allowlist.
func TestLabASCIIHeaderTokenPairs(test *testing.T) {
	alphabet := "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	for value := 0; value <= 255; value++ {
		test.Run(fmt.Sprintf("byte-%02x", value), func(test *testing.T) {
			if folded, ok := foldHeaderName("X-API-KEY"); !ok || folded != "x-api-key" {
				test.Fatal("ASCII header valid control refused")
			}
			candidate := "A" + string([]byte{byte(value)}) + "Z"
			folded, ok := foldHeaderName(candidate)
			allowed := strings.ContainsAny(string([]byte{byte(value)}), alphabet)
			if ok != allowed {
				test.Fatalf("header token alphabet verdict: byte=%02x admit=%v", value, allowed)
			}
			if allowed {
				expected := "a" + strings.ToLower(string([]byte{byte(value)})) + "z"
				if folded != expected {
					test.Fatal("ASCII header fold differs from token control")
				}
			}
		})
	}
	if _, ok := foldHeaderName(""); ok {
		test.Fatal("empty header token admitted")
	}
}

// Claim: every beta byte position rejects every non-HTAB control and non-ASCII byte; SP/HTAB pass only at token boundaries, beside unchanged valid requests.
func TestLabGeneratedBetaOWSBytePairs(test *testing.T) {
	valid, beta, paths := wireControls(test)
	index := slices.IndexFunc(valid.Request.Headers, func(header [2]string) bool { return header[0] == "anthropic-beta" })
	if index < 0 {
		test.Fatal("missing beta control")
	}
	for offset := 0; offset <= len(beta); offset++ {
		test.Run(fmt.Sprintf("position-%d", offset), func(test *testing.T) {
			boundary := offset == 0 || offset == len(beta) || beta[offset-1] == ',' || beta[offset] == ','
			controlOffset := strings.LastIndex(beta[:offset], ",") + 1
			for _, whitespace := range []byte{' ', '\t'} {
				control := cloneWire(test, valid)
				control.Request.Headers[index][1] = beta[:controlOffset] + string(whitespace) + beta[controlOffset:]
				if reason := wireRefusal(control, beta, paths); reason != "" {
					test.Fatalf("SP/HTAB OWS control refused: %s", reason)
				}
				changed := cloneWire(test, valid)
				changed.Request.Headers[index][1] = beta[:offset] + string(whitespace) + beta[offset:]
				expected := "beta"
				if boundary {
					expected = ""
				}
				if reason := wireRefusal(changed, beta, paths); reason != expected {
					test.Fatalf("SP/HTAB position verdict: reason=%s expected=%s", reason, expected)
				}
			}
			for value := 0; value <= 255; value++ {
				if value == '\t' || value >= ' ' && value < 127 {
					continue
				}
				test.Run(fmt.Sprintf("forbidden-byte-%02x", value), func(test *testing.T) {
					if wireRefusal(valid, beta, paths) != "" {
						test.Fatal("beta byte valid control refused")
					}
					changed := cloneWire(test, valid)
					changed.Request.Headers[index][1] = beta[:offset] + string([]byte{byte(value)}) + beta[offset:]
					if reason := wireRefusal(changed, beta, paths); reason != "beta" {
						test.Fatalf("forbidden beta byte admitted or wrong step: byte=%02x reason=%s", value, reason)
					}
				})
			}
		})
	}
}
