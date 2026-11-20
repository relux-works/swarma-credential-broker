package labcontractv0

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

const contractRoot = "../../contracts/lab-v0"
const indexSHA256 = "4f9a81562d391153764b5ae75d7914cf83f03c1bb3d956461211d8eb36f6e7d8"

type recordShape struct {
	Format     string            `json:"format"`
	Writer     string            `json:"writer"`
	Readers    []string          `json:"readers"`
	Acceptance []string          `json:"acceptance"`
	MaxBytes   int               `json:"max_bytes"`
	Fields     map[string]string `json:"fields"`
}

type contractSet struct {
	Structures map[string]recordShape `json:"structures"`
	Surfaces   []recordShape          `json:"surfaces"`
}

type contractCase struct {
	Surface         string           `json:"surface"`
	Valid           map[string]any   `json:"valid"`
	Negative        map[string]any   `json:"negative"`
	NegativeReason  string           `json:"negative_reason"`
	NestedNegatives []nestedNegative `json:"nested_negatives"`
}

func readContract(test *testing.T, name string) []byte {
	test.Helper()
	data, err := os.ReadFile(filepath.Join(contractRoot, name))
	if err != nil {
		test.Fatal(err)
	}
	return data
}

func decodeContract(test *testing.T, name string, target any) {
	test.Helper()
	if err := json.Unmarshal(readContract(test, name), target); err != nil {
		test.Fatal(err)
	}
}

func canonicalObject(test *testing.T, object map[string]any) []byte {
	test.Helper()
	data, err := wire.Encode(object)
	if err != nil {
		test.Fatal(err)
	}
	return data
}

func cloneObject(test *testing.T, object map[string]any) map[string]any {
	test.Helper()
	data := canonicalObject(test, object)
	var cloned map[string]any
	if err := json.Unmarshal(data, &cloned); err != nil {
		test.Fatal(err)
	}
	return cloned
}

func hashContract(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func checkFields(object map[string]any, shape recordShape, set contractSet) error {
	if len(object) != len(shape.Fields) {
		return fmt.Errorf("field_set")
	}
	for name, fieldType := range shape.Fields {
		value, present := object[name]
		if !present || value == nil {
			return fmt.Errorf("field_set: %s", name)
		}
		if err := checkValue(value, fieldType, set); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func checkValue(value any, fieldType string, set contractSet) error {
	if strings.HasPrefix(fieldType, "[]") {
		items, ok := value.([]any)
		if !ok || len(items) > 256 {
			return fmt.Errorf("array")
		}
		for _, item := range items {
			if err := checkValue(item, fieldType[2:], set); err != nil {
				return err
			}
		}
		return nil
	}
	if strings.HasPrefix(fieldType, "@") {
		shape, exists := set.Structures[fieldType[1:]]
		object, ok := value.(map[string]any)
		if !exists || !ok {
			return fmt.Errorf("structure")
		}
		return checkFields(object, shape, set)
	}
	if strings.HasPrefix(fieldType, "=") {
		if value != fieldType[1:] {
			return fmt.Errorf("singleton")
		}
		return nil
	}
	if strings.Contains(fieldType, "|") {
		text, ok := value.(string)
		if !ok || !slices.Contains(strings.Split(fieldType, "|"), text) {
			return fmt.Errorf("enum")
		}
		return nil
	}
	if fieldType == "time" {
		text, ok := value.(string)
		if !ok {
			return fmt.Errorf("time")
		}
		parsed, err := time.Parse(time.RFC3339Nano, text)
		if err != nil || parsed.UTC().Format(time.RFC3339Nano) != text || !parsed.After(time.Unix(0, 0)) {
			return fmt.Errorf("time")
		}
		return nil
	}
	if fieldType == "bool" {
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("boolean")
		}
		return nil
	}
	patterns := map[string]string{"id": `^[\x21-\x7e]{1,128}$`, "digest": `^sha256:[0-9a-f]{64}$`, "operation": `^[0-9a-f]{32}$`, "uuid": `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`, "commit": `^[0-9a-f]{40}$`, "material": `^[\x21-\x7e]+$`}
	if pattern, exists := patterns[fieldType]; exists {
		text, ok := value.(string)
		if !ok || (fieldType == "material" && len(text) > 4096) || !regexp.MustCompile(pattern).MatchString(text) {
			return fmt.Errorf("%s", fieldType)
		}
		return nil
	}
	number, ok := value.(int64)
	if !ok {
		return fmt.Errorf("integer: %s", fieldType)
	}
	minimum, maximum := int64(0), int64(9007199254740991)
	switch fieldType {
	case "uint":
	case "positive":
		minimum = 1
	case "root":
		maximum = 0
	case "lifetime":
		minimum, maximum = 1, 900
	case "alignment":
		maximum = 2
	case "exit":
		maximum = 255
	case "poll":
		minimum, maximum = 250, 250
	case "capture-timeout":
		minimum, maximum = 300, 300
	default:
		return fmt.Errorf("unknown grammar: %s", fieldType)
	}
	if number < minimum || number > maximum {
		return fmt.Errorf("range: %s", fieldType)
	}
	return nil
}

func checkPayloadSize(data []byte, maxBytes int) error {
	if len(data) > maxBytes {
		return fmt.Errorf("size")
	}
	return nil
}

func checkRecord(data []byte, shape recordShape, set contractSet) error {
	if err := checkPayloadSize(data, shape.MaxBytes); err != nil {
		return err
	}
	object, err := wire.Parse(data)
	if err != nil {
		return fmt.Errorf("canonical")
	}
	return checkFields(object, shape, set)
}

func loadContracts(test *testing.T) (contractSet, []contractCase) {
	test.Helper()
	var set contractSet
	decodeContract(test, "surfaces.json", &set)
	var fixtures struct {
		Cases []contractCase `json:"cases"`
	}
	decodeContract(test, "fixtures.json", &fixtures)
	return set, fixtures.Cases
}

func contentPinValid(data []byte, expected string) bool {
	return hashContract(data) == expected
}

// Claim: a valid artifact pin admits its file bytes while an unresealed changed temporary copy fails the same verifier used for the inventory.
func TestLabContentPinChangedCopy(test *testing.T) {
	original := readContract(test, "surfaces.json")
	expected := hashContract(original)
	path := filepath.Join(test.TempDir(), "surfaces.json")
	for _, change := range []bool{false, true} {
		data := bytes.Clone(original)
		if change {
			data = append(data, '\n')
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			test.Fatal(err)
		}
		stored, err := os.ReadFile(path)
		if err != nil {
			test.Fatal(err)
		}
		if contentPinValid(stored, expected) == change {
			test.Fatal("pin verifier wrong verdict")
		}
	}
}

// Claim: every sealed artifact/source matches its frozen digest and the index contains no commit locator; changed-copy controls exercise the same pin verifier.
func TestLabContractContentPins(test *testing.T) {
	index := readContract(test, "index.json")
	if hashContract(index) != indexSHA256 {
		test.Fatal("index seal changed")
	}
	var entries struct {
		Files   map[string]string `json:"files"`
		Sources map[string]string `json:"source_files"`
	}
	if err := json.Unmarshal(index, &entries); err != nil {
		test.Fatal(err)
	}
	if len(entries.Files) < 12 {
		test.Fatal("incomplete seal")
	}
	for name, expected := range entries.Files {
		data := readContract(test, name)
		if !contentPinValid(data, expected) {
			test.Fatalf("content pin: %s", name)
		}
	}
	if len(entries.Sources) != 6 {
		test.Fatal("incomplete source seals")
	}
	for name, expected := range entries.Sources {
		data, err := os.ReadFile(filepath.Join("../..", name))
		if err != nil {
			test.Fatal(err)
		}
		if !contentPinValid(data, expected) {
			test.Fatalf("source content pin: %s", name)
		}
	}
	if bytes.Contains(index, []byte("spec_commit")) {
		test.Fatal("commit locator is not a content pin")
	}
}

func checkInventory(wanted map[string]bool, set contractSet, fixtures []contractCase) error {
	if len(wanted) != 24 || len(set.Surfaces) != len(wanted) || len(fixtures) != len(wanted) {
		return fmt.Errorf("inventory size")
	}
	seen := map[string]bool{}
	for position, shape := range set.Surfaces {
		if !wanted[shape.Format] || seen[shape.Format] || fixtures[position].Surface != shape.Format {
			return fmt.Errorf("inventory identity")
		}
		seen[shape.Format] = true
		if shape.Writer == "" || len(shape.Readers) == 0 || len(shape.Acceptance) == 0 {
			return fmt.Errorf("unowned contract")
		}
	}
	return nil
}

// Claim: profile section 5.2 has exactly one closed schema/fixture per format; missing, duplicated and undeclared surfaces fail beside the complete valid inventory.
func TestLabClosedInventory(test *testing.T) {
	set, fixtures := loadContracts(test)
	profile, err := os.ReadFile("../../docs/lab-profile-v0.md")
	if err != nil {
		test.Fatal(err)
	}
	section := strings.Split(strings.Split(string(profile), "### 5.2 C0's closed byte inventory and consumer joins")[1], "Root mutating requests")[0]
	names := regexp.MustCompile("`((?:swarma-(?:broker-lab|lab-release-set)|anthropic-api-key-lab)[a-z-]*/1)`").FindAllStringSubmatch(section, -1)
	wanted := map[string]bool{}
	for _, match := range names {
		wanted[match[1]] = true
	}
	if err := checkInventory(wanted, set, fixtures); err != nil {
		test.Fatalf("valid inventory refused: %v", err)
	}
	missing := set
	missing.Surfaces = set.Surfaces[:23]
	if checkInventory(wanted, missing, fixtures) == nil {
		test.Fatal("missing surface admitted")
	}
	changed := set
	changed.Surfaces = append([]recordShape{}, set.Surfaces...)
	changed.Surfaces[1] = changed.Surfaces[0]
	if checkInventory(wanted, changed, fixtures) == nil {
		test.Fatal("duplicate surface admitted")
	}
	changed.Surfaces[1].Format = "undeclared-format"
	if checkInventory(wanted, changed, fixtures) == nil {
		test.Fatal("undeclared surface admitted")
	}
}

// Claim: valid sealed surfaces admit; re-sealed closure negatives fail specifically before seal verification, while format/encoding variants also refuse.
func TestLabClosedSurfacePairs(test *testing.T) {
	set, fixtures := loadContracts(test)
	for position, shape := range set.Surfaces {
		test.Run(shape.Format, func(test *testing.T) {
			fixture := fixtures[position]
			valid := canonicalObject(test, fixture.Valid)
			if err := checkSealedRecord(valid, shape, set); err != nil {
				test.Fatalf("valid refused: %v", err)
			}
			if fixture.NegativeReason != "unknown_field" {
				test.Fatal("wrong closure reason")
			}
			assertClosureSealControl(test, shape, fixture.Negative)
			assertClosureRefusal(test, fixture.Negative, shape, set)
			for name := range shape.Fields {
				missing := cloneObject(test, fixture.Valid)
				delete(missing, name)
				resealClosure(test, missing)
				assertClosureRefusal(test, missing, shape, set)
				null := cloneObject(test, fixture.Valid)
				null[name] = nil
				resealClosure(test, null)
				assertClosureRefusal(test, null, shape, set)
			}
			for _, format := range []string{"production", shape.Format + "-other", "swarma-broker-activation/1"} {
				changed := cloneObject(test, fixture.Valid)
				changed["format"] = format
				if checkRecord(canonicalObject(test, changed), shape, set) == nil {
					test.Fatal("foreign discriminator admitted")
				}
			}
			if checkRecord(append(bytes.Clone(valid), '\n'), shape, set) == nil {
				test.Fatal("trailing newline admitted")
			}
			keys := make([]string, 0, len(shape.Fields))
			for name := range shape.Fields {
				keys = append(keys, name)
			}
			slices.Sort(keys)
			first := canonicalObject(test, map[string]any{keys[0]: fixture.Valid[keys[0]]})
			duplicate := append(bytes.Clone(first[:len(first)-1]), ',')
			duplicate = append(duplicate, valid[1:]...)
			if !json.Valid(duplicate) {
				test.Fatal("duplicate control is not valid JSON")
			}
			if checkRecord(duplicate, shape, set) == nil {
				test.Fatal("duplicate member admitted")
			}
		})
	}
}

func accessAdmitted(object map[string]any) bool {
	endpoint := object["endpoint"].(map[string]any)
	for _, value := range endpoint {
		if value != true {
			return false
		}
	}
	for _, name := range []string{"guest_and_control_plane", "vendor_principals"} {
		principals := object[name].([]any)
		if len(principals) == 0 {
			return false
		}
		for _, entry := range principals {
			if entry.(map[string]any)["controller"] != "human" {
				return false
			}
		}
	}
	vendor := object["vendor"].(map[string]any)
	return vendor["audit_complete"] == true && vendor["roster_unchanged"] == true
}

// Claim: owner-only access metadata is valid; every endpoint exclusion, agent privilege and changed/incomplete vendor audit closes fixture admission, not native access proof.
func TestLabAccessAttestationPairs(test *testing.T) {
	set, fixtures := loadContracts(test)
	for position, shape := range set.Surfaces {
		if shape.Format != "swarma-broker-lab-access-attestation/1" {
			continue
		}
		valid, err := wire.Parse(canonicalObject(test, fixtures[position].Valid))
		if err != nil {
			test.Fatal(err)
		}
		if !accessAdmitted(valid) {
			test.Fatal("owner-only control refused")
		}
		for name := range valid["endpoint"].(map[string]any) {
			changed, _ := wire.Parse(canonicalObject(test, fixtures[position].Valid))
			changed["endpoint"].(map[string]any)[name] = false
			if accessAdmitted(changed) {
				test.Fatalf("unsafe endpoint admitted: %s", name)
			}
		}
		for _, name := range []string{"guest_and_control_plane", "vendor_principals"} {
			changed, _ := wire.Parse(canonicalObject(test, fixtures[position].Valid))
			changed[name].([]any)[0].(map[string]any)["controller"] = "agent"
			if accessAdmitted(changed) {
				test.Fatalf("agent authority admitted: %s", name)
			}
		}
		for _, name := range []string{"audit_complete", "roster_unchanged"} {
			changed, _ := wire.Parse(canonicalObject(test, fixtures[position].Valid))
			changed["vendor"].(map[string]any)[name] = false
			if accessAdmitted(changed) {
				test.Fatalf("vendor change/gap admitted: %s", name)
			}
		}
		return
	}
	test.Fatal("missing access fixture")
}

// Claim: exact amendment/API/join bytes are extracted from the reviewed profile, while a changed amendment is not that consent; actual C consent remains unrecorded.
func TestLabCOpeningContentAndDecision(test *testing.T) {
	profile, err := os.ReadFile("../../docs/lab-profile-v0.md")
	if err != nil {
		test.Fatal(err)
	}
	quoted := strings.Split(strings.Split(string(profile), "> For LAB PROFILE v0")[1], "\n### 4.3")[0]
	blocks := strings.Split("> For LAB PROFILE v0"+quoted, "\n\n> DN-09 C qualification")
	unquote := func(text string) []byte {
		lines := strings.Split(strings.TrimSpace(text), "\n")
		for position, line := range lines {
			lines[position] = strings.TrimPrefix(strings.TrimPrefix(line, ">"), " ")
		}
		return []byte(strings.Join(lines, "\n") + "\n")
	}
	joins := strings.Split(strings.Split(string(profile), "### 4.3 Joined start, high-water and native obligations\n\n")[1], "\n## 5.")[0]
	expected := map[string][]byte{"amendment.txt": unquote(blocks[0]), "api-exception.txt": unquote("> DN-09 C qualification" + blocks[1]), "joins.txt": []byte(strings.TrimRight(joins, "\n") + "\n")}
	var decisions map[string]any
	decodeContract(test, "decisions.json", &decisions)
	for name, content := range expected {
		if !bytes.Equal(content, readContract(test, name)) {
			test.Fatalf("source text changed: %s", name)
		}
		key := strings.ReplaceAll(strings.TrimSuffix(name, ".txt"), "-", "_") + "_sha256"
		if decisions[key] != "sha256:"+hashContract(content) {
			test.Fatalf("decision text pin: %s", name)
		}
	}
	if decisions["owner_acceptance"] != "not_recorded" || decisions["live_construction"] != "closed" || decisions["enrollment"] != "closed" || decisions["production_acceptance"] != false {
		test.Fatal("fixture asserted owner or production acceptance")
	}
}

func rootOutcomeValid(object map[string]any) bool {
	state := object["state"].(string)
	exits := map[string]int64{"committed": 0, "refused": 1, "not_committed:enrol_no_forward": 1, "unknown": 2, "attempted": 2, "not_started": 2, "incomplete": 2, "syntax": 64, "closed": 69}
	expected, exists := exits[state]
	return exists && object["exit_code"] == expected && (object["phase"] == "result" || state == "not_started")
}

// Claim: root-control fixtures distinguish committed/no-forward/UNKNOWN exits and disallow a request claiming commitment; no native replay effect is claimed.
func TestLabOperationOutcomePairs(test *testing.T) {
	set, fixtures := loadContracts(test)
	for position, shape := range set.Surfaces {
		if shape.Format != "swarma-broker-lab-root-control/1" {
			continue
		}
		valid, err := wire.Parse(canonicalObject(test, fixtures[position].Valid))
		if err != nil {
			test.Fatal(err)
		}
		if !rootOutcomeValid(valid) {
			test.Fatal("valid result refused")
		}
		for state, exit := range map[string]int64{"committed": 0, "refused": 1, "not_committed:enrol_no_forward": 1, "unknown": 2, "attempted": 2, "not_started": 2, "incomplete": 2, "syntax": 64, "closed": 69} {
			valid["state"], valid["exit_code"] = state, exit
			if !rootOutcomeValid(valid) {
				test.Fatalf("valid state refused: %s", state)
			}
			valid["exit_code"] = (exit + 1) % 3
			if rootOutcomeValid(valid) {
				test.Fatalf("wrong exit admitted: %s", state)
			}
		}
		valid["state"], valid["exit_code"], valid["phase"] = "committed", int64(0), "request"
		if rootOutcomeValid(valid) {
			test.Fatal("request claimed commitment")
		}
		valid["state"], valid["exit_code"] = "not_started", int64(2)
		if !rootOutcomeValid(valid) {
			test.Fatal("valid request refused")
		}
		return
	}
	test.Fatal("missing root-control fixture")
}

type wireFixture struct {
	Name    string `json:"name"`
	Admit   bool   `json:"admit"`
	Request struct {
		Method       string         `json:"method"`
		Path         string         `json:"path"`
		Headers      [][2]string    `json:"headers"`
		Body         map[string]any `json:"body"`
		SourceScheme string         `json:"source_scheme"`
	} `json:"request"`
}

func structuralPaths(value any, prefix string, paths map[string]bool) {
	switch child := value.(type) {
	case map[string]any:
		for name, nested := range child {
			path := name
			if prefix != "" {
				path = prefix + "." + name
			}
			paths[path] = true
			structuralPaths(nested, path, paths)
		}
	case []any:
		for _, nested := range child {
			structuralPaths(nested, prefix+"[]", paths)
		}
	}
}

func wireAdmitted(fixture wireFixture, beta string, allowedPaths map[string]bool) bool {
	return wireRefusal(fixture, beta, allowedPaths) == ""
}

func foldHeaderName(name string) (string, bool) {
	if name == "" {
		return "", false
	}
	folded := []byte(name)
	for index, char := range folded {
		if char >= 'A' && char <= 'Z' {
			folded[index] = char + ('a' - 'A')
		} else if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(char))) {
			return "", false
		}
	}
	return string(folded), true
}

func wireRefusal(fixture wireFixture, beta string, allowedPaths map[string]bool) string {
	request := fixture.Request
	if request.SourceScheme != "api-key" {
		return "source_scheme"
	}
	headers := map[string]string{}
	for _, header := range request.Headers {
		name, token := foldHeaderName(header[0])
		if !token {
			return "envelope"
		}
		if _, exists := headers[name]; exists {
			return "envelope"
		}
		if !slices.Contains([]string{"x-api-key", "anthropic-beta", "anthropic-version", "user-agent"}, name) {
			return "envelope"
		}
		headers[name] = header[1]
	}
	if request.Method == "GET" {
		if request.Path == "/api/claude_code/policy_limits" && len(request.Body) == 0 && len(headers) == 1 && headers["user-agent"] == "claude-code/2.1.328" {
			return ""
		}
		return "envelope"
	}
	if request.Method != "POST" || request.Path != "/v1/messages?beta=true" || len(headers) != 4 || headers["x-api-key"] != "ssh-placeholder" || headers["anthropic-version"] != "2023-06-01" || headers["user-agent"] != "claude-cli/2.1.328 (external, sdk-cli)" {
		return "envelope"
	}
	wanted := strings.Split(beta, ",")
	seen := map[string]bool{}
	for _, token := range strings.Split(headers["anthropic-beta"], ",") {
		token = strings.Trim(token, " \t")
		if seen[token] || !slices.Contains(wanted, token) {
			return "beta"
		}
		seen[token] = true
	}
	if len(seen) != len(wanted) {
		return "beta"
	}
	if err := wireBodyClosure(request.Body, "", allowedPaths); err != nil {
		return "body_fields"
	}
	paths := map[string]bool{}
	structuralPaths(request.Body, "", paths)
	if len(paths) != len(allowedPaths) {
		return "body_fields"
	}
	for path := range paths {
		if !allowedPaths[path] {
			return "body_fields"
		}
	}
	body := request.Body
	tools, ok := body["tools"].([]any)
	if !ok || len(tools) != 0 {
		return "body_value"
	}
	for _, member := range []string{"metadata", "diagnostics"} {
		object, ok := body[member].(map[string]any)
		if !ok {
			return "body_value"
		}
		name := map[string]string{"metadata": "user_id", "diagnostics": "previous_message_id"}[member]
		if _, ok := object[name].(string); !ok {
			return "body_value"
		}
	}
	if body["stream"] != true || body["model"] != "claude-opus-5-5" || body["max_tokens"] != float64(128000) {
		return "body_value"
	}
	for _, name := range []string{"thinking", "output_config", "context_management"} {
		encoded, _ := json.Marshal(body[name])
		wanted := map[string]string{"thinking": `{"display":"omitted","type":"adaptive"}`, "output_config": `{"effort":"medium"}`, "context_management": `{"edits":[{"keep":"all","type":"clear_thinking_20251015"}]}`}
		if string(encoded) != wanted[name] {
			return "body_value"
		}
	}
	systems, ok := body["system"].([]any)
	if !ok || len(systems) != 2 {
		return "body_value"
	}
	caches := []string{}
	for _, item := range systems {
		object, ok := item.(map[string]any)
		if !ok || len(object) != 3 || object["type"] != "text" {
			return "body_value"
		}
		if _, ok := object["text"].(string); !ok {
			return "body_value"
		}
		cache, _ := json.Marshal(object["cache_control"])
		caches = append(caches, string(cache))
	}
	messages, ok := body["messages"].([]any)
	if !ok || len(messages) != 1 {
		return "body_value"
	}
	message, ok := messages[0].(map[string]any)
	if !ok || len(message) != 3 || message["role"] != "user" {
		return "body_value"
	}
	output, _ := json.Marshal(message["output_config"])
	if string(output) != `{"effort":"medium"}` {
		return "body_value"
	}
	contents, ok := message["content"].([]any)
	if !ok || len(contents) != 1 {
		return "body_value"
	}
	content, ok := contents[0].(map[string]any)
	if !ok || len(content) != 3 || content["type"] != "text" {
		return "body_value"
	}
	if _, ok := content["text"].(string); !ok {
		return "body_value"
	}
	cache, _ := json.Marshal(content["cache_control"])
	caches = append(caches, string(cache))
	slices.Sort(caches)
	if !slices.Equal(caches, []string{`{"scope":"global","type":"ephemeral"}`, `{"type":"ephemeral"}`, `{"type":"ephemeral"}`}) {
		return "body_value"
	}

	return ""
}

// Claim: the reconstructed API-key request matches measured field paths and all eleven flags; OAuth, duplicated/missing flags, forbidden bodies and credentialed GET refuse beside valid POST/GET.
func TestLabAPIKeyWireFixturePairs(test *testing.T) {
	var fixtures struct {
		Cases         []wireFixture `json:"cases"`
		Reconstructed bool          `json:"body_is_reconstructed"`
		LiveBudget    bool          `json:"live_budget_approved"`
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
	if len(observed.Requests) != 2 || !fixtures.Reconstructed || fixtures.LiveBudget {
		test.Fatal("observation provenance changed")
	}
	paths := map[string]bool{}
	for _, path := range observed.Requests[1].Shape.Paths {
		paths[path] = true
	}
	beta := observed.Requests[1].Headers["anthropic-beta"].(string)
	if len(strings.Split(beta, ",")) != 11 {
		test.Fatal("eleven-token profile changed")
	}
	validCount, refusedCount := 0, 0
	for _, fixture := range fixtures.Cases {
		test.Run(fixture.Name, func(test *testing.T) {
			if wireAdmitted(fixture, beta, paths) != fixture.Admit {
				test.Fatal("wrong wire verdict")
			}
		})
		if fixture.Admit {
			validCount++
		} else {
			refusedCount++
		}
	}
	if validCount != 2 || refusedCount != 74 {
		test.Fatal("missing wire controls")
	}
	test.Run("cache-placement-multiset", func(test *testing.T) {
		for _, fixture := range fixtures.Cases {
			if fixture.Name != "messages-valid" {
				continue
			}
			fixture.Request.Body = cloneObject(test, fixture.Request.Body)
			systems := fixture.Request.Body["system"].([]any)
			first := systems[0].(map[string]any)
			second := systems[1].(map[string]any)
			first["cache_control"], second["cache_control"] = second["cache_control"], first["cache_control"]
			if !wireAdmitted(fixture, beta, paths) {
				test.Fatal("valid cache multiset position swap refused")
			}
			first["cache_control"].(map[string]any)["scope"] = "PUBLIC-OTHER-SCOPE"
			if wireAdmitted(fixture, beta, paths) {
				test.Fatal("changed cache multiset admitted")
			}
			return
		}
		test.Fatal("missing valid message fixture")
	})
}

func ownersAccepted(object map[string]any) bool {
	roles := object["roles"].([]any)
	if len(roles) != 3 {
		return false
	}
	seen := map[string]bool{}
	for _, item := range roles {
		role := item.(map[string]any)
		name := role["role"].(string)
		if seen[name] || role["accepted"] != true || !slices.Contains([]string{"repository", "time-contract", "user-manager"}, name) {
			return false
		}
		seen[name] = true
	}
	return object["residual_accepted"] == true
}

// Claim: synthetic three-role consent has exact amendment/API/join pins, while absent/duplicate/unaccepted roles or residual-only consent cannot open C.
func TestLabOwnerRolePairs(test *testing.T) {
	set, fixtures := loadContracts(test)
	for position, shape := range set.Surfaces {
		if shape.Format != "swarma-broker-lab-owner-decision/1" {
			continue
		}
		valid, err := wire.Parse(canonicalObject(test, fixtures[position].Valid))
		if err != nil {
			test.Fatal(err)
		}
		if !ownersAccepted(valid) {
			test.Fatal("synthetic all-role consent refused")
		}
		for _, name := range []string{"amendment", "api-exception", "joins"} {
			key := strings.ReplaceAll(name, "-", "_") + "_sha256"
			if valid[key] != "sha256:"+hashContract(readContract(test, name+".txt")) {
				test.Fatalf("wrong owner text pin: %s", name)
			}
		}
		for _, mutation := range []string{"missing", "duplicate", "unaccepted", "residual-only"} {
			changed, _ := wire.Parse(canonicalObject(test, fixtures[position].Valid))
			roles := changed["roles"].([]any)
			switch mutation {
			case "missing":
				changed["roles"] = roles[:2]
			case "duplicate":
				roles[2] = roles[0]
			case "unaccepted":
				roles[0].(map[string]any)["accepted"] = false
			case "residual-only":
				changed["roles"] = []any{}
			}
			if ownersAccepted(changed) {
				test.Fatalf("bad consent admitted: %s", mutation)
			}
		}
		return
	}
	test.Fatal("missing owner-decision fixture")
}

func contractInstant(value any) time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, value.(string))
	if err != nil {
		panic(err)
	}
	return parsed
}

// Claim: lease ceilings include 1 and 900 only, and every earlier authority deadline clips the synthetic lease without discarding subsecond precision.
func TestLabLeaseDeadlinePairs(test *testing.T) {
	set, fixtures := loadContracts(test)
	for position, shape := range set.Surfaces {
		if shape.Format != "anthropic-api-key-lab/1" {
			continue
		}
		valid, err := wire.Parse(canonicalObject(test, fixtures[position].Valid))
		if err != nil {
			test.Fatal(err)
		}
		bounds := valid["bounds"].(map[string]any)
		deadlineValid := func() bool {
			issued, lifetime := contractInstant(bounds["issued_at"]), bounds["lifetime_seconds"].(int64)
			if lifetime < 1 || lifetime > 900 {
				return false
			}
			deadline := issued.Add(time.Duration(lifetime) * time.Second)
			for _, name := range []string{"authority_until", "caller_until", "time_until", "qualification_until"} {
				if contractInstant(bounds[name]).Before(deadline) {
					deadline = contractInstant(bounds[name])
				}
			}
			return contractInstant(bounds["authorized_until"]).Equal(deadline) && deadline.After(issued)
		}
		if !deadlineValid() {
			test.Fatal("valid bound refused")
		}
		for _, lifetime := range []int64{1, 900, 0, 901} {
			bounds["lifetime_seconds"], bounds["authorized_until"] = lifetime, contractInstant(bounds["issued_at"]).Add(time.Duration(lifetime)*time.Second).Format(time.RFC3339Nano)
			if deadlineValid() != (lifetime >= 1 && lifetime <= 900) {
				test.Fatalf("ceiling pair: %d", lifetime)
			}
		}
		bounds["lifetime_seconds"] = int64(900)
		for _, name := range []string{"authority_until", "caller_until", "time_until", "qualification_until"} {
			original := bounds[name]
			clipped := contractInstant(bounds["issued_at"]).Add(time.Nanosecond)
			bounds[name], bounds["authorized_until"] = clipped.Format(time.RFC3339Nano), clipped.Format(time.RFC3339Nano)
			if !deadlineValid() {
				test.Fatalf("clipped bound refused: %s", name)
			}
			bounds["authorized_until"] = clipped.Add(time.Nanosecond).Format(time.RFC3339Nano)
			if deadlineValid() {
				test.Fatalf("earliest deadline ignored: %s", name)
			}
			bounds[name] = original
		}
		return
	}
	test.Fatal("missing lease fixture")
}

func matcherSummaryAllowed(object map[string]any) bool {
	verdict := object["verdict"]
	if verdict == "incomplete" {
		return true
	}
	if verdict == "match" {
		return object["hold_result"] == "committed"
	}
	if verdict != "clean" || object["complete"] != true || object["hold_result"] != "not_required" || len(object["issued_versions"].([]any)) == 0 {
		return false
	}
	wanted := map[string]bool{"raw/false/0": true, "json/false/0": true, "percent/false/0": true}
	for _, name := range []string{"base64", "base64url"} {
		for _, padded := range []bool{true, false} {
			for alignment := range 3 {
				wanted[fmt.Sprintf("%s/%t/%d", name, padded, alignment)] = true
			}
		}
	}
	for _, item := range object["encodings"].([]any) {
		encoding := item.(map[string]any)
		key := fmt.Sprintf("%s/%t/%d", encoding["name"], encoding["padded"], encoding["alignment"])
		if !wanted[key] || encoding["initialized"] != true {
			return false
		}
		delete(wanted, key)
	}
	return len(wanted) == 0
}

// Claim: complete full-version/all-alignment matcher metadata may be clean, while missing version/alignment, incomplete initialization and unknown hold cannot claim clean/match.
func TestLabMatcherSummaryPairs(test *testing.T) {
	set, fixtures := loadContracts(test)
	for position, shape := range set.Surfaces {
		if shape.Format != "swarma-broker-lab-match/1" {
			continue
		}
		valid, err := wire.Parse(canonicalObject(test, fixtures[position].Valid))
		if err != nil {
			test.Fatal(err)
		}
		if !matcherSummaryAllowed(valid) {
			test.Fatal("complete valid summary refused")
		}
		for _, mutation := range []string{"no-versions", "missing-alignment", "not-initialized", "incomplete", "unknown-hold"} {
			changed, _ := wire.Parse(canonicalObject(test, fixtures[position].Valid))
			switch mutation {
			case "no-versions":
				changed["issued_versions"] = []any{}
			case "missing-alignment":
				changed["encodings"] = changed["encodings"].([]any)[:14]
			case "not-initialized":
				changed["encodings"].([]any)[0].(map[string]any)["initialized"] = false
			case "incomplete":
				changed["complete"] = false
			case "unknown-hold":
				changed["verdict"], changed["hold_result"] = "match", "unknown"
			}
			if matcherSummaryAllowed(changed) {
				test.Fatalf("bad summary admitted: %s", mutation)
			}
		}
		valid["verdict"], valid["hold_result"] = "match", "committed"
		if !matcherSummaryAllowed(valid) {
			test.Fatal("durable-match metadata refused")
		}
		return
	}
	test.Fatal("missing matcher fixture")
}

func approvalTargetValid(object map[string]any) bool {
	for _, name := range []string{"approval", "owner_approval"} {
		approval, exists := object[name].(map[string]any)
		if !exists {
			continue
		}
		record := map[string]any{}
		for key, value := range object {
			if key != name {
				record[key] = value
			}
		}
		encoded, err := wire.Encode(map[string]any{"domain": "swarma-broker-lab-approval-target/1", "record": record})
		return err == nil && approval["approved_sha256"] == "sha256:"+hashContract(encoded)
	}
	return false
}

// Claim: the same approval-target verifier accepts each sealed subject and refuses a changed subject retaining the old approval; no live approval is claimed.
func TestLabApprovalTargetPairs(test *testing.T) {
	_, fixtures := loadContracts(test)
	checked := 0
	for _, fixture := range fixtures {
		for _, name := range []string{"approval", "owner_approval"} {
			if _, present := fixture.Valid[name]; !present {
				continue
			}
			if !approvalTargetValid(fixture.Valid) {
				test.Fatalf("approval target mismatch: %s", fixture.Surface)
			}
			changed := cloneObject(test, fixture.Valid)
			changed["format"] = "unapproved-input"
			if approvalTargetValid(changed) {
				test.Fatal("changed approval subject admitted")
			}
			checked++
		}
	}
	if checked != 5 {
		test.Fatalf("approval target inventory: %d", checked)
	}
}

func journalHeadValid(object map[string]any) bool {
	head := object["head"].(map[string]any)
	record := map[string]any{}
	for key, value := range object {
		if key != "head" {
			record[key] = value
		}
	}
	encoded, err := wire.Encode(map[string]any{"domain": "swarma-broker-lab-journal-head/1", "record": record})
	return err == nil && head["sequence"] == int64(len(record["entries"].([]any))) && head["sha256"] == "sha256:"+hashContract(encoded)
}

// Claim: the same journal verifier accepts the complete sealed snapshot and refuses a changed lease retaining its old head, without a self-referential hash.
func TestLabJournalHeadPairs(test *testing.T) {
	_, fixtures := loadContracts(test)
	for _, fixture := range fixtures {
		if fixture.Surface != "swarma-broker-lab-service-journal/1" {
			continue
		}
		record, err := wire.Parse(canonicalObject(test, fixture.Valid))
		if err != nil {
			test.Fatal(err)
		}
		if !journalHeadValid(record) {
			test.Fatal("valid snapshot head refused")
		}
		record["leases"].([]any)[0].(map[string]any)["status"] = "revoked"
		if journalHeadValid(record) {
			test.Fatal("unsealed changed lease admitted")
		}
		return
	}
	test.Fatal("missing journal fixture")
}

func resealClosure(test *testing.T, object map[string]any) {
	test.Helper()
	for _, name := range []string{"approval", "owner_approval"} {
		if approval, exists := object[name].(map[string]any); exists {
			record := map[string]any{}
			for key, value := range object {
				if key != name {
					record[key] = value
				}
			}
			approval["approved_sha256"] = "sha256:" + hashContract(canonicalObject(test, map[string]any{"domain": "swarma-broker-lab-approval-target/1", "record": record}))
		}
	}
	if object["format"] == "swarma-broker-lab-service-journal/1" {
		if head, exists := object["head"].(map[string]any); exists {
			record := map[string]any{}
			for key, value := range object {
				if key != "head" {
					record[key] = value
				}
			}
			head["sha256"] = "sha256:" + hashContract(canonicalObject(test, map[string]any{"domain": "swarma-broker-lab-journal-head/1", "record": record}))
			if entries, present := record["entries"].([]any); present && head["sequence"] != nil {
				head["sequence"] = int64(len(entries))
			}
		}
	}
}

func checkSealedRecord(data []byte, shape recordShape, set contractSet) error {
	if err := checkRecord(data, shape, set); err != nil {
		return err
	}
	object, err := wire.Parse(data)
	if err != nil {
		return err
	}
	for _, name := range []string{"approval", "owner_approval"} {
		if _, sealed := shape.Fields[name]; sealed && !approvalTargetValid(object) {
			return fmt.Errorf("approval_seal")
		}
	}
	if shape.Format == "swarma-broker-lab-service-journal/1" && !journalHeadValid(object) {
		return fmt.Errorf("journal_seal")
	}
	return nil
}

func assertClosureRefusal(test *testing.T, object map[string]any, shape recordShape, set contractSet) {
	test.Helper()
	if err := checkSealedRecord(canonicalObject(test, object), shape, set); err == nil || !strings.Contains(err.Error(), "field_set") {
		test.Fatalf("closure gate admitted or wrong refusal: %v", err)
	}
}

func assertClosureSealControl(test *testing.T, shape recordShape, object map[string]any) {
	test.Helper()
	record, err := wire.Parse(canonicalObject(test, object))
	if err != nil {
		test.Fatal(err)
	}
	for _, name := range []string{"approval", "owner_approval"} {
		if _, sealed := shape.Fields[name]; sealed && !approvalTargetValid(record) {
			test.Fatal("closure negative has stale approval seal")
		}
	}
	if shape.Format == "swarma-broker-lab-service-journal/1" {
		if !journalHeadValid(record) {
			test.Fatal("closure negative has stale journal seal")
		}
	}
}

type nestedNegative struct {
	Path      []any          `json:"path"`
	Structure string         `json:"structure"`
	Field     string         `json:"field"`
	Mutation  string         `json:"mutation"`
	Record    map[string]any `json:"record"`
}

type fieldVisit struct {
	Path  []any
	Type  string
	Value any
}

func pathValue(object any, path []any) any {
	for _, part := range path {
		switch key := part.(type) {
		case string:
			object = object.(map[string]any)[key]
		case int:
			object = object.([]any)[key]
		case float64:
			object = object.([]any)[int(key)]
		}
	}
	return object
}

func putPath(object map[string]any, path []any, value any) {
	parent := pathValue(object, path[:len(path)-1])
	switch key := path[len(path)-1].(type) {
	case string:
		parent.(map[string]any)[key] = value
	case int:
		parent.([]any)[key] = value
	}
}

func visitFields(object any, kind string, path []any, set contractSet, visits *[]fieldVisit) {
	*visits = append(*visits, fieldVisit{path, kind, object})
	if strings.HasPrefix(kind, "[]") {
		for index, value := range object.([]any) {
			visitFields(value, kind[2:], append(slices.Clone(path), index), set, visits)
		}
	} else if strings.HasPrefix(kind, "@") {
		for name, fieldType := range set.Structures[kind[1:]].Fields {
			visitFields(object.(map[string]any)[name], fieldType, append(slices.Clone(path), name), set, visits)
		}
	}
}

func fixtureFields(object map[string]any, shape recordShape, set contractSet) []fieldVisit {
	var visits []fieldVisit
	for name, kind := range shape.Fields {
		visitFields(object[name], kind, []any{name}, set, &visits)
	}
	return visits
}

// Claim: every nested type rejects unknown/missing/null at closure before seals, while every re-sealed target passes its independent seal-only control.
func TestLabNestedClosurePairs(test *testing.T) {
	set, fixtures := loadContracts(test)
	covered := map[string]bool{}
	for position, shape := range set.Surfaces {
		fixture := fixtures[position]
		wanted := map[string]bool{}
		typesAtPath := map[string]string{}
		for _, field := range fixtureFields(fixture.Valid, shape, set) {
			if strings.HasPrefix(field.Type, "@") {
				wanted[field.Type[1:]] = true
				path, _ := json.Marshal(field.Path)
				typesAtPath[string(path)] = field.Type
			}
		}
		seen := map[string]bool{}
		for _, negative := range fixture.NestedNegatives {
			name := shape.Format + "/" + negative.Structure + "/" + negative.Mutation
			test.Run(name, func(test *testing.T) {
				if err := checkSealedRecord(canonicalObject(test, fixture.Valid), shape, set); err != nil {
					test.Fatal(err)
				}
				path, _ := json.Marshal(negative.Path)
				if !wanted[negative.Structure] || typesAtPath[string(path)] != "@"+negative.Structure {
					test.Fatal("uninstantiated negative or wrong nested path")
				}
				key := negative.Structure + "/" + negative.Mutation
				if seen[key] {
					test.Fatal("duplicate nested control")
				}
				seen[key] = true
				changed := cloneObject(test, fixture.Valid)
				target := pathValue(changed, negative.Path).(map[string]any)
				if _, required := set.Structures[negative.Structure].Fields[negative.Field]; !required {
					test.Fatal("not a required member")
				}
				switch negative.Mutation {
				case "unknown":
					target["unexpected_field"] = "PUBLIC-UNKNOWN"
				case "missing":
					delete(target, negative.Field)
				case "null":
					target[negative.Field] = nil
				default:
					test.Fatal("unknown mutation")
				}
				resealClosure(test, changed)
				if !bytes.Equal(canonicalObject(test, changed), canonicalObject(test, negative.Record)) {
					test.Fatal("nested vector changed after reseal")
				}
				assertClosureSealControl(test, shape, negative.Record)
				assertClosureRefusal(test, negative.Record, shape, set)
				covered[negative.Structure] = true
			})
		}
		if len(seen) != 3*len(wanted) {
			test.Fatalf("incomplete nested controls: %s", shape.Format)
		}
	}
	if len(covered) != len(set.Structures) {
		test.Fatalf("unexercised nested type: %d/%d", len(covered), len(set.Structures))
	}
}

type grammarPair struct {
	Name    string
	Valid   []any
	Invalid []any
}

func stringValues(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}

func grammarValues(kind string) grammarPair {
	if strings.HasPrefix(kind, "=") {
		text := kind[1:]
		variant := strings.ToUpper(text)
		if variant == text {
			variant = strings.ToLower(text)
		}
		return grammarPair{"singleton", []any{text}, []any{text[:len(text)-1], text + "x", variant, false}}
	}
	if strings.Contains(kind, "|") {
		members := strings.Split(kind, "|")
		invalid := []any{"PUBLIC-OUT-OF-ENUM", false}
		for _, member := range members {
			for _, variant := range []string{strings.ToUpper(member), strings.ToLower(member), member[:len(member)-1], member + "x"} {
				if !slices.Contains(members, variant) {
					invalid = append(invalid, variant)
				}
			}
		}
		return grammarPair{"enum", stringValues(members), invalid}
	}
	maximum := int64(9007199254740991)
	pairs := map[string]grammarPair{
		"id":              {"id", []any{"!", "~", "x", strings.Repeat("x", 128)}, []any{"", strings.Repeat("x", 129), "with space", "line\nfeed", "x\x7f", "é"}},
		"digest":          {"digest", []any{"sha256:" + strings.Repeat("a", 64), "sha256:" + strings.Repeat("0", 64), "sha256:" + strings.Repeat("9", 64), "sha256:" + strings.Repeat("f", 64)}, []any{"sha256:" + strings.Repeat("A", 64), "sha256:" + strings.Repeat("a", 63), "sha256:" + strings.Repeat("a", 65), "sha512:" + strings.Repeat("a", 64), "sha255:" + strings.Repeat("a", 64), "sha257:" + strings.Repeat("a", 64)}},
		"operation":       {"operation", []any{strings.Repeat("a", 32), strings.Repeat("0", 32), strings.Repeat("9", 32), strings.Repeat("f", 32)}, []any{strings.Repeat("a", 31), strings.Repeat("a", 33), strings.Repeat("A", 32)}},
		"uuid":            {"uuid", []any{"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "00000000-0000-0000-0000-000000000000", "99999999-9999-9999-9999-999999999999", "ffffffff-ffff-ffff-ffff-ffffffffffff"}, []any{"AAAAAAAA-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
		"commit":          {"commit", []any{strings.Repeat("a", 40), strings.Repeat("0", 40), strings.Repeat("9", 40), strings.Repeat("f", 40)}, []any{strings.Repeat("A", 40), strings.Repeat("a", 39), strings.Repeat("a", 41)}},
		"material":        {"material", []any{"!", "~", "PUBLIC-SYNTHETIC", strings.Repeat("x", 4096)}, []any{"", strings.Repeat("x", 4097), "with space", "line\nfeed", "x\x7f", "é"}},
		"time":            {"time", []any{"1970-01-01T00:00:00.000000001Z", "2027-01-01T00:00:00Z", "2027-01-01T00:00:00.000000001Z", "9999-12-31T23:59:59.999999999Z"}, []any{"2027-01-01T00:00:00+00:00", "2027-01-01T00:00:00.000Z", "1970-01-01T00:00:00Z", "1969-12-31T23:59:59.999999999Z", "10000-01-01T00:00:00Z", "not-time", false}},
		"bool":            {"boolean", []any{true, false}, []any{"true", int64(1)}},
		"uint":            {"range: uint", []any{int64(0), maximum}, []any{int64(-1), "0"}},
		"positive":        {"range: positive", []any{int64(1), maximum}, []any{int64(0), int64(-1), "1"}},
		"root":            {"range: root", []any{int64(0)}, []any{int64(1), int64(-1), "0"}},
		"lifetime":        {"range: lifetime", []any{int64(1), int64(900)}, []any{int64(0), int64(901), "900"}},
		"alignment":       {"range: alignment", []any{int64(0), int64(2)}, []any{int64(-1), int64(3), "0"}},
		"exit":            {"range: exit", []any{int64(0), int64(255)}, []any{int64(-1), int64(256), "0"}},
		"poll":            {"range: poll", []any{int64(250)}, []any{int64(249), int64(251), "250"}},
		"capture-timeout": {"range: capture-timeout", []any{int64(300)}, []any{int64(299), int64(301), "300"}},
	}
	pair := pairs[kind]
	for _, mutation := range scalarMutations(kind) {
		if mutation.Admit {
			pair.Valid = append(pair.Valid, mutation.Value)
		} else if _, text := mutation.Value.(string); text {
			pair.Invalid = append(pair.Invalid, mutation.Value)
		}
	}
	if slices.Contains([]string{"digest", "operation", "uuid", "commit"}, kind) {
		valid := pair.Valid[0].(string)
		prefix := 0
		if kind == "digest" {
			prefix = len("sha256:")
		}
		for _, outside := range []byte{'/', ':', '`', 'g'} {
			pair.Invalid = append(pair.Invalid, valid[:prefix]+string(outside)+valid[prefix+1:])
		}
		if kind == "uuid" {
			for group := range strings.Split(valid, "-") {
				for _, delta := range []int{-1, 1} {
					groups := strings.Split(valid, "-")
					groups[group] = strings.Repeat("a", len(groups[group])+delta)
					pair.Invalid = append(pair.Invalid, strings.Join(groups, "-"))
				}
			}
		}
	}
	return pair
}

// Claim: every primitive field exercises both length/range/ASCII/hex edges, exact enum case and canonical time beside valid controls; unsafe integers fail the canonical gate.
func TestLabFieldGrammarPairs(test *testing.T) {
	set, fixtures := loadContracts(test)
	for position, shape := range set.Surfaces {
		fixture := fixtures[position]
		for _, field := range fixtureFields(fixture.Valid, shape, set) {
			if strings.HasPrefix(field.Type, "@") || strings.HasPrefix(field.Type, "[]") {
				continue
			}
			test.Run(fmt.Sprint(shape.Format, "/", field.Path), func(test *testing.T) {
				pair := grammarValues(field.Type)
				if len(pair.Valid) == 0 || len(pair.Invalid) == 0 {
					test.Fatalf("uncovered grammar: %s", field.Type)
				}
				for _, value := range pair.Valid {
					changed := cloneObject(test, fixture.Valid)
					putPath(changed, field.Path, value)
					if err := checkRecord(canonicalObject(test, changed), shape, set); err != nil {
						test.Fatalf("valid boundary refused: %v", err)
					}
				}
				if field.Type == "uint" || field.Type == "positive" {
					changed := cloneObject(test, fixture.Valid)
					putPath(changed, field.Path, int64(9007199254740992))
					raw, err := json.Marshal(changed)
					if err != nil {
						test.Fatal(err)
					}
					if err = checkRecord(raw, shape, set); err == nil || err.Error() != "canonical" {
						test.Fatalf("unsafe integer wrong refusal: %v", err)
					}
				}
				for index, value := range pair.Invalid {
					test.Run(fmt.Sprint("invalid-", index), func(test *testing.T) {
						changed := cloneObject(test, fixture.Valid)
						putPath(changed, field.Path, value)
						err := checkRecord(canonicalObject(test, changed), shape, set)
						if err == nil {
							test.Fatalf("invalid %s admitted", field.Type)
						}
						expected := pair.Name
						if strings.HasPrefix(expected, "range:") {
							expected = field.Type
						}
						if !strings.Contains(err.Error(), expected) {
							test.Fatalf("wrong grammar refusal for %s: %v", field.Type, err)
						}
					})
				}
			})
		}
	}
}

// Claim: every frozen payload ceiling permits the exact-size preflight and refuses one byte over specifically for size; canonical full-record controls remain separate.
func TestLabPayloadLimitPairs(test *testing.T) {
	set, fixtures := loadContracts(test)
	for position, shape := range set.Surfaces {
		test.Run(shape.Format, func(test *testing.T) {
			valid := canonicalObject(test, fixtures[position].Valid)
			if err := checkRecord(valid, shape, set); err != nil {
				test.Fatal(err)
			}
			atLimit := append(bytes.Clone(valid), bytes.Repeat([]byte(" "), shape.MaxBytes-len(valid))...)
			if err := checkPayloadSize(atLimit, shape.MaxBytes); err != nil {
				test.Fatalf("exact-size preflight refused: %v", err)
			}
			if err := checkPayloadSize(append(bytes.Clone(atLimit), ' '), shape.MaxBytes); err == nil || err.Error() != "size" {
				test.Fatalf("over-limit wrong refusal: %v", err)
			}
			if err := checkRecord(atLimit, shape, set); err == nil || err.Error() != "canonical" {
				test.Fatalf("exact-size preflight changed: %v", err)
			}
			if err := checkRecord(append(atLimit, ' '), shape, set); err == nil || err.Error() != "size" {
				test.Fatalf("over-limit wrong refusal: %v", err)
			}
		})
	}
}

func exactLimitFixture(test *testing.T, fixture map[string]any, shape recordShape, set contractSet) map[string]any {
	test.Helper()
	record := cloneObject(test, fixture)
	if strings.HasSuffix(shape.Format, "account/1") {
		for _, name := range []string{"hold_ids", "issued_versions"} {
			record[name] = []any{}
			for len(record[name].([]any)) < 256 && len(canonicalObject(test, record)) < shape.MaxBytes {
				record[name] = append(record[name].([]any), strings.Repeat("x", 128))
			}
		}
	} else {
		asset := cloneObject(test, record["assets"].([]any)[0].(map[string]any))
		member := cloneObject(test, asset["members"].([]any)[0].(map[string]any))
		member["path"] = strings.Repeat("x", 128)
		record["assets"] = []any{}
		for len(canonicalObject(test, record)) < shape.MaxBytes {
			item := cloneObject(test, asset)
			item["members"] = []any{}
			record["assets"] = append(record["assets"].([]any), item)
			for len(item["members"].([]any)) < 256 && len(canonicalObject(test, record)) < shape.MaxBytes {
				item["members"] = append(item["members"].([]any), cloneObject(test, member))
			}
		}
	}
	excess := len(canonicalObject(test, record)) - shape.MaxBytes
	if excess < 0 {
		test.Fatal("fixture cannot reach limit")
	}
	for _, field := range fixtureFields(record, shape, set) {
		if field.Type != "id" {
			continue
		}
		value := field.Value.(string)
		removed := min(excess, len(value)-1)
		putPath(record, field.Path, value[:len(value)-removed])
		excess -= removed
		if excess == 0 {
			break
		}
	}
	if len(canonicalObject(test, record)) != shape.MaxBytes {
		test.Fatal("boundary construction failed")
	}
	return record
}

// Claim: account and release records admit exact 65536/262144-byte controls and refuse one extra byte without relaxing field or array bounds.
func TestLabExactLimitRecordPairs(test *testing.T) {
	set, fixtures := loadContracts(test)
	for position, shape := range set.Surfaces {
		if shape.Format != "swarma-broker-lab-account/1" && shape.Format != "swarma-lab-release-set/1" {
			continue
		}
		test.Run(shape.Format, func(test *testing.T) {
			data := canonicalObject(test, exactLimitFixture(test, fixtures[position].Valid, shape, set))
			if err := checkRecord(data, shape, set); err != nil {
				test.Fatalf("exact-limit valid record refused: %v", err)
			}
			if err := checkRecord(append(data, ' '), shape, set); err == nil || err.Error() != "size" {
				test.Fatalf("one byte over admitted: %v", err)
			}
		})
	}
}

// Claim: a full record admits 256 array members and refuses 257 specifically for the array bound, beside a wrong-container-type refusal.
func TestLabArrayLimitPairs(test *testing.T) {
	set, fixtures := loadContracts(test)
	for position, shape := range set.Surfaces {
		if shape.Format != "swarma-broker-lab-account/1" {
			continue
		}
		record := cloneObject(test, fixtures[position].Valid)
		items := make([]any, 256)
		for index := range items {
			items[index] = "public-id"
		}
		record["issued_versions"] = items
		if err := checkRecord(canonicalObject(test, record), shape, set); err != nil {
			test.Fatal(err)
		}
		for _, invalid := range []any{append(items, "public-id"), "not-array"} {
			record["issued_versions"] = invalid
			if err := checkRecord(canonicalObject(test, record), shape, set); err == nil || !strings.Contains(err.Error(), "array") {
				test.Fatalf("array bound/type wrong refusal: %v", err)
			}
		}
		return
	}
	test.Fatal("missing account")
}

func principalsDisjoint(gateway, caller map[string]any) bool {
	return gateway["uid"] != caller["uid"] && gateway["generation"] != caller["generation"] && gateway["execution_id"] != caller["execution_id"] && gateway["kind"] == "service" && caller["kind"] == "worker"
}

// Claim: authority, lease and journal pairs require disjoint UID/generation/execution and service/worker kinds; shared tuple components and each single-side or jointly swapped kind refuse beside valid pairs.
func TestLabPrincipalDisjointPairs(test *testing.T) {
	_, fixtures := loadContracts(test)
	count := 0
	for _, fixture := range fixtures {
		records := []map[string]any{fixture.Valid}
		if fixture.Surface == "swarma-broker-lab-service-journal/1" {
			records = append(records, fixture.Valid["bindings"].([]any)[0].(map[string]any))
		}
		for _, record := range records {
			gateway, exists := record["gateway"].(map[string]any)
			if !exists {
				continue
			}
			caller, exists := record["caller"].(map[string]any)
			if !exists {
				caller = record["worker"].(map[string]any)
			}
			test.Run(fixture.Surface, func(test *testing.T) {
				if !principalsDisjoint(gateway, caller) {
					test.Fatal("valid principal pair refused")
				}
				for _, principal := range []string{"gateway", "caller"} {
					test.Run("wrong-kind-"+principal, func(test *testing.T) {
						changedGateway := cloneObject(test, gateway)
						changedCaller := cloneObject(test, caller)
						if principal == "gateway" {
							changedGateway["kind"] = "worker"
						} else {
							changedCaller["kind"] = "service"
						}
						if principalsDisjoint(changedGateway, changedCaller) {
							test.Fatalf("wrong %s kind admitted", principal)
						}
					})
				}
				test.Run("swapped-kinds", func(test *testing.T) {
					changedGateway := cloneObject(test, gateway)
					changedCaller := cloneObject(test, caller)
					changedGateway["kind"], changedCaller["kind"] = caller["kind"], gateway["kind"]
					if principalsDisjoint(changedGateway, changedCaller) {
						test.Fatal("swapped kinds admitted")
					}
				})
				for _, name := range []string{"uid", "generation", "execution_id"} {
					changed := cloneObject(test, caller)
					changed[name] = gateway[name]
					if principalsDisjoint(gateway, changed) {
						test.Fatalf("shared %s admitted", name)
					}
				}
			})
			count++
		}
	}
	if count != 3 {
		test.Fatal("principal pair inventory")
	}
}

func timingTextAgrees(profile, contract string) bool {
	return strings.Contains(profile, "250 ms cadence + **200 ms RPC timeout**") && strings.Contains(contract, "every 250 ms use a 200 ms RPC")
}

// Claim: C0's frozen cadence/RPC text agrees with the design's 190 ms valid-control budget; the old 100 ms contradiction refuses, without claiming native timing qualification.
func TestLabTimingContractPairs(test *testing.T) {
	profile, err := os.ReadFile("../../docs/lab-profile-v0.md")
	if err != nil {
		test.Fatal(err)
	}
	contract := string(readContract(test, "README.md"))
	if !timingTextAgrees(string(profile), contract) {
		test.Fatal("design/C0 timeout mismatch")
	}
	if timingTextAgrees(string(profile), strings.Replace(contract, "200 ms RPC", "100 ms RPC", 1)) {
		test.Fatal("old timeout contradiction admitted")
	}
}
