//go:build linux && broker_lab

package labcontract

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

//go:embed surfaces.json
var externalInventory []byte

//go:embed recovery-surfaces.json
var privateInventory []byte

type Shape struct {
	Format   string            `json:"format"`
	MaxBytes int               `json:"max_bytes"`
	Fields   map[string]string `json:"fields"`
}

type inventory struct {
	Structures map[string]Shape `json:"structures"`
	Surfaces   []Shape          `json:"surfaces"`
}

var shapes, structures = loadInventory()

func loadInventory() (map[string]Shape, map[string]Shape) {
	surfaces, nested := map[string]Shape{}, map[string]Shape{}
	for _, raw := range [][]byte{externalInventory, privateInventory} {
		var document inventory
		if json.Unmarshal(raw, &document) != nil {
			panic("invalid lab contract inventory")
		}
		for name, shape := range document.Structures {
			if _, exists := nested[name]; exists {
				panic("duplicate lab structure")
			}
			nested[name] = shape
		}
		for _, shape := range document.Surfaces {
			if _, exists := surfaces[shape.Format]; exists {
				panic("duplicate lab format")
			}
			surfaces[shape.Format] = shape
		}
	}
	return surfaces, nested
}

func Read(format string, raw []byte) (map[string]any, error) {
	if format == "swarma-broker-lab-service-recovery/1" {
		return nil, fmt.Errorf("private_recovery")
	}
	return read(format, raw)
}

func ReadRecovery(raw []byte) (map[string]any, error) {
	return read("swarma-broker-lab-service-recovery/1", raw)
}

func read(format string, raw []byte) (map[string]any, error) {
	shape, exists := shapes[format]
	if !exists || len(raw) > shape.MaxBytes {
		return nil, fmt.Errorf("size_or_format")
	}
	object, err := wire.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("canonical")
	}
	if err = fields(object, shape); err != nil {
		return nil, err
	}
	return object, nil
}

func fields(object map[string]any, shape Shape) error {
	if len(object) != len(shape.Fields) {
		return fmt.Errorf("field_set")
	}
	for name, grammar := range shape.Fields {
		value, present := object[name]
		if !present || value == nil {
			return fmt.Errorf("field_set")
		}
		if err := field(value, grammar); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

var patterns = map[string]*regexp.Regexp{
	"id":        regexp.MustCompile(`^[\x21-\x7e]{1,128}$`),
	"digest":    regexp.MustCompile(`^sha256:[0-9a-f]{64}$`),
	"operation": regexp.MustCompile(`^[0-9a-f]{32}$`),
	"uuid":      regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
	"commit":    regexp.MustCompile(`^[0-9a-f]{40}$`),
	"material":  regexp.MustCompile(`^[\x21-\x7e]+$`),
}

func field(value any, grammar string) error {
	if strings.HasPrefix(grammar, "[]") {
		items, ok := value.([]any)
		if !ok || len(items) > 256 {
			return fmt.Errorf("array")
		}
		for _, item := range items {
			if err := field(item, grammar[2:]); err != nil {
				return err
			}
		}
		return nil
	}
	if strings.HasPrefix(grammar, "@") {
		object, ok := value.(map[string]any)
		shape, exists := structures[grammar[1:]]
		if !ok || !exists {
			return fmt.Errorf("structure")
		}
		return fields(object, shape)
	}
	if strings.HasPrefix(grammar, "=") {
		if value != grammar[1:] {
			return fmt.Errorf("singleton")
		}
		return nil
	}
	if strings.Contains(grammar, "|") {
		text, ok := value.(string)
		if !ok || !slices.Contains(strings.Split(grammar, "|"), text) {
			return fmt.Errorf("enum")
		}
		return nil
	}
	if pattern, exists := patterns[grammar]; exists {
		text, ok := value.(string)
		if !ok || grammar == "material" && len(text) > 4096 || !pattern.MatchString(text) {
			return fmt.Errorf("%s", grammar)
		}
		return nil
	}
	if grammar == "bool" {
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("boolean")
		}
		return nil
	}
	if grammar == "time" {
		text, ok := value.(string)
		instant, err := time.Parse(time.RFC3339Nano, text)
		if !ok || err != nil || instant.UTC().Format(time.RFC3339Nano) != text || !instant.After(time.Unix(0, 0)) {
			return fmt.Errorf("time")
		}
		return nil
	}
	minimum, maximum := int64(0), int64(9007199254740991)
	switch grammar {
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
		return fmt.Errorf("unknown_grammar")
	}
	number, ok := value.(int64)
	if !ok || number < minimum || number > maximum {
		return fmt.Errorf("range")
	}
	return nil
}

func Equal(left, right any) bool {
	first, err := wire.Encode(left)
	second, other := wire.Encode(right)
	return err == nil && other == nil && bytes.Equal(first, second)
}
