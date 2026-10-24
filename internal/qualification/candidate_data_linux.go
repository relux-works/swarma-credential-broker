//go:build linux

package qualification

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"
)

// canonicalJSON preserves JSON number lexemes, orders object keys, removes
// insignificant whitespace and rejects invalid Unicode escapes, duplicate keys,
// trailing values and excessive nesting. Array order is preserved.
func canonicalJSON(raw []byte) ([]byte, error) {
	if !utf8.Valid(raw) || !validJSONEscapes(raw) {
		return nil, ErrUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, e := jsonValue(d, 0)
	if e != nil {
		return nil, ErrUnavailable
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, ErrUnavailable
	}
	if _, ok := v.(map[string]any); !ok {
		return nil, ErrUnavailable
	}
	return json.Marshal(v)
}

// encoding/json replaces unpaired surrogate escapes before returning tokens.
// Check the original string bytes first, including object keys. Other JSON
// syntax is still checked by the decoder; escaped backslashes are skipped so
// literal text such as "\\ud800" is not mistaken for a Unicode escape.
func validJSONEscapes(raw []byte) bool {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '"' {
			continue
		}
		i++
		for i < len(raw) && raw[i] != '"' {
			if raw[i] != '\\' {
				i++
				continue
			}
			i++
			if i >= len(raw) {
				return false
			}
			if raw[i] == 'u' {
				if i+4 >= len(raw) {
					return false
				}
				n, e := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
				if e != nil {
					return false
				}
				i += 4
				if n >= 0xd800 && n <= 0xdbff {
					if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
						return false
					}
					low, e := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
					if e != nil || low < 0xdc00 || low > 0xdfff {
						return false
					}
					i += 6
				} else if n >= 0xdc00 && n <= 0xdfff {
					return false
				}
			}
			i++
		}
		if i >= len(raw) {
			return false
		}
	}
	return true
}

func jsonValue(d *json.Decoder, depth int) (any, error) {
	if depth > 128 {
		return nil, ErrUnavailable
	}
	t, e := d.Token()
	if e != nil {
		return nil, e
	}
	if delim, ok := t.(json.Delim); ok {
		switch delim {
		case '{':
			m := map[string]any{}
			for d.More() {
				k, e := d.Token()
				s, ok := k.(string)
				if e != nil || !ok {
					return nil, ErrUnavailable
				}
				if _, exists := m[s]; exists {
					return nil, ErrUnavailable
				}
				v, e := jsonValue(d, depth+1)
				if e != nil {
					return nil, e
				}
				m[s] = v
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return nil, ErrUnavailable
			}
			return m, nil
		case '[':
			a := []any{}
			for d.More() {
				v, e := jsonValue(d, depth+1)
				if e != nil {
					return nil, e
				}
				a = append(a, v)
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return nil, ErrUnavailable
			}
			return a, nil
		default:
			return nil, ErrUnavailable
		}
	}
	return t, nil
}
func schemaDirectory(ctx context.Context, root string) ([]byte, error) {
	files := map[string]json.RawMessage{}
	total, entries := 0, 0
	var walk func(string, int) error
	walk = func(dir string, depth int) error {
		if ctx.Err() != nil || depth > 32 {
			return ErrUnavailable
		}
		directory, e := os.OpenFile(dir, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY|syscall.O_NONBLOCK, 0)
		if e != nil {
			return ErrUnavailable
		}
		defer directory.Close()
		for {
			batch, readErr := directory.ReadDir(64)
			if readErr != nil && readErr != io.EOF {
				return ErrUnavailable
			}
			for _, entry := range batch {
				entries++
				if ctx.Err() != nil || entries > 8192 {
					return ErrUnavailable
				}
				path := filepath.Join(dir, entry.Name())
				if entry.IsDir() {
					if e := walk(path, depth+1); e != nil {
						return e
					}
					continue
				}
				if len(files) >= 2048 || entry.Type()&os.ModeSymlink != 0 || !strings.HasSuffix(entry.Name(), ".json") {
					return ErrUnavailable
				}
				if e := func() error {
					f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
					if e != nil {
						return ErrUnavailable
					}
					defer f.Close()
					s, e := f.Stat()
					if e != nil || !s.Mode().IsRegular() {
						return ErrUnavailable
					}
					st, ok := s.Sys().(*syscall.Stat_t)
					if !ok || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) {
						return ErrUnavailable
					}
					b, e := boundedRead(f, 8<<20)
					if e != nil {
						return e
					}
					total += len(b)
					if total > 32<<20 {
						return ErrUnavailable
					}
					b, e = canonicalJSON(b)
					if e != nil {
						return e
					}
					rel, e := filepath.Rel(root, path)
					if e != nil {
						return e
					}
					files[filepath.ToSlash(rel)] = b
					return nil
				}(); e != nil {
					return e
				}
			}
			if readErr == io.EOF {
				return nil
			}
		}
	}
	if walk(root, 0) != nil || ctx.Err() != nil || len(files) == 0 {
		return nil, ErrUnavailable
	}
	return json.Marshal(files)
}

func (o NativeObserver) Catalog(ctx context.Context) (Measurement, Catalog, error) {
	if _, e := o.Version(ctx); e != nil {
		return Measurement{}, Catalog{}, ErrUnavailable
	}
	r, e := o.candidate(ctx, "catalog/1", []string{"app-server", "--listen", "stdio://", "-c", `cli_auth_credentials_store="ephemeral"`}, 4<<20, catalogExchange)
	if e != nil {
		return Measurement{}, Catalog{}, ErrUnavailable
	}
	var c Catalog
	if json.Unmarshal(r.stdout, &c) != nil || len(c.Models) == 0 {
		return Measurement{}, Catalog{}, ErrUnavailable
	}
	b, e := wire.Encode(c)
	if e != nil {
		return Measurement{}, Catalog{}, ErrUnavailable
	}
	return measure("catalog", b), c, nil
}

func catalogExchange(ctx context.Context, in, out *os.File) ([]byte, error) {
	defer in.Close()
	scanner := bufio.NewScanner(out)
	scanner.Buffer(make([]byte, 4096), 4<<20)
	total := 0
	messages := 0
	// Every frame, including shutdown output, consumes this same budget.
	nextFrame := func() ([]byte, error) {
		if ctx.Err() != nil {
			return nil, ErrUnavailable
		}
		if !scanner.Scan() {
			if scanner.Err() != nil {
				return nil, ErrUnavailable
			}
			return nil, io.EOF
		}
		total += len(scanner.Bytes())
		messages++
		if total > 8<<20 || messages > 128 || ctx.Err() != nil {
			return nil, ErrUnavailable
		}
		return scanner.Bytes(), nil
	}
	send := func(v any) error {
		b, e := json.Marshal(v)
		if e != nil {
			return e
		}
		_, e = in.Write(append(b, '\n'))
		return e
	}
	receive := func(id int) (json.RawMessage, error) {
		for {
			raw, e := nextFrame()
			if e != nil {
				return nil, ErrUnavailable
			}
			b, e := canonicalJSON(raw)
			if e != nil {
				return nil, e
			}
			var m struct {
				ID     *int            `json:"id"`
				Method string          `json:"method"`
				Result json.RawMessage `json:"result"`
				Error  json.RawMessage `json:"error"`
			}
			if json.Unmarshal(b, &m) != nil {
				return nil, ErrUnavailable
			}
			if m.Method != "" {
				if m.ID != nil {
					return nil, ErrUnavailable
				}
				continue
			}
			if m.ID == nil || *m.ID != id || len(m.Error) > 0 || len(m.Result) == 0 {
				return nil, ErrUnavailable
			}
			return m.Result, nil
		}
	}
	if send(map[string]any{"id": 1, "method": "initialize", "params": map[string]any{"clientInfo": map[string]string{"name": "credential_broker_qualification", "version": "1"}, "capabilities": map[string]bool{"experimentalApi": true}}}) != nil {
		return nil, ErrUnavailable
	}
	if _, e := receive(1); e != nil {
		return nil, e
	}
	if send(map[string]any{"method": "initialized", "params": map[string]any{}}) != nil {
		return nil, ErrUnavailable
	}
	catalog := Catalog{Models: []Model{}}
	seen := map[string]bool{}
	cursors := map[string]bool{}
	var cursor *string
	for page := 0; page < 16; page++ {
		id := page + 2
		if send(map[string]any{"id": id, "method": "model/list", "params": map[string]any{"cursor": cursor, "limit": 100, "includeHidden": true}}) != nil {
			return nil, ErrUnavailable
		}
		raw, e := receive(id)
		if e != nil {
			return nil, e
		}
		var result struct {
			Data []struct {
				Model   string `json:"model"`
				Efforts []struct {
					Effort string `json:"reasoningEffort"`
				} `json:"supportedReasoningEfforts"`
			} `json:"data"`
			Next *string `json:"nextCursor"`
		}
		if json.Unmarshal(raw, &result) != nil || result.Data == nil {
			return nil, ErrUnavailable
		}
		for _, m := range result.Data {
			if m.Model == "" || len(m.Model) > 256 || seen[m.Model] || len(m.Efforts) == 0 || len(m.Efforts) > 32 || len(catalog.Models) >= 1024 {
				return nil, ErrUnavailable
			}
			seen[m.Model] = true
			efforts := []string{}
			es := map[string]bool{}
			for _, v := range m.Efforts {
				if v.Effort == "" || len(v.Effort) > 64 || es[v.Effort] {
					return nil, ErrUnavailable
				}
				es[v.Effort] = true
				efforts = append(efforts, v.Effort)
			}
			sort.Strings(efforts)
			catalog.Models = append(catalog.Models, Model{m.Model, efforts})
		}
		if result.Next == nil {
			if len(catalog.Models) == 0 {
				return nil, ErrUnavailable
			}
			sort.Slice(catalog.Models, func(i, j int) bool { return catalog.Models[i].Name < catalog.Models[j].Name })
			in.Close()
			// Drain only bounded shutdown output, so a leftover writer cannot hide
			// an unbounded stream or strand the collector after the response.
			for {
				_, e := nextFrame()
				if e == io.EOF {
					return json.Marshal(catalog)
				}
				if e != nil {
					return nil, e
				}
			}
		}
		if *result.Next == "" || len(*result.Next) > 1024 || cursors[*result.Next] {
			return nil, ErrUnavailable
		}
		cursors[*result.Next] = true
		cursor = result.Next
	}
	return nil, ErrUnavailable
}
