//go:build linux

package qualification

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"
)

// canonicalJSON preserves JSON number lexemes, orders object keys, removes
// insignificant whitespace and rejects duplicate keys, trailing values and
// excessive nesting. Array order is significant and is preserved.
func canonicalJSON(raw []byte) ([]byte, error) {
	if !utf8.Valid(raw) {
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
func schemaDirectory(root string) ([]byte, error) {
	files := map[string]json.RawMessage{}
	total := 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return ErrUnavailable
		}
		if entry.IsDir() {
			return nil
		}
		if len(files) >= 2048 || entry.Type()&os.ModeSymlink != 0 || !strings.HasSuffix(entry.Name(), ".json") {
			return ErrUnavailable
		}
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
	})
	if err != nil || len(files) == 0 {
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
	send := func(v any) error {
		b, e := json.Marshal(v)
		if e != nil {
			return e
		}
		_, e = in.Write(append(b, '\n'))
		return e
	}
	receive := func(id int) (json.RawMessage, error) {
		for scanner.Scan() {
			total += len(scanner.Bytes())
			messages++
			if total > 8<<20 || messages > 128 || ctx.Err() != nil {
				return nil, ErrUnavailable
			}
			b, e := canonicalJSON(scanner.Bytes())
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
		return nil, ErrUnavailable
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
			for scanner.Scan() {
				total += len(scanner.Bytes())
				if total > 8<<20 {
					return nil, ErrUnavailable
				}
			}
			if scanner.Err() != nil {
				return nil, ErrUnavailable
			}
			return json.Marshal(catalog)
		}
		if *result.Next == "" || len(*result.Next) > 1024 || cursors[*result.Next] {
			return nil, ErrUnavailable
		}
		cursors[*result.Next] = true
		cursor = result.Next
	}
	return nil, ErrUnavailable
}
