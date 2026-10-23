//go:build linux

package authowner

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/store"
)

type material struct {
	Token, Account, Digest string
	Expires                time.Time
}

// HomeIdentity pins the protected directory created by explicit enrolment. It
// does not adopt credentials, validate freshness or repair an absent directory.
func HomeIdentity(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", ErrUnavailable
	}
	st, e := os.Lstat(path)
	if e != nil || st.Mode() != os.ModeDir|0700 {
		return "", ErrUnavailable
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || s.Uid != uint32(os.Geteuid()) {
		return "", ErrUnavailable
	}
	b, _ := json.Marshal([]uint64{uint64(s.Dev), s.Ino, uint64(s.Uid)})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
func load(c AccountConfig, flush bool) (material, error) {
	var out material
	home, e := HomeIdentity(c.Home)
	if e != nil || home != c.HomeID {
		return out, ErrUnavailable
	}
	path := filepath.Join(c.Home, "auth.json")
	b, e := store.ReadProtected(path, uint32(os.Geteuid()))
	if e != nil {
		return out, ErrUnavailable
	}
	var a struct {
		Mode   string  `json:"auth_mode"`
		APIKey *string `json:"OPENAI_API_KEY"`
		Tokens struct {
			Access  string `json:"access_token"`
			Refresh string `json:"refresh_token"`
			Account string `json:"account_id"`
		} `json:"tokens"`
	}
	if json.Unmarshal(b, &a) != nil || a.APIKey != nil || a.Mode != "chatgpt" || a.Tokens.Account != c.VendorID || a.Tokens.Access == "" || a.Tokens.Refresh == "" {
		return out, ErrUnavailable
	}
	parts := strings.Split(a.Tokens.Access, ".")
	if len(parts) != 3 {
		return out, ErrUnavailable
	}
	payload, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil {
		return out, ErrUnavailable
	}
	var claims struct {
		Exp  int64 `json:"exp"`
		Auth struct {
			Account string `json:"chatgpt_account_id"`
		} `json:"https://api.openai.com/auth"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Exp <= 0 || claims.Auth.Account != c.VendorID {
		return out, ErrUnavailable
	}
	// JWT claims here provide conservative bounds on vendor-supplied material;
	// they are not a signature or independent qualification/freshness check.
	if flush {
		f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if e != nil {
			return out, ErrUnavailable
		}
		e = f.Sync()
		f.Close()
		if e != nil {
			return out, ErrUnavailable
		}
		d, e := os.Open(c.Home)
		if e != nil {
			return out, ErrUnavailable
		}
		e = d.Sync()
		d.Close()
		if e != nil {
			return out, ErrUnavailable
		}
		current, e := store.ReadProtected(path, uint32(os.Geteuid()))
		if e != nil || string(current) != string(b) {
			return out, ErrUnavailable
		}
	}
	h := sha256.Sum256(b)
	return material{a.Tokens.Access, a.Tokens.Account, hex.EncodeToString(h[:]), time.Unix(claims.Exp, 0).UTC()}, nil
}

type rpcResult struct {
	Outcome Disposition
	Plan    string
}

// managed performs no OAuth exchange. Only the approved vendor receives this
// bounded, token-free request sequence; response message/data is discarded.
func managed(ctx context.Context, r *os.File, w *os.File, classifier Classifier) rpcResult {
	deadline, ok := ctx.Deadline()
	if !ok {
		return rpcResult{Outcome: Unknown}
	}
	if r.SetReadDeadline(deadline) != nil || w.SetWriteDeadline(deadline) != nil {
		return rpcResult{Outcome: Unknown}
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { r.SetReadDeadline(time.Now()); w.SetWriteDeadline(time.Now()); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
	}()
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	write := func(v any) bool {
		b, e := json.Marshal(v)
		if e != nil {
			return false
		}
		b = append(b, '\n')
		_, e = w.Write(b)
		return e == nil
	}
	read := func(id int) (json.RawMessage, *RPCError, bool) {
		for scanner.Scan() {
			var v struct {
				ID     *int            `json:"id"`
				Method string          `json:"method"`
				Result json.RawMessage `json:"result"`
				Error  *struct {
					Code int `json:"code"`
				} `json:"error"`
			}
			if json.Unmarshal(scanner.Bytes(), &v) != nil {
				return nil, nil, false
			}
			if v.ID == nil {
				if v.Method != "" {
					continue
				}
				return nil, nil, false
			}
			if *v.ID != id || (len(v.Result) > 0) == (v.Error != nil) {
				return nil, nil, false
			}
			if v.Error != nil {
				return nil, &RPCError{v.Error.Code}, true
			}
			return v.Result, nil, true
		}
		return nil, nil, false
	}
	if !write(map[string]any{"id": 1, "method": "initialize", "params": map[string]any{"clientInfo": map[string]string{"name": "credential-broker", "version": "0"}, "capabilities": map[string]bool{"experimentalApi": false}}}) {
		return rpcResult{Outcome: Unknown}
	}
	if _, rpc, ok := read(1); !ok || rpc != nil {
		return rpcResult{Outcome: Unknown}
	}
	if !write(map[string]any{"method": "initialized"}) || !write(map[string]any{"id": 2, "method": "account/read", "params": map[string]bool{"refreshToken": true}}) {
		return rpcResult{Outcome: Unknown}
	}
	result, rpc, ok := read(2)
	if !ok {
		return rpcResult{Outcome: Unknown}
	}
	if rpc != nil {
		if classifier != nil {
			d := classifier.Classify(*rpc)
			if d == Safe || d == Rejected {
				return rpcResult{Outcome: d}
			}
		}
		return rpcResult{Outcome: Unknown}
	}
	var v struct {
		Requires *bool `json:"requiresOpenaiAuth"`
		Account  *struct {
			Type string `json:"type"`
			Plan string `json:"planType"`
		} `json:"account"`
	}
	if json.Unmarshal(result, &v) != nil || v.Requires == nil || !*v.Requires || v.Account == nil || v.Account.Type != "chatgpt" || !validPlan(v.Account.Plan) {
		return rpcResult{Outcome: Unknown}
	}
	return rpcResult{Committed, v.Account.Plan}
}

func validPlan(plan string) bool {
	switch plan {
	case "free", "go", "plus", "pro", "prolite", "promax", "team", "self_serve_business_prolite", "self_serve_business_usage_based", "business", "ent26", "enterprise_cbp_automation", "enterprise_cbp_usage_based", "enterprise", "edu", "edu_plus", "edu_pro", "unknown":
		return true
	}
	return false
}

func digestToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
