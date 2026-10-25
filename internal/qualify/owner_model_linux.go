//go:build linux

package qualify

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/authowner"
	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/store"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

func ownerAccountPath(root string) string {
	return filepath.Join(root, "metadata", "account-"+qualificationHash([]byte(ownerLabel)))
}
func ownerMaterial(now time.Time, which string) ([]byte, string) {
	claims, _ := wire.Encode(map[string]any{"exp": now.Add(time.Hour).Unix(), "sub": "synthetic-" + which, "https://api.openai.com/auth": map[string]string{"chatgpt_account_id": "synthetic-vendor"}})
	token := "synthetic." + base64.RawURLEncoding.EncodeToString(claims) + ".fixture"
	b, _ := wire.Encode(map[string]any{"auth_mode": "chatgpt", "tokens": map[string]any{"access_token": token, "refresh_token": "synthetic-refresh", "id_token": "synthetic-id", "account_id": "synthetic-vendor"}})
	return b, token
}
func ownerWriteNative(root string, b []byte) error {
	path := filepath.Join(root, "home", "auth.json")
	f, e := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	d, x := os.Open(filepath.Dir(path))
	if x != nil {
		return errors.Join(e, x)
	}
	return errors.Join(e, d.Sync(), d.Close())
}

// ownerSeed creates only a new synthetic root. It never repairs an epoch.
func ownerSeed(root, digest, scenario string) (c ownerContext, tokens [2]string, err error) {
	c = ownerContext{Root: root, Candidate: digest, Scenario: scenario, Now: time.Now().UTC().Truncate(time.Second), Epoch: 1, Parent: os.Getpid()}
	if err = os.Mkdir(filepath.Join(root, "home"), 0700); err != nil {
		return
	}
	var b []byte
	b, tokens[0] = ownerMaterial(c.Now, "initial")
	_, tokens[1] = ownerMaterial(c.Now, "replacement")
	if err = ownerWriteNative(root, b); err != nil {
		return
	}
	c.HomeID, err = authowner.HomeIdentity(filepath.Join(root, "home"))
	if err != nil {
		return
	}
	s, e := store.Open(filepath.Join(root, "metadata"), "synthetic-install", uint32(os.Geteuid()), true, nil)
	if e != nil {
		return c, tokens, e
	}
	defer s.Close()
	if err = s.PolicyGeneration(1, true); err != nil {
		return
	}
	disk, e := s.Account(ownerLabel, true)
	if e != nil {
		return c, tokens, e
	}
	cp := authowner.Checkpoint{Kind: "account-checkpoint/1", Installation: "synthetic-install", Revision: 1, Account: ownerLabel, VendorID: "synthetic-vendor", HomeID: c.HomeID, State: "active", StoreGeneration: 1, TokenGeneration: 1, Policy: 1, Watermark: c.Now, StoreDigest: qualificationHash(b), TokenDigest: lease.Digest(tokens[0]), Plan: "plus"}
	err = disk.Put("owner-checkpoint.json", 0, cp)
	return
}
func ownerRecords(root string) (cp authowner.Checkpoint, intents []authowner.Intent, evidence []authowner.Evidence, err error) {
	dir := ownerAccountPath(root)
	entries, e := os.ReadDir(dir)
	if e != nil {
		err = e
		return
	}
	if len(entries) > 16 {
		err = errors.New("owner record budget")
		return
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "owner-") {
			continue
		}
		b, e := store.ReadProtected(filepath.Join(dir, entry.Name()), uint32(os.Geteuid()))
		if e != nil || len(b) > 16384 {
			err = errors.New("owner record unreadable")
			return
		}
		if entry.Name() == "owner-checkpoint.json" {
			err = ownerDecodeRecord(b, &cp)
		} else if strings.HasSuffix(entry.Name(), "-000001.json") {
			var v authowner.Intent
			err = ownerDecodeRecord(b, &v)
			intents = append(intents, v)
		} else {
			var v authowner.Evidence
			err = ownerDecodeRecord(b, &v)
			evidence = append(evidence, v)
		}
		if err != nil {
			return
		}
	}
	return
}

type ownerStopFact struct {
	Before, After authowner.Observation
	Error         string
}
type ownerModel struct {
	inputs                []ownerStopFact
	c                     ownerContext
	mode                  string
	starts, native, stops int
	before                authowner.Observation
	lastStop              authowner.Observation
	stopError             string
	attempt               string
}

func (m *ownerModel) identity() authowner.Identity {
	v := authowner.Identity{Boot: "synthetic-boot", UID: uint32(os.Geteuid()), Epoch: "synthetic-epoch"}
	if m.c.Epoch == 2 {
		if m.mode == "boot" {
			v.Boot += "-changed"
		}
		if m.mode == "epoch" {
			v.Epoch += "-changed"
		}
	}
	return v
}
func (m *ownerModel) serve(ch *ownerChannel, req ownerMessage) error {
	var result any
	var refusal error
	switch req.Op {
	case "ready", "owned", "unload":
	case "identity":
		result = m.identity()
	case "confidence":
		var v struct {
			Label, Home string
			Generation  uint64
			Lower       time.Time
		}
		if wire.Decode(req.Data, &v) != nil || v.Label != ownerLabel || v.Home != m.c.HomeID || v.Generation < 1 || v.Generation > 2 || v.Lower.After(m.c.Now) {
			return errors.New("confidence premise binding")
		}
		result = authowner.TimeEvidence{Now: m.c.Now, AuthorityUntil: m.c.Now.Add(time.Minute), Trusted: true, Fresh: true}
	case "start":
		m.starts++ // Count every attempt before deciding whether it is permitted.
		if m.starts != 1 {
			return errors.New("unexpected model start")
		}
		var s struct {
			Name, Daemon, Executable, Home, Digest string
			Args, Environment                      []string
			Runtime                                time.Duration
		}
		cp, intents, _, e := ownerRecords(m.c.Root)
		if wire.Decode(req.Data, &s) != nil || e != nil || len(intents) != 1 || cp.PendingAttempt != intents[0].Attempt || cp.State != "owner_unavailable" || s.Name != intents[0].Unit || s.Daemon != "synthetic-owner.service" || s.Executable != "/proc/self/fd/6" || s.Digest != m.c.Candidate || s.Home != filepath.Join(m.c.Root, "home") || strings.Join(s.Args, " ") != "app-server" || s.Runtime != 120*time.Second || strings.Join(s.Environment, "\x00") != strings.Join([]string{"HOME=" + s.Home, "CODEX_HOME=" + s.Home, "LANG=C.UTF-8", "PATH=/usr/bin:/bin"}, "\x00") {
			return fmt.Errorf("model start missing durable binding: records=%v count=%d state=%s spec-valid=%v", e, len(intents), cp.State, []bool{s.Daemon == "synthetic-owner.service", s.Executable == "/proc/self/fd/6", s.Digest == m.c.Candidate, s.Home == filepath.Join(m.c.Root, "home"), strings.Join(s.Args, " ") == "app-server", s.Runtime == 120*time.Second, strings.Join(s.Environment, "\x00") == strings.Join([]string{"HOME=" + s.Home, "CODEX_HOME=" + s.Home, "LANG=C.UTF-8", "PATH=/usr/bin:/bin"}, "\x00")})
		}
		m.attempt = intents[0].Attempt
		m.before = authowner.Observation{Identity: m.identity(), Unit: s.Name, Invocation: "synthetic-invocation", Cgroup: "/synthetic-writer", CgroupID: "synthetic-cgroup", MainPID: 42, ProcessStart: 1, Properties: "synthetic-properties", Active: "active", Substate: "running", Complete: true, RestartNo: true, Observed: m.c.Now}
	case "observe":
		var name string
		if wire.Decode(req.Data, &name) != nil || name != m.before.Unit {
			return errors.New("model observe binding")
		}
		result = m.before
	case "native":
		m.native++
		var v struct {
			ID     int             `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if json.Unmarshal(req.Data, &v) != nil {
			return errors.New("native protocol")
		}
		switch m.native {
		case 1:
			if v.ID != 1 || v.Method != "initialize" || !strings.Contains(string(v.Params), `"experimentalApi":false`) {
				return errors.New("native initialize")
			}
			result = json.RawMessage(`{"id":1,"result":{}}`)
		case 2:
			if v.Method != "initialized" || v.ID != 0 {
				return errors.New("native initialized")
			}
			result = json.RawMessage("null")
		case 3:
			if v.ID != 2 || v.Method != "account/read" || string(v.Params) != `{"refreshToken":true}` {
				return errors.New("native refresh")
			}
			b, _ := ownerMaterial(m.c.Now, "replacement")
			if e := ownerWriteNative(m.c.Root, b); e != nil {
				return e
			}
			result = json.RawMessage(`{"id":2,"result":{"requiresOpenaiAuth":true,"account":{"type":"chatgpt","planType":"plus"}}}`)
		default:
			return errors.New("native protocol budget")
		}
	case "stop":
		m.stops++
		var before authowner.Observation
		if wire.Decode(req.Data, &before) != nil || before != m.before || m.native != 3 || m.stops > 2 {
			return errors.New("model stop binding")
		}
		cp, intents, events, e := ownerRecords(m.c.Root)
		if e != nil || len(intents) != 1 || intents[0].Attempt != m.attempt || cp.PendingAttempt != m.attempt || len(events) < 3 || events[len(events)-1].Phase != "stopping" || events[len(events)-1].RPC != authowner.Committed {
			return errors.New("stop lacks durable RPC outcome")
		}
		v := before
		v.MainPID = 0
		v.Active = "inactive"
		v.Substate = "dead"
		v.StopCompleted = true
		v.Empty = true
		v.PopulatedZero = true
		switch m.mode {
		case "stop-denied":
			refusal = errors.New("synthetic_stop_denied")
		case "unit-missing":
			refusal = errors.New("synthetic_unit_missing")
		case "partial":
			v.Complete = false
		case "invocation":
			v.Invocation += "-conflict"
		case "cgroup":
			v.Cgroup = ""
		case "pid-only":
			v.Empty = false
			v.PopulatedZero = false
		case "boot":
			v.Identity.Boot += "-changed"
		case "epoch":
			v.Identity.Epoch += "-changed"
		}
		m.lastStop = v
		if refusal != nil {
			m.stopError = refusal.Error()
		} else {
			m.stopError = ""
		}
		m.inputs = append(m.inputs, ownerStopFact{Before: before, After: v, Error: m.stopError})
		result = v
	default:
		return fmt.Errorf("unexpected owner model method %s", req.Op)
	}
	return ch.send(req.Op, result, refusal)
}

// Embedded binding fields use the engine's canonical re-encoding rule, rather
// than wire.Decode's transport schema (which does not flatten embedded structs).
func ownerDecodeRecord(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return errors.New("owner record decode")
	}
	encoded, e := wire.Encode(v)
	if e != nil || !bytes.Equal(b, encoded) {
		return errors.New("owner record canonical mismatch")
	}
	return nil
}

func ownerReleasedRecords(root string, want int) error {
	entries, e := os.ReadDir(ownerAccountPath(root))
	if e != nil {
		return e
	}
	n := 0
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "lease-") {
			continue
		}
		n++
		b, e := os.ReadFile(filepath.Join(ownerAccountPath(root), entry.Name()))
		var r lease.Record
		if e != nil || ownerDecodeRecord(b, &r) != nil || r.State != "released" {
			return errors.New("unexpected durable lease admission")
		}
	}
	if n != want {
		return errors.New("unexpected durable lease count")
	}
	return nil
}
