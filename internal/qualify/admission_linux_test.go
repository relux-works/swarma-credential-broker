//go:build linux && amd64

package qualify

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// Claim: each established account/qualification fault gets its exact correlated
// refusal before Snapshot; adjacent valid tuples get one real synthetic grant.
// The ended variants start from real grants; release/expiry cannot renew or
// change the baseline, while live renewal and duplicate release succeed.
func TestAdmissionFaultFixtures(t *testing.T) {
	for _, id := range []string{"account-denied", "account-unknown", "release-unqualified", "lease-ended"} {
		t.Run(id, func(t *testing.T) {
			for _, side := range []string{"positive", "negative"} {
				ends := []string{"released"}
				if id == "lease-ended" && side == "negative" {
					ends = append(ends, "expired")
				}
				for _, end := range ends {
					t.Run(side+"-"+end, func(t *testing.T) {
						_, c, _ := setup(t)
						root := t.TempDir()
						if os.Mkdir(filepath.Join(root, "home"), 0700) != nil {
							t.Fatal("home")
						}
						in := admissionInput(rowInput{Policy: c.Policy, Peer: uint32(os.Geteuid()), ID: id, Side: side})
						if id == "lease-ended" {
							in.EndedBy = end
						}
						if !validAdmissionInput(in) {
							t.Fatal("fixture fault not established")
						}
						if id == "account-denied" && in.Policy.Accounts[0].Enabled != (side == "positive") {
							t.Fatal("disabled fault missing")
						}
						var pid atomic.Int64
						pid.Store(int64(os.Getpid()))
						ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
						defer cancel()
						var counters admissionEffects
						socket, closeRow, files, e := startAdmissionRow(ctx, root, in, &pid, &counters)
						if e != nil {
							t.Fatal("fixture setup", e)
						}
						for _, f := range files {
							defer f.Close()
						}
						in.Socket = socket
						var phase, ack *os.File
						if len(files) == 2 {
							phase, ack = files[0], files[1]
						}
						code, facts, e := admissionExchangeWithPhase(in, phase, ack)
						effects := closeRow()
						want := rowPositive(id)
						if side == "negative" {
							want = rowRefusal(id)
						}
						if e != nil || code != want || !effects {
							t.Fatal("admission verdict/effects", code, e, effects)
						}
						if id == "lease-ended" && side == "negative" && end == "expired" {
							if len(facts) != 3 || !validAdmissionGrant(facts[1], "fixture-request") || !validAdmissionError(facts[2], id, "fixture-renew") {
								t.Fatal("expiry envelope")
							}
						} else if !validRowEnvelopes(rowObservation{ID: id, Side: side, Envelopes: facts}, c.Policy.Generation) {
							t.Fatal("admission envelope facts")
						}
					})
				}
			}
		})
	}
}

// Claim: admission controls leave the production list and both activation names
// byte-identical. Only diagnostics in the evidence directory may be added.
func TestAdmissionPublicationFence(t *testing.T) {
	worker := rowTool(t, "../../cmd/swarma-credential-broker")
	path, c, root := setup(t)
	config := rowConfiguration(t, c.Policy, filepath.Dir(path))
	dir := qualification.Directory(path)
	if os.Mkdir(dir, 0700) != nil {
		t.Fatal("repository")
	}
	before := map[string][]byte{}
	for _, name := range []string{"qualified.json", "activation.json", "pending-activation"} {
		b := []byte("synthetic protected " + name + "\n")
		before[name] = b
		if os.WriteFile(filepath.Join(dir, name), b, 0600) != nil {
			t.Fatal("publication fixture")
		}
	}
	cases := qualification.Pending(qualification.Identity{}).Cases
	d := driver{rowExecutable: worker}
	d.runRows(context.Background(), config, c.Policy, root, cases)
	for _, row := range cases {
		if admissionRow(row.ID) && (row.Positive.Verdict != "passed" || row.Negative.Verdict != "passed") {
			t.Fatal("publication control", row.ID)
		}
	}
	for name, b := range before {
		after, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil || !bytes.Equal(after, b) {
			t.Fatal("production qualification changed", name)
		}
	}
	names, e := os.ReadDir(dir)
	if e != nil || len(names) != len(before) {
		t.Fatal("publication entry created")
	}
}

// Claim: release source has no new test selector. Synthetic fixture routing is
// private and does not add flags, environment keys or conditional build tags.
func TestAdmissionNoPublicSelector(t *testing.T) {
	source, e := parser.ParseFile(token.NewFileSet(), "command_linux.go", nil, 0)
	if e != nil {
		t.Fatal(e)
	}
	var flags []string
	ast.Inspect(source, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		method, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || method.Sel.Name != "StringVar" && method.Sel.Name != "BoolVar" {
			return true
		}
		if len(call.Args) < 2 {
			t.Fatal("flag shape")
		}
		name, ok := call.Args[1].(*ast.BasicLit)
		if !ok {
			t.Fatal("dynamic flag")
		}
		value, err := strconv.Unquote(name.Value)
		if err != nil {
			t.Fatal(err)
		}
		flags = append(flags, value)
		return true
	})
	if !reflect.DeepEqual(flags, []string{"executable", "evidence-dir", "approval-ref", "account", "fixture-config", "fixtures", "live"}) {
		t.Fatal("public flag inventory changed")
	}

	for path, forbidden := range map[string][]string{
		"command_linux.go":                           {"rowExecutable:", "admissionFixture:", "ENDED_BY", "SYNTHETIC_OWNER"},
		"../../cmd/swarma-credential-broker/main.go": {"admissionInput(", "startAdmissionRow(", "NewQualificationAdmission("},
	} {
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		for _, term := range forbidden {
			if bytes.Contains(b, []byte(term)) {
				t.Fatal("public fixture selector", term)
			}
		}
	}
	b, e := os.ReadFile("admission_linux.go")
	if e != nil || !strings.HasPrefix(string(b), "//go:build linux\n") || strings.Contains(string(b), "os.Getenv(") {
		t.Fatal("fixture runtime selector")
	}
}

// Claim: extending authority or admitting the anchor invalidates the closed
// fixture context; no out-of-range policy is accepted by its parent setup.
func TestAdmissionContextBounds(t *testing.T) {
	_, c, _ := setup(t)
	good := admissionInput(rowInput{Policy: c.Policy, Peer: uint32(os.Geteuid()), ID: "account-denied", Side: "positive"})
	if !validAdmissionInput(good) {
		t.Fatal("positive context")
	}
	for _, change := range []string{"lifetime", "anchor", "subject", "peer", "side", "end-mode"} {
		bad := good
		bad.Policy = good.Policy.Clone()
		switch change {
		case "lifetime":
			bad.Policy.MaxLeaseSeconds = 6
		case "anchor":
			bad.Policy.Accounts[1].QualificationID = "issuable"
		case "subject":
			bad.Policy.Accounts[0].VendorID = "other"
		case "peer":
			bad.Peer++
		case "side":
			bad.Side = "unknown"
		case "end-mode":
			bad.EndedBy = "unknown"
		}
		if validAdmissionInput(bad) || reflect.DeepEqual(bad, good) {
			t.Fatal("extended authority accepted", change)
		}
	}
}

// Claim: refusal facts reject changed correlation, code, shape and fixed
// text/details. Successful material facts are checked by the paired
// fixture scripts above; these plants target refusal envelopes only.
func TestAdmissionEnvelopeDefects(t *testing.T) {
	id := "fixture-request"
	errorBytes, _ := wire.Encode(map[string]any{"request_id": id, "error": wire.Refuse("lease_account_unknown")})
	if _, e := decodeAdmissionError(errorBytes, "account-unknown", id); e != nil {
		t.Fatal("positive refusal", e)
	}
	for _, plant := range []map[string]any{
		{"request_id": "other", "error": wire.Refuse("lease_account_unknown")},
		{"request_id": nil, "error": wire.Refuse("lease_account_unknown")},
		{"request_id": id, "error": wire.Refuse("lease_not_authorised")},
		{"request_id": id, "error": wire.Refuse("lease_account_unknown"), "result": nil},
		{"request_id": id, "error": map[string]any{"code": "lease_account_unknown", "message": "other", "details": map[string]any{}}},
		{"request_id": id, "error": map[string]any{"code": "lease_account_unknown", "message": "request refused", "details": map[string]any{"extra": true}}},
	} {
		b, _ := wire.Encode(plant)
		if _, e := decodeAdmissionError(b, "account-unknown", id); e == nil {
			t.Fatal("admission refusal defect credited")
		}
	}
}

// Claim: correct refusal frames do not hide same-byte metadata rewrites or a
// home create/remove. Parent teardown refuses those effects independently.
func TestAdmissionUnexpectedEffects(t *testing.T) {
	for _, plant := range []string{"metadata-rewrite", "home-create-remove"} {
		t.Run(plant, func(t *testing.T) {
			_, c, _ := setup(t)
			root := t.TempDir()
			if os.Mkdir(filepath.Join(root, "home"), 0700) != nil {
				t.Fatal("home")
			}
			in := admissionInput(rowInput{Policy: c.Policy, Peer: uint32(os.Geteuid()), ID: "account-unknown", Side: "negative"})
			var pid atomic.Int64
			pid.Store(int64(os.Getpid()))
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var counters admissionEffects
			socket, closeRow, _, e := startAdmissionRow(ctx, root, in, &pid, &counters)
			if e != nil {
				t.Fatal(e)
			}
			in.Socket = socket
			code, _, e := admissionExchangeWithPhase(in, nil, nil)
			if e != nil || code != "lease_account_unknown" {
				closeRow()
				t.Fatal("baseline refusal", e)
			}
			if plant == "metadata-rewrite" {
				tree, e := admissionTree(filepath.Join(root, "store"))
				if e != nil {
					closeRow()
					t.Fatal(e)
				}
				planted := false
				for name, f := range tree {
					if f.Mode.IsRegular() {
						if os.WriteFile(filepath.Join(root, "store", name), []byte(f.Data), 0600) != nil {
							closeRow()
							t.Fatal("metadata plant")
						}
						planted = true
						break
					}
				}
				if !planted {
					closeRow()
					t.Fatal("no metadata plant")
				}
			} else {
				path := filepath.Join(root, "home", "temporary-fixture")
				if os.WriteFile(path, []byte("synthetic"), 0600) != nil || os.Remove(path) != nil {
					closeRow()
					t.Fatal("home plant")
				}
			}
			if closeRow() {
				t.Fatal("unexpected effect credited", plant)
			}
		})
	}
}
