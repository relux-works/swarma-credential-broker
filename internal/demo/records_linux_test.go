//go:build linux

package demo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func fixtureRoster() Roster {
	r := Roster{Format: "swarma-user-manager demo-roster/1", SourceRevision: SourceRevision, BootID: "11111111-2222-3333-4444-555555555555", Operator: Service{"agent", 1001, 1001}, Dispatcher: Dispatcher{"swarma-demo-dispatcher", 1101, 1101, "swarma-demo-dispatcher", strings.Repeat("1", 32)}, Executor: Executor{"swarma-demo-executor", "/usr/local/libexec/swarma/swarma-demo-executor", strings.Repeat("a", 64)}, Runtime: Runtime{true, true, true, true}}
	for i, name := range []string{"swarma-demo-01", "swarma-demo-02", "swarma-demo-03"} {
		r.Accounts = append(r.Accounts, Row{name, uint32(30000 + i), uint32(30000 + i), strings.Repeat(string(rune('2'+i)), 32), r.Dispatcher.Principal, "/srv/swarma-demo/home/" + name, "/srv/swarma-demo/work/" + name, strings.Repeat("b", 64)})
	}
	return r
}
func raw(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestCanonicalExecutorPairsAndRevision(t *testing.T) {
	for _, codex := range []bool{false, true} {
		r := fixtureRoster()
		if codex {
			r.Executor.ID, r.Executor.Path = ExecutorID, ExecutorPath
		}
		decoded, err := DecodeRoster(raw(t, r))
		if err != nil || FixedExecutorApproved(decoded) != codex {
			t.Fatalf("canonical executor pair codex=%t refused or misapproved: %v", codex, err)
		}
		r.SourceRevision = "7d705966aa92acaebea2d55060dcb84ddf7e5031"
		if _, err := DecodeRoster(raw(t, r)); err == nil {
			t.Fatalf("old revision accepted for codex=%t", codex)
		}
	}
}
func TestCanonicalRosterClosedAndBoundaries(t *testing.T) {
	r := fixtureRoster()
	if _, e := DecodeRoster(raw(t, r)); e != nil {
		t.Fatal("canonical fixture refused")
	}
	for _, uid := range []uint32{30000, 30019} {
		v := fixtureRoster()
		v.Accounts[0].UID = uid
		v.Accounts[0].GID = uid
		if _, e := DecodeRoster(raw(t, v)); e != nil {
			t.Fatalf("inside UID boundary %d", uid)
		}
	}
	for name, mutate := range map[string]func(*Roster){
		"uid-low": func(r *Roster) { r.Accounts[0].UID = 29999 }, "uid-high": func(r *Roster) { r.Accounts[0].UID = 30020 }, "gid": func(r *Roster) { r.Accounts[0].GID = 30019 },
		"owner": func(r *Roster) { r.Accounts[0].OwningDispatcher = "other" }, "dispatcher-uid": func(r *Roster) { r.Dispatcher.UID = 1102 }, "dispatcher-principal": func(r *Roster) { r.Dispatcher.Principal = "other" },
		"duplicate-uid": func(r *Roster) { r.Accounts[1].UID = r.Accounts[0].UID; r.Accounts[1].GID = r.Accounts[0].GID }, "duplicate-generation": func(r *Roster) { r.Accounts[1].Generation = r.Accounts[0].Generation },
		"zero-generation": func(r *Roster) { r.Accounts[0].Generation = strings.Repeat("0", 32) }, "source": func(r *Roster) { r.SourceRevision = strings.Repeat("c", 40) }, "workspace": func(r *Roster) { r.Accounts[0].Workspace = "/tmp" },
		"third-executor": func(r *Roster) {
			r.Executor.ID = "third-executor"
			r.Executor.Path = "/usr/local/libexec/swarma/third-executor"
		},
		"codex-wrong-path":    func(r *Roster) { r.Executor.ID = ExecutorID },
		"codex-wrong-id":      func(r *Roster) { r.Executor.Path = ExecutorPath },
		"old-source-revision": func(r *Roster) { r.SourceRevision = "7d705966aa92acaebea2d55060dcb84ddf7e5031" },
	} {
		t.Run(name, func(t *testing.T) {
			v := fixtureRoster()
			mutate(&v)
			if _, e := DecodeRoster(raw(t, v)); e == nil {
				t.Fatal("invalid roster accepted")
			}
		})
	}
	base := string(raw(t, r))
	for _, bad := range []string{
		strings.Replace(base, `"format":`, `"format":null,"format":`, 1), strings.Replace(base, `"format":`, `"Format":`, 1), strings.Replace(base, `"format":`, `"extra":1,"format":`, 1), strings.Replace(base, `"uid":1001`, `"uid":null`, 1), strings.Replace(base, `"uid":1001`, `"uid":true`, 1), strings.Replace(base, `"uid":1001`, `"uid":1001.0`, 1), strings.Replace(base, `"admitted":true`, `"admitted":1`, 1), `{"accounts":[]}`,
	} {
		if _, e := DecodeRoster([]byte(bad)); e == nil {
			t.Fatal("noncanonical schema accepted")
		}
	}
}
func TestExecutionIDPreservesP1Grammar(t *testing.T) {
	for _, id := range []string{"a", "A_0.-", "EX-" + strings.Repeat("a", 32), strings.Repeat("z", 64)} {
		p, e := LaunchPath(id)
		if e != nil || p != LaunchDirectory+"/"+id+".json" {
			t.Fatal("valid identifier refused")
		}
	}
	for _, id := range []string{"", ".", "..", "../x", "a/../b", "a/b", "/a", "-a", "_a", strings.Repeat("a", 65), "a\\b", "a\x00b", "a\nb", "é"} {
		if _, e := LaunchPath(id); e == nil {
			t.Fatal("ambiguous identifier admitted")
		}
	}
}
func TestPlanReadOnceExactBytesAndIndependentDigest(t *testing.T) {
	p := Plan{"EX-fixture", "one fixed prompt", "fixture-model", "medium"}
	exact := append([]byte(" \n"), raw(t, p)...)
	f := sealed(t, exact)
	defer f.Close()
	got, sum, e := ReadPlan(f)
	if e != nil || got != p || sum != Hash(exact) {
		t.Fatal("exact sealed bytes not used")
	}
	if _, _, e = ReadPlan(f); e == nil {
		t.Fatal("descriptor read twice")
	}
	// Adjacent size controls keep the JSON and semantics valid; only the byte
	// count changes. Whitespace remains part of the admitted digest.
	encoded := raw(t, p)
	boundary := append(encoded, []byte(strings.Repeat(" ", PlanMax-len(encoded)))...)
	atLimit := sealed(t, boundary)
	if _, sum, e := ReadPlan(atLimit); e != nil || sum != Hash(boundary) {
		t.Fatal("exact decoded-byte limit refused")
	}
	atLimit.Close()
	overLimit := sealed(t, append(boundary, ' '))
	if _, _, e := ReadPlan(overLimit); e == nil {
		t.Fatal("valid JSON above decoded-byte limit accepted")
	}
	overLimit.Close()
	r := LaunchRecord{p.ExecutionID, 30000, strings.Repeat("a", 32), sum, fixtureRoster().BootID}
	if MatchPlan(p, sum, r, 30000) != nil {
		t.Fatal("protected match refused")
	}
	r.PlanSHA256 = Hash([]byte("caller assertion"))
	if MatchPlan(p, sum, r, 30000) == nil {
		t.Fatal("self-issued digest accepted")
	}
	for _, b := range [][]byte{nil, []byte(`{"execution_id":"../x","prompt":"x","model":"m","reasoning_effort":"low"}`), append(raw(t, p), []byte(` {}`)...), []byte(strings.Repeat("x", PlanMax+1))} {
		f := sealed(t, b)
		if _, _, e := ReadPlan(f); e == nil {
			t.Fatal("bad plan accepted")
		}
		f.Close()
	}
	unsealed, e := os.CreateTemp(t.TempDir(), "plan")
	if e != nil {
		t.Fatal(e)
	}
	defer unsealed.Close()
	unsealed.Write(raw(t, p))
	unsealed.Seek(0, 0)
	if _, _, e := ReadPlan(unsealed); e == nil {
		t.Fatal("unsealed writable descriptor accepted")
	}
	readonly, e := os.Open(unsealed.Name())
	if e != nil {
		t.Fatal(e)
	}
	defer readonly.Close()
	if _, _, e := ReadPlan(readonly); e == nil {
		t.Fatal("read-only unsealed descriptor accepted")
	}
}
func sealed(t *testing.T, b []byte) *os.File {
	t.Helper()
	fd, e := unix.MemfdCreate("synthetic-plan", unix.MFD_ALLOW_SEALING|unix.MFD_CLOEXEC)
	if e != nil {
		t.Fatal(e)
	}
	w := os.NewFile(uintptr(fd), "synthetic-plan")
	if _, e = w.Write(b); e != nil {
		t.Fatal(e)
	}
	if _, e = unix.FcntlInt(w.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_SEAL|unix.F_SEAL_WRITE|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(filepath.Join("/proc/self/fd", itoa(fd)))
	w.Close()
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
func TestRootRecordCustody(t *testing.T) {
	// Root identity here is synthetic in an isolated user namespace; no host-root
	// ownership, VM privilege or cross-UID qualification is asserted.
	if os.Geteuid() != 0 {
		t.Skip("synthetic root filesystem fixture requires an isolated user namespace")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "EX-fixture.json")
	r := LaunchRecord{"EX-fixture", 30000, strings.Repeat("a", 32), strings.Repeat("b", 64), fixtureRoster().BootID}
	if e := os.WriteFile(path, raw(t, r), 0444); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(path, 0444); e != nil {
		t.Fatal(e)
	}
	if _, e := readLaunch(path, r.ExecutionID); e != nil {
		t.Fatal("synthetic immutable root record refused")
	}
	for _, mode := range []os.FileMode{0644, 0666, 0400} {
		if e := os.Chmod(path, mode); e != nil {
			t.Fatal(e)
		}
		if _, e := readLaunch(path, r.ExecutionID); e == nil {
			t.Fatal("wrong launch record mode accepted")
		}
	}
	os.Chmod(path, 0444)
	alias := filepath.Join(dir, "alias")
	os.Symlink(path, alias)
	if _, e := readLaunch(alias, r.ExecutionID); e == nil {
		t.Fatal("symlink accepted")
	}
	hard := filepath.Join(dir, "hard")
	os.Link(path, hard)
	if _, e := readLaunch(path, r.ExecutionID); e == nil {
		t.Fatal("hardlink accepted")
	}
	os.Remove(hard)
	os.Chmod(dir, 0777)
	if _, e := readLaunch(path, r.ExecutionID); e == nil {
		t.Fatal("writable ancestor accepted")
	}
	os.Chmod(dir, 0700)
	r.ExecutionID = "other"
	os.Chmod(path, 0600)
	os.WriteFile(path, raw(t, r), 0600)
	os.Chmod(path, 0444)
	if _, e := readLaunch(path, "EX-fixture"); e == nil {
		t.Fatal("filename/key mismatch accepted")
	}
}
func TestPrincipalDoesNotTrustCallerGeneration(t *testing.T) {
	r := fixtureRoster()
	a := r.Accounts[0]
	l := LaunchRecord{"EX-fixture", a.UID, a.Generation, strings.Repeat("a", 64), r.BootID}
	if _, e := r.Principal(a.UID, l); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*LaunchRecord){func(l *LaunchRecord) { l.Generation = strings.Repeat("9", 32) }, func(l *LaunchRecord) { l.BootID = "22222222-2222-3333-4444-555555555555" }, func(l *LaunchRecord) { l.UID = 30019 }} {
		v := l
		change(&v)
		if _, e := r.Principal(a.UID, v); e == nil {
			t.Fatal("stale protected record admitted")
		}
	}
	r.Runtime.Admitted = false
	if _, e := r.Principal(a.UID, l); e == nil {
		t.Fatal("runtime hold bypassed")
	}
}
