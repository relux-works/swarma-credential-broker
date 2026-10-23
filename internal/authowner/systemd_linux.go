//go:build linux

package authowner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"
)

const destination = "org.freedesktop.systemd1"
const managerPath = dbus.ObjectPath("/org/freedesktop/systemd1")

type property struct {
	Name  string
	Value dbus.Variant
}
type execStart struct {
	Path   string
	Args   []string
	Ignore bool
}
type execRead struct {
	Path                                                       string
	Args                                                       []string
	Ignore                                                     bool
	StartRealtime, StartMonotonic, ExitRealtime, ExitMonotonic uint64
	PID                                                        uint32
	Code, Status                                               int32
}
type auxiliary struct {
	Name       string
	Properties []property
}

var attemptPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var unitPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]*\.service$`)
var prefixPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]*-$`)

type Systemd struct {
	conn           *dbus.Conn
	prefix, daemon string
	uid            uint32
	mu             sync.Mutex
	specs          map[string]UnitSpec
	retained       map[string]bool
	verified       Identity
}

func NewSystemd(ctx context.Context, prefix, daemon string) (*Systemd, error) {
	if !prefixPattern.MatchString(prefix) || !unitPattern.MatchString(daemon) {
		return nil, ErrUnavailable
	}
	uid := uint32(os.Geteuid())
	runtime := fmt.Sprintf("/run/user/%d", uid)
	st, err := os.Stat(runtime)
	if err != nil || st.Mode() != os.ModeDir|0700 || st.Sys().(*syscall.Stat_t).Uid != uid {
		return nil, ErrUnavailable
	}
	conn, err := dbus.Dial("unix:path=" + runtime + "/bus")
	if err != nil {
		return nil, ErrUnavailable
	}
	fail := func() (*Systemd, error) { conn.Close(); return nil, ErrUnavailable }
	if conn.Auth([]dbus.Auth{dbus.AuthExternal(strconv.FormatUint(uint64(uid), 10))}) != nil || conn.Hello() != nil || !conn.SupportsUnixFDs() {
		return fail()
	}
	m := &Systemd{conn: conn, prefix: prefix, daemon: daemon, uid: uid, specs: map[string]UnitSpec{}, retained: map[string]bool{}}
	if conn.Object(destination, managerPath).CallWithContext(ctx, destination+".Manager.Subscribe", 0).Err != nil {
		return fail()
	}
	if _, err = m.Identity(ctx); err != nil {
		return fail()
	}
	return m, nil
}
func (m *Systemd) Close() error { return m.conn.Close() }
func (m *Systemd) Identity(ctx context.Context) (Identity, error) {
	var name string
	var uid uint32
	bus := m.conn.Object("org.freedesktop.DBus", "/org/freedesktop/DBus")
	if bus.CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, destination).Store(&name) != nil || name == "" {
		return Identity{}, ErrUnavailable
	}
	if bus.CallWithContext(ctx, "org.freedesktop.DBus.GetConnectionUnixUser", 0, name).Store(&uid) != nil || uid != m.uid {
		return Identity{}, ErrUnavailable
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return Identity{}, ErrUnavailable
	}
	return Identity{strings.TrimSpace(string(boot)), uid, name}, nil
}
func (m *Systemd) allowed(name string) bool {
	return unitPattern.MatchString(name) && strings.HasPrefix(name, m.prefix) && name != m.daemon
}
func prop(name string, v any) property { return property{name, dbus.MakeVariant(v)} }
func properties(s UnitSpec) []property {
	return []property{
		prop("Type", "exec"), prop("Restart", "no"), prop("KillMode", "control-group"), prop("SendSIGKILL", true), prop("TimeoutStopUSec", uint64(2*time.Second/time.Microsecond)), prop("RuntimeMaxUSec", uint64(s.Runtime/time.Microsecond)), prop("RemainAfterExit", true), prop("Delegate", false), prop("NoNewPrivileges", true), prop("ProtectControlGroups", true), prop("StandardInput", "null"), prop("StandardOutput", "null"), prop("StandardError", "null"), prop("BindsTo", []string{s.Daemon}), prop("After", []string{s.Daemon}), prop("PartOf", []string{s.Daemon}), prop("Environment", s.Environment), prop("WorkingDirectory", s.Home), prop("AddRef", true), prop("ExecStart", []execStart{{s.Executable, append([]string{s.Executable}, s.Args...), false}}),
	}
}
func (m *Systemd) Start(ctx context.Context, s UnitSpec) error {
	if !m.allowed(s.Name) || s.Daemon != m.daemon || s.Runtime <= 0 || s.Runtime > 120*time.Second || s.Input == nil || s.Output == nil || !filepath.IsAbs(s.Home) || filepath.Clean(s.Home) != s.Home || !filepath.IsAbs(s.Executable) {
		return ErrUnavailable
	}
	// Revalidate the exact qualified executable immediately before admission.
	// Shared-UID hostile replacement is outside this profile's trust boundary.
	image, err := os.OpenFile(s.Executable, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrUnavailable
	}
	defer image.Close()
	hash := sha256.New()
	if _, err = io.Copy(hash, image); err != nil || hex.EncodeToString(hash.Sum(nil)) != s.ExecutableSHA256 {
		return ErrUnavailable
	}
	// Record the requested identity locally before the uncertain D-Bus call.
	m.mu.Lock()
	if _, ok := m.specs[s.Name]; ok {
		m.mu.Unlock()
		return ErrUnavailable
	}
	m.specs[s.Name] = s
	// If this uncertain submission creates the unit, AddRef belongs to this connection.
	m.retained[s.Name] = true
	m.mu.Unlock()
	props := append(properties(s), prop("StandardInputFileDescriptor", dbus.UnixFD(s.Input.Fd())), prop("StandardOutputFileDescriptor", dbus.UnixFD(s.Output.Fd())))
	return m.job(ctx, s.Name, "StartTransientUnit", "fail", props, []auxiliary{})
}

// job subscribes before the request, correlates the returned job path and exact
// never-reused unit name, and requires JobRemoved(result=done). Disappearance or
// cancellation alone is not a successful stop result.
func (m *Systemd) job(ctx context.Context, name, method string, args ...any) error {
	rule := fmt.Sprintf("type='signal',sender='%s',interface='%s.Manager',member='JobRemoved',path='%s',arg2='%s'", destination, destination, managerPath, name)
	bus := m.conn.Object("org.freedesktop.DBus", "/org/freedesktop/DBus")
	signals := make(chan *dbus.Signal, 16)
	m.conn.Signal(signals)
	defer m.conn.RemoveSignal(signals)
	if bus.CallWithContext(ctx, "org.freedesktop.DBus.AddMatch", 0, rule).Err != nil {
		return ErrUnavailable
	}
	defer func() {
		cleanup, c := context.WithTimeout(context.Background(), time.Second)
		defer c()
		bus.CallWithContext(cleanup, "org.freedesktop.DBus.RemoveMatch", 0, rule)
	}()
	all := append([]any{name}, args...)
	var path dbus.ObjectPath
	if m.conn.Object(destination, managerPath).CallWithContext(ctx, destination+".Manager."+method, 0, all...).Store(&path) != nil {
		return ErrUnavailable
	}
	for {
		select {
		case <-ctx.Done():
			return ErrUnavailable
		case signal, ok := <-signals:
			if !ok {
				return ErrUnavailable
			}
			if signal == nil || signal.Name != destination+".Manager.JobRemoved" || len(signal.Body) != 4 {
				continue
			}
			unit, ok := signal.Body[2].(string)
			if !ok || unit != name {
				continue
			}
			job, ok := signal.Body[1].(dbus.ObjectPath)
			if !ok || job != path {
				continue
			}
			result, ok := signal.Body[3].(string)
			if !ok || result != "done" {
				return ErrUnavailable
			}
			return nil
		}
	}
}

func (m *Systemd) all(ctx context.Context, path dbus.ObjectPath, iface string) (map[string]dbus.Variant, error) {
	var values map[string]dbus.Variant
	err := m.conn.Object(destination, path).CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", 0, iface).Store(&values)
	if err != nil {
		return nil, ErrUnavailable
	}
	return values, nil
}
func value[T any](p map[string]dbus.Variant, key string) (T, bool) {
	var zero T
	v, ok := p[key]
	if !ok {
		return zero, false
	}
	x, ok := v.Value().(T)
	return x, ok
}
func (m *Systemd) Observe(ctx context.Context, name string) (Observation, error) {
	o := Observation{Unit: name, Observed: time.Now().UTC()}
	if !m.allowed(name) {
		return o, ErrUnavailable
	}
	before, err := m.Identity(ctx)
	if err != nil {
		return o, err
	}
	o.Identity = before
	var path dbus.ObjectPath
	if m.conn.Object(destination, managerPath).CallWithContext(ctx, destination+".Manager.GetUnit", 0, name).Store(&path) != nil {
		return o, ErrUnavailable
	}
	unit, err := m.all(ctx, path, destination+".Unit")
	if err != nil {
		return o, err
	}
	service, err := m.all(ctx, path, destination+".Service")
	if err != nil {
		return o, err
	}
	for _, key := range []string{"Id", "ActiveState", "SubState", "InvocationID", "BindsTo", "After", "PartOf"} {
		if _, ok := unit[key]; !ok {
			return o, ErrUnavailable
		}
	}
	for _, key := range []string{"ControlGroup", "Type", "Restart", "MainPID", "ExecMainStartTimestampMonotonic", "ExecMainStatus", "Result", "KillMode", "SendSIGKILL", "TimeoutStopUSec", "RuntimeMaxUSec", "RemainAfterExit", "Delegate", "NoNewPrivileges", "ProtectControlGroups", "StandardInput", "StandardOutput", "StandardError", "Environment", "WorkingDirectory", "ExecStart"} {
		if _, ok := service[key]; !ok {
			return o, ErrUnavailable
		}
	}
	if nameValue, _ := value[string](unit, "Id"); nameValue != name {
		return o, ErrUnavailable
	}
	invocation, ok := value[[]byte](unit, "InvocationID")
	if !ok || len(invocation) != 16 || bytes.Equal(invocation, make([]byte, 16)) {
		return o, ErrUnavailable
	}
	o.Invocation = hex.EncodeToString(invocation)
	var valid bool
	if o.Active, valid = value[string](unit, "ActiveState"); !valid {
		return o, ErrUnavailable
	}
	if o.Substate, valid = value[string](unit, "SubState"); !valid {
		return o, ErrUnavailable
	}
	if o.Cgroup, valid = value[string](service, "ControlGroup"); !valid {
		return o, ErrUnavailable
	}
	if o.MainPID, valid = value[uint32](service, "MainPID"); !valid {
		return o, ErrUnavailable
	}
	if o.ProcessStart, valid = value[uint64](service, "ExecMainStartTimestampMonotonic"); !valid {
		return o, ErrUnavailable
	}
	if o.ExitStatus, valid = value[int32](service, "ExecMainStatus"); !valid {
		return o, ErrUnavailable
	}
	if o.Result, valid = value[string](service, "Result"); !valid {
		return o, ErrUnavailable
	}
	restart, _ := value[string](service, "Restart")
	o.RestartNo = restart == "no"
	m.mu.Lock()
	spec, known := m.specs[name]
	m.mu.Unlock()
	// Recovery may observe a recorded name after daemon replacement; required
	// runtime bounds still apply, while the engine binds its exact property digest.
	expected := map[string]any{"Type": "exec", "Restart": "no", "KillMode": "control-group", "SendSIGKILL": true, "TimeoutStopUSec": uint64(2e6), "RemainAfterExit": true, "Delegate": false, "NoNewPrivileges": true, "ProtectControlGroups": true, "StandardInput": "null", "StandardOutput": "null", "StandardError": "null"}
	checked := map[string]any{}
	for key, want := range expected {
		got := service[key].Value()
		if !reflect.DeepEqual(got, want) {
			return o, ErrUnavailable
		}
		checked[key] = got
	}
	runtime, ok := value[uint64](service, "RuntimeMaxUSec")
	if !ok || runtime == 0 || runtime > uint64(120e6) || known && runtime != uint64(spec.Runtime/time.Microsecond) {
		return o, ErrUnavailable
	}
	checked["RuntimeMaxUSec"] = runtime
	for _, key := range []string{"BindsTo", "After", "PartOf"} {
		names, ok := value[[]string](unit, key)
		found := false
		for _, n := range names {
			found = found || n == m.daemon
		}
		if !ok || !found {
			return o, ErrUnavailable
		}
		checked[key] = m.daemon
	}
	env, ok := value[[]string](service, "Environment")
	if !ok || known && !reflect.DeepEqual(env, spec.Environment) {
		return o, ErrUnavailable
	}
	checked["Environment"] = env
	home, ok := value[string](service, "WorkingDirectory")
	if !ok || !filepath.IsAbs(home) || known && home != spec.Home {
		return o, ErrUnavailable
	}
	checked["WorkingDirectory"] = home
	var commands []execRead
	if dbus.Store([]any{service["ExecStart"].Value()}, &commands) != nil || len(commands) != 1 || !filepath.IsAbs(commands[0].Path) || commands[0].Ignore {
		return o, ErrUnavailable
	}
	if known && commands[0].Path != spec.Executable {
		return o, ErrUnavailable
	}
	if known && !reflect.DeepEqual(commands[0].Args, append([]string{spec.Executable}, spec.Args...)) {
		return o, ErrUnavailable
	}
	checked["ExecStartPath"] = commands[0].Path
	checked["ExecStartArgs"] = commands[0].Args
	raw, _ := json.Marshal(checked)
	hash := sha256.Sum256(raw)
	o.Properties = hex.EncodeToString(hash[:])
	if o.Cgroup != "" {
		o.CgroupID, o.Empty, o.PopulatedZero, err = readCgroup(o.Cgroup)
		if err != nil {
			return o, ErrUnavailable
		}
	}
	after, err := m.Identity(ctx)
	if err != nil || after != before {
		return o, ErrUnavailable
	}
	o.Complete = true
	return o, nil
}
func readCgroup(group string) (string, bool, bool, error) {
	if !strings.HasPrefix(group, "/") || filepath.Clean(group) != group || group == "/" {
		return "", false, false, ErrUnavailable
	}
	root := "/sys/fs/cgroup" + group
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() {
		return "", false, false, ErrUnavailable
	}
	stat := info.Sys().(*syscall.Stat_t)
	identity := fmt.Sprintf("%d:%d", stat.Dev, stat.Ino)
	empty := true
	zero := false
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.Type()&os.ModeSymlink != 0 {
			return ErrUnavailable
		}
		if !d.IsDir() {
			return nil
		}
		p, e := os.ReadFile(filepath.Join(path, "cgroup.procs"))
		if e != nil {
			return e
		}
		if len(strings.Fields(string(p))) != 0 {
			empty = false
		}
		events, e := os.ReadFile(filepath.Join(path, "cgroup.events"))
		if e != nil {
			return e
		}
		valid := false
		fields := strings.Fields(string(events))
		for i := 0; i+1 < len(fields); i += 2 {
			if fields[i] == "populated" {
				if fields[i+1] != "0" && fields[i+1] != "1" {
					return ErrUnavailable
				}
				valid = true
				if path == root {
					zero = fields[i+1] == "0"
				}
			}
		}
		if !valid {
			return ErrUnavailable
		}
		return nil
	})
	current, e := os.Lstat(root)
	if e != nil || !os.SameFile(info, current) {
		return identity, false, false, ErrUnavailable
	}
	return identity, empty, zero, err
}
func (m *Systemd) Stop(ctx context.Context, name string, before Observation) (Observation, error) {
	if !m.allowed(name) || !before.Complete || before.Unit != name || before.Invocation == "" || before.Cgroup == "" || before.CgroupID == "" {
		return Observation{}, ErrUnavailable
	}
	identity, err := m.Identity(ctx)
	if err != nil || identity != before.Identity {
		return Observation{}, ErrUnavailable
	}
	// AddRef at creation belongs to that D-Bus connection. Replacement must pin
	// the retained unit itself before a stop can make it collectible. Keep this
	// reference through durable terminal publication; only Unload releases it.
	// Failure (including prior collection) is unknown, never confirmed absence.
	m.mu.Lock()
	held := m.retained[name]
	m.mu.Unlock()
	// The engine serializes lifecycle calls for each never-reused unit name.
	// RefUnit is counted: repeated stops must reuse this connection's reference.
	if !held {
		if m.conn.Object(destination, managerPath).CallWithContext(ctx, destination+".Manager.RefUnit", 0, name).Err != nil {
			return Observation{}, ErrUnavailable
		}
		m.mu.Lock()
		m.retained[name] = true
		m.mu.Unlock()
	}
	current, err := m.Observe(ctx, name)
	if err != nil || current.Invocation != before.Invocation || current.Properties != before.Properties || !current.RestartNo {
		return Observation{}, ErrUnavailable
	}
	if m.job(ctx, name, "StopUnit", "replace") != nil {
		return Observation{}, ErrUnavailable
	}
	after, err := m.Observe(ctx, name)
	if err != nil || after.Invocation != before.Invocation || after.Identity != before.Identity || after.Properties != before.Properties || (after.Active != "inactive" && after.Active != "failed") {
		return after, ErrUnavailable
	}
	after.StopCompleted = true
	if after.Cgroup == "" {
		_, err := os.Lstat("/sys/fs/cgroup" + before.Cgroup)
		if os.IsNotExist(err) {
			after.Cgroup = before.Cgroup
			after.CgroupID = before.CgroupID
			after.CgroupRemoved = true
			after.Empty = true
			after.PopulatedZero = true
		} else {
			return after, ErrUnavailable
		}
	} else if after.Cgroup != before.Cgroup || after.CgroupID != before.CgroupID {
		return after, ErrUnavailable
	}
	if !after.Empty || !after.PopulatedZero {
		return after, ErrUnavailable
	}
	return after, nil
}
func (m *Systemd) Unload(ctx context.Context, name string) error {
	if !m.allowed(name) {
		return ErrUnavailable
	}
	unit, err := m.Observe(ctx, name)
	if err != nil || unit.Active != "inactive" && unit.Active != "failed" {
		return ErrUnavailable
	}
	obj := m.conn.Object(destination, managerPath)
	if unit.Active == "failed" && obj.CallWithContext(ctx, destination+".Manager.ResetFailedUnit", 0, name).Err != nil {
		return ErrUnavailable
	}
	if obj.CallWithContext(ctx, destination+".Manager.UnrefUnit", 0, name).Err != nil {
		return ErrUnavailable
	}
	m.mu.Lock()
	delete(m.retained, name)
	m.mu.Unlock()
	return nil
}

// Ready checks FD negotiation and the explicitly configured daemon in this
// manager. Every writer additionally passes full property readback before RPC.
func (m *Systemd) daemonActive(ctx context.Context) error {
	if !m.conn.SupportsUnixFDs() {
		return ErrUnavailable
	}
	before, err := m.Identity(ctx)
	if err != nil {
		return ErrUnavailable
	}
	var path dbus.ObjectPath
	if m.conn.Object(destination, managerPath).CallWithContext(ctx, destination+".Manager.GetUnit", 0, m.daemon).Store(&path) != nil {
		return ErrUnavailable
	}
	unit, err := m.all(ctx, path, destination+".Unit")
	if err != nil {
		return ErrUnavailable
	}
	active, ok := value[string](unit, "ActiveState")
	if !ok || active != "active" {
		return ErrUnavailable
	}
	after, err := m.Identity(ctx)
	if err != nil || after != before {
		return ErrUnavailable
	}
	return nil
}

// Probe qualifies this manager epoch with a bounded, token-free echo helper in
// an explicitly fresh empty home. It is not a vendor writer or refresh attempt.
// The installer supplies the approved helper path/digest; no ambient executable
// or login is selected. The returned name permits exact cleanup accounting.
func (m *Systemd) Probe(ctx context.Context, executable, digest, home string) (name string, err error) {
	if m.daemonActive(ctx) != nil {
		return "", ErrUnavailable
	}
	if _, err = HomeIdentity(home); err != nil {
		return "", ErrUnavailable
	}
	entries, err := os.ReadDir(home)
	if err != nil || len(entries) != 0 {
		return "", ErrUnavailable
	}
	name = m.prefix + "readiness-" + id() + ".service"
	input, write, err := os.Pipe()
	if err != nil {
		return name, ErrUnavailable
	}
	defer input.Close()
	defer write.Close()
	read, output, err := os.Pipe()
	if err != nil {
		return name, ErrUnavailable
	}
	defer read.Close()
	defer output.Close()
	success := false
	defer func() {
		if success {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		obj := m.conn.Object(destination, managerPath)
		m.job(cleanup, name, "StopUnit", "replace")
		obj.CallWithContext(cleanup, destination+".Manager.ResetFailedUnit", 0, name)
		obj.CallWithContext(cleanup, destination+".Manager.UnrefUnit", 0, name)
	}()
	spec := UnitSpec{Name: name, Daemon: m.daemon, Executable: executable, ExecutableSHA256: digest, Home: home, Environment: []string{"HOME=" + home, "LANG=C.UTF-8", "PATH=/usr/bin:/bin"}, Runtime: 120 * time.Second, Input: input, Output: output}
	if m.Start(ctx, spec) != nil {
		return name, ErrUnavailable
	}
	input.Close()
	output.Close()
	before, err := m.Observe(ctx, name)
	if err != nil || !before.Complete || before.Active != "active" || before.MainPID == 0 || before.Cgroup == "" {
		return name, ErrUnavailable
	}
	deadline := time.Now().Add(time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	read.SetReadDeadline(deadline)
	write.SetWriteDeadline(deadline)
	nonce := id() + "\n"
	if _, err = write.Write([]byte(nonce)); err != nil {
		return name, ErrUnavailable
	}
	b := make([]byte, len(nonce))
	if _, err = io.ReadFull(read, b); err != nil || string(b) != nonce {
		return name, ErrUnavailable
	}
	after, err := m.Stop(ctx, name, before)
	if err != nil || !confirmed(Binding{Unit: name, Identity: before.Identity}, before, after) {
		return name, ErrUnavailable
	}
	if m.Unload(ctx, name) != nil {
		return name, ErrUnavailable
	}
	m.mu.Lock()
	m.verified = before.Identity
	m.mu.Unlock()
	success = true
	return name, nil
}

// Ready stays closed until Probe has demonstrated property application, private
// FD exchange and correlated absence for this exact boot/manager epoch.
func (m *Systemd) Ready(ctx context.Context) error {
	if m.daemonActive(ctx) != nil {
		return ErrUnavailable
	}
	identity, err := m.Identity(ctx)
	if err != nil {
		return ErrUnavailable
	}
	m.mu.Lock()
	verified := m.verified
	m.mu.Unlock()
	if verified != identity {
		return ErrUnavailable
	}
	return nil
}

// Owned refuses a terminal-launched adapter or an unrelated named daemon. The
// actual owner must be running inside that service in this same user manager.
func (m *Systemd) Owned(ctx context.Context) error {
	if m.Ready(ctx) != nil {
		return ErrUnavailable
	}
	var path dbus.ObjectPath
	if m.conn.Object(destination, managerPath).CallWithContext(ctx, destination+".Manager.GetUnit", 0, m.daemon).Store(&path) != nil {
		return ErrUnavailable
	}
	service, err := m.all(ctx, path, destination+".Service")
	if err != nil {
		return ErrUnavailable
	}
	group, ok := value[string](service, "ControlGroup")
	if !ok || group == "" || group == "/" {
		return ErrUnavailable
	}
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ErrUnavailable
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "0::") {
			own := strings.TrimPrefix(line, "0::")
			if own == group || strings.HasPrefix(own, group+"/") {
				return nil
			}
		}
	}
	return ErrUnavailable
}
