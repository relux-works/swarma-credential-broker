//go:build linux

package qualification

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/egress"
	"golang.org/x/sys/unix"
)

// CandidateEvidence is diagnostic measurement evidence, never publication
// authority. Raw candidate output, temporary paths and environment are excluded.
type CandidateEvidence struct {
	Version          Measurement    `json:"version"`
	Runs             []CandidateRun `json:"runs"`
	SchemaComparison string         `json:"schema_comparison"`
}

func (o NativeObserver) CandidateMeasurements() CandidateEvidence {
	if o.Evidence == nil {
		return CandidateEvidence{Runs: []CandidateRun{}}
	}
	evidence := *o.Evidence
	if evidence.Runs == nil {
		evidence.Runs = []CandidateRun{}
	}
	return evidence
}

type CandidateRun struct {
	Observer        string                   `json:"observer"`
	Command         []string                 `json:"command"`
	Summary         map[string]egress.Counts `json:"egress_summary"`
	Incomplete      bool                     `json:"incomplete"`
	IsolationFailed bool                     `json:"isolation_failed"`
}

// CandidateLauncherMain is the broker's private descriptor-bound bootstrap.
// FD3 must implement the egress handshake; FD4 is the retained candidate. No
// policy, account or lease authority is available through this entry point.
func CandidateLauncherMain(args []string) (bool, int) {
	if len(args) == 0 || args[0] != "--internal-qualification-candidate" {
		return false, 0
	}
	if len(args) < 2 || args[1] != "/proc/self/fd/4" {
		return true, 125
	}
	// A flag selects the embedding broker's private entry point. An executable
	// without that entry point rejects the flag instead of treating a positional
	// target as an ordinary invocation (which could recursively run a test suite).
	os.Args = append([]string{os.Args[0]}, args[1:]...)
	if egress.Bootstrap() != nil {
		return true, 125
	}
	return true, 125 // Bootstrap returns only on failure; successful exec replaces us.
}

type candidateOutput struct {
	stdout []byte
	schema []byte
}

// candidate retains both executable objects across hashing and exec. The
// candidate is FD4 and the trusted broker/launcher is FD5. The child resolves
// proc descriptors only after os/exec installs those exact selected objects.
func (o NativeObserver) candidate(parent context.Context, name string, args []string, limit int, exchange func(context.Context, *os.File, *os.File) ([]byte, error)) (result candidateOutput, err error) {
	if !validHash(o.ExecutableSHA256) {
		return result, ErrUnavailable
	}
	if o.Evidence != nil && len(o.Evidence.Runs) >= 64 {
		return result, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	f, e := OpenExecutable(o.ExecutablePath)
	if e != nil {
		return result, ErrUnavailable
	}
	defer f.Close()
	digest, e := hashFile(ctx, f)
	if e != nil || digest != o.ExecutableSHA256 {
		return result, ErrUnavailable
	}
	var launch *os.File
	if o.LauncherPath != "" {
		launch, e = OpenExecutable(o.LauncherPath)
	} else {
		launch, e = os.Open("/proc/self/exe")
	}
	if e != nil {
		return result, ErrUnavailable
	}
	defer launch.Close()
	s, e := launch.Stat()
	if e != nil || !s.Mode().IsRegular() {
		return result, ErrUnavailable
	}
	home, e := os.MkdirTemp(o.ScratchRoot, "candidate-")
	if e != nil {
		return result, ErrUnavailable
	}
	defer func() {
		if os.RemoveAll(home) != nil {
			result = candidateOutput{}
			err = ErrUnavailable
		}
	}()
	s, e = os.Lstat(home)
	if e != nil || s.Mode() != os.ModeDir|0700 {
		return result, ErrUnavailable
	}
	// os.MkdirTemp creates this directory as the effective user. Verify it via
	// fstat rather than accepting a pre-existing caller-supplied home.
	var hs unix.Stat_t
	if unix.Lstat(home, &hs) != nil || hs.Uid != uint32(os.Geteuid()) {
		return result, ErrUnavailable
	}
	entries, e := os.ReadDir(home)
	if e != nil || len(entries) != 0 {
		return result, ErrUnavailable
	}
	proxy, e := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		return result, ErrUnavailable
	}
	defer unix.Close(proxy)
	if unix.Bind(proxy, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}) != nil {
		return result, ErrUnavailable
	}
	addr, e := unix.Getsockname(proxy)
	if e != nil {
		return result, ErrUnavailable
	}
	env, e := egress.ProxyEnvironment([]string{"HOME=" + home, "CODEX_HOME=" + home, "PATH=/usr/bin:/bin", "LANG=C.UTF-8"}, uint16(addr.(*unix.SockaddrInet4).Port), nil)
	if e != nil {
		return result, ErrUnavailable
	}
	argv := append([]string{}, args...)
	for i, a := range argv {
		if a == "<schema-directory>" {
			argv[i] = filepath.Join(home, "schema")
		}
	}
	inR, inW, e := os.Pipe()
	if e != nil {
		return result, ErrUnavailable
	}
	defer inR.Close()
	defer inW.Close()
	outR, outW, e := os.Pipe()
	if e != nil {
		return result, ErrUnavailable
	}
	defer outR.Close()
	defer outW.Close()
	errR, errW, e := os.Pipe()
	if e != nil {
		return result, ErrUnavailable
	}
	defer errR.Close()
	defer errW.Close()
	stop := context.AfterFunc(ctx, func() { inW.Close(); outR.Close(); errR.Close() })
	defer stop()
	stderr := make(chan error, 1)
	go func() {
		_, e := boundedRead(errR, 65536)
		if e != nil {
			cancel()
		}
		stderr <- e
	}()
	output := make(chan struct {
		b []byte
		e error
	}, 1)
	go func() {
		var b []byte
		var e error
		if exchange != nil {
			b, e = exchange(ctx, inW, outR)
		} else {
			inW.Close()
			b, e = boundedRead(outR, limit)
		}
		if e != nil {
			cancel()
		}
		output <- struct {
			b []byte
			e error
		}{b, e}
	}()
	report, runErr := egress.Run(ctx, egress.Config{Launcher: "/proc/self/fd/5", LauncherArgs: []string{"--internal-qualification-candidate"}, Executable: "/proc/self/fd/4", Args: argv, Env: env, Policy: egress.Policy{MaxEvents: 4096}, Stdin: inR, Stdout: outW, Stderr: errW, ExtraFiles: []*os.File{f, launch}})
	outW.Close()
	errW.Close()
	inR.Close()
	b := <-output
	stderrErr := <-stderr
	isolation := false
	for _, event := range report.Events {
		if event.Class == "external" || event.Class == "unix" || ((event.Syscall == "connect" || event.Syscall == "sendto" || event.Syscall == "sendmsg" || event.Syscall == "sendmmsg") && event.Class == "other") {
			isolation = true
		}
	}
	if o.Evidence != nil {
		o.Evidence.Runs = append(o.Evidence.Runs, CandidateRun{name, append([]string{}, args...), report.Summary, report.Incomplete, isolation})
	}
	if runErr != nil || report.Incomplete || isolation || b.e != nil || stderrErr != nil || ctx.Err() != nil {
		return result, errors.Join(ErrUnavailable, runErr, b.e, stderrErr, ctx.Err())
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return result, ErrUnavailable
	}
	digest, e = hashFile(ctx, f)
	if e != nil || digest != o.ExecutableSHA256 {
		return result, ErrUnavailable
	}
	result.stdout = b.b
	if name == "schema/1" {
		result.schema, e = schemaDirectory(ctx, filepath.Join(home, "schema"))
		if e != nil {
			return candidateOutput{}, ErrUnavailable
		}
	}
	if ctx.Err() != nil {
		return candidateOutput{}, ErrUnavailable
	}
	return result, nil
}

func boundedRead(r io.Reader, limit int) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if e != nil || len(b) > limit {
		return nil, ErrUnavailable
	}
	return b, nil
}

func (o NativeObserver) Version(ctx context.Context) (string, error) {
	if o.Evidence != nil {
		o.Evidence.Version = Measurement{}
	}
	r, e := o.candidate(ctx, "version/1", []string{"--version"}, 256, nil)
	if e != nil {
		return "", e
	}
	if !bytes.Equal(r.stdout, []byte("codex-cli 0.163.0\n")) {
		return "", ErrUnavailable
	}
	if o.Evidence != nil {
		o.Evidence.Version = measure("version", []byte("0.163.0"))
	}
	return "0.163.0", nil
}

func (o NativeObserver) Schema(ctx context.Context) (Measurement, error) {
	if o.Evidence != nil {
		o.Evidence.SchemaComparison = "unavailable"
	}
	if _, e := o.Version(ctx); e != nil {
		return Measurement{}, ErrUnavailable
	}
	help, e := o.candidate(ctx, "schema-help/1", []string{"app-server", "--help"}, 65536, nil)
	if e != nil || !strings.Contains(string(help.stdout), "generate-json-schema") {
		return Measurement{}, ErrUnavailable
	}
	help, e = o.candidate(ctx, "schema-help/1", []string{"app-server", "generate-json-schema", "--help"}, 65536, nil)
	if e != nil || !strings.Contains(string(help.stdout), "--experimental") || !strings.Contains(string(help.stdout), "--out") {
		return Measurement{}, ErrUnavailable
	}
	args := []string{"app-server", "generate-json-schema", "--experimental", "--out", "<schema-directory>"}
	a, e := o.candidate(ctx, "schema/1", args, 65536, nil)
	if e != nil {
		return Measurement{}, ErrUnavailable
	}
	b, e := o.candidate(ctx, "schema/1", args, 65536, nil)
	if e != nil {
		return Measurement{}, ErrUnavailable
	}
	if !bytes.Equal(a.schema, b.schema) {
		if o.Evidence != nil {
			o.Evidence.SchemaComparison = "different"
		}
		return Measurement{}, ErrUnavailable
	}
	if o.Evidence != nil {
		o.Evidence.SchemaComparison = "equal"
	}
	return measure("schema", a.schema), nil
}
