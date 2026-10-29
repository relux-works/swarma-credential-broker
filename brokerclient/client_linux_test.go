//go:build linux

package brokerclient_test

import (
	"context"
	"errors"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/brokerclient"
)

// Claim: the zero/nil/failed observer API produces a closed typed error with a
// zero result; its method set cannot acquire/renew/release or send arbitrary RPC.
func TestObserverPublicRefusals(t *testing.T) {
	for _, o := range []*brokerclient.Observer{nil, {}} {
		r, err := o.Check(context.Background(), brokerclient.AllowlistRequest{})
		var refusal *brokerclient.Refusal
		if !errors.As(err, &refusal) || refusal.Code != "allowlist_unavailable" || r != (brokerclient.AllowlistResult{}) {
			t.Fatal("zero observer did not refuse")
		}
		if o.Close() != nil {
			t.Fatal("zero close")
		}
	}
	typ := reflect.TypeOf((*brokerclient.Observer)(nil))
	if typ.NumMethod() != 2 {
		t.Fatal("observer method surface widened")
	}
	for _, name := range []string{"Request", "Renew", "Release", "VerifyServer", "Call"} {
		if _, ok := typ.MethodByName(name); ok {
			t.Fatal("observer exports credential operation")
		}
	}
	if _, err := brokerclient.DialObserver(context.Background(), filepath.Join(t.TempDir(), "missing"), uint32(os.Geteuid())); err == nil {
		t.Fatal("missing socket became observer")
	}
}

// Claim: the public constructor/check accepts a complete bound response over a
// real same-UID protocol fixture. This is client behavior, not policy admission
// or a broker/observer cross-UID deployment qualification.
func TestObserverPublicPositive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := l.AcceptUnix()
		if e != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		raw, e := wire.Read(c)
		if e != nil {
			return
		}
		var hello wire.Request
		if wire.Decode(raw, &hello) != nil {
			return
		}
		wire.Write(c, map[string]any{"request_id": hello.ID, "result": map[string]any{"version": 1, "profile": wire.Profile, "principal": map[string]any{"uid": uint32(os.Geteuid())}, "policy_generation": uint64(1)}})
		raw, e = wire.Read(c)
		if e != nil {
			return
		}
		var request wire.Request
		if wire.Decode(raw, &request) != nil || request.Method != "allowlist.check" {
			return
		}
		var tuple wire.AllowlistRequest
		if wire.Decode(request.Params, &tuple) != nil {
			return
		}
		wire.Write(c, map[string]any{"request_id": request.ID, "result": wire.AllowlistResult{Tuple: tuple, Generation: 1, Decision: "allow"}})
	}()
	c, err := brokerclient.DialObserver(context.Background(), path, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r := brokerclient.AllowlistRequest{TargetUID: 42, Account: "example", Profile: "example", Harness: "codex_cli", Channel: "external-token", Binding: brokerclient.Binding{Digest: "binding", Harness: "codex_cli", Profile: "example", Account: "example", Channel: "external-token", Endpoint: "https://example.invalid", ExecutableSHA256: "executable", PolicyGeneration: 1}, ExpectedGeneration: 1}
	got, err := c.Check(context.Background(), r)
	if err != nil || got.Tuple != r || got.Generation != 1 || got.Decision != "allow" {
		t.Fatal("public observation failed")
	}
	<-done
}

// Claim: the public observer verifies real SO_PEERCRED before sending hello;
// the peer receives zero protocol bytes when its configured UID is wrong.
func TestObserverPeerBeforeBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan bool, 1)
	go func() {
		c, e := l.AcceptUnix()
		if e != nil {
			done <- false
			return
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(time.Second))
		var b [1]byte
		n, _ := c.Read(b[:])
		done <- n == 0
	}()
	_, err = brokerclient.DialObserver(context.Background(), path, uint32(os.Geteuid())+1)
	var refusal *brokerclient.Refusal
	if !errors.As(err, &refusal) || refusal.Code != "server_identity_mismatch" {
		t.Fatal("wrong broker identity admitted")
	}
	if !<-done {
		t.Fatal("protocol sent before identity check")
	}
}

// Claim: a genuinely different Go module imports and type-checks both APIs and
// runs caller-owned erasure without internal imports or source-tree mutation.
func TestExternalBrokerConsumer(t *testing.T) {
	goexe := os.Getenv("GO")
	if goexe == "" {
		goexe = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	mod := "module example.invalid/consumer\n\ngo 1.25\n\nrequire github.com/relux-works/swarma-credential-broker v0.0.0\nreplace github.com/relux-works/swarma-credential-broker => " + filepath.ToSlash(root) + "\n"
	source := `package consumer
import (
 "context"
 "testing"
 b "github.com/relux-works/swarma-credential-broker/brokerclient"
)
var _ func(context.Context,string)(b.Worker,error) = b.DialWorker
var _ func(context.Context,string,uint32)(*b.Observer,error) = b.DialObserver
func TestContract(t *testing.T) {
 binding:=b.Binding{Digest:"opaque-binding",PolicyGeneration:1}
 _=b.LeaseRequest{CredentialBinding:binding,Executor:b.Executor{Capabilities:[]string{"credential-injection/1"}}}
 _=b.AllowlistRequest{TargetUID:42,Binding:binding,ExpectedGeneration:1}
 _=b.AllowlistResult{}
 _=b.RenewRequest{}
 _=b.HelloRequest{Versions:[]int{1},Profile:b.ProtocolProfile}
 token:=[]byte("synthetic-material"); l:=b.Lease{Token:token};l.Erase()
 for _,v:=range token{if v!=0{t.Fatal("token not cleared")}}
 var o *b.Observer; if _,err:=o.Check(context.Background(),b.AllowlistRequest{});err==nil{t.Fatal("nil observation allowed")}
}
`
	if os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0600) != nil || os.WriteFile(filepath.Join(dir, "consumer_test.go"), []byte(source), 0600) != nil {
		t.Fatal("external fixture write")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, goexe, "test", "-mod=mod", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=local")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("external consumer failed: %v\n%s", err, out)
	}
}
