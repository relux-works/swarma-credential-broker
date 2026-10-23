//go:build linux && realmanager

package authowner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// Claim: a RefUnit reply lost after the manager applies it must not create an
// extra retained reference on retry. An uncertain reply must keep Stop/Unload
// unavailable; a successful reply permits one unload and collection.
// The interceptor delays only that reply; production Stop/Unload are unchanged.
func TestProbeReferenceReplyTiming(t *testing.T) {
	for _, fault := range []bool{false, true} {
		t.Run(fmt.Sprintf("delayed-reply-%t", fault), func(t *testing.T) {
			m, prefix, add := realManager(t)
			name := prefix + "writer.service"
			add(name)
			cat, err := exec.LookPath("cat")
			if err != nil {
				t.Fatal(err)
			}
			spec, _, _ := realSpec(t, m, name, cat, t.TempDir(), nil, 120*time.Second)
			before := startReal(t, m, spec)
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			next, err := NewSystemd(ctx, prefix, m.daemon)
			if err != nil {
				t.Fatal(err)
			}
			next.Close()
			var references atomic.Uint32
			var target atomic.Uint32
			var captured atomic.Bool
			received := make(chan struct{})
			release := make(chan struct{})
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			conn, err := dbus.Dial(fmt.Sprintf("unix:path=/run/user/%d/bus", os.Geteuid()),
				dbus.WithOutgoingInterceptor(func(msg *dbus.Message) {
					if msg.Type == dbus.TypeMethodCall && msg.Headers[dbus.FieldMember].Value() == "RefUnit" {
						references.Add(1)
						if fault && target.Load() == 0 {
							target.Store(msg.Serial())
						}
					}
				}),
				dbus.WithIncomingInterceptor(func(msg *dbus.Message) {
					if fault && msg.Type == dbus.TypeMethodReply && target.Load() != 0 && msg.Headers[dbus.FieldReplySerial].Value() == target.Load() && captured.CompareAndSwap(false, true) {
						close(received)
						<-release
					}
				}))
			if err != nil {
				t.Fatal(err)
			}
			next.conn = conn
			defer next.Close()
			if conn.Auth([]dbus.Auth{dbus.AuthExternal(strconv.Itoa(os.Geteuid()))}) != nil || conn.Hello() != nil {
				t.Fatal("instrumented connection setup")
			}
			if conn.Object(destination, managerPath).CallWithContext(ctx, destination+".Manager.Subscribe", 0).Err != nil {
				t.Fatal("subscribe")
			}
			// Preserve an independent cleanup connection, then close the original owner.
			cleanup, err := NewSystemd(ctx, prefix, m.daemon)
			if err != nil {
				t.Fatal(err)
			}
			original := m.conn
			m.conn = cleanup.conn
			if err = original.Close(); err != nil {
				t.Fatal(err)
			}
			if fault {
				limited, stopCancel := context.WithCancel(ctx)
				done := make(chan error, 1)
				go func() { _, e := next.Stop(limited, name, before); done <- e }()
				select {
				case <-received:
				case <-ctx.Done():
					stopCancel()
					t.Fatal("target reply not observed")
				}
				stopCancel()
				select {
				case e := <-done:
					if !errors.Is(e, ErrUnavailable) {
						t.Fatal("lost reply did not refuse", e)
					}
				case <-ctx.Done():
					t.Fatal("stop did not cancel")
				}
				close(release)
			}
			if fault {
				after, stopErr := next.Stop(ctx, name, before)
				if !errors.Is(stopErr, ErrUnavailable) || after.Complete || after.StopCompleted {
					t.Fatal("uncertain reference admitted retry", stopErr)
				}
				// Stop through the independent cleanup connection so the unknown
				// retention check is also exercised on a genuinely terminal unit.
				if m.job(ctx, name, "StopUnit", "replace") != nil {
					t.Fatal("independent fixture stop")
				}
				terminal, readErr := next.Observe(ctx, name)
				if readErr != nil || !terminal.Complete || terminal.Active != "inactive" && terminal.Active != "failed" {
					t.Fatal("uncertain reference lost terminal retention", readErr)
				}
				if err = next.Unload(ctx, name); !errors.Is(err, ErrUnavailable) {
					t.Fatal("uncertain reference reported clean unload", err)
				}
				if references.Load() != 1 {
					t.Fatal("uncertain reference was acquired twice", references.Load())
				}
				// Closing only this owned connection releases its possible reference.
				// Independently confirm collection; failure cleanup also uses exact names.
				next.Close()
				testutilAwait(t, func() bool {
					var path dbus.ObjectPath
					return noUnit(m.conn.Object(destination, managerPath).CallWithContext(ctx, destination+".Manager.GetUnit", 0, name).Store(&path))
				})
				return
			}
			after, err := next.Stop(ctx, name, before)
			if err != nil || !confirmed(Binding{Unit: name, Identity: before.Identity}, before, after) {
				t.Fatal("retry/control stop", err)
			}
			if err = next.Unload(ctx, name); err != nil {
				t.Fatal("unload", err)
			}
			// Bounded exact-name polling distinguishes a retained unit from asynchronous GC.
			end := time.Now().Add(300 * time.Millisecond)
			for {
				var path dbus.ObjectPath
				err = conn.Object(destination, managerPath).CallWithContext(ctx, destination+".Manager.GetUnit", 0, name).Store(&path)
				if noUnit(err) {
					return
				}
				if err != nil {
					t.Fatal("lookup", err)
				}
				if time.Now().After(end) {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			// One additional unref is an independent witness of the excess counted ref.
			if conn.Object(destination, managerPath).CallWithContext(ctx, destination+".Manager.UnrefUnit", 0, name).Err != nil {
				t.Fatal("extra reference witness")
			}
			testutilAwait(t, func() bool {
				var p dbus.ObjectPath
				return noUnit(conn.Object(destination, managerPath).CallWithContext(ctx, destination+".Manager.GetUnit", 0, name).Store(&p))
			})
			t.Fatal("one Unload left an extra sender reference after uncertain RefUnit; a second Unref collected the unit")
		})
	}
}

// Claim: replacement connection loss, before or after stop, must not be
// reconstructed as confirmed absence by a later replacement.
func TestProbeReplacementConnectionLoss(t *testing.T) {
	for _, stopped := range []bool{false, true} {
		t.Run(fmt.Sprintf("stopped-%t", stopped), func(t *testing.T) {
			m, prefix, add := realManager(t)
			name := prefix + "writer.service"
			add(name)
			cat, err := exec.LookPath("cat")
			if err != nil {
				t.Fatal(err)
			}
			spec, _, _ := realSpec(t, m, name, cat, t.TempDir(), nil, 120*time.Second)
			before := startReal(t, m, spec)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			next, err := NewSystemd(ctx, prefix, m.daemon)
			if err != nil {
				t.Fatal(err)
			}
			cleanup, err := NewSystemd(ctx, prefix, m.daemon)
			if err != nil {
				next.Close()
				t.Fatal(err)
			}
			original := m.conn
			m.conn = cleanup.conn
			original.Close()
			if stopped {
				after, err := next.Stop(ctx, name, before)
				if err != nil || !confirmed(Binding{Unit: name, Identity: before.Identity}, before, after) {
					next.Close()
					t.Fatal("first stop", err)
				}
			}
			next.Close()
			after, err := next.Stop(ctx, name, before)
			if !errors.Is(err, ErrUnavailable) || after.Complete || after.StopCompleted {
				t.Fatal("lost connection accepted absence")
			}
			if stopped {
				testutilAwait(t, func() bool {
					var p dbus.ObjectPath
					return noUnit(m.conn.Object(destination, managerPath).CallWithContext(ctx, destination+".Manager.GetUnit", 0, name).Store(&p))
				})
				after, err = m.Stop(ctx, name, before)
				if !errors.Is(err, ErrUnavailable) || after.Complete || after.StopCompleted {
					t.Fatal("collected terminal unit accepted absence")
				}
			}
		})
	}
}

// Claim: the normal tagged manager subset includes delayed-reference and loss controls.
func TestRealReferenceReplyTiming(t *testing.T)      { TestProbeReferenceReplyTiming(t) }
func TestRealReplacementConnectionLoss(t *testing.T) { TestProbeReplacementConnectionLoss(t) }
