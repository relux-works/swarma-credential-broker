//go:build linux && realmanager

package authowner

import (
	"context"
	"errors"
	"os/exec"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// Claim: completed writer units remain available until terminal evidence is
// durable, including when the original owner's D-Bus connection disappears.
func TestProbeManagerConnectionRetention(t *testing.T) {
	for _, mode := range []string{"connected-control", "replacement-connection"} {
		t.Run(mode, func(t *testing.T) {
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
			active := m
			if mode == "replacement-connection" {
				next, err := NewSystemd(ctx, prefix, m.daemon)
				if err != nil {
					t.Fatal("replacement connection", err)
				}
				// Preserve the test's cleanup route before deliberately dropping the owner connection.
				original := m.conn
				m.conn = next.conn
				active = next
				if err = original.Close(); err != nil {
					t.Fatal("close original connection", err)
				}
			}
			after, err := active.Stop(ctx, name, before)
			if err != nil || !confirmed(Binding{Unit: name, Identity: before.Identity}, before, after) {
				var path dbus.ObjectPath
				lookup := active.conn.Object(destination, managerPath).CallWithContext(ctx, destination+".Manager.GetUnit", 0, name).Store(&path)
				t.Fatalf("terminal unit evidence unavailable after stop: stop=%v lookup_not_found=%t", err, noUnit(lookup))
			}
			// Stop must leave terminal readback available until the caller persists it.
			retained, readErr := active.Observe(ctx, name)
			if readErr != nil || !retained.Complete || retained.Invocation != before.Invocation || retained.Properties != before.Properties {
				t.Fatal("terminal unit was released before durable publication", readErr)
			}
			// Recovery can repeat a stop before publication; this must not leak references.
			repeated, stopErr := active.Stop(ctx, name, before)
			if stopErr != nil || !confirmed(Binding{Unit: name, Identity: before.Identity}, before, repeated) {
				t.Fatal("repeated stop lost terminal evidence", stopErr)
			}
			if err = active.Unload(ctx, name); err != nil {
				t.Fatal("unload", err)
			}
			// Wait for our own explicit retirement, then verify missing never means absent.
			testutilAwait(t, func() bool {
				var path dbus.ObjectPath
				return noUnit(active.conn.Object(destination, managerPath).CallWithContext(ctx, destination+".Manager.GetUnit", 0, name).Store(&path))
			})
			missing, stopErr := active.Stop(ctx, name, before)
			if !errors.Is(stopErr, ErrUnavailable) || missing.StopCompleted || missing.Complete {
				t.Fatal("collected unit became confirmed absence", stopErr)
			}
		})
	}
}

// Claim: the standard real-manager subset includes the connection replacement regression.
func TestRealManagerConnectionRetention(t *testing.T) { TestProbeManagerConnectionRetention(t) }
