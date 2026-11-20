package qualify

import (
	"context"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/egress"
)

// Claim: an acknowledged post-startup pause preserves real entered observations
// until cancellation; ordinary clean exit and cancellation still run unaltered.
func TestOwnerCloseTimeoutSnapshotOverlay(t *testing.T) {
	ownerCloseTimeoutSnapshot(t, func(t *testing.T, ctx context.Context) (func(), <-chan struct{}) {
		armed, paused := make(chan struct{}), make(chan struct{})
		egress.OwnerCloseFixturePause = func(runContext context.Context) {
			select {
			case <-armed:
				select {
				case <-paused:
					return
				default:
					close(paused)
				}
				<-runContext.Done()
			case <-ctx.Done():
			default:
			}
		}
		t.Cleanup(func() { egress.OwnerCloseFixturePause = nil })
		return func() { close(armed) }, paused
	})
}
