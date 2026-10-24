//go:build linux && amd64

package qualification

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Claim: malformed schema data is refused through Schema, while valid Unicode
// and ordinary reordered data retain deterministic measurements.
func TestReviewSchemaParsing(t *testing.T) {
	for _, mode := range []string{"correct", "schema-surrogate-valid", "schema-utf8", "schema-trailing", "schema-depth", "schema-escaped-duplicate", "schema-hardlink", "schema-surrogate-high", "schema-surrogate-low", "schema-surrogate-drift"} {
		t.Run(mode, func(t *testing.T) {
			o, root := candidateObserver(t, mode)
			m, e := o.Schema(context.Background())
			valid := mode == "correct" || mode == "schema-surrogate-valid"
			if valid {
				want := Hash([]byte(`{"schema.json":{"a":1,"b":2}}`))
				if mode == "schema-surrogate-valid" {
					want = Hash([]byte(`{"schema.json":{"value":"😀"}}`))
				}
				if e != nil || m.SHA256 != want {
					t.Errorf("valid schema unavailable or wrong digest: %v", e)
				}
			} else if !errors.Is(e, ErrUnavailable) || m.SHA256 != "" {
				t.Errorf("malformed schema produced measurement: error=%v measured=%v comparison=%s", e, m.SHA256 != "", o.Evidence.SchemaComparison)
			}
			if !valid && o.Evidence.SchemaComparison == "equal" {
				t.Error("invalid schema declared equal")
			}
			noHomes(t, root)
		})
	}
}

// Claim: Catalog rejects duplicate/empty/malformed data and observes its
// documented 128-frame bound before and after the final model-list response.
func TestReviewCatalogParsing(t *testing.T) {
	for _, mode := range []string{"correct", "catalog-duplicate-model", "catalog-duplicate-effort", "catalog-duplicate-field", "catalog-empty-efforts", "catalog-null", "catalog-login-request", "catalog-refresh-request", "catalog-paginated", "catalog-cursor-repeat", "catalog-page-limit", "catalog-prefinal-limit", "catalog-tail126", "catalog-tail127"} {
		t.Run(mode, func(t *testing.T) {
			o, root := candidateObserver(t, mode)
			m, c, e := o.Catalog(context.Background())
			valid := mode == "correct" || mode == "catalog-tail126" || mode == "catalog-paginated"
			if valid {
				want := Hash([]byte(`{"models":[{"efforts":["low","medium"],"name":"fixture-model"}]}`))
				if mode == "catalog-paginated" {
					want = Hash([]byte(`{"models":[{"efforts":["low"],"name":"model-2"},{"efforts":["low"],"name":"model-3"}]}`))
				}
				if e != nil || m.SHA256 != want || len(c.Models) == 0 {
					t.Errorf("valid catalog unavailable or wrong digest: %v", e)
				}
			} else if !errors.Is(e, ErrUnavailable) || m.SHA256 != "" || len(c.Models) != 0 {
				t.Errorf("invalid catalog produced measurement: error=%v measured=%v models=%d", e, m.SHA256 != "", len(c.Models))
			}
			if mode == "catalog-paginated" && len(c.Models) != 2 {
				t.Errorf("two-page catalog count=%d", len(c.Models))
			}
			noHomes(t, root)
		})
	}
}

// Claim: malformed bootstrap requests return promptly without launching a
// candidate. An embedding test binary rejects the private flag before tests run.
func TestReviewBootstrapEntry(t *testing.T) {
	for _, args := range [][]string{nil, {"ordinary"}, {"--internal-qualification-candidate"}, {"--internal-qualification-candidate", "/not-a-descriptor"}} {
		handled, code := CandidateLauncherMain(args)
		want := len(args) > 0 && args[0] == "--internal-qualification-candidate"
		if handled != want || want && code != 125 {
			t.Fatal("entry dispatch mismatch", handled, code)
		}
	}
	self, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, self, "--internal-qualification-candidate", "/proc/self/fd/4")
	cmd.Env = []string{"CANDIDATE_TRACE_CHILD=1", "PATH=/usr/bin:/bin"}
	out, e := cmd.CombinedOutput()
	if ctx.Err() != nil || e == nil || len(out) > 65536 {
		t.Fatal("embedding did not promptly refuse private flag", e)
	}
}
