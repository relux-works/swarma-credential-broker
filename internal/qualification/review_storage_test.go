//go:build linux

package qualification

import (
	"context"
	"errors"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"os"
	"path/filepath"
	"testing"
)

// Claim: all listed records need protected, present evidence, including an
// unmatched tuple before or after the matching tuple; valid one-entry control.
func TestReviewWholeListEvidence(t *testing.T) {
	for _, position := range []string{"before", "after"} {
		for _, mode := range []string{"missing-record", "bad-record", "record-mode", "record-symlink", "missing-artifact", "bad-artifact", "artifact-mode", "missing-approval", "bad-approval", "approval-mode", "valid"} {
			t.Run(position+"/"+mode, func(t *testing.T) {
				r, _, rec := fixtureRepository(t)
				check(t, r.Publish(context.Background(), rec))
				other := retupleFixture(t, r, rec)
				raw, e := wire.Encode(other)
				check(t, e)
				ref := Hash(raw)
				rp := filepath.Join(r.Path, "record-"+ref+".json")
				check(t, os.WriteFile(rp, raw, 0600))
				switch mode {
				case "missing-record":
					check(t, os.Remove(rp))
				case "bad-record":
					raw = []byte("{}")
					ref = Hash(raw)
					check(t, os.WriteFile(filepath.Join(r.Path, "record-"+ref+".json"), raw, 0600))
				case "record-mode":
					check(t, os.Chmod(rp, 0644))
				case "record-symlink":
					check(t, os.Rename(rp, rp+".original"))
					check(t, os.Symlink(rp+".original", rp))
				case "missing-artifact":
					check(t, os.Remove(filepath.Join(r.Path, "artifact-"+other.Cases[0].Positive.Artifacts[0]+".json")))
				case "bad-artifact":
					check(t, os.WriteFile(filepath.Join(r.Path, "artifact-"+other.Cases[0].Positive.Artifacts[0]+".json"), []byte("{}"), 0600))
				case "artifact-mode":
					check(t, os.Chmod(filepath.Join(r.Path, "artifact-"+other.Cases[0].Positive.Artifacts[0]+".json"), 0644))
				case "missing-approval":
					check(t, os.Remove(filepath.Join(r.Path, "approval-"+other.Approval+".json")))
				case "bad-approval":
					check(t, os.WriteFile(filepath.Join(r.Path, "approval-"+other.Approval+".json"), []byte("{}"), 0600))
				case "approval-mode":
					check(t, os.Chmod(filepath.Join(r.Path, "approval-"+other.Approval+".json"), 0644))
				}
				path := filepath.Join(r.Path, "qualified.json")
				raw, e = os.ReadFile(path)
				check(t, e)
				var list List
				check(t, wire.Decode(raw, &list))
				entry := Entry{Identity: other.Identity, Evidence: ref}
				if position == "before" {
					list.Entries = append([]Entry{entry}, list.Entries...)
				} else {
					list.Entries = append(list.Entries, entry)
				}
				raw, e = wire.Encode(list)
				check(t, e)
				check(t, os.WriteFile(path, raw, 0600))
				sealFixtureList(t, r.Path, raw)
				_, _, e = r.Read(context.Background())
				if mode == "valid" {
					check(t, e)
				} else if !errors.Is(e, ErrUnavailable) && !errors.Is(e, ErrInvalid) {
					t.Fatal("read admitted tuple despite unvalidated record elsewhere in list")
				}
			})
		}
	}
}

// retupleFixture writes synthetic source metadata only; no qualification row ran.
func retupleFixture(t *testing.T, r Repository, rec Record) Record {
	t.Helper()
	b, e := wire.Encode(rec)
	check(t, e)
	other, e := DecodeRecord(b)
	check(t, e)
	other.Identity.Executable = measure("executable", []byte("different executable"))
	other.Approval, e = r.PutApproval(Approval{"qualification-approval/1", other.Identity, "matched", true})
	check(t, e)
	for n, c := range other.Cases {
		for _, side := range []string{"positive", "negative"} {
			x := c.Positive
			if side == "negative" {
				x = c.Negative
			}
			x.Artifacts = []string{}
			ref, e := r.PutArtifact(Artifact{"qualification-case/1", other.Identity, c.ID, side, x})
			check(t, e)
			x.Artifacts = []string{ref}
			if side == "positive" {
				other.Cases[n].Positive = x
			} else {
				other.Cases[n].Negative = x
			}
		}
	}
	return other
}

// Claim: publishers exclude each other and readers while active, including a
// reader that acquired its lock first; stale fences remain fail-closed.
func TestReviewPublicationLocks(t *testing.T) {
	for _, mode := range []string{"publisher-active", "reader-active", "stale-fence", "success"} {
		t.Run(mode, func(t *testing.T) {
			r, _, rec := fixtureRepository(t)
			if mode == "stale-fence" {
				check(t, os.WriteFile(filepath.Join(r.Path, "in-progress"), []byte("stale"), 0600))
				if r.Publish(context.Background(), rec) == nil {
					t.Fatal("stale fence ignored")
				}
				reject(t, r)
				return
			}
			if mode == "reader-active" {
				check(t, r.Publish(context.Background(), rec))
				root, e := r.root(false)
				check(t, e)
				defer root.Close()
				l, e := r.lock(root, 1)
				check(t, e)
				if r.Publish(context.Background(), rec) == nil {
					t.Fatal("publisher ignored reader lock")
				}
				l.Close()
				check(t, r.Publish(context.Background(), rec))
				return
			}
			if mode == "publisher-active" {
				r.Fault = func(at string) error {
					if at == "after-evidence-flush" {
						second := r
						second.Fault = nil
						if second.Publish(context.Background(), rec) == nil {
							t.Error("concurrent publisher admitted")
						}
						reject(t, second)
					}
					return nil
				}
			}
			check(t, r.Publish(context.Background(), rec))
			_, _, e := r.Read(context.Background())
			check(t, e)
		})
	}
}
