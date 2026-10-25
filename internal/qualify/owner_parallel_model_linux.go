//go:build linux

package qualify

import (
	"errors"

	"github.com/relux-works/swarma-credential-broker/internal/authowner"
)

// Only the parent event loop touches the persistent ledger. Each session keeps
// its own immutable context; no contender overwrites another session's context.
type parallelService struct {
	c      ownerContext
	ledger *lifecycleModel
}

func (s *parallelService) setContext(c ownerContext) { s.c = c }
func (s *parallelService) serve(ch *ownerChannel, r ownerMessage) error {
	local := *s.ledger
	local.c = s.c
	e := local.serve(ch, r)
	original := s.ledger.c
	*s.ledger = local
	s.ledger.c = original
	return e
}
func (m *lifecycleModel) successorOrder(cp authowner.Checkpoint, is []authowner.Intent, es []authowner.Evidence) error {
	if len(m.writers) != 1 || len(m.inputs) != 1 || !m.inputs[0].After.Complete || !m.inputs[0].After.StopCompleted || !m.inputs[0].After.Empty || !m.inputs[0].After.PopulatedZero || cp.TokenGeneration != 2 || cp.StoreGeneration != 2 || cp.RetainedAttempts != 1 || len(is) != 2 || len(es) != 5 {
		return errors.New("successor before complete Stop and committed history")
	}
	for i, e := range es {
		if e.Attempt != m.writers[0].fact.Attempt || e.Phase != []string{"submitted", "running", "stopping", "absent", "resolved"}[i] || i == 4 && e.Outcome != authowner.Committed {
			return errors.New("successor history binding")
		}
	}
	return nil
}
