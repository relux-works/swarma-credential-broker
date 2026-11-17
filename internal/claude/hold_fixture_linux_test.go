//go:build linux

package claude

// Hold is a test-only legacy metadata fixture, unavailable to production code.
// It is not the section 5.8 service hold: that hold changes no account state
// and is owned exclusively by the service journal and its authenticated RPC.
func (a *Account) Hold() error {
	if a == nil {
		return ErrUnavailable
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	m, err := a.readMetadata()
	if err != nil {
		return err
	}
	// Reserve a readable successor inside the local canonical integer bound.
	if m.Revision >= 9007199254740990 {
		return ErrUnavailable
	}
	// Even an observed held record is republished durably: a previous attempt
	// may have failed after rename but before directory sync. Reading that
	// record through a fresh wrapper cannot itself acknowledge durability.
	prior := m.Revision
	m.Revision++
	m.Status.State = "held"
	if err = a.store.Put(metadataName, prior, m); err != nil {
		a.failed = true
		return ErrUnavailable
	}
	return nil
}
