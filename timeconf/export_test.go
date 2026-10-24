package timeconf

// ParseSources exposes the standalone parser only to tests. Production source
// inventories must use the protected recursive reader in SystemCollector.
func ParseSources(b []byte) (Sources, error) {
	return parseSources(b, false, nil)
}
