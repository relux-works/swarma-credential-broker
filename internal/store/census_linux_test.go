package store

import (
	"errors"
	"testing"
)

// Claim: an empty-account census reads no record payload: any extra entry, including an unreadable/dangling record, prevents fresh initialization; lost protection is unavailable, never empty.
func TestAccountRecordCensus(test *testing.T) {
	for _, name := range []string{"owner-material.json", "pending-owner-service.json"} {
		test.Run(name, func(test *testing.T) {
			_, account := fresh(test, nil)
			if present, err := account.HasRecords(); err != nil || present {
				test.Fatal("empty account control refused", present, err)
			}
			if err := account.root.Symlink("nonexistent-inert-record", name); err != nil {
				test.Fatal(err)
			}
			if present, err := account.HasRecords(); err != nil || !present {
				test.Fatal("record census opened a payload or claimed nonempty state was fresh", present, err)
			}
			if err := account.root.Chmod(".", 0755); err != nil {
				test.Fatal(err)
			}
			if present, err := account.HasRecords(); !errors.Is(err, ErrUnavailable) || present {
				test.Fatal("lost protection became fresh state", present, err)
			}
		})
	}
	var account *Account
	if present, err := account.HasRecords(); !errors.Is(err, ErrUnavailable) || present {
		test.Fatal("nil store became empty", present, err)
	}
}
