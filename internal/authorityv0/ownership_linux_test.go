package authorityv0

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/assemblyv0"
	"github.com/relux-works/swarma-credential-broker/internal/protectedio"
)

// Claim: every production source policy matches spec 4.1/4.3 with distinct root/broker IDs; the real-filesystem paired controls separately witness enforcement, not privileged provisioning.
func TestSourceOwnershipPolicies(test *testing.T) {
	fixture := newFixture(test)
	validWindow(test, fixture)
	reader := &Reader{rootUID: 100, rootGID: 200, brokerUID: 300, brokerGID: 400}
	actual := reader.sourcePolicies()
	for _, row := range []struct {
		name     string
		actual   protectedio.FilePolicy
		expected protectedio.FilePolicy
	}{
		{"authority", actual.authority, protectedio.FilePolicy{UID: 100, GID: 400, Mode: 0640, Links: 1, MaxBytes: 1 << 20}},
		{"lock", actual.lock, protectedio.FilePolicy{UID: 100, GID: 400, Mode: 0640, Links: 1}},
		{"passwd", actual.passwd, protectedio.FilePolicy{UID: 100, GID: 200, Mode: 0644, Links: 1, MaxBytes: 1 << 20}},
		{"group", actual.group, protectedio.FilePolicy{UID: 100, GID: 200, Mode: 0644, Links: 1, MaxBytes: 1 << 20}},
	} {
		test.Run(row.name, func(test *testing.T) {
			if row.actual != row.expected {
				test.Fatalf("source ownership policy differs from spec: got %+v want %+v", row.actual, row.expected)
			}
		})
	}
	for _, row := range []struct {
		name     string
		actual   directoryPolicy
		expected directoryPolicy
	}{
		{"configuration", actual.configuration, directoryPolicy{file: protectedio.FilePolicy{UID: 100, GID: 400, Mode: 0750}, ancestorUID: 100}},
		{"data", actual.data, directoryPolicy{file: protectedio.FilePolicy{UID: 300, GID: 400, Mode: 0700}, ancestorUID: 100}},
		{"store", actual.store, directoryPolicy{file: protectedio.FilePolicy{UID: 300, GID: 400, Mode: 0700}, ancestorUID: 300}},
	} {
		test.Run(row.name, func(test *testing.T) {
			if row.actual != row.expected {
				test.Fatalf("directory ownership policy differs from spec: got %+v want %+v", row.actual, row.expected)
			}
		})
	}
}

// Claim: a prepended UID alias or unrelated duplicate GID refuses current identity without a callback; the original protected fixture admits both identity and pinned use first.
func TestDirectoryUniquenessWitnesses(test *testing.T) {
	for _, name := range []string{"prepended-passwd-uid", "unrelated-group-gid"} {
		test.Run(name, func(test *testing.T) {
			fixture := newFixture(test)
			validWindow(test, fixture)
			switch name {
			case "prepended-passwd-uid":
				fixture.passwd = fmt.Sprintf("alias:x:%d:5500::%s:/bin/sh\n", fixture.document.Operator.UID, fixture.document.Operator.Home) + fixture.passwd
				write(test, fixture.reader.paths.passwd, []byte(fixture.passwd), 0644)
			case "unrelated-group-gid":
				fixture.group += "unrelated-one:x:65001:\nunrelated-two:x:65001:\n"
				write(test, fixture.reader.paths.group, []byte(fixture.group), 0644)
			}
			called := false
			err := fixture.reader.WithIdentity(context.Background(), func(context.Context, assemblyv0.AuthorityDocument) error { called = true; return nil })
			if !errors.Is(err, ErrIdentityChanged) || called {
				test.Fatalf("ambiguous directory admitted: %v callback=%v", err, called)
			}
		})
	}
}

// Claim: repeated root keys refuse startup without returning a document or pins, beside a valid unchanged startup and identity control.
func TestRootKeyUniquenessWitness(test *testing.T) {
	fixture := newFixture(test)
	validWindow(test, fixture)
	fixture.document.RootKeys = append(fixture.document.RootKeys, fixture.document.RootKeys[0])
	fixture.publish(test)
	document, pins, err := fixture.reader.Load(context.Background())
	if !errors.Is(err, ErrIdentityChanged) || document.Format != "" || pins.owner != nil {
		test.Fatalf("duplicate root key admitted: %v", err)
	}
}

// Claim: broker UID zero and GID zero independently refuse the identity predicate; other directory and format facts remain valid in each negative.
func TestNonRootBrokerWitness(test *testing.T) {
	for _, name := range []string{"uid", "gid"} {
		test.Run(name, func(test *testing.T) {
			fixture := newFixture(test)
			validWindow(test, fixture)
			document := fixture.document
			if !validIdentity(document, document.Broker.UID, document.Broker.GID) {
				test.Fatal("valid non-root broker identity refused")
			}
			if name == "uid" {
				document.Broker.UID = 0
			} else {
				document.Broker.GID = 0
			}
			if validIdentity(document, document.Broker.UID, document.Broker.GID) {
				test.Fatal("root broker identity admitted")
			}
		})
	}
}
