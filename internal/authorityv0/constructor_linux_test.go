package authorityv0

import (
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/protectedio"
	"github.com/relux-works/swarma-credential-broker/timeconf"
)

// Claim: without field overrides, New binds the literal spec 4.1/4.3 source table to root and the non-root process, not the distinct configured broker; this is not a provisioning test.
func TestNewProductionPolicies(test *testing.T) {
	brokerUID, brokerGID := uint32(os.Geteuid()), uint32(os.Getegid())
	if brokerUID == 0 || brokerGID == 0 {
		test.Fatal("production constructor witness requires a non-root process UID and GID")
	}
	configuredUID := brokerUID + 7000
	if configuredUID == 0 || configuredUID == brokerUID {
		test.Fatal("production constructor witness requires a distinct non-root configured broker")
	}
	reader := New(policy.Config{Policy: policy.Policy{BrokerUID: configuredUID}})
	expected := sourcePolicies{
		authority: filePolicy{path: "/etc/swarma/credential-broker/authority-v0.json", file: protectedio.FilePolicy{UID: 0, GID: brokerGID, Mode: 0640, Links: 1, MaxBytes: 1 << 20}},
		lock:      filePolicy{path: "/etc/swarma/credential-broker/authority.lock", file: protectedio.FilePolicy{UID: 0, GID: brokerGID, Mode: 0640, Links: 1, MaxBytes: 0}},
		passwd:    filePolicy{path: "/etc/passwd", file: protectedio.FilePolicy{UID: 0, GID: 0, Mode: 0644, Links: 1, MaxBytes: 1 << 20}},
		group:     filePolicy{path: "/etc/group", file: protectedio.FilePolicy{UID: 0, GID: 0, Mode: 0644, Links: 1, MaxBytes: 1 << 20}},
		configuration: directoryPolicy{
			path: "/etc/swarma/credential-broker",
			file: protectedio.FilePolicy{UID: 0, GID: brokerGID, Mode: 0750, Links: 0, MaxBytes: 0}, ancestorUID: 0,
		},
		data: directoryPolicy{
			path: "/opt/swarma/services/swarma-credential-broker",
			file: protectedio.FilePolicy{UID: brokerUID, GID: brokerGID, Mode: 0700, Links: 0, MaxBytes: 0}, ancestorUID: 0,
		},
		store: directoryPolicy{
			path: "/opt/swarma/services/swarma-credential-broker/store",
			file: protectedio.FilePolicy{UID: brokerUID, GID: brokerGID, Mode: 0700, Links: 0, MaxBytes: 0}, ancestorUID: brokerUID,
		},
	}
	if actual := reader.sourcePolicies(); actual != expected {
		test.Fatalf("production New() source table differs: got %+v want %+v", actual, expected)
	}
}

// Claim: New preserves all supplied configuration values and privately copies the operational authority-duplicate slices; no deep-copy claim is made for the time-confidence policy.
func TestNewPreservesConfiguration(test *testing.T) {
	configuration := func() policy.Config {
		return policy.Config{
			SocketPath: "/synthetic/broker.sock", StoreRoot: "/synthetic/store",
			Policy: policy.Policy{
				TimeConfidence: &timeconf.Policy{
					Source: timeconf.NTSConfig, Chronyc: "/synthetic/chronyc", SourceFiles: []string{"/synthetic/time.conf"},
					MaxSyncAge: time.Second, MaxUncertainty: 2 * time.Millisecond, MaxOffset: 3 * time.Millisecond,
					MaxRootDistance: 4 * time.Millisecond, AuthorityWindow: 5 * time.Millisecond,
					BackwardTolerance: 6 * time.Millisecond, StepTolerance: 7 * time.Millisecond,
					Timeout: 8 * time.Millisecond, MaxOutputBytes: 4096, Resync: "operator",
				},
				Installation: "synthetic-installation", Generation: 9, BrokerUID: 7000,
				Executable: "/synthetic/executor", ExecutableSHA256: "synthetic-digest", MaxLeaseSeconds: 30,
				ObserverUIDs: []uint32{7001, 7002},
				Accounts: []policy.Account{{
					Label: "synthetic-account", VendorID: "synthetic-vendor", AllowedUIDs: []uint32{7003, 7004}, Profiles: []string{"first", "second"},
					Endpoint: "synthetic-endpoint", ReleaseVersion: "synthetic-release", QualificationID: "synthetic-qualification",
					Enabled: true, NetworkRequired: true,
				}},
			},
		}
	}
	config, expected := configuration(), configuration()
	reader := New(config)
	if !reflect.DeepEqual(reader.config, expected) {
		test.Fatalf("constructor changed configuration values: got %+v want %+v", reader.config, expected)
	}
	config.Policy.ObserverUIDs[0]++
	config.Policy.Accounts[0].AllowedUIDs[0]++
	config.Policy.Accounts[0].Profiles[0] = "changed"
	config.Policy.Accounts[0].Label = "changed"
	if !reflect.DeepEqual(reader.config, expected) {
		test.Fatal("constructor retained caller-owned operational authority slices")
	}
	if zero := New(policy.Config{}); !reflect.DeepEqual(zero.config, policy.Config{}) {
		test.Fatal("constructor changed zero configuration")
	}
}

// Claim: New captures process IDs, keeps root IDs zero, and starts with a zero mutex and no lazily acquired configuration gate.
func TestNewInitialState(test *testing.T) {
	reader := New(policy.Config{})
	if reader.brokerUID != uint32(os.Geteuid()) || reader.brokerGID != uint32(os.Getegid()) || reader.rootUID != 0 || reader.rootGID != 0 {
		test.Fatalf("constructor identity state differs: broker=%d:%d root=%d:%d", reader.brokerUID, reader.brokerGID, reader.rootUID, reader.rootGID)
	}
	if !reflect.ValueOf(&reader.mu).Elem().IsZero() || reader.gate != nil {
		test.Fatal("constructor must leave mutex zero and configuration gate unacquired")
	}
}
