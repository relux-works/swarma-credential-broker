package authorityv0

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/relux-works/swarma-credential-broker/internal/assemblyv0"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/protectedio"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

const (
	AuthorityPath = "/etc/swarma/credential-broker/authority-v0.json"
	LockPath      = "/etc/swarma/credential-broker/authority.lock"
	DataRoot      = "/opt/swarma/services/swarma-credential-broker"
	StoreRoot     = DataRoot + "/store"
	SocketPath    = "/opt/swarma/run/credential-broker/broker.sock"
)

var ErrIdentityChanged = errors.New("principal_identity_changed")
var ErrContinuity = errors.New("STOP:O-21")

type StartupPins struct {
	AuthorityDigest assemblyv0.Digest
	Revision        uint64
	owner           *Reader
	contents        []byte
}

type paths struct {
	authority, lock, passwd, group, directory, data, store string
}

type filePolicy struct {
	path string
	file protectedio.FilePolicy
}

type directoryPolicy struct {
	path        string
	file        protectedio.FilePolicy
	ancestorUID uint32
}

type sourcePolicies struct {
	authority, lock, passwd, group filePolicy
	configuration, data, store     directoryPolicy
}

func (reader *Reader) sourcePolicies() sourcePolicies {
	return sourcePolicies{
		authority: filePolicy{path: reader.paths.authority, file: protectedio.FilePolicy{UID: reader.rootUID, GID: reader.brokerGID, Mode: 0640, Links: 1, MaxBytes: protectedio.MaxBytes}},
		lock:      filePolicy{path: reader.paths.lock, file: protectedio.FilePolicy{UID: reader.rootUID, GID: reader.brokerGID, Mode: 0640, Links: 1}},
		passwd:    filePolicy{path: reader.paths.passwd, file: protectedio.FilePolicy{UID: reader.rootUID, GID: reader.rootGID, Mode: 0644, Links: 1, MaxBytes: protectedio.MaxBytes}},
		group:     filePolicy{path: reader.paths.group, file: protectedio.FilePolicy{UID: reader.rootUID, GID: reader.rootGID, Mode: 0644, Links: 1, MaxBytes: protectedio.MaxBytes}},
		configuration: directoryPolicy{
			path: reader.paths.directory,
			file: protectedio.FilePolicy{UID: reader.rootUID, GID: reader.brokerGID, Mode: 0750}, ancestorUID: reader.rootUID,
		},
		data: directoryPolicy{
			path: reader.paths.data,
			file: protectedio.FilePolicy{UID: reader.brokerUID, GID: reader.brokerGID, Mode: 0700}, ancestorUID: reader.rootUID,
		},
		store: directoryPolicy{
			path: reader.paths.store,
			file: protectedio.FilePolicy{UID: reader.brokerUID, GID: reader.brokerGID, Mode: 0700}, ancestorUID: reader.brokerUID,
		},
	}
}

type protectedReader interface {
	assemblyv0.ProtectedRead
	CheckDirectory(context.Context, string, protectedio.FilePolicy, uint32) error
}

type Reader struct {
	config               policy.Config
	brokerUID, brokerGID uint32
	rootUID, rootGID     uint32
	paths                paths
	files                protectedReader
	newGate              func(context.Context, string, protectedio.FilePolicy) (protectedio.ConfigGate, error)
	mu                   sync.Mutex
	gate                 assemblyv0.ConfigGate
}

func New(config policy.Config) *Reader {
	config.Policy.ObserverUIDs = append([]uint32(nil), config.Policy.ObserverUIDs...)
	config.Policy.Accounts = append([]policy.Account(nil), config.Policy.Accounts...)
	for index := range config.Policy.Accounts {
		account := &config.Policy.Accounts[index]
		account.AllowedUIDs = append([]uint32(nil), account.AllowedUIDs...)
		account.Profiles = append([]string(nil), account.Profiles...)
	}
	return &Reader{config: config, files: protectedio.Reader{}, newGate: protectedio.NewConfigGate, brokerUID: uint32(os.Geteuid()), brokerGID: uint32(os.Getegid()), paths: paths{
		authority: AuthorityPath, lock: LockPath, passwd: "/etc/passwd", group: "/etc/group",
		directory: "/etc/swarma/credential-broker", data: DataRoot, store: StoreRoot,
	}}
}

func digest(contents []byte) assemblyv0.Digest {
	sum := sha256.Sum256(contents)
	return assemblyv0.Digest("sha256:" + hex.EncodeToString(sum[:]))
}

func (reader *Reader) configGate(ctx context.Context) (assemblyv0.ConfigGate, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if reader.gate == nil {
		lock := reader.sourcePolicies().lock
		gate, err := reader.newGate(ctx, lock.path, lock.file)
		if err != nil {
			return nil, ErrIdentityChanged
		}
		reader.gate = gate
	}
	return reader.gate, nil
}

func (reader *Reader) directories(ctx context.Context) error {
	policies := reader.sourcePolicies()
	for _, entry := range []directoryPolicy{
		policies.configuration,
		policies.data,
		policies.store,
	} {
		if reader.files.CheckDirectory(ctx, entry.path, entry.file, entry.ancestorUID) != nil {
			return ErrIdentityChanged
		}
	}
	return nil
}

type snapshot struct {
	document                 assemblyv0.AuthorityDocument
	authority, passwd, group []byte
}

func (reader *Reader) current(ctx context.Context, use bool) (snapshot, error) {
	var result snapshot
	policies := reader.sourcePolicies()
	if reader.directories(ctx) != nil {
		return result, ErrIdentityChanged
	}
	var err error
	_, result.authority, err = reader.files.Read(ctx, policies.authority.path, policies.authority.file)
	if err != nil {
		return snapshot{}, ErrIdentityChanged
	}
	if _, err := wire.Parse(result.authority); err != nil || wire.Decode(result.authority, &result.document) != nil {
		return snapshot{}, ErrIdentityChanged
	}
	if result.document.Continuity.Kind != "production" {
		return snapshot{}, ErrContinuity
	}
	if !validIdentity(result.document, reader.brokerUID, reader.brokerGID) {
		return snapshot{}, ErrIdentityChanged
	}
	for _, target := range []struct {
		destination *[]byte
		policy      filePolicy
	}{
		{&result.passwd, policies.passwd}, {&result.group, policies.group},
	} {
		_, *target.destination, err = reader.files.Read(ctx, target.policy.path, target.policy.file)
		if err != nil {
			return snapshot{}, ErrIdentityChanged
		}
	}
	if !directoryJoins(result.document, result.passwd, result.group) || use && !reader.equalConfig(result.document) {
		return snapshot{}, ErrIdentityChanged
	}
	return result, nil
}

func (reader *Reader) window(ctx context.Context, pins *StartupPins, use bool, callback func(context.Context, snapshot) error) error {
	if ctx == nil || callback == nil || reader == nil {
		return ErrIdentityChanged
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if pins != nil && (pins.owner != reader || len(pins.contents) == 0 || digest(pins.contents) != pins.AuthorityDigest) {
		return ErrIdentityChanged
	}
	gate, err := reader.configGate(ctx)
	if err != nil {
		return err
	}
	return gate.WithRead(ctx, func(ctx context.Context) error {
		current, err := reader.current(ctx, use)
		if err != nil {
			return err
		}
		if pins != nil && (current.document.Revision != pins.Revision || !bytes.Equal(current.authority, pins.contents)) {
			return ErrIdentityChanged
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := callback(ctx, current); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		after, err := reader.current(ctx, use)
		if err != nil {
			return err
		}
		if !bytes.Equal(current.authority, after.authority) || !bytes.Equal(current.passwd, after.passwd) || !bytes.Equal(current.group, after.group) {
			return ErrIdentityChanged
		}
		return ctx.Err()
	})
}

func (reader *Reader) Load(ctx context.Context) (assemblyv0.AuthorityDocument, StartupPins, error) {
	var document assemblyv0.AuthorityDocument
	var pins StartupPins
	err := reader.window(ctx, nil, true, func(ctx context.Context, current snapshot) error {
		document = current.document
		pins = StartupPins{AuthorityDigest: digest(current.authority), Revision: document.Revision, owner: reader, contents: append([]byte(nil), current.authority...)}
		return nil
	})
	if err != nil {
		return assemblyv0.AuthorityDocument{}, StartupPins{}, err
	}
	return document, pins, nil
}

func (reader *Reader) WithPinned(ctx context.Context, pins StartupPins, callback func(context.Context, assemblyv0.AuthorityDocument) error) error {
	if callback == nil {
		return ErrIdentityChanged
	}
	return reader.window(ctx, &pins, true, func(ctx context.Context, current snapshot) error { return callback(ctx, current.document) })
}

func (reader *Reader) WithIdentity(ctx context.Context, callback func(context.Context, assemblyv0.AuthorityDocument) error) error {
	if callback == nil {
		return ErrIdentityChanged
	}
	return reader.window(ctx, nil, false, func(ctx context.Context, current snapshot) error { return callback(ctx, current.document) })
}

func absolute(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsAny(path, "\x00\r\n")
}

func publicKey(key assemblyv0.PublicKey) bool {
	if !strings.HasPrefix(string(key), "ed25519:") {
		return false
	}
	encoded := strings.TrimPrefix(string(key), "ed25519:")
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == encoded
}

func validIdentity(document assemblyv0.AuthorityDocument, uid, gid uint32) bool {
	if uid == 0 || gid == 0 || document.Format != assemblyv0.AuthorityFormat || document.InstallationID == "" || document.Revision == 0 || document.Revision > assemblyv0.MaxSafeInteger || document.EventSchema != "broker-events/1" || document.Broker.UID != uid || document.Broker.GID != gid || document.Broker.Name != "swarma-credential-broker" || document.Broker.Home != DataRoot || document.Operator.Name != "swarma-operator" || document.Observer.Name != "swarma-observer" || document.OperatorEntry.Path != "/usr/libexec/swarma-credential-broker-operator-v0" {
		return false
	}
	for _, value := range []assemblyv0.Digest{document.OperatorEntry.Digest, document.TerminalAuth.SudoDigest, document.TerminalAuth.SudoersDigest, document.TerminalAuth.PAMDigest, document.TerminalAuth.WitnessDigest, document.TerminalAuth.ConfinementDigest, document.TerminalAuth.LauncherDigest, document.TerminalAuth.TrustedPathDigest} {
		if !validDigest(value) {
			return false
		}
	}
	if document.TerminalAuth.PAMService == "" {
		return false
	}
	logins := map[assemblyv0.LoginPath]bool{}
	for _, login := range document.TerminalAuth.LoginPaths {
		if logins[login] || login.Kind != "ssh" || login.Implementation == "" || !validDigest(login.ExecutableDigest) || !validDigest(login.ConfigDigest) {
			return false
		}
		logins[login] = true
	}
	roles := map[uint32]bool{uid: true}
	for _, pin := range append([]assemblyv0.PrincipalPin{document.Operator, document.Observer}, document.TerminalCallers...) {
		if roles[pin.UID] || pin.UID == 0 || pin.Name == "" || strings.ContainsAny(pin.Name, ":\x00\r\n") || !absolute(pin.Home) {
			return false
		}
		roles[pin.UID] = true
	}
	for _, pin := range document.Dispatchers {
		if roles[pin.UID] || pin.UID == 0 || len(pin.Generation) != 32 || !policy.Hash(string(pin.Generation)+string(pin.Generation)) || !publicKey(pin.Key) {
			return false
		}
		roles[pin.UID] = true
	}
	return true
}

func validDigest(value assemblyv0.Digest) bool {
	return strings.HasPrefix(string(value), "sha256:") && policy.Hash(strings.TrimPrefix(string(value), "sha256:"))
}

func (reader *Reader) equalConfig(document assemblyv0.AuthorityDocument) bool {
	config := reader.config
	if config.Policy.Installation != document.InstallationID || config.Policy.BrokerUID != document.Broker.UID || config.SocketPath != SocketPath || config.StoreRoot != StoreRoot || len(config.Policy.ObserverUIDs) != 1 || config.Policy.ObserverUIDs[0] != document.Observer.UID || len(config.Policy.Accounts) != len(document.Accounts) || !publicKey(document.OperatorKey) {
		return false
	}
	roots := map[assemblyv0.PublicKey]bool{}
	for _, key := range document.RootKeys {
		if roots[key] || !publicKey(key) {
			return false
		}
		roots[key] = true
	}
	if !roots[document.OperatorKey] {
		return false
	}
	accounts := map[string]bool{}
	for _, account := range document.Accounts {
		if account.Account == "" || accounts[account.Account] || account.OwnerUID != document.Operator.UID || account.Harness != "claude_code" || account.Kind != "claude-oauth-token" || account.Mode != "secret-free" {
			return false
		}
		accounts[account.Account] = true
	}
	for _, account := range config.Policy.Accounts {
		if !accounts[account.Label] || !account.Enabled || len(account.AllowedUIDs) != 0 {
			return false
		}
		delete(accounts, account.Label)
	}
	return len(accounts) == 0
}

func number(value string) (uint32, bool) {
	parsed, err := strconv.ParseUint(value, 10, 32)
	return uint32(parsed), err == nil && strconv.FormatUint(parsed, 10) == value
}

func directoryJoins(document assemblyv0.AuthorityDocument, passwd, groups []byte) bool {
	byUID := map[uint32][]string{}
	byName := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(string(passwd), "\n"), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 7 || fields[0] == "" || byName[fields[0]] {
			return false
		}
		uid, validUID := number(fields[2])
		gid, validGID := number(fields[3])
		if !validUID || !validGID || byUID[uid] != nil || gid == document.Broker.GID && uid != document.Broker.UID {
			return false
		}
		byUID[uid], byName[fields[0]] = fields, true
	}
	broker := byUID[document.Broker.UID]
	if len(broker) != 7 || broker[0] != document.Broker.Name || broker[5] != document.Broker.Home || broker[3] != strconv.FormatUint(uint64(document.Broker.GID), 10) {
		return false
	}
	for _, pin := range append([]assemblyv0.PrincipalPin{document.Operator, document.Observer}, document.TerminalCallers...) {
		entry := byUID[pin.UID]
		if len(entry) != 7 || entry[0] != pin.Name || entry[5] != pin.Home {
			return false
		}
	}
	seenGID := map[uint32]bool{}
	seenName := map[string]bool{}
	matched := false
	for _, line := range strings.Split(strings.TrimSuffix(string(groups), "\n"), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 4 || fields[0] == "" || seenName[fields[0]] {
			return false
		}
		gid, valid := number(fields[2])
		if !valid || seenGID[gid] {
			return false
		}
		seenGID[gid], seenName[fields[0]] = true, true
		if gid == document.Broker.GID || fields[0] == document.Broker.Name {
			if gid != document.Broker.GID || fields[0] != document.Broker.Name || fields[3] != "" && fields[3] != document.Broker.Name {
				return false
			}
			matched = true
		}
	}
	return matched
}
