// Package activationv0 implements inactive construction-time activation selection.
// Enabled selections are structural data, not permission to construct a use assembly.
package activationv0

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/assemblyv0"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

const (
	Path               = "/etc/swarma/credential-broker/activation-v0.json"
	maxBytes           = 16 * 1024
	maxLifetimeSeconds = 900
)

var (
	ErrRefused              = errors.New("activation refused")
	ErrUnacceptedContinuity = errors.New("STOP:O-21")
)

type State uint8

const (
	Refused State = iota
	Absent
	Inactive
	Enabled
)

type Selection struct {
	state    State
	document assemblyv0.ActivationDocument
	identity assemblyv0.FileIdentity
	source   []byte
	lifetime time.Duration
}

func (selection Selection) State() State { return selection.state }

func (selection Selection) ServiceLifetime() time.Duration { return selection.lifetime }

func (selection Selection) Document() assemblyv0.ActivationDocument {
	document := selection.document
	if document.ServiceLeaseMaxLifetimeSeconds != nil {
		seconds := *document.ServiceLeaseMaxLifetimeSeconds
		document.ServiceLeaseMaxLifetimeSeconds = &seconds
	}
	return document
}

func (selection Selection) Identity() assemblyv0.FileIdentity { return selection.identity }

func (selection Selection) Bytes() []byte { return bytes.Clone(selection.source) }

func (selection Selection) Digest() assemblyv0.Digest {
	if selection.state != Inactive && selection.state != Enabled {
		return ""
	}
	digest := sha256.Sum256(selection.source)
	return assemblyv0.Digest("sha256:" + hex.EncodeToString(digest[:]))
}

type Loader struct {
	Reader assemblyv0.ProtectedRead
}

func (loader Loader) Load(ctx context.Context, config policy.Config) (Selection, error) {
	if ctx == nil || loader.Reader == nil {
		return Selection{}, ErrRefused
	}
	if err := ctx.Err(); err != nil {
		return Selection{}, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	filePolicy := assemblyv0.ProtectedFilePolicy{UID: 0, GID: 0, Mode: 0644, Links: 1, MaxBytes: maxBytes}
	identity, source, err := loader.Reader.Read(ctx, Path, filePolicy)
	if contextErr := ctx.Err(); contextErr != nil {
		return Selection{}, fmt.Errorf("%w: %w", ErrRefused, contextErr)
	}
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && identity == (assemblyv0.FileIdentity{}) && len(source) == 0 {
			return Selection{state: Absent}, nil
		}
		return Selection{}, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	if identity.UID != filePolicy.UID || identity.GID != filePolicy.GID || identity.Mode != filePolicy.Mode || identity.Links != filePolicy.Links || identity.Size != int64(len(source)) || len(source) == 0 || len(source) > maxBytes {
		return Selection{}, ErrRefused
	}
	source = bytes.Clone(source)
	object, err := wire.Parse(source)
	if err != nil {
		return Selection{}, ErrRefused
	}
	if continuity, ok := object["continuity"].(map[string]any); ok && continuity["kind"] == "test-c" {
		return Selection{}, fmt.Errorf("%w: %w", ErrRefused, ErrUnacceptedContinuity)
	}
	seconds := int64(maxLifetimeSeconds)
	if member, present := object["service_lease_max_lifetime_seconds"]; present {
		var integral bool
		seconds, integral = member.(int64)
		if !integral || seconds < 1 || seconds > maxLifetimeSeconds {
			return Selection{}, ErrRefused
		}
	}
	var document assemblyv0.ActivationDocument
	if wire.Decode(source, &document) != nil || document.Format != assemblyv0.ActivationFormat || document.TestProfile != "v0" || document.InstallationID == "" || document.InstallationID != config.Policy.Installation || document.PlatformRoot != "/opt/swarma" || document.ServiceName != "credential-gateway" || document.Kind != "claude-oauth-token" || document.Continuity.Kind != "production" || !strings.HasPrefix(string(document.AuthorityDigest), "sha256:") || !policy.Hash(strings.TrimPrefix(string(document.AuthorityDigest), "sha256:")) {
		return Selection{}, ErrRefused
	}
	state := Inactive
	if document.Enabled {
		state = Enabled
	}
	return Selection{
		state:    state,
		document: document,
		identity: identity,
		source:   source,
		lifetime: time.Duration(seconds) * time.Second,
	}, nil
}
