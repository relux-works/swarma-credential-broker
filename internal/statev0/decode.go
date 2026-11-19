package statev0

import (
	"encoding/json"

	"github.com/relux-works/swarma-credential-broker/internal/assemblyv0"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

func (receipt *OperationReceipt) UnmarshalJSON(data []byte) error {
	var fields struct {
		Nonce          assemblyv0.Nonce        `json:"nonce"`
		TerminalCaller assemblyv0.PrincipalPin `json:"terminal_caller"`
		BootID         string                  `json:"boot_id"`
		PeerPID        uint64                  `json:"peer_pid"`
		PeerStartTicks uint64                  `json:"peer_start_ticks"`
		Freshness      json.RawMessage         `json:"freshness"`
	}
	if wire.Decode(data, &fields) != nil {
		return wire.ErrMalformed
	}
	freshness, err := decodeFreshness(fields.Freshness)
	if err != nil {
		return err
	}
	*receipt = OperationReceipt{fields.Nonce, fields.TerminalCaller, fields.BootID, fields.PeerPID, fields.PeerStartTicks, freshness}
	return nil
}

func decodeFreshness(data []byte) (assemblyv0.Freshness, error) {
	object, err := wire.Parse(data)
	if err != nil {
		return nil, wire.ErrMalformed
	}
	switch object["kind"] {
	case "utc":
		var freshness assemblyv0.UTCFreshness
		if wire.Decode(data, &freshness) == nil {
			return freshness, nil
		}
	case "boottime":
		var freshness assemblyv0.BoottimeFreshness
		if wire.Decode(data, &freshness) == nil {
			return freshness, nil
		}
	}
	return nil, wire.ErrMalformed
}

func (state *BaselineRevocationState) UnmarshalJSON(data []byte) error {
	var fields struct {
		Seq     uint64            `json:"seq"`
		Records []json.RawMessage `json:"records"`
	}
	if wire.Decode(data, &fields) != nil {
		return wire.ErrMalformed
	}
	records := make([]assemblyv0.RevocationEnvelope, len(fields.Records))
	for position, record := range fields.Records {
		decoded, err := decodeRevocation(record)
		if err != nil {
			return err
		}
		records[position] = decoded
	}
	*state = BaselineRevocationState{fields.Seq, records}
	return nil
}

func decodeRevocation(data []byte) (assemblyv0.RevocationEnvelope, error) {
	var envelope struct {
		Body json.RawMessage      `json:"body"`
		ID   assemblyv0.Digest    `json:"id"`
		Sig  assemblyv0.Signature `json:"sig"`
	}
	var body struct {
		Type    string               `json:"type"`
		Revokes json.RawMessage      `json:"revokes"`
		By      assemblyv0.PublicKey `json:"by"`
		At      assemblyv0.UTC       `json:"at"`
		Reason  *string              `json:"reason,omitempty"`
	}
	if wire.Decode(data, &envelope) != nil || wire.Decode(envelope.Body, &body) != nil {
		return assemblyv0.RevocationEnvelope{}, wire.ErrMalformed
	}
	object, err := wire.Parse(envelope.Body)
	if err != nil {
		return assemblyv0.RevocationEnvelope{}, wire.ErrMalformed
	}
	if reason, present := object["reason"]; present && reason == nil {
		return assemblyv0.RevocationEnvelope{}, wire.ErrMalformed
	}
	target, err := wire.Parse(body.Revokes)
	if err != nil || len(target) != 1 {
		return assemblyv0.RevocationEnvelope{}, wire.ErrMalformed
	}
	var revokes assemblyv0.RevocationTarget
	if _, present := target["grant"]; present {
		var grant assemblyv0.GrantTarget
		if wire.Decode(body.Revokes, &grant) != nil {
			return assemblyv0.RevocationEnvelope{}, wire.ErrMalformed
		}
		revokes = grant
	} else if _, present := target["key"]; present {
		var key assemblyv0.KeyTarget
		if wire.Decode(body.Revokes, &key) != nil {
			return assemblyv0.RevocationEnvelope{}, wire.ErrMalformed
		}
		revokes = key
	} else {
		return assemblyv0.RevocationEnvelope{}, wire.ErrMalformed
	}
	return assemblyv0.RevocationEnvelope{Body: assemblyv0.RevocationBody{Type: body.Type, Revokes: revokes, By: body.By, At: body.At, Reason: body.Reason}, ID: envelope.ID, Sig: envelope.Sig}, nil
}
