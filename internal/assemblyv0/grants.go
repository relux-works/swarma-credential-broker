package assemblyv0

type GrantBody struct {
	Type      string    `json:"type"`
	Issuer    PublicKey `json:"issuer"`
	Subject   string    `json:"subject"`
	Actions   []string  `json:"actions"`
	Accounts  []string  `json:"accounts"`
	Harnesses []string  `json:"harnesses"`
	Profiles  []string  `json:"profiles"`
	NotBefore UTC       `json:"not_before"`
	ExpiresAt UTC       `json:"expires_at"`
	Depth     uint64    `json:"depth"`
	Parent    *Digest   `json:"parent"`
}

type GrantEnvelope struct {
	Body GrantBody `json:"body"`
	ID   Digest    `json:"id"`
	Sig  Signature `json:"sig"`
}

type RevocationTarget interface{ revocationTarget() }

type GrantTarget struct {
	Grant Digest `json:"grant"`
}

type KeyTarget struct {
	Key PublicKey `json:"key"`
}

func (GrantTarget) revocationTarget() {}
func (KeyTarget) revocationTarget()   {}

type RevocationBody struct {
	Type    string           `json:"type"`
	Revokes RevocationTarget `json:"revokes"`
	By      PublicKey        `json:"by"`
	At      UTC              `json:"at"`
	Reason  *string          `json:"reason,omitempty"`
}

type RevocationEnvelope struct {
	Body RevocationBody `json:"body"`
	ID   Digest         `json:"id"`
	Sig  Signature      `json:"sig"`
}

type Chain []GrantEnvelope
