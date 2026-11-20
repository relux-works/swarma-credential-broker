package assemblyv0

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

var updateVectors = flag.Bool("update-assembly-vectors", false, "rewrite synthetic construction vectors after source review")

const (
	vectorDirectory     = "testdata/construction-v0"
	specificationPath   = "spec/operator-and-activation-v0.md"
	specificationSHA256 = "feacdfe6e6cb551b9f175800ccd45eb8e09b299533bfad86e2607dace2834eb4"
	fixtureInstallation = "fixture-installation-v0"
	fixtureAccount      = "fixture/claude/subscription"
	fixtureOperation    = OperationID("00112233445566778899aabbccddeeff")
	fixtureBoot         = "11111111-2222-4333-8444-555555555555"
	fixtureToken        = "SYNTHETIC-ONLY-NOT-A-VENDOR-TOKEN"
)

const baselineSpecificationSHA256 = "e45be31c8b3701806b628d9fe6ca011c8a55e17969892a2e2f95b29bdeeeea87"

type sourceReference struct {
	Path          string `json:"path"`
	FirstLine     int    `json:"first_line"`
	LastLine      int    `json:"last_line"`
	ExcerptSHA256 string `json:"excerpt_sha256"`
}

type vectorEntry struct {
	File    string            `json:"file"`
	SHA256  string            `json:"sha256"`
	Claim   string            `json:"claim"`
	Sources []sourceReference `json:"sources"`
}

type vectorIndex struct {
	BaselineSpecSHA256 string        `json:"baseline_spec_sha256"`
	Construction       string        `json:"construction"`
	SpecSHA256         string        `json:"spec_sha256"`
	Unresolved         []string      `json:"unresolved"`
	Vectors            []vectorEntry `json:"vectors"`
}

type constructionVector struct {
	value   any
	bytes   []byte
	claim   string
	sources []sourceReference
}

func sourceLines(first, last int) sourceReference {
	return sealedSourceReference(specificationPath, first, last)
}

func digestBytes(data []byte) Digest {
	sum := sha256.Sum256(data)
	return Digest("sha256:" + hex.EncodeToString(sum[:]))
}

func canonicalBytes(value any) []byte {
	encoded, err := wire.Encode(value)
	if err != nil {
		panic("invalid synthetic fixture declaration")
	}
	return encoded
}

func actPreimage(body OperatorBody) []byte {
	return append([]byte(OperatorActDomain+"\n"), canonicalBytes(body)...)
}

func argumentsPreimage(body OperatorBody) []byte {
	return append([]byte(OperatorArgumentsDomain+"\n"+body.Method+"\n"), canonicalBytes(body.Arguments)...)
}

func enrollmentPreimage() []byte {
	identity := struct {
		InstallationID string      `json:"installation_id"`
		OperationID    OperationID `json:"operation_id"`
	}{fixtureInstallation, fixtureOperation}
	preimage := append([]byte(EnrollmentTokenDomain+"\n"), canonicalBytes(identity)...)
	return append(append(preimage, '\n'), []byte(fixtureToken)...)
}

func syntheticKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
}

func fixtureAuthority() AuthorityDocument {
	key := PublicKey("ed25519:" + base64.RawURLEncoding.EncodeToString(syntheticKey().Public().(ed25519.PublicKey)))
	pin := digestBytes([]byte("synthetic enforcement pin; not an installed executable"))
	return AuthorityDocument{
		Format: AuthorityFormat, InstallationID: fixtureInstallation, Revision: 1,
		Broker:          BrokerPin{4001, 4001, "swarma-credential-broker", "/opt/swarma/services/swarma-credential-broker"},
		Operator:        PrincipalPin{4002, "swarma-operator", "/var/empty/swarma-operator"},
		Observer:        PrincipalPin{4003, "swarma-observer", "/var/empty/swarma-observer"},
		OperatorEntry:   EntryPin{"/usr/libexec/swarma-credential-broker-operator-v0", pin},
		OperatorKey:     key,
		TerminalCallers: []PrincipalPin{{4004, "fixture-person", "/var/empty/fixture-person"}},
		TerminalAuth: TerminalAuth{
			SudoDigest: pin, SudoersDigest: pin, PAMService: "fixture-password-only", PAMDigest: pin,
			WitnessDigest: pin, ConfinementDigest: pin, LauncherDigest: pin, TrustedPathDigest: pin,
			LoginPaths: []LoginPath{{"ssh", "synthetic-login-not-a-selected-stack", pin, pin}},
		},
		Continuity: Continuity{"production"}, EventSchema: "broker-events/1",
		RootKeys: []PublicKey{key}, Dispatchers: []DispatcherPin{},
		Accounts: []AccountPolicy{{fixtureAccount, 4002, "claude_code", "claude-oauth-token", "secret-free", false}},
	}
}

func constructionVectors() map[string]constructionVector {
	vectors := map[string]constructionVector{}
	add := func(name string, value any, claim string, sources ...sourceReference) {
		vectors[name] = constructionVector{value, canonicalBytes(value), claim, sources}
	}
	addBytes := func(name string, data []byte, claim string, sources ...sourceReference) {
		vectors[name] = constructionVector{nil, data, claim, sources}
	}
	authority := fixtureAuthority()
	authorityDigest := digestBytes(canonicalBytes(authority))
	add("authority.json", authority, "Complete synthetic authority with explicit empty dispatchers and full-byte policy digest.", sourceLines(75, 85), sourceLines(785, 824))
	emptyAuthority := authority
	emptyAuthority.TerminalCallers = []PrincipalPin{}
	emptyAuthority.TerminalAuth.LoginPaths = []LoginPath{}
	emptyAuthority.RootKeys = []PublicKey{authority.OperatorKey}
	emptyAuthority.Accounts = []AccountPolicy{}
	add("authority-empty-arrays.json", emptyAuthority, "Required arrays are explicit, not null or omitted; empty facts grant no runtime authority.", sourceLines(75, 85), sourceLines(785, 824))
	activation := ActivationDocument{
		Format: ActivationFormat, Enabled: false, TestProfile: "v0", InstallationID: fixtureInstallation,
		PlatformRoot: "/opt/swarma", ServiceName: "credential-gateway", Kind: "claude-oauth-token",
		AuthorityDigest: authorityDigest, Continuity: Continuity{"production"},
	}
	add("activation-default.json", activation, "Disabled document with omitted lifetime; sole selector defaults to 900 seconds.", sourceLines(1415, 1437), sourceLines(1456, 1466), sourceLines(1516, 1525))
	for _, seconds := range []uint32{1, 900} {
		selected := activation
		selected.ServiceLeaseMaxLifetimeSeconds = &seconds
		add(fmt.Sprintf("activation-%d.json", seconds), selected, "Disabled document with an explicit admitted lifetime boundary, without clamping.", sourceLines(1415, 1437), sourceLines(1516, 1525))
	}
	activation.Enabled = true
	add("activation-enabled-synthetic.json", activation, "Structurally enabled test bytes only; no installed file, protected-source join or use authority.", sourceLines(1415, 1437), sourceLines(1476, 1496))
	prefixSum := sha256.Sum256(enrollmentPreimage())
	prefix := TokenPrefix(hex.EncodeToString(prefixSum[:16]))
	expiry := UTC("2030-02-01T00:00:00Z")
	cases := []struct {
		name      string
		method    string
		arguments OperatorArguments
	}{
		{"act-bind", "service.bind", BindArguments{fixtureOperation, "credential-gateway", 4006, "aabbccddeeff00112233445566778899", fixtureAccount, "claude-oauth-token", authorityDigest}},
		{"act-enrol-null", "account.enrol", EnrolArguments{fixtureOperation, fixtureAccount, "claude_code", "claude-oauth-token", nil, prefix}},
		{"act-enrol-expiry", "account.enrol", EnrolArguments{fixtureOperation, fixtureAccount, "claude_code", "claude-oauth-token", &expiry, prefix}},
		{"act-unbind", "service.unbind", UnbindArguments{fixtureOperation, "11223344556677889900aabbccddeeff"}},
		{"act-lift", "account.hold.lift", LiftArguments{fixtureOperation, "22334455667788990011aabbccddeeff", fixtureAccount}},
	}
	for position, entry := range cases {
		var freshness Freshness = UTCFreshness{"utc", "2030-01-01T00:00:00Z", "2030-01-01T00:05:00Z"}
		confirmation := "exact-content"
		if entry.method == "service.unbind" {
			freshness = BoottimeFreshness{"boottime", fixtureBoot, 1000, 301000}
			confirmation = "not-required"
		}
		body := OperatorBody{
			Format: OperatorActFormat, InstallationID: fixtureInstallation, AuthorityRevision: 1,
			AuthorityDigest: authorityDigest, Operator: authority.Operator, OperationID: fixtureOperation,
			Nonce: Nonce(fmt.Sprintf("%032x", position+1)), Freshness: freshness, Method: entry.method, Arguments: entry.arguments,
		}
		preimage := actPreimage(body)
		envelope := OperatorEnvelope{body, digestBytes(preimage), Signature(base64.RawURLEncoding.EncodeToString(ed25519.Sign(syntheticKey(), preimage)))}
		add(entry.name+".body.json", body, "Exact closed act body, method-specific freshness and equal inner/body operation identities.", sourceLines(409, 433), sourceLines(454, 488))
		addBytes(entry.name+".preimage", preimage, "Exact act domain, one LF, CCJ-1 body, no terminal LF; envelope id hashes these bytes.", sourceLines(435, 446))
		addBytes(entry.name+".arguments-preimage", argumentsPreimage(body), "Separate arguments domain, LF, exact method, LF and canonical complete arguments.", sourceLines(447, 450))
		add(entry.name+".envelope.json", envelope, "Closed envelope, recomputed id and deterministic signature from a public synthetic test seed only.", sourceLines(435, 446))
		var token *string
		if entry.method == "account.enrol" {
			material := fixtureToken
			token = &material
		}
		add(entry.name+".request.json", OperatorRequest{envelope, body.Nonce, token}, "Exactly act/receipt_nonce/token, with null token for every non-enrollment method.", sourceLines(518, 536))
		receipt := TerminalReceipt{
			Format: TerminalReceiptFormat, InstallationID: fixtureInstallation, AuthorityRevision: 1,
			AuthorityDigest: authorityDigest, ActID: envelope.ID, Nonce: body.Nonce, OperatorUID: authority.Operator.UID,
			TerminalCaller: authority.TerminalCallers[0], LoginSession: LoginSession{"ssh", 7, 4004, 100, 1234, authority.OperatorEntry.Digest},
			BootID: fixtureBoot, PeerPID: 101, PeerStartTicks: 1235, ExecutableDigest: authority.OperatorEntry.Digest,
			TTYDevice: TTYDevice{136, 1}, Freshness: freshness, Authentication: "password-sudo", Confirmation: confirmation,
		}
		add(entry.name+".receipt.json", receipt, "Closed synthetic root-receipt values; no token or arguments and no claim of protected provenance.", sourceLines(826, 850))
	}
	addBytes("enrollment-token.preimage", enrollmentPreimage(), "Synthetic token prefix preimage with exact scoped identity and domain; no real token.", sourceLines(469, 474))
	add("candidate-enrol.json", OperatorCandidate{"account.enrol", EnrolCandidateArguments{fixtureOperation, fixtureAccount, "claude_code", "claude-oauth-token", nil}}, "Pre-sudo enrollment candidate omits the derived token prefix; nullable vendor expiry is required.", sourceLines(91, 113), sourceLines(148, 151), sourceLines(458, 468))
	add("session-unbind.json", TerminalSession{
		Format: TerminalSessionFormat, InstallationID: fixtureInstallation, AuthorityRevision: 1,
		AuthorityDigest: authorityDigest, Nonce: "00000000000000000000000000000004", Operator: authority.Operator,
		TerminalCaller: authority.TerminalCallers[0], BrokerUID: authority.Broker.UID,
		SocketPath: "/opt/swarma/run/credential-broker/broker.sock", Freshness: BoottimeFreshness{"boottime", fixtureBoot, 1000, 301000},
		TTYDevice: TTYDevice{136, 1}, AccountPolicy: nil, Continuity: nil,
	}, "Unbind terminal session retains required null account_policy/continuity and the spec-pinned installed socket.", sourceLines(349, 364), sourceLines(1599, 1601), sealedSourceReference("spec/broker.md", 957, 957))
	session := vectors["session-unbind.json"].value.(TerminalSession)
	session.Freshness = UTCFreshness{"utc", "2030-01-01T00:00:00Z", "2030-01-01T00:05:00Z"}
	session.AccountPolicy = &SessionAccountPolicy{fixtureAccount, false}
	session.Continuity = &Continuity{"production"}
	add("session-widening.json", session, "Widening session has UTC freshness and protected non-null account policy and production continuity.", sourceLines(349, 364), sourceLines(424, 433), sourceLines(1599, 1601), sealedSourceReference("spec/broker.md", 957, 957))
	unicodeBody := vectors["act-lift.body.json"].value.(OperatorBody)
	unicodeArguments := unicodeBody.Arguments.(LiftArguments)
	unicodeArguments.Account = "fixture/λ/😀"
	unicodeBody.Arguments = unicodeArguments
	add("act-lift-unicode.body.json", unicodeBody, "Non-ASCII act members remain literal CCJ-1 UTF-8; display escaping is not signed or hashed.", sourceLines(485, 503))
	addBytes("act-lift-unicode.preimage", actPreimage(unicodeBody), "Act hashing uses literal UTF-8 rather than the reversible escaped display.", sourceLines(435, 446), sourceLines(499, 503))
	for _, kind := range []string{"lease_expiring", "lease_expired", "reauth_required"} {
		add("event-"+kind+".json", LeaseEvent{kind}, "Closed nonauthorizing tagged event without class or arbitrary metadata.", sourceLines(1055, 1061))
	}
	for _, class := range []string{"auth", "permission", "quota", "unknown"} {
		add("event-error-"+class+".json", CredentialErrorEvent{"credential_error", class}, "Closed credential_error class from the four allowed values.", sourceLines(1055, 1061))
	}
	grantBody := GrantBody{
		Type: "grant/1", Issuer: authority.OperatorKey, Subject: "agent:aabbccddeeff00112233445566778899",
		Actions: []string{"credential.lease"}, Accounts: []string{fixtureAccount}, Harnesses: []string{"claude_code"},
		Profiles: []string{"fixture"}, NotBefore: "2030-01-01T00:00:00Z", ExpiresAt: "2030-01-01T01:00:00Z", Depth: 0, Parent: nil,
	}
	grantPreimage := append([]byte("swarma-credential-broker grant/1\n"), canonicalBytes(grantBody)...)
	grant := GrantEnvelope{grantBody, digestBytes(grantPreimage), Signature(base64.RawURLEncoding.EncodeToString(ed25519.Sign(syntheticKey(), grantPreimage)))}
	add("grant-envelope.json", grant, "Unchanged baseline signed value shape with required null parent; no new root-delegation ceremony.", sealedSourceReference("spec/broker.md", 391, 413), sourceLines(81, 85))
	for _, target := range []struct {
		name   string
		target RevocationTarget
	}{{"grant", GrantTarget{grant.ID}}, {"key", KeyTarget{authority.OperatorKey}}} {
		body := RevocationBody{Type: "revocation/1", Revokes: target.target, By: authority.OperatorKey, At: "2030-01-01T00:00:00Z"}
		preimage := append([]byte("swarma-credential-broker revocation/1\n"), canonicalBytes(body)...)
		envelope := RevocationEnvelope{body, digestBytes(preimage), Signature(base64.RawURLEncoding.EncodeToString(ed25519.Sign(syntheticKey(), preimage)))}
		add("revocation-"+target.name+".json", envelope, "Unchanged baseline revocation target sum and omitted optional reason; no publication or revocation authority.", sealedSourceReference("spec/broker.md", 441, 453), sourceLines(81, 85))
		if target.name == "key" {
			reason := "synthetic revocation reason"
			body.Reason = &reason
			preimage = append([]byte("swarma-credential-broker revocation/1\n"), canonicalBytes(body)...)
			envelope = RevocationEnvelope{body, digestBytes(preimage), Signature(base64.RawURLEncoding.EncodeToString(ed25519.Sign(syntheticKey(), preimage)))}
			add("revocation-key-reason.json", envelope, "Signed key-target revocation with a non-empty optional string reason beside omitted/null controls.", sealedSourceReference("spec/broker.md", 441, 453))
		}
	}
	return vectors
}

// Claim: every stored vector has exact spec-bound bytes, a typed round trip and a sealed source index; these are not runtime admission tests.
func TestConstructionVectors(test *testing.T) {
	vectors := constructionVectors()
	names := make([]string, 0, len(vectors))
	for name := range vectors {
		names = append(names, name)
	}
	sort.Strings(names)
	index := vectorIndex{
		BaselineSpecSHA256: baselineSpecificationSHA256,
		Construction:       "C0-inactive", SpecSHA256: specificationSHA256,
		Unresolved: []string{"O-01: publication/acceptance", "O-07: enrollment result/reply", "O-09: producer/principal/effect/replacement", "O-19: engineering acceptance", "O-21: C excluded"},
	}
	for _, name := range names {
		vector := vectors[name]
		index.Vectors = append(index.Vectors, vectorEntry{name, string(digestBytes(vector.bytes)), vector.claim, vector.sources})
		test.Run(name, func(test *testing.T) {
			path := filepath.Join(vectorDirectory, name)
			if *updateVectors {
				if err := os.MkdirAll(vectorDirectory, 0755); err != nil {
					test.Fatal("cannot create vector directory")
				}
				if err := os.WriteFile(path, vector.bytes, 0644); err != nil {
					test.Fatal("cannot write vector")
				}
			}
			stored, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(stored, vector.bytes) {
				test.Fatal("exact vector bytes differ")
			}
			if vector.value == nil {
				return
			}
			decoded := reflect.New(reflect.TypeOf(vector.value)).Interface()
			if decodeFixture(stored, decoded) != nil || !bytes.Equal(canonicalBytes(decoded), stored) {
				test.Fatal("closed typed vector round trip failed")
			}
			if envelope, ok := vector.value.(OperatorEnvelope); ok {
				signature, err := base64.RawURLEncoding.DecodeString(string(envelope.Sig))
				public := syntheticKey().Public().(ed25519.PublicKey)
				if err != nil || !ed25519.Verify(public, actPreimage(envelope.Body), signature) {
					test.Fatal("synthetic envelope signature failed")
				}
			}
		})
	}
	indexBytes, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		test.Fatal("cannot encode vector index")
	}
	indexBytes = append(indexBytes, '\n')
	if *updateVectors {
		if err := os.WriteFile(filepath.Join(vectorDirectory, "index.json"), indexBytes, 0644); err != nil {
			test.Fatal("cannot write vector index")
		}
	}
	storedIndex, err := os.ReadFile(filepath.Join(vectorDirectory, "index.json"))
	if err != nil || !bytes.Equal(indexBytes, storedIndex) {
		test.Fatal("source/byte index differs")
	}
	entries, err := os.ReadDir(vectorDirectory)
	if err != nil || len(entries) != len(vectors)+1 {
		test.Fatal("unindexed or missing vector file")
	}
	baseline, err := os.ReadFile(filepath.Join("..", "..", "spec", "broker.md"))
	if err != nil || string(digestBytes(baseline)) != "sha256:"+baselineSpecificationSHA256 {
		test.Fatal("baseline grammar source pin changed; contract revision required")
	}
	specification, err := os.ReadFile(filepath.Join("..", "..", specificationPath))
	if err != nil || string(digestBytes(specification)) != "sha256:"+specificationSHA256 {
		test.Fatal("source specification pin changed; contract revision required")
	}
}
