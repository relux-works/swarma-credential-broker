// Package assemblyv0 declares inactive construction values, not admission or authority.
// Its construction contract is docs/assembly-v0-construction-contract.md.
package assemblyv0

const (
	OperatorActFormat       = "swarma-broker-operator-act/1"
	OperatorActDomain       = "swarma-credential-broker operator-act/1"
	OperatorArgumentsDomain = "swarma-credential-broker operator-arguments/1"
	EnrollmentTokenDomain   = "swarma-credential-broker enrollment-token/1"
	AuthorityFormat         = "swarma-broker-authority/1"
	ActivationFormat        = "swarma-broker-activation/1"
	TerminalSessionFormat   = "swarma-broker-terminal-session/1"
	TerminalReceiptFormat   = "swarma-broker-terminal-receipt/1"
	MaxSafeInteger          = uint64(9007199254740991)
)

type Digest string
type OperationID string
type Nonce string
type Generation string
type TokenPrefix string
type PublicKey string
type Signature string
type UTC string

type PrincipalPin struct {
	UID  uint32 `json:"uid"`
	Name string `json:"name"`
	Home string `json:"home"`
}

type BrokerPin struct {
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid"`
	Name string `json:"name"`
	Home string `json:"home"`
}

type Freshness interface{ freshness() }

type UTCFreshness struct {
	Kind      string `json:"kind"`
	NotBefore UTC    `json:"not_before"`
	ExpiresAt UTC    `json:"expires_at"`
}

type BoottimeFreshness struct {
	Kind        string `json:"kind"`
	BootID      string `json:"boot_id"`
	NotBeforeMS uint64 `json:"not_before_ms"`
	ExpiresAtMS uint64 `json:"expires_at_ms"`
}

func (UTCFreshness) freshness()      {}
func (BoottimeFreshness) freshness() {}

// Continuity has only the production form; the unaccepted C form is not declared.
type Continuity struct {
	Kind string `json:"kind"`
}

type EntryPin struct {
	Path   string `json:"path"`
	Digest Digest `json:"digest"`
}

type LoginPath struct {
	Kind             string `json:"kind"`
	Implementation   string `json:"implementation"`
	ExecutableDigest Digest `json:"executable_digest"`
	ConfigDigest     Digest `json:"config_digest"`
}

type TerminalAuth struct {
	SudoDigest        Digest      `json:"sudo_digest"`
	SudoersDigest     Digest      `json:"sudoers_digest"`
	PAMService        string      `json:"pam_service"`
	PAMDigest         Digest      `json:"pam_digest"`
	WitnessDigest     Digest      `json:"witness_digest"`
	ConfinementDigest Digest      `json:"confinement_digest"`
	LauncherDigest    Digest      `json:"launcher_digest"`
	TrustedPathDigest Digest      `json:"trusted_path_digest"`
	LoginPaths        []LoginPath `json:"login_paths"`
}

type DispatcherPin struct {
	UID        uint32     `json:"uid"`
	Generation Generation `json:"generation"`
	Key        PublicKey  `json:"key"`
}

type AccountPolicy struct {
	Account          string `json:"account"`
	OwnerUID         uint32 `json:"owner_uid"`
	Harness          string `json:"harness"`
	Kind             string `json:"kind"`
	Mode             string `json:"mode"`
	TestSubscription bool   `json:"test_subscription"`
}

type AuthorityDocument struct {
	Format          string          `json:"format"`
	InstallationID  string          `json:"installation_id"`
	Revision        uint64          `json:"revision"`
	Broker          BrokerPin       `json:"broker"`
	Operator        PrincipalPin    `json:"operator"`
	Observer        PrincipalPin    `json:"observer"`
	OperatorEntry   EntryPin        `json:"operator_entry"`
	OperatorKey     PublicKey       `json:"operator_key"`
	TerminalCallers []PrincipalPin  `json:"terminal_callers"`
	TerminalAuth    TerminalAuth    `json:"terminal_auth"`
	Continuity      Continuity      `json:"continuity"`
	EventSchema     string          `json:"event_schema"`
	RootKeys        []PublicKey     `json:"root_keys"`
	Dispatchers     []DispatcherPin `json:"dispatchers"`
	Accounts        []AccountPolicy `json:"accounts"`
}

type ActivationDocument struct {
	Format                         string     `json:"format"`
	Enabled                        bool       `json:"enabled"`
	TestProfile                    string     `json:"test_profile"`
	InstallationID                 string     `json:"installation_id"`
	PlatformRoot                   string     `json:"platform_root"`
	ServiceName                    string     `json:"service_name"`
	Kind                           string     `json:"kind"`
	AuthorityDigest                Digest     `json:"authority_digest"`
	Continuity                     Continuity `json:"continuity"`
	ServiceLeaseMaxLifetimeSeconds *uint32    `json:"service_lease_max_lifetime_seconds,omitempty"`
}

type LoginSession struct {
	Kind                  string `json:"kind"`
	ID                    uint64 `json:"id"`
	LoginUID              uint32 `json:"loginuid"`
	LoginPID              uint64 `json:"login_pid"`
	LoginStartTicks       uint64 `json:"login_start_ticks"`
	LoginExecutableDigest Digest `json:"login_executable_digest"`
}

type TTYDevice struct {
	Major uint64 `json:"major"`
	Minor uint64 `json:"minor"`
}

type SessionAccountPolicy struct {
	Account          string `json:"account"`
	TestSubscription bool   `json:"test_subscription"`
}

type TerminalSession struct {
	Format            string                `json:"format"`
	InstallationID    string                `json:"installation_id"`
	AuthorityRevision uint64                `json:"authority_revision"`
	AuthorityDigest   Digest                `json:"authority_digest"`
	Nonce             Nonce                 `json:"nonce"`
	Operator          PrincipalPin          `json:"operator"`
	TerminalCaller    PrincipalPin          `json:"terminal_caller"`
	BrokerUID         uint32                `json:"broker_uid"`
	SocketPath        string                `json:"socket_path"`
	Freshness         Freshness             `json:"freshness"`
	TTYDevice         TTYDevice             `json:"tty_device"`
	AccountPolicy     *SessionAccountPolicy `json:"account_policy"`
	Continuity        *Continuity           `json:"continuity"`
}

type TerminalReceipt struct {
	Format            string       `json:"format"`
	InstallationID    string       `json:"installation_id"`
	AuthorityRevision uint64       `json:"authority_revision"`
	AuthorityDigest   Digest       `json:"authority_digest"`
	ActID             Digest       `json:"act_id"`
	Nonce             Nonce        `json:"nonce"`
	OperatorUID       uint32       `json:"operator_uid"`
	TerminalCaller    PrincipalPin `json:"terminal_caller"`
	LoginSession      LoginSession `json:"login_session"`
	BootID            string       `json:"boot_id"`
	PeerPID           uint64       `json:"peer_pid"`
	PeerStartTicks    uint64       `json:"peer_start_ticks"`
	ExecutableDigest  Digest       `json:"executable_digest"`
	TTYDevice         TTYDevice    `json:"tty_device"`
	Freshness         Freshness    `json:"freshness"`
	Authentication    string       `json:"authentication"`
	Confirmation      string       `json:"confirmation"`
}

type OperatorArguments interface{ operatorArguments() }
type CandidateArguments interface{ candidateArguments() }

type BindArguments struct {
	OperationID              OperationID `json:"operation_id"`
	ServiceName              string      `json:"service_name"`
	UID                      uint32      `json:"uid"`
	ServiceGeneration        Generation  `json:"service_generation"`
	Account                  string      `json:"account"`
	Kind                     string      `json:"kind"`
	InstallationPolicyDigest Digest      `json:"installation_policy_digest"`
}

type EnrolArguments struct {
	OperationID       OperationID `json:"operation_id"`
	Account           string      `json:"account"`
	Harness           string      `json:"harness"`
	Kind              string      `json:"kind"`
	TokenExpiresAt    *UTC        `json:"token_expires_at"`
	TokenSHA256Prefix TokenPrefix `json:"token_sha256_prefix"`
}

type EnrolCandidateArguments struct {
	OperationID    OperationID `json:"operation_id"`
	Account        string      `json:"account"`
	Harness        string      `json:"harness"`
	Kind           string      `json:"kind"`
	TokenExpiresAt *UTC        `json:"token_expires_at"`
}

type UnbindArguments struct {
	OperationID      OperationID `json:"operation_id"`
	ServiceBindingID string      `json:"service_binding_id"`
}

type LiftArguments struct {
	OperationID OperationID `json:"operation_id"`
	HoldID      string      `json:"hold_id"`
	Account     string      `json:"account"`
}

func (BindArguments) operatorArguments()   {}
func (EnrolArguments) operatorArguments()  {}
func (UnbindArguments) operatorArguments() {}
func (LiftArguments) operatorArguments()   {}

func (BindArguments) candidateArguments()           {}
func (EnrolCandidateArguments) candidateArguments() {}
func (UnbindArguments) candidateArguments()         {}
func (LiftArguments) candidateArguments()           {}

type OperatorCandidate struct {
	Method    string             `json:"method"`
	Arguments CandidateArguments `json:"arguments"`
}

type OperatorBody struct {
	Format            string            `json:"format"`
	InstallationID    string            `json:"installation_id"`
	AuthorityRevision uint64            `json:"authority_revision"`
	AuthorityDigest   Digest            `json:"authority_digest"`
	Operator          PrincipalPin      `json:"operator"`
	OperationID       OperationID       `json:"operation_id"`
	Nonce             Nonce             `json:"nonce"`
	Freshness         Freshness         `json:"freshness"`
	Method            string            `json:"method"`
	Arguments         OperatorArguments `json:"arguments"`
}

type OperatorEnvelope struct {
	Body OperatorBody `json:"body"`
	ID   Digest       `json:"id"`
	Sig  Signature    `json:"sig"`
}

type OperatorRequest struct {
	Act          OperatorEnvelope `json:"act"`
	ReceiptNonce Nonce            `json:"receipt_nonce"`
	Token        *string          `json:"token"`
}

type Event interface{ event() }

type LeaseEvent struct {
	Kind string `json:"kind"`
}

type CredentialErrorEvent struct {
	Kind  string `json:"kind"`
	Class string `json:"class"`
}

func (LeaseEvent) event()           {}
func (CredentialErrorEvent) event() {}
