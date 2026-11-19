package assemblyv0

import (
	"bytes"
	"encoding/base64"
	"errors"
	"path"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

var errFixture = errors.New("invalid construction vector")
var bootPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// This decoder is a test instrument only; production validators stay with the owning leaves.
func decodeFixture(data []byte, destination any) error {
	wrapped := append([]byte(`{"vector":`), data...)
	wrapped = append(wrapped, '}')
	parsed, err := wire.Parse(wrapped)
	if err != nil {
		return errFixture
	}
	target := reflect.ValueOf(destination)
	if target.Kind() != reflect.Pointer || target.IsNil() {
		return errFixture
	}
	if target.Elem().Type() == reflect.TypeFor[ActivationDocument]() && len(data) > 16*1024 {
		return errFixture
	}
	return fillFixture(parsed["vector"], target.Elem(), "")
}

func fillFixture(node any, target reflect.Value, method string) error {
	if target.Kind() == reflect.Interface {
		object, ok := node.(map[string]any)
		if !ok {
			return errFixture
		}
		var selected any
		switch target.Type() {
		case reflect.TypeFor[Freshness]():
			switch object["kind"] {
			case "utc":
				selected = UTCFreshness{}
			case "boottime":
				selected = BoottimeFreshness{}
			}
		case reflect.TypeFor[OperatorArguments]():
			switch method {
			case "service.bind":
				selected = BindArguments{}
			case "account.enrol":
				selected = EnrolArguments{}
			case "service.unbind":
				selected = UnbindArguments{}
			case "account.hold.lift":
				selected = LiftArguments{}
			}
		case reflect.TypeFor[CandidateArguments]():
			switch method {
			case "service.bind":
				selected = BindArguments{}
			case "account.enrol":
				selected = EnrolCandidateArguments{}
			case "service.unbind":
				selected = UnbindArguments{}
			case "account.hold.lift":
				selected = LiftArguments{}
			}
		case reflect.TypeFor[RevocationTarget]():
			if _, exists := object["grant"]; exists {
				selected = GrantTarget{}
			} else {
				selected = KeyTarget{}
			}
		}
		if selected == nil {
			return errFixture
		}
		concrete := reflect.New(reflect.TypeOf(selected)).Elem()
		if fillFixture(node, concrete, method) != nil {
			return errFixture
		}
		target.Set(concrete)
		return nil
	}
	if target.Kind() == reflect.Pointer {
		if node == nil {
			target.SetZero()
			return nil
		}
		target.Set(reflect.New(target.Type().Elem()))
		return fillFixture(node, target.Elem(), method)
	}
	switch target.Kind() {
	case reflect.Struct:
		object, ok := node.(map[string]any)
		if !ok {
			return errFixture
		}
		if selected, ok := object["method"].(string); ok {
			method = selected
		}
		allowed := map[string]bool{}
		for position := 0; position < target.NumField(); position++ {
			field := target.Type().Field(position)
			tag := strings.Split(field.Tag.Get("json"), ",")
			name := tag[0]
			if name == "" || name == "-" {
				return errFixture
			}
			allowed[name] = true
			value, present := object[name]
			optional := len(tag) == 2 && tag[1] == "omitempty"
			if !present {
				if optional {
					continue
				}
				return errFixture
			}
			if optional && value == nil {
				return errFixture
			}
			if fillFixture(value, target.Field(position), method) != nil {
				return errFixture
			}
		}
		for name := range object {
			if !allowed[name] {
				return errFixture
			}
		}
	case reflect.Slice:
		items, ok := node.([]any)
		if !ok {
			return errFixture
		}
		target.Set(reflect.MakeSlice(target.Type(), len(items), len(items)))
		for position, item := range items {
			if fillFixture(item, target.Index(position), method) != nil {
				return errFixture
			}
		}
	case reflect.String:
		value, ok := node.(string)
		if !ok {
			return errFixture
		}
		target.SetString(value)
	case reflect.Bool:
		value, ok := node.(bool)
		if !ok {
			return errFixture
		}
		target.SetBool(value)
	case reflect.Uint32, reflect.Uint64:
		value, ok := node.(int64)
		if !ok || value < 0 || uint64(value) > MaxSafeInteger || target.OverflowUint(uint64(value)) {
			return errFixture
		}
		target.SetUint(uint64(value))
	default:
		return errFixture
	}
	return checkFixture(target.Interface())
}

func lowerHex(value string, length int) bool {
	return len(value) == length && strings.IndexFunc(value, func(character rune) bool {
		return !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f')
	}) == -1
}

func absolutePath(value string) bool {
	return path.IsAbs(value) && path.Clean(value) == value && !strings.ContainsRune(value, 0)
}

func parsedUTC(value UTC) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, string(value))
	if err != nil || !strings.HasSuffix(string(value), "Z") || parsed.Year() < 1 || parsed.Year() > 9999 {
		return time.Time{}, errFixture
	}
	return parsed, nil
}

func vendorExpiry(value *UTC) bool {
	if value == nil {
		return true
	}
	parsed, err := parsedUTC(*value)
	return err == nil && !parsed.IsZero() && parsed.Nanosecond() == 0 && parsed.Format(time.RFC3339) == string(*value)
}

func checkFixture(value any) error {
	valid := true
	switch typed := value.(type) {
	case Digest:
		valid = strings.HasPrefix(string(typed), "sha256:") && lowerHex(strings.TrimPrefix(string(typed), "sha256:"), 64)
	case OperationID:
		valid = lowerHex(string(typed), 32)
	case Nonce:
		valid = lowerHex(string(typed), 32)
	case Generation:
		valid = lowerHex(string(typed), 32)
	case TokenPrefix:
		valid = lowerHex(string(typed), 32)
	case PublicKey:
		decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(string(typed), "ed25519:"))
		valid = strings.HasPrefix(string(typed), "ed25519:") && err == nil && len(decoded) == 32 && "ed25519:"+base64.RawURLEncoding.EncodeToString(decoded) == string(typed)
	case Signature:
		decoded, err := base64.RawURLEncoding.DecodeString(string(typed))
		valid = err == nil && len(decoded) == 64 && base64.RawURLEncoding.EncodeToString(decoded) == string(typed)
	case UTC:
		_, err := parsedUTC(typed)
		valid = err == nil
	case PrincipalPin:
		valid = typed.Name != "" && absolutePath(typed.Home)
	case BrokerPin:
		valid = typed.Name == "swarma-credential-broker" && typed.Home == "/opt/swarma/services/swarma-credential-broker"
	case Continuity:
		valid = typed.Kind == "production"
	case UTCFreshness:
		start, firstErr := parsedUTC(typed.NotBefore)
		end, lastErr := parsedUTC(typed.ExpiresAt)
		valid = typed.Kind == "utc" && firstErr == nil && lastErr == nil && end.After(start) && end.Sub(start) <= 300*time.Second
	case BoottimeFreshness:
		valid = typed.Kind == "boottime" && bootPattern.MatchString(typed.BootID) && typed.ExpiresAtMS > typed.NotBeforeMS && typed.ExpiresAtMS-typed.NotBeforeMS <= 300000
	case EntryPin:
		valid = typed.Path == "/usr/libexec/swarma-credential-broker-operator-v0"
	case LoginPath:
		valid = typed.Kind == "ssh" && typed.Implementation != ""
	case TerminalAuth:
		valid = typed.PAMService != ""
	case AccountPolicy:
		valid = typed.Account != "" && typed.Harness == "claude_code" && typed.Kind == "claude-oauth-token" && typed.Mode == "secret-free"
	case AuthorityDocument:
		valid = validAuthority(typed)
	case ActivationDocument:
		valid = typed.Format == ActivationFormat && typed.TestProfile == "v0" && typed.InstallationID != "" && typed.PlatformRoot == "/opt/swarma" && typed.ServiceName == "credential-gateway" && typed.Kind == "claude-oauth-token"
		if typed.ServiceLeaseMaxLifetimeSeconds != nil {
			valid = valid && *typed.ServiceLeaseMaxLifetimeSeconds >= 1 && *typed.ServiceLeaseMaxLifetimeSeconds <= 900
		}
	case BindArguments:
		valid = typed.ServiceName == "credential-gateway" && typed.Account != "" && typed.Kind == "claude-oauth-token"
	case EnrolArguments:
		valid = typed.Account != "" && typed.Harness == "claude_code" && typed.Kind == "claude-oauth-token" && vendorExpiry(typed.TokenExpiresAt)
	case EnrolCandidateArguments:
		valid = typed.Account != "" && typed.Harness == "claude_code" && typed.Kind == "claude-oauth-token" && vendorExpiry(typed.TokenExpiresAt)
	case UnbindArguments:
		valid = typed.ServiceBindingID != ""
	case LiftArguments:
		valid = typed.HoldID != "" && typed.Account != ""
	case OperatorCandidate:
		valid = typed.Method == "service.bind" || typed.Method == "account.enrol" || typed.Method == "service.unbind" || typed.Method == "account.hold.lift"
	case OperatorBody:
		var inner OperationID
		switch arguments := typed.Arguments.(type) {
		case BindArguments:
			inner = arguments.OperationID
			valid = typed.Method == "service.bind" && arguments.InstallationPolicyDigest == typed.AuthorityDigest
		case EnrolArguments:
			inner = arguments.OperationID
			valid = typed.Method == "account.enrol"
		case UnbindArguments:
			inner = arguments.OperationID
			valid = typed.Method == "service.unbind"
		case LiftArguments:
			inner = arguments.OperationID
			valid = typed.Method == "account.hold.lift"
		default:
			valid = false
		}
		_, narrowing := typed.Freshness.(BoottimeFreshness)
		valid = valid && typed.Format == OperatorActFormat && typed.InstallationID != "" && typed.AuthorityRevision > 0 && typed.Operator.Name == "swarma-operator" && inner == typed.OperationID && narrowing == (typed.Method == "service.unbind")
	case OperatorEnvelope:
		valid = typed.ID == digestBytes(actPreimage(typed.Body))
	case OperatorRequest:
		valid = typed.ReceiptNonce == typed.Act.Body.Nonce && (typed.Token != nil) == (typed.Act.Body.Method == "account.enrol")
		if typed.Token != nil {
			valid = valid && len(*typed.Token) > 0 && len(*typed.Token) <= 4096
		}
	case LoginSession:
		valid = typed.Kind == "ssh" && typed.LoginPID > 0
	case TerminalReceipt:
		_, narrowing := typed.Freshness.(BoottimeFreshness)
		valid = typed.Format == TerminalReceiptFormat && typed.InstallationID != "" && typed.AuthorityRevision > 0 && bootPattern.MatchString(typed.BootID) && typed.PeerPID > 0 && typed.LoginSession.LoginUID == typed.TerminalCaller.UID && typed.Authentication == "password-sudo" && (typed.Confirmation == "not-required" && narrowing || typed.Confirmation == "exact-content" && !narrowing)
		if freshness, ok := typed.Freshness.(BoottimeFreshness); ok {
			valid = valid && typed.BootID == freshness.BootID
		}
	case SessionAccountPolicy:
		valid = typed.Account != ""
	case TerminalSession:
		_, narrowing := typed.Freshness.(BoottimeFreshness)
		valid = typed.Format == TerminalSessionFormat && typed.InstallationID != "" && typed.AuthorityRevision > 0 && absolutePath(typed.SocketPath) && ((narrowing && typed.AccountPolicy == nil && typed.Continuity == nil) || (!narrowing && typed.AccountPolicy != nil && typed.Continuity != nil))
	case LeaseEvent:
		valid = typed.Kind == "lease_expiring" || typed.Kind == "lease_expired" || typed.Kind == "reauth_required"
	case CredentialErrorEvent:
		valid = typed.Kind == "credential_error" && (typed.Class == "auth" || typed.Class == "permission" || typed.Class == "quota" || typed.Class == "unknown")
	case GrantBody:
		valid = typed.Type == "grant/1" && (strings.HasPrefix(typed.Subject, "ed25519:") || strings.HasPrefix(typed.Subject, "agent:")) && len(typed.Actions) == 1 && typed.Actions[0] == "credential.lease"
	case GrantEnvelope:
		valid = typed.ID == digestBytes(append([]byte("swarma-credential-broker grant/1\n"), canonicalBytes(typed.Body)...))
	case RevocationBody:
		valid = typed.Type == "revocation/1"
	case RevocationEnvelope:
		valid = typed.ID == digestBytes(append([]byte("swarma-credential-broker revocation/1\n"), canonicalBytes(typed.Body)...))
	}
	if !valid {
		return errFixture
	}
	return nil
}

func validAuthority(authority AuthorityDocument) bool {
	if authority.Format != AuthorityFormat || authority.InstallationID == "" || authority.Revision == 0 || authority.EventSchema != "broker-events/1" || authority.Operator.Name != "swarma-operator" || authority.Observer.Name != "swarma-observer" {
		return false
	}
	roles := map[uint32]bool{}
	for _, uid := range []uint32{authority.Broker.UID, authority.Operator.UID, authority.Observer.UID} {
		if roles[uid] {
			return false
		}
		roles[uid] = true
	}
	for _, caller := range authority.TerminalCallers {
		if roles[caller.UID] {
			return false
		}
		roles[caller.UID] = true
	}
	for _, dispatcher := range authority.Dispatchers {
		if roles[dispatcher.UID] {
			return false
		}
		roles[dispatcher.UID] = true
	}
	roots := map[PublicKey]bool{}
	for _, key := range authority.RootKeys {
		if roots[key] {
			return false
		}
		roots[key] = true
	}
	if !roots[authority.OperatorKey] {
		return false
	}
	accounts := map[string]bool{}
	for _, account := range authority.Accounts {
		identity := account.Account + "\x00" + account.Kind
		if accounts[identity] || account.OwnerUID != authority.Operator.UID {
			return false
		}
		accounts[identity] = true
	}
	loginPaths := map[string]bool{}
	for _, login := range authority.TerminalAuth.LoginPaths {
		identity := string(canonicalBytes(login))
		if loginPaths[identity] {
			return false
		}
		loginPaths[identity] = true
	}
	return true
}

func fixtureTree(data []byte) map[string]any {
	wrapped := append(append([]byte(`{"vector":`), data...), '}')
	parsed, err := wire.Parse(wrapped)
	if err != nil {
		panic("invalid synthetic fixture tree")
	}
	return parsed["vector"].(map[string]any)
}

func objectAt(root map[string]any, location []any) map[string]any {
	var current any = root
	for _, step := range location {
		switch position := step.(type) {
		case string:
			current = current.(map[string]any)[position]
		case int:
			current = current.([]any)[position]
		}
	}
	return current.(map[string]any)
}

func objectLocations(value any, location []any) [][]any {
	var locations [][]any
	switch current := value.(type) {
	case map[string]any:
		locations = append(locations, append([]any{}, location...))
		for key, child := range current {
			locations = append(locations, objectLocations(child, append(append([]any{}, location...), key))...)
		}
	case []any:
		for position, child := range current {
			locations = append(locations, objectLocations(child, append(append([]any{}, location...), position))...)
		}
	}
	return locations
}

// Claim: every vector's nested objects reject unknown, missing required and forbidden-null members beside the unchanged valid control.
func TestClosedSchemaRefusals(test *testing.T) {
	for name, vector := range constructionVectors() {
		if vector.value == nil {
			continue
		}
		test.Run(name, func(test *testing.T) {
			check := func(data []byte, accepted bool) {
				test.Helper()
				target := reflect.New(reflect.TypeOf(vector.value)).Interface()
				err := decodeFixture(data, target)
				if accepted && err != nil || !accepted && !errors.Is(err, errFixture) {
					test.Fatal("unexpected closed-schema verdict")
				}
			}
			check(vector.bytes, true)
			for _, location := range objectLocations(fixtureTree(vector.bytes), nil) {
				modified := fixtureTree(vector.bytes)
				objectAt(modified, location)["unpublished_member"] = true
				check(canonicalBytes(modified), false)
				for member, original := range objectAt(fixtureTree(vector.bytes), location) {
					if member != "service_lease_max_lifetime_seconds" {
						modified = fixtureTree(vector.bytes)
						delete(objectAt(modified, location), member)
						check(canonicalBytes(modified), false)
					}
					if original == nil || member == "token_expires_at" {
						continue
					}
					modified = fixtureTree(vector.bytes)
					objectAt(modified, location)[member] = nil
					check(canonicalBytes(modified), false)
				}
			}
		})
	}
}

// Claim: the existing parser rejects the named canonical violations, while literal Unicode and safe integer boundaries remain valid.
func TestCanonicalRefusals(test *testing.T) {
	for _, valid := range []string{`{"label":"λ😀"}`, `{"bound":9007199254740991}`, `{"bound":-9007199254740991}`} {
		if _, err := wire.Parse([]byte(valid)); err != nil {
			test.Fatal("valid canonical control refused")
		}
	}
	cases := map[string][]byte{
		"duplicate":         []byte(`{"kind":"production","kind":"production"}`),
		"unicode-surrogate": []byte(`{"label":"\ud800"}`),
		"invalid-utf8":      {'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'},
		"float":             []byte(`{"value":1.0}`), "negative-zero": []byte(`{"value":-0}`),
		"unsafe": []byte(`{"value":9007199254740992}`), "trailing-lf": []byte("{}\n"),
		"whitespace": []byte(`{ "kind":"production"}`), "second-object": []byte(`{}{}`),
	}
	for name, data := range cases {
		test.Run(name, func(test *testing.T) {
			if _, err := wire.Parse(data); !errors.Is(err, wire.ErrMalformed) {
				test.Fatal("canonical violation was not refused")
			}
		})
	}
}

// Claim: exact domains bind method, argument, installation and operation bytes; a domain-confused or altered digest cannot match the fixed vector.
func TestDomainSeparation(test *testing.T) {
	vectors := constructionVectors()
	body := vectors["act-enrol-null.body.json"].value.(OperatorBody)
	preimage := vectors["act-enrol-null.preimage"].bytes
	if !bytes.HasPrefix(preimage, []byte("swarma-credential-broker operator-act/1\n{")) || bytes.HasSuffix(preimage, []byte{'\n'}) {
		test.Fatal("wrong act domain or line boundary")
	}
	if digestBytes(preimage) == digestBytes(argumentsPreimage(body)) || digestBytes(preimage) == digestBytes(canonicalBytes(body)) {
		test.Fatal("domains are not separated")
	}
	for _, method := range []string{"service.bind", "account.hold.lift"} {
		changed := body
		changed.Method = method
		if digestBytes(argumentsPreimage(changed)) == digestBytes(argumentsPreimage(body)) {
			test.Fatal("argument commitment omitted method")
		}
	}
	arguments := body.Arguments.(EnrolArguments)
	changedIdentity := strings.Replace(string(enrollmentPreimage()), fixtureInstallation, "another-fixture-installation", 1)
	changedOperation := strings.Replace(string(enrollmentPreimage()), string(fixtureOperation), "ffeeddccbbaa99887766554433221100", 1)
	for _, changed := range []string{changedIdentity, changedOperation, string(enrollmentPreimage()) + "x"} {
		if strings.HasPrefix(string(digestBytes([]byte(changed))), "sha256:"+string(arguments.TokenSHA256Prefix)) {
			test.Fatal("token prefix omitted a scoped input")
		}
	}
}
