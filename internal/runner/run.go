package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

// Command is the embeddable run-codex subcommand. All authority and transport
// dependencies come from protected integration, with no CLI bypass to qualify.
func Command(parent context.Context, args []string, streams IO, d Dependencies) int {
	if streams.Out == nil {
		streams.Out = io.Discard
	}
	if streams.Err == nil {
		streams.Err = io.Discard
	}
	o, err := Parse(args)
	if err != nil {
		return finish(streams.Err, err)
	}
	type promptResult struct {
		b   []byte
		err error
	}
	promptCh := make(chan promptResult)
	go func() {
		b, e := readPrompt(o, streams.In)
		select {
		case promptCh <- promptResult{b, e}:
		case <-parent.Done():
			clear(b)
		}
	}()
	var prompt []byte
	select {
	case r := <-promptCh:
		prompt, err = r.b, r.err
	case <-parent.Done():
		return finish(streams.Err, refuse("interrupted", 130))
	}
	if err != nil {
		return finish(streams.Err, err)
	}
	defer clear(prompt)
	ctx, cancel := context.WithTimeout(parent, o.Timeout)
	defer cancel()
	err = execute(ctx, parent, o, prompt, streams, d)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			err = refuse("interrupted", 130)
		} else if errors.Is(err, context.DeadlineExceeded) {
			err = refuse("execution_deadline", 124)
		}
	}
	return finish(streams.Err, err)
}
func finish(w io.Writer, err error) int {
	if err == nil {
		return 0
	}
	var e *Refusal
	if errors.As(err, &e) {
		report(w, e.Code)
		return e.Status
	}
	report(w, "credential_injection_unavailable")
	return 75
}

func execute(ctx, parent context.Context, o Options, prompt []byte, streams IO, d Dependencies) (result error) {
	fingerprint, err := inspectSources(o, d.Environment)
	if err != nil {
		return err
	}
	h, err := lockHome(o.LaunchHome)
	if err != nil {
		return err
	}
	clean := true
	guardClosed := false
	defer func() {
		if !guardClosed {
			if err := h.close(clean); err != nil {
				result = refuse("teardown_unconfirmed", 75)
			}
		}
	}()
	output, err := prepareOutput(o.Output)
	if err != nil {
		return err
	}
	defer output.abort()
	policy, err := resolve(ctx, d, o)
	if err != nil {
		return err
	}
	if policy.ConfigSHA256 != fingerprint {
		return refuse("lease_binding_mismatch", 69)
	}
	if err = h.intent(); err != nil {
		clean = false
		return refuse("credential_injection_unavailable", 75)
	}
	// --version runs only after the exact pinned digest has qualified. It uses
	// the same private environment and containment, with no real login access.
	if err = versionProbe(ctx, d, o, h, policy); err != nil {
		if errors.Is(err, errContainment) {
			clean = false
			return refuse("teardown_unconfirmed", 75)
		}
		return err
	}
	if d.Connect == nil {
		return refuse("lease_owner_unavailable", 69)
	}
	broker, err := d.Connect(ctx)
	if err != nil {
		return refuse("lease_owner_unavailable", 69)
	}
	defer broker.Close()
	admission := func() error {
		call, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		if e := broker.VerifyServer(call, policy.BrokerUID); e != nil {
			return refuse("server_identity_mismatch", 69)
		}
		hello, e := broker.Hello(call, HelloRequest{[]int{1}, ProtocolProfile})
		if e != nil {
			return brokerFailure(e, 69)
		}
		if hello.Version != 1 || hello.Profile != ProtocolProfile || hello.UID != policy.UID || hello.PolicyGeneration != policy.PolicyGeneration {
			return refuse("lease_binding_mismatch", 69)
		}
		return nil
	}
	if err = admission(); err != nil {
		return err
	}
	call, ccancel := context.WithTimeout(ctx, 30*time.Second)
	lease, err := broker.Request(call, LeaseRequest{Harness: "codex_cli", Profile: o.Profile, Account: o.Account, Channel: "external-token", LaunchID: randomID(), CredentialBinding: Binding{policy.BindingDigest, "codex_cli", o.Profile, o.Account, "external-token", policy.Endpoint, policy.ExecutableSHA256, policy.PolicyGeneration}, Executor: Executor{[]string{"credential-injection/1"}, Version}})
	ccancel()
	if err != nil {
		lease.erase()
		return brokerFailure(err, 69)
	}
	defer lease.erase()
	stream := &textStream{out: contextWriter{ctx: ctx, out: streams.Out}}
	defer stream.erase()
	stream.addSecret(lease.Token)
	var proc *process
	var client *rpc
	session := &session{ctx: ctx, broker: broker, lease: &lease, policy: policy, stream: stream, answered: map[string]bool{}}
	// Teardown always uses an independent, total five-second budget, including
	// interrupt transport, descendant confirmation and the release receipt.
	cleanup := func() error {
		stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if client != nil && session.thread != "" && session.turn != "" {
			interrupt, done := context.WithTimeout(stop, 100*time.Millisecond)
			client.request(interrupt, "turn/interrupt", map[string]any{"threadId": session.thread, "turnId": session.turn})
			done()
		}
		var failure error
		if proc != nil {
			absence, c := context.WithTimeout(stop, 3500*time.Millisecond)
			e := proc.stop(absence)
			c()
			if e != nil {
				failure = refuse("teardown_unconfirmed", 75)
				clean = false
			}
		}
		if client != nil {
			close(client.closed)
		}
		release, c := context.WithTimeout(stop, 2*time.Second)
		e := broker.Release(release, lease.ID)
		c()
		if e != nil {
			failure = refuse("lease_release_failed", 75)
		}
		broker.Close()
		// A noncooperative adapter cannot retain material beyond cleanup silently.
		if session.renewDone != nil {
			select {
			case <-session.renewDone:
			case <-stop.Done():
				failure = refuse("renew_timeout", 75)
			}
		}
		lease.erase()
		return failure
	}
	run := func() ([]byte, error) {
		if !validLease(lease, policy, nil) {
			return nil, refuse("external_token_init_failed", 69)
		}
		latest, e := resolve(ctx, d, o)
		if e != nil {
			return nil, e
		}
		if !samePolicy(policy, latest) {
			return nil, refuse("lease_binding_mismatch", 69)
		}
		nowSources, e := inspectSources(o, d.Environment)
		if e != nil {
			return nil, e
		}
		if nowSources != fingerprint {
			return nil, refuse("credential_source_conflict", 69)
		}
		proc, e = startProcess(d, o, h, policy, []string{"app-server", "--listen", "stdio://", "-c", `cli_auth_credentials_store="ephemeral"`})
		if e != nil {
			return nil, refuse("external_token_init_failed", 69)
		}
		client = newRPC(ctx, proc)
		session.rpc = client
		return session.drive(prompt, o)
	}
	final, runErr := run()
	defer clear(final)
	if cleanupErr := cleanup(); cleanupErr != nil {
		return cleanupErr
	}
	var runRefusal *Refusal
	if errors.As(runErr, &runRefusal) && runRefusal.Status == 75 {
		return runErr
	}
	if parent.Err() != nil {
		return refuse("interrupted", 130)
	}
	if ctx.Err() != nil {
		return refuse("execution_deadline", 124)
	}
	if runErr != nil {
		return runErr
	}
	guardClosed = true
	if err = h.close(clean); err != nil {
		return refuse("teardown_unconfirmed", 75)
	}
	if err = stream.write("", true); err != nil {
		return outputFailure(err)
	}
	if err = output.commit(final); err != nil {
		return err
	}
	return nil
}

// Preserve the cause of interrupted stdout without allowing cancellation to
// override genuine output failures or the cleanup/renewal dominance checks.
func outputFailure(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return refuse("output_unavailable", 75)
}

var errContainment = errors.New("containment unknown")

func versionProbe(ctx context.Context, d Dependencies, o Options, h *homeGuard, p Policy) error {
	probe, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	proc, err := startProcess(d, o, h, p, []string{"--version"})
	if err != nil {
		return refuse("lease_harness_unqualified", 69)
	}
	ch := make(chan []byte, 1)
	go func() { b, _ := io.ReadAll(io.LimitReader(proc.out, 256)); ch <- b }()
	var b []byte
	select {
	case b = <-ch:
	case <-probe.Done():
	}
	stop, c := context.WithTimeout(context.Background(), 4*time.Second)
	e := proc.stop(stop)
	c()
	if e != nil {
		return errContainment
	}
	if probe.Err() != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return refuse("lease_harness_unqualified", 69)
	}
	if strings.TrimSpace(string(b)) != p.Release {
		return refuse("lease_harness_unqualified", 69)
	}
	return nil
}
func validLease(l Lease, p Policy, old *Lease) bool {
	now := time.Now()
	if !validOpaqueID(l.ID) || l.Account != p.Account || l.Harness != "codex_cli" || l.Channel != "external-token" || !l.Renewable || l.ChatGPTAccountID != p.ChatGPTAccountID || p.ChatGPTAccountID == "" || len(l.Token) == 0 || len(l.Token) > 65536 || !utf8.Valid(l.Token) || !l.TokenExpiresAt.After(now) || !l.AuthorizedUntil.After(now) {
		return false
	}
	if old != nil && (l.ID != old.ID || l.Account != old.Account || !l.AuthorizedUntil.Equal(old.AuthorizedUntil)) {
		return false
	}
	return true
}
func brokerFailure(err error, status int) error {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return refuse("request_deadline_exceeded", status)
	}
	var e *Refusal
	if errors.As(err, &e) {
		switch e.Code {
		case "server_identity_mismatch", "role_not_permitted", "peer_identity_unavailable", "version_unsupported", "lease_not_authorised", "lease_account_unknown", "lease_harness_mismatch", "lease_account_revoked", "lease_reauth_required", "lease_owner_unavailable", "lease_channel_unsupported", "lease_harness_unqualified", "lease_binding_mismatch", "lease_network_enforcement_unavailable", "lease_not_owner", "lease_not_active", "renew_not_current", "renew_timeout", "renew_failed", "request_deadline_exceeded":
			return refuse(e.Code, status)
		}
	}
	return refuse("lease_owner_unavailable", status)
}

type session struct {
	ctx          context.Context
	broker       BrokerClient
	lease        *Lease
	policy       Policy
	rpc          *rpc
	stream       *textStream
	thread, turn string
	answered     map[string]bool
	renewDone    chan struct{}
}

func (s *session) drive(prompt []byte, o Options) ([]byte, error) {
	init := map[string]any{"clientInfo": map[string]any{"name": "swarma_credential_broker", "version": Version}, "capabilities": map[string]bool{"experimentalApi": true}}
	if _, err := s.rpc.call(s.ctx, "initialize", init, s.callback); err != nil {
		return nil, s.initError(err)
	}
	if err := s.rpc.notify(s.ctx, "initialized", map[string]any{}); err != nil {
		return nil, s.initError(err)
	}
	login := map[string]any{"type": "chatgptAuthTokens", "accessToken": string(s.lease.Token), "chatgptAccountId": s.lease.ChatGPTAccountID}
	if s.lease.PlanType != "" {
		login["chatgptPlanType"] = s.lease.PlanType
	}
	raw, err := s.rpc.call(s.ctx, "account/login/start", login, s.callback)
	delete(login, "accessToken")
	if err != nil {
		return nil, s.initError(err)
	}
	var logged struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &logged) != nil || logged.Type != "chatgptAuthTokens" {
		return nil, refuse("external_token_init_failed", 69)
	}
	raw, err = s.rpc.call(s.ctx, "thread/start", map[string]any{"model": o.Model, "cwd": o.Cwd, "approvalPolicy": "untrusted", "allowProviderModelFallback": false}, s.callback)
	if err != nil {
		return nil, s.initError(err)
	}
	var thread struct {
		Thread struct {
			ID string `json:"id"`
		} `json:"thread"`
		Model string `json:"model"`
	}
	if json.Unmarshal(raw, &thread) != nil || thread.Thread.ID == "" || thread.Model != o.Model {
		return nil, refuse("external_token_init_failed", 69)
	}
	s.thread = thread.Thread.ID
	raw, err = s.rpc.call(s.ctx, "turn/start", map[string]any{"threadId": s.thread, "model": o.Model, "effort": o.ReasoningEffort, "input": []any{map[string]any{"type": "text", "text": string(prompt)}}}, s.callback)
	if err != nil {
		return nil, s.initError(err)
	}
	var started struct {
		Turn struct {
			ID string `json:"id"`
		} `json:"turn"`
	}
	if json.Unmarshal(raw, &started) != nil || started.Turn.ID == "" {
		return nil, refuse("external_token_init_failed", 69)
	}
	s.turn = started.Turn.ID
	messages := map[string]string{}
	var order []string
	record := func(items []agentItem) {
		for _, item := range items {
			if item.Type == "agentMessage" && (item.Phase == "" || item.Phase == "final_answer") {
				if _, ok := messages[item.ID]; !ok {
					order = append(order, item.ID)
				}
				messages[item.ID] = item.Text
			}
		}
	}
	authority, acancel := context.WithDeadline(s.ctx, s.lease.AuthorizedUntil)
	defer acancel()
	for {
		var m message
		if len(s.rpc.queue) > 0 {
			m = s.rpc.queue[0]
			s.rpc.queue = s.rpc.queue[1:]
		} else {
			m, err = s.rpc.receive(authority)
			if err != nil {
				if authority.Err() != nil && s.ctx.Err() == nil {
					return nil, refuse("lease_not_active", 75)
				}
				return nil, err
			}
		}
		if len(m.ID) > 0 && m.Method != "" {
			if err = s.callback(m); err != nil {
				return nil, err
			}
			continue
		}
		if m.Method == "" {
			return nil, refuse("external_token_init_failed", 69)
		}
		switch m.Method {
		case "item/agentMessage/delta":
			var p struct {
				ThreadID string `json:"threadId"`
				TurnID   string `json:"turnId"`
				Delta    string `json:"delta"`
			}
			if json.Unmarshal(m.Params, &p) != nil {
				return nil, refuse("external_token_init_failed", 69)
			}
			if p.ThreadID == s.thread && p.TurnID == s.turn {
				if err = s.stream.write(p.Delta, false); err != nil {
					return nil, outputFailure(err)
				}
			}
		case "item/completed":
			var p struct {
				ThreadID string    `json:"threadId"`
				TurnID   string    `json:"turnId"`
				Item     agentItem `json:"item"`
			}
			if json.Unmarshal(m.Params, &p) != nil {
				return nil, refuse("external_token_init_failed", 69)
			}
			if p.ThreadID == s.thread && p.TurnID == s.turn {
				record([]agentItem{p.Item})
			}
		case "turn/completed":
			var p struct {
				ThreadID string `json:"threadId"`
				Turn     struct {
					ID     string      `json:"id"`
					Status string      `json:"status"`
					Items  []agentItem `json:"items"`
				} `json:"turn"`
			}
			if json.Unmarshal(m.Params, &p) != nil {
				return nil, refuse("external_token_init_failed", 69)
			}
			if p.ThreadID != s.thread || p.Turn.ID != s.turn {
				continue
			}
			if p.Turn.Status != "completed" {
				return nil, refuse("vendor_turn_failed", 1)
			}
			record(p.Turn.Items)
			var text bytes.Buffer
			for _, id := range order {
				text.WriteString(messages[id])
			}
			return s.stream.redact(text.Bytes()), nil
		}
	}
}

type agentItem struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Text  string `json:"text"`
	Phase string `json:"phase"`
}

func (s *session) initError(err error) error {
	var r *Refusal
	if errors.As(err, &r) {
		return err
	}
	if s.ctx.Err() != nil {
		return s.ctx.Err()
	}
	return refuse("external_token_init_failed", 69)
}
func (s *session) callback(m message) error {
	key, validID := callbackID(m.ID)
	if !validID || s.answered[key] {
		return refuse("external_token_init_failed", 75)
	}
	s.answered[key] = true
	if len(s.answered) > 1024 {
		return refuse("external_token_init_failed", 75)
	}
	if m.Method != "account/chatgptAuthTokens/refresh" {
		var result any
		switch m.Method {
		case "item/commandExecution/requestApproval", "item/fileChange/requestApproval":
			result = map[string]any{"decision": "decline"}
		case "execCommandApproval", "applyPatchApproval":
			result = map[string]any{"decision": "abort"}
		case "item/permissions/requestApproval":
			result = map[string]any{"permissions": map[string]any{}, "scope": "turn"}
		default:
			return s.rpc.send(s.ctx, map[string]any{"id": m.ID, "error": map[string]any{"code": -32601, "message": "headless_request_denied"}})
		}
		return s.rpc.send(s.ctx, map[string]any{"id": m.ID, "result": result})
	}
	// 8.5 s local cutoff includes the broker's 8 s budget and transport. A
	// separate 0.5 s write reserve puts every reply before 9 s of the 10 s bound.
	cutoff := m.received.Add(8500 * time.Millisecond)
	replyLimit := m.received.Add(9 * time.Second)
	var p struct {
		Reason   string  `json:"reason"`
		Previous *string `json:"previousAccountId"`
	}
	fail := func(code string) error {
		reply, c := context.WithDeadline(s.ctx, replyLimit)
		defer c()
		s.rpc.send(reply, map[string]any{"id": m.ID, "error": map[string]any{"code": -32000, "message": code}})
		return refuse(code, 75)
	}
	if json.Unmarshal(m.Params, &p) != nil || p.Reason != "unauthorized" || p.Previous != nil && *p.Previous != s.lease.ChatGPTAccountID {
		return fail("renew_failed")
	}
	renew, cancel := context.WithDeadline(s.ctx, cutoff)
	defer cancel()
	if !time.Now().Before(cutoff) {
		return fail("renew_timeout")
	}
	type response struct {
		lease Lease
		err   error
	}
	ch := make(chan response)
	s.renewDone = make(chan struct{})
	done := s.renewDone
	request := RenewRequest{s.lease.ID, digest(s.lease.Token)}
	go func() {
		defer close(done)
		l, e := s.broker.Renew(renew, request)
		select {
		case ch <- response{l, e}:
		case <-renew.Done():
			l.erase()
		}
	}()
	var renewed Lease
	var err error
	select {
	case v := <-ch:
		renewed, err = v.lease, v.err
	case <-renew.Done():
		return fail("renew_timeout")
	}
	defer renewed.erase()
	if renew.Err() != nil || !time.Now().Before(cutoff) {
		return fail("renew_timeout")
	}
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return fail("renew_timeout")
		}
		r := brokerFailure(err, 75).(*Refusal)
		return fail(r.Code)
	}
	if !validLease(renewed, s.policy, s.lease) {
		return fail("renew_failed")
	}
	s.stream.addSecret(renewed.Token)
	reply, c := context.WithDeadline(s.ctx, replyLimit)
	defer c()
	payload := map[string]any{"accessToken": string(renewed.Token), "chatgptAccountId": renewed.ChatGPTAccountID}
	if renewed.PlanType != "" {
		payload["chatgptPlanType"] = renewed.PlanType
	}
	err = s.rpc.send(reply, map[string]any{"id": m.ID, "result": payload})
	delete(payload, "accessToken")
	if err != nil {
		return refuse("renew_timeout", 75)
	}
	s.lease.erase()
	*s.lease = renewed
	renewed.Token = nil
	return nil
}

func validOpaqueID(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if c > 127 {
			return false
		}
	}
	return true
}
func callbackID(raw json.RawMessage) (string, bool) {
	var text string
	if len(raw) > 0 && raw[0] == '"' {
		if json.Unmarshal(raw, &text) != nil || len(text) > 1024 {
			return "", false
		}
		return "string:" + text, true
	}
	var number int64
	if json.Unmarshal(raw, &number) != nil || bytes.Equal(raw, []byte("null")) {
		return "", false
	}
	return fmt.Sprintf("integer:%d", number), true
}
