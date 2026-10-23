//go:build linux

package qualify

import (
	"bytes"
	"context"
	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"os"
	"path/filepath"
	"testing"
)

// Claim: public CLI cannot select a fixture observer from flags/environment or
// files; production pending rows never execute a synthetic candidate or publish.
func TestReviewPublicCommand(t *testing.T) {
	for _, mode := range []string{"native", "environment-override", "argument-override", "cancelled", "existing-report", "live-with-reference"} {
		t.Run(mode, func(t *testing.T) {
			path, c, evidence := setup(t)
			// Keep the socket fixture independent of the subtest name and the
			// platform's Unix-domain address length limit.
			shortEvidence, err := os.MkdirTemp("", "qc-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(shortEvidence) })
			evidence = shortEvidence
			marker := filepath.Join(evidence, "candidate-executed")
			candidate := []byte("#!/bin/sh\n: > '" + marker + "'\nexit 0\n")
			if os.WriteFile(c.Policy.Executable, candidate, 0700) != nil {
				t.Fatal("synthetic executable fixture")
			}
			c.Policy.ExecutableSHA256 = qualification.Hash(candidate)
			raw, e := wire.Encode(c)
			if e != nil || os.WriteFile(path, raw, 0600) != nil {
				t.Fatal("policy fixture")
			}
			args := []string{"--executable", c.Policy.Executable, "--evidence-dir", evidence, "--fixtures"}
			env := []string{}
			want := 69
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "environment-override":
				env = []string{"QUALIFICATION_OBSERVER=fixture", "QUALIFICATION_QUALIFIED=true"}
			case "argument-override":
				args = append(args, "--observer=fixture")
				want = 64
			case "cancelled":
				cancel()
			case "existing-report":
				if os.WriteFile(filepath.Join(evidence, "run.json"), []byte("existing"), 0600) != nil {
					t.Fatal("report fixture")
				}
			case "live-with-reference":
				args[len(args)-1] = "--live"
				args = append(args, "--approval-ref", "fixture", "--account", "fixture")
			}
			var out bytes.Buffer
			if got := Command(ctx, args, path, env, &out); got != want {
				t.Fatalf("status %d want %d", got, want)
			}
			for _, p := range []string{marker, filepath.Join(qualification.Directory(path), "qualified.json"), filepath.Join(evidence, "qualification.sock")} {
				if _, e := os.Lstat(p); !os.IsNotExist(e) {
					t.Fatal("forbidden execution/publication or leftover socket")
				}
			}
			if mode == "native" || mode == "environment-override" {
				var report report
				if wire.Decode(bytes.TrimSpace(out.Bytes()), &report) != nil {
					t.Fatal("pending report missing")
				}
				if len(report.Unavailable) < 4 {
					t.Fatal("production inputs overridden")
				}
				for _, c := range report.Cases {
					if c.Positive.Executed || c.Negative.Executed {
						t.Fatal("pending row executed")
					}
				}
			}
			if mode == "existing-report" {
				raw, e := os.ReadFile(filepath.Join(evidence, "run.json"))
				if e != nil || string(raw) != "existing" {
					t.Fatal("existing evidence overwritten")
				}
			}
		})
	}
}
