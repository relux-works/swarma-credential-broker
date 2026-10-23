package runner

import (
	"flag"
	"io"
	"math"
	"os"
	"path/filepath"
	"time"
	"unicode/utf8"
)

const MaxPrompt = 1 << 20

type Options struct {
	Account, Profile, LaunchHome, PromptFile, Model, ReasoningEffort, Output, Cwd, Resume string
	PromptStdin                                                                           bool
	Timeout                                                                               time.Duration
}

func Parse(args []string) (Options, error) {
	var o Options
	var seconds float64
	f := flag.NewFlagSet("run-codex", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&o.Account, "account", "", "")
	f.StringVar(&o.Profile, "profile", "", "")
	f.StringVar(&o.LaunchHome, "launch-home", "", "")
	f.StringVar(&o.PromptFile, "prompt-file", "", "")
	f.BoolVar(&o.PromptStdin, "prompt-stdin", false, "")
	f.StringVar(&o.Model, "model", "", "")
	f.StringVar(&o.ReasoningEffort, "reasoning-effort", "", "")
	f.StringVar(&o.Output, "output-last-message", "", "")
	f.StringVar(&o.Cwd, "cwd", "", "")
	f.StringVar(&o.Resume, "resume", "", "")
	f.Float64Var(&seconds, "timeout", 300, "")
	if f.Parse(args) != nil || f.NArg() != 0 || seconds <= 0 || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds > float64(math.MaxInt64)/float64(time.Second) {
		return o, refuse("invalid_command", 64)
	}
	seen := map[string]bool{}
	duplicate := false
	f.Visit(func(x *flag.Flag) { seen[x.Name] = true })
	// flag accepts duplicate selectors; reject these rather than silently prefer one.
	counts := map[string]int{}
	for _, a := range args {
		if len(a) > 2 && a[:2] == "--" {
			n := a[2:]
			for i, c := range n {
				if c == '=' {
					n = n[:i]
					break
				}
			}
			counts[n]++
			if counts[n] > 1 {
				duplicate = true
			}
		}
	}
	if duplicate || o.Account == "" || o.Profile == "" || o.LaunchHome == "" || o.Model == "" || o.ReasoningEffort == "" || o.Output == "" || o.PromptStdin == seen["prompt-file"] || (seen["prompt-file"] && o.PromptFile == "") {
		return o, refuse("invalid_command", 64)
	}
	if seen["resume"] {
		return o, refuse("lease_harness_unqualified", 69)
	}
	o.Timeout = time.Duration(seconds * float64(time.Second))
	if o.Timeout <= 0 {
		return o, refuse("invalid_command", 64)
	}
	if o.Cwd == "" {
		var err error
		o.Cwd, err = os.Getwd()
		if err != nil {
			return o, refuse("invalid_command", 64)
		}
	}
	for _, p := range []*string{&o.LaunchHome, &o.Cwd, &o.Output} {
		var err error
		*p, err = filepath.Abs(*p)
		if err != nil {
			return o, refuse("invalid_command", 64)
		}
	}
	cwd, err := filepath.EvalSymlinks(o.Cwd)
	if err != nil {
		return o, refuse("invalid_command", 64)
	}
	info, err := os.Stat(cwd)
	if err != nil || !info.IsDir() {
		return o, refuse("invalid_command", 64)
	}
	o.Cwd = cwd
	return o, nil
}

func readPrompt(o Options, in io.Reader) ([]byte, error) {
	if !o.PromptStdin {
		f, err := openRegular(o.PromptFile)
		if err != nil {
			return nil, refuse("invalid_prompt", 64)
		}
		defer f.Close()
		in = f
	}
	if in == nil {
		return nil, refuse("invalid_prompt", 64)
	}
	b, err := io.ReadAll(io.LimitReader(in, MaxPrompt+1))
	if err != nil || len(b) > MaxPrompt || !utf8.Valid(b) {
		clear(b)
		return nil, refuse("invalid_prompt", 64)
	}
	return b, nil
}
