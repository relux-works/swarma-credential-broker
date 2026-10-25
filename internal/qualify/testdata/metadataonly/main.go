// This private fault fixture reports completion metadata without starting a case.
// It performs no socket exchange and can never supply a passing observation.
package main

import (
	"encoding/json"
	"os"
)

func main() {
	if len(os.Args) > 1 {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"Execution": map[string]any{"case_started": true, "case_completed": true, "worker_exit": 17, "case_exit": 17}})
		os.Exit(17)
	}
	dec := json.NewDecoder(os.Stdin)
	var context json.RawMessage
	if dec.Decode(&context) != nil {
		os.Exit(20)
	}
	enc := json.NewEncoder(os.Stdout)
	if enc.Encode(struct {
		UID, GID uint32
		PID      int
	}{uint32(os.Geteuid()), uint32(os.Getegid()), os.Getpid()}) != nil {
		os.Exit(21)
	}
	var ack string
	if dec.Decode(&ack) != nil || ack != "ready" {
		os.Exit(22)
	}
	// A malformed lifecycle report is the only fault. No canonical entry, case
	// descriptor, child process or network operation occurs in this executable.
	report := map[string]any{"Execution": map[string]any{"case_started": true, "case_completed": true, "worker_exit": 17, "case_exit": 17, "diagnostic": "observation_invalid"}, "Incomplete": true}
	if enc.Encode(report) != nil {
		os.Exit(23)
	}
}
