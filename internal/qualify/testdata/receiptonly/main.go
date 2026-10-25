// This private fault fixture emits only a receipt and exits. It does not invoke
// a canonical case, create children, connect a socket, or read fixture context.
package main

import (
	"encoding/json"
	"os"
)

func main() {
	if len(os.Args) == 1 {
		// A helper-owned receipt exists, but no canonical case process exists.
		dec := json.NewDecoder(os.Stdin)
		var input json.RawMessage
		if dec.Decode(&input) != nil {
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
		r, w, e := os.Pipe()
		if e != nil {
			os.Exit(23)
		}
		if _, e = w.Write([]byte{'c'}); e != nil {
			os.Exit(24)
		}
		w.Close()
		var receipt [1]byte
		if _, e = r.Read(receipt[:]); e != nil {
			os.Exit(25)
		}
		r.Close()
		if enc.Encode(map[string]any{"Execution": map[string]any{"case_started": receipt[0] == 'c', "case_completed": false, "worker_exit": -1, "case_exit": -1}}) != nil {
			os.Exit(26)
		}
		return
	}
	f := os.NewFile(9, "fixture-receipt")
	if f == nil {
		os.Exit(22)
	}
	if _, e := f.Write([]byte{'c'}); e != nil {
		os.Exit(23)
	}
	if f.Close() != nil {
		os.Exit(24)
	}
	os.Exit(17)
}
