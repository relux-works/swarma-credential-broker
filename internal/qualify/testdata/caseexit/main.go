// caseexit runs the real canonical fixture, then deliberately returns status 17.
package main

import (
	"os"

	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/qualify"
	"github.com/relux-works/swarma-credential-broker/internal/runner"
)

func main() {
	if handled, code := runner.SupervisorMain(os.Args[1:]); handled {
		os.Exit(code)
	}
	if handled, code := qualification.CandidateLauncherMain(os.Args[1:]); handled {
		os.Exit(code)
	}
	var code int
	if len(os.Args) == 1 || len(os.Args) > 2 && os.Args[2] == "peer-denied" {
		code = qualify.PeerHelperMain()
	} else {
		_, code = qualify.CaseMain(os.Args[1:])
	}
	if len(os.Args) > 1 && code == 0 {
		// Corrupt only synthetic observation metadata after the real exchange.
		os.Stdout.Write([]byte("\ninvalid\n"))
		code = 17
	}
	os.Exit(code)
}
