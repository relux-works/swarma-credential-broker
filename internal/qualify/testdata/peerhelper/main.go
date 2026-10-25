// peerhelper is a separately installed, synthetic qualification client.
package main

import (
	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/qualify"
	"os"
)

func main() {
	if handled, code := qualification.CandidateLauncherMain(os.Args[1:]); handled {
		os.Exit(code)
	}
	os.Exit(qualify.PeerHelperMain())
}
