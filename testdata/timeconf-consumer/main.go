// This separate module builds the documented Linux embedding without running
// the system collector or reading a real policy during tests.
package main

import (
	"context"
	"log"
	"os"

	"github.com/relux-works/swarma-credential-broker/timeconf"
)

func main() {
	timeconf.CollectorEntry()
	// Use the deployment's fixed protected policy path; there is no source flag.
	policy, err := timeconf.LoadPolicy("/etc/timeconf/policy.json", uint32(os.Geteuid()))
	if err != nil {
		log.Fatal("time policy unavailable")
	}
	provider, err := timeconf.Production(&policy, nil)
	if err != nil {
		log.Fatal("time provider unavailable")
	}
	sample, err := provider.StartSample(context.Background())
	if err != nil {
		log.Fatal("time confidence unavailable")
	}
	// Apply Now, Uncertainty and AuthorityUntil to the service's time decision.
	log.Print(sample.Now)
}
