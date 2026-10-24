//go:build testonlyapi

package main

import "github.com/relux-works/swarma-credential-broker/timeconf"

// This negative fixture must fail to build: test-only exports are not API.
var _ = timeconf.ParseSources
