//go:build linux && broker_lab

package labtimev0

import (
	"context"
	"path/filepath"

	"github.com/relux-works/swarma-credential-broker/timeconf"
)

type Consumer = timeconf.Consumer
type Enrollment = timeconf.Enrollment
type Policy = timeconf.Policy
type ConsumptionRequest = timeconf.ConsumptionRequest
type WitnessHead = timeconf.WitnessHead
type ClockPoint = timeconf.ClockPoint
type Authentication = timeconf.Authentication
type ActivationRefusal = timeconf.ActivationRefusal
type ClosedWitness = timeconf.ClosedWitness
type storeSession = timeconf.LabSession
type checkpointHead = timeconf.LabPointer
type settlement = timeconf.LabSettlement
type savedClock = timeconf.LabSavedClock
type localCollection = timeconf.LabCollection

const NTSAuthData = timeconf.NTSAuthData
const NTSConfig = timeconf.NTSConfig
const receiptLimit = 65536

var ErrUnavailable = timeconf.ErrUnavailable
var canonical = timeconf.LabCanonical
var strictRecord = timeconf.LabStrictRecord
var witnessBytes = timeconf.LabWitnessBytes
var objectName = timeconf.LabObjectName
var point = timeconf.LabPoint
var integer = timeconf.LabInteger
var protectedRead = timeconf.LabProtectedRead
var openLabStore = timeconf.LabOpenStore
var digestPattern = patterns["digest"]

func sum(raw []byte) string { return Digest(raw) }
func cleanPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/"
}

type localCollectorPath interface {
	collect(context.Context, Policy) (localCollection, error)
}
type labRuntime struct {
	clock     timeconf.Clock
	collector localCollectorPath
}

var labRuntimeFor = func(inventory string) labRuntime {
	return labRuntime{timeconf.SystemClock{}, labSource{inventory}}
}

func configureLab(consumer *Consumer, witness *labWitness, runtime labRuntime) {
	consumer.LabConfigure(witness, runtime.clock, runtime.collector.collect)
}
