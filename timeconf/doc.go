// Package timeconf collects independent clock confidence for local services.
// Until a tagged version exists, consumers should pin a specific commit; the
// public API has no compatibility guarantee between untagged commits.
//
// The production collector and protected policy loaders require Linux. Programs
// using SystemRunner must call CollectorEntry as the first statement in main,
// before parsing arguments. Importing the package does not dispatch collectors.
// Production defaults to unavailable until a protected policy selects a source.
package timeconf
