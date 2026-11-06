# Inert validation example and neighboring refusal

This is a source-backed Go example for static reading or an independently
authorized synthetic test. It uses only constant public bytes in memory. No
serialized fixture path or fixture CLI exists for this example. Do not substitute
host reports, protected policy, account data or credential payloads.

The valid CSV is exactly `goodCSV` in
[collect_test.go](../../../../timeconf/collect_test.go).
`TestTrackingParserNegativeAndControl` checks both that input and the adjacent
missing-final-newline refusal. The public
[ParseTracking](../../../../timeconf/parse.go) parser requires one 14-field row
with a terminal LF; the internal row parser rejects the missing LF before
interpreting the fields.

```go
package example

import (
    "errors"

    "github.com/relux-works/swarma-credential-broker/timeconf"
)

// ValidateSyntheticTracking returns only a fixed validation outcome.
// It performs no I/O, collection, credential operation or logging.
func ValidateSyntheticTracking() bool {
    const csv = "C0000201,192.0.2.1,3,1893553444.000000000,0.001,0.001,0.001,1.0,0.1,0.1,0.002,0.001,10.0,Normal\n"
    parsed, err := timeconf.ParseTracking([]byte(csv))
    if err != nil || parsed.Stratum != 3 ||
        parsed.Address != "192.0.2.1" || parsed.RootDelay != 0.002 {
        return false
    }

    // Actual adjacent refusal: remove only the required final LF.
    _, err = timeconf.ParseTracking([]byte(csv[:len(csv)-1]))
    return errors.Is(err, timeconf.ErrUnavailable)
}
```

The expected function result is `true` by the implemented parser and existing
control; this documentation task does not execute or compile it. `Stratum`,
`Address` and `RootDelay` are fields of
[Tracking](../../../../timeconf/provider.go). `ErrUnavailable` is declared in
[policy.go](../../../../timeconf/policy.go).

Parsing establishes report syntax and the parser's numeric checks. It does not
establish source authenticity, freshness, a trusted clock, durable settlement,
lease admission or owner presence. Even a syntactically accepted leap status may
fail later provider checks. Never promote a parser pass into a broker action.
