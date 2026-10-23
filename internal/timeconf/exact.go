package timeconf

import (
	"math/big"
	"strconv"
	"strings"
	"time"
)

const (
	systemOffset = iota
	lastOffset
	rmsOffset
	frequency
	residualFrequency
	skew
	rootDelay
	rootDispersion
	updateInterval
	trackingFieldCount
)

// Parsed values are immutable after construction. Copies of Tracking may share
// them; every arithmetic operation below allocates its own receiver.
type trackingNumbers [trackingFieldCount]*big.Rat

// decimal accepts bounded decimal/scientific notation, never binary, fractions
// or nonfinite values. Bounds prevent an adversarial exponent from causing an
// unbounded allocation while exceeding the precision used in chronyc reports.
func decimal(s string) (*big.Rat, error) {
	if len(s) == 0 || len(s) > 256 {
		return nil, ErrUnavailable
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c == '.' || c == '+' || c == '-' || c == 'e' || c == 'E') {
			return nil, ErrUnavailable
		}
	}
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		exponent, err := strconv.Atoi(s[i+1:])
		if err != nil || exponent < -4096 || exponent > 4096 {
			return nil, ErrUnavailable
		}
	}
	v, ok := new(big.Rat).SetString(s)
	if !ok {
		return nil, ErrUnavailable
	}
	return v, nil
}

func (t Tracking) numericValues() [trackingFieldCount]float64 {
	return [trackingFieldCount]float64{t.SystemOffset, t.LastOffset, t.RMSOffset, t.Frequency, t.ResidualFrequency, t.Skew, t.RootDelay, t.RootDispersion, t.UpdateInterval}
}

func (t Tracking) numbers() (trackingNumbers, error) {
	var values trackingNumbers
	for i, diagnostic := range t.numericValues() {
		if !finite(diagnostic) {
			return values, ErrUnavailable
		}
		if t.exact != nil {
			v := t.exact[i]
			if v == nil {
				return values, ErrUnavailable
			}
			// Diagnostics cannot override the exact report or be changed separately.
			approximation, _ := v.Float64()
			if diagnostic != approximation {
				return values, ErrUnavailable
			}
			values[i] = v
		} else {
			// Programmatic collectors have no decimal report. Preserve their actual
			// binary value exactly, including every positive term. Parsed reports
			// always use the decimal branch above, even after diagnostic underflow.
			values[i] = new(big.Rat).SetFloat64(diagnostic)
		}
	}
	return values, nil
}

func (v trackingNumbers) valid() bool {
	million := big.NewRat(1000000, 1)
	return v[rmsOffset].Sign() >= 0 && v[skew].Sign() >= 0 && v[rootDelay].Sign() >= 0 && v[rootDispersion].Sign() >= 0 &&
		new(big.Rat).Abs(v[frequency]).Cmp(million) <= 0 && new(big.Rat).Abs(v[residualFrequency]).Cmp(million) <= 0 && v[skew].Cmp(million) <= 0
}

func (v trackingNumbers) offset() *big.Rat {
	out := new(big.Rat).Abs(v[systemOffset])
	for _, candidate := range []*big.Rat{new(big.Rat).Abs(v[lastOffset]), v[rmsOffset]} {
		if candidate.Cmp(out) > 0 {
			out.Set(candidate)
		}
	}
	return out
}

func (v trackingNumbers) rootDistance() *big.Rat {
	out := new(big.Rat).Quo(v[rootDelay], big.NewRat(2, 1))
	return out.Add(out, v[rootDispersion])
}

func durationSeconds(v time.Duration) *big.Rat {
	return big.NewRat(int64(v), int64(time.Second))
}

func uncertainty(t Tracking, now time.Time, cap time.Duration) (time.Duration, error) {
	v, err := t.numbers()
	age := now.Sub(t.Reference)
	if err != nil || !v.valid() || age < 0 || cap <= 0 {
		return 0, ErrUnavailable
	}
	seconds := v.offset()
	seconds.Add(seconds, v.rootDistance())
	growth := new(big.Rat).Mul(durationSeconds(age), v[skew])
	growth.Quo(growth, big.NewRat(1000000, 1))
	seconds.Add(seconds, growth)
	// Compare in the same exact domain before conversion. The cap is an integer
	// number of nanoseconds, so ceil(bound) <= cap iff bound <= cap.
	if seconds.Cmp(durationSeconds(cap)) > 0 {
		return 0, ErrUnavailable
	}
	nanos := new(big.Rat).Mul(seconds, big.NewRat(int64(time.Second), 1))
	whole, remainder := new(big.Int), new(big.Int)
	whole.QuoRem(nanos.Num(), nanos.Denom(), remainder)
	if remainder.Sign() > 0 {
		whole.Add(whole, big.NewInt(1))
	}
	if !whole.IsInt64() {
		return 0, ErrUnavailable
	}
	return time.Duration(whole.Int64()), nil
}
