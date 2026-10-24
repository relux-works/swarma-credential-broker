package timeconf

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"strings"
	"testing"
	"time"
)

func decimalFixture(t *testing.T, age time.Duration, fields [9]string, cap time.Duration) (*Provider, Tracking, time.Time) {
	t.Helper()
	_, c, clock := providerFixture(t)
	ref := clock.point.Now.Add(-age)
	report := fmt.Sprintf("C0000201,192.0.2.1,3,%d.%09d,%s,%s,%s,%s,%s,%s,%s,%s,%s,Normal\n", ref.Unix(), ref.Nanosecond(), fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6], fields[7], fields[8])
	tracking, err := ParseTracking([]byte(report))
	if err != nil {
		t.Fatal("decimal fixture refused", err)
	}
	c.evidence.Tracking = tracking
	q := platformTestPolicy()
	q.MaxUncertainty = cap
	p, err := New(q, c, clock, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p, tracking, clock.point.Now
}

// Claim: positive growth smaller than float64 resolution still requires the
// next nanosecond and refusal at either cap; zero age at exactly that cap trusts.
// This ports the reported boundary witness and includes a decimal underflow.
func TestUncertaintyPositiveGrowthRounding(t *testing.T) {
	for _, tc := range []struct {
		name, offset, delay, dispersion string
		cap                             time.Duration
	}{
		{"shared", "0.5", "0.5", "0.75", 1500 * time.Millisecond},
		{"service", "0.25", "0.5", "0.5", time.Second},
	} {
		for _, growth := range []struct {
			name, skew string
			age        time.Duration
		}{
			{"exact-cap", "0.01", 0}, {"positive-growth", "0.01", time.Nanosecond}, {"underflow-growth", "1e-400", time.Nanosecond},
		} {
			t.Run(tc.name+"/"+growth.name, func(t *testing.T) {
				fields := [9]string{tc.offset, "0", "0", "0", "0", growth.skew, tc.delay, tc.dispersion, "1040"}
				p, _, _ := decimalFixture(t, growth.age, fields, tc.cap)
				if growth.age == 0 {
					if got := trusted(t, p); got.Uncertainty != tc.cap {
						t.Fatal("exact cap changed", got.Uncertainty)
					}
				} else {
					refused(t, p)
				}
			})
		}
	}
}

// oracleNanoseconds independently scales each decimal component to rational
// nanoseconds before summing. Generated fractions have at most 18 places. It
// does not call production parsing, scaling, summation or rounding helpers.
func oracleNanoseconds(t *testing.T, fields [9]string, age int64) *big.Rat {
	t.Helper()
	values := make([]*big.Rat, 9)
	for i, s := range fields {
		var ok bool
		values[i], ok = new(big.Rat).SetString(s)
		if !ok {
			t.Fatal("oracle input")
		}
	}
	abs := func(v *big.Rat) *big.Rat { return new(big.Rat).Abs(v) }
	correction := abs(values[0])
	if v := abs(values[1]); v.Cmp(correction) > 0 {
		correction = v
	}
	if values[2].Cmp(correction) > 0 {
		correction = new(big.Rat).Set(values[2])
	}
	// Scale components separately and use division with explicit integer factors.
	out := new(big.Rat).Mul(correction, big.NewRat(1000000000, 1))
	out.Add(out, new(big.Rat).Mul(values[6], big.NewRat(500000000, 1)))
	out.Add(out, new(big.Rat).Mul(values[7], big.NewRat(1000000000, 1)))
	growth := new(big.Rat).Mul(values[5], new(big.Rat).SetInt64(age))
	out.Add(out, new(big.Rat).Quo(growth, big.NewRat(1000000, 1)))
	return out
}

// Claim: fixed-seed random decimal reports match an independent rational oracle
// exactly after upward rounding; trust follows the shared/stricter cap. Measured
// fields are kept within their own limits, so cap refusal is the only variable.
func TestExactDecimalUncertaintyProperty(t *testing.T) {
	for _, seed := range []int64{1, 19, 20261023} {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			accepted, rejected := 0, 0
			for i := 0; i < 96; i++ {
				fraction := func(limit int64) string { return fmt.Sprintf("0.%018d", rng.Int63n(limit)) }
				fields := [9]string{fraction(500000000000000000), fraction(500000000000000000), fraction(500000000000000000), "0", "0", fmt.Sprintf("%d.%09d", rng.Intn(2000), rng.Intn(1000000000)), fraction(500000000000000000), fraction(500000000000000000), "1040"}
				if rng.Intn(2) == 0 {
					fields[0] = "-" + fields[0]
				}
				if rng.Intn(2) == 0 {
					fields[1] = "-" + fields[1]
				}
				age := time.Duration(rng.Int63n(int64(2048 * time.Second)))
				cap := time.Second
				if i%2 == 0 {
					cap = 1500 * time.Millisecond
				}
				p, _, _ := decimalFixture(t, age, fields, cap)
				exact := oracleNanoseconds(t, fields, int64(age))
				q, r := new(big.Int), new(big.Int)
				q.QuoRem(exact.Num(), exact.Denom(), r)
				if r.Sign() > 0 {
					q.Add(q, big.NewInt(1))
				}
				if q.Cmp(big.NewInt(int64(cap))) > 0 {
					rejected++
					refused(t, p)
				} else {
					accepted++
					v, err := p.Sample(context.Background())
					if err != nil || !v.Trusted || !v.Fresh || v.Uncertainty != time.Duration(q.Int64()) {
						t.Fatalf("case %d: rational ceil=%s, got=%v trusted=%t err=%v", i, q, v.Uncertainty, v.Trusted, err)
					}
				}
			}
			if accepted == 0 || rejected == 0 {
				t.Fatal("property did not exercise both verdicts", accepted, rejected)
			}
		})
	}
}

// Claim: decimal differences below float64 resolution still decide measured
// thresholds, including signed offsets and a summed/scaled root distance. Each
// rejected report has a trusted exact-bound control in the same field.
func TestExactDecimalThresholdNeighbors(t *testing.T) {
	for _, tc := range []struct {
		name     string
		index    int
		at, over string
	}{
		{"system", 0, "0.5", "0.50000000000000000001"},
		{"negative-system", 0, "-0.5", "-0.50000000000000000001"},
		{"last", 1, "0.5", "0.50000000000000000001"},
		{"rms", 2, "0.5", "0.50000000000000000001"},
		{"root-delay-halved-plus-dispersion", 6, "1", "1.00000000000000000002"},
		{"root-dispersion", 7, "1", "1.00000000000000000001"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, bad := range []bool{false, true} {
				fields := [9]string{"0", "0", "0", "0", "0", "0", "0", "0", "1040"}
				if tc.index == 6 {
					fields[7] = "0.5"
				}
				fields[tc.index] = tc.at
				if bad {
					fields[tc.index] = tc.over
				}
				p, _, _ := decimalFixture(t, 0, fields, 1500*time.Millisecond)
				if bad {
					refused(t, p)
				} else {
					trusted(t, p)
				}
			}
		})
	}
}

// Claim: exact signs and frequency/skew ceilings are enforced before any float
// diagnostic conversion can hide a violation; malformed or resource-excessive
// decimals refuse, while their ordinary and underflow-positive controls parse.
func TestExactTrackingNumericStructure(t *testing.T) {
	for _, tc := range []struct {
		index     int
		bad, good string
	}{
		{6, "-1e-400", "1e-400"}, {9, "-1e-400", "1e-400"},
		{10, "-1e-400", "1e-400"}, {11, "-1e-400", "1e-400"},
		{7, "1000000.000000000000001", "1000000"},
		{8, "-1000000.000000000000001", "-1000000"},
		{9, "1000000.000000000000001", "1000000"},
		{5, "1/2", "0.5"}, {5, "0x1p-1", "0.5"}, {5, "1_0", "10"},
		{5, "1e-4097", "1e-4096"}, {5, "1e9999999999999999999999", "1"},
		{5, strings.Repeat("0", 257), "0"},
	} {
		t.Run(fmt.Sprintf("%d/%s", tc.index, tc.good), func(t *testing.T) {
			fields := strings.Split(strings.TrimSpace("C0000201,192.0.2.1,3,1893553444,0.001,0.001,0.001,1,0.1,0.1,0.002,0.001,1040,Normal"), ",")
			fields[tc.index] = tc.bad
			if _, err := ParseTracking([]byte(strings.Join(fields, ",") + "\n")); !errors.Is(err, ErrUnavailable) {
				t.Fatal("invalid exact field accepted", err)
			}
			fields[tc.index] = tc.good
			if _, err := ParseTracking([]byte(strings.Join(fields, ",") + "\n")); err != nil {
				t.Fatal("valid exact field refused", err)
			}
		})
	}
}

// Claim: changing a rounded diagnostic cannot override its retained exact
// report. Programmatic float evidence also retains tiny positive binary growth.
func TestExactTrackingDiagnosticIntegrity(t *testing.T) {
	fields := [9]string{"0.5", "0", "0", "0", "0", "0.01", "0.5", "0.75", "1040"}
	p, parsed, _ := decimalFixture(t, 0, fields, 1500*time.Millisecond)
	trusted(t, p)
	parsed.SystemOffset = 0
	p.collector.(*fakeCollector).evidence.Tracking = parsed
	refused(t, p)
	parsed.SystemOffset = 0.5
	parsed.exact = nil
	parsed.Reference = parsed.Reference.Add(-time.Nanosecond)
	p.collector.(*fakeCollector).evidence.Tracking = parsed
	refused(t, p)
	parsed.Reference = parsed.Reference.Add(time.Nanosecond)
	p.collector.(*fakeCollector).evidence.Tracking = parsed
	trusted(t, p)
}

// Claim: configuration numeric limits also use exact signs and ceilings after
// replacing the common decimal reader; positive underflow is not mistaken for
// zero. These directives cannot introduce an unauthenticated source.
func TestExactSourceNumericThresholds(t *testing.T) {
	for _, tc := range []struct {
		directive string
		ok        bool
	}{
		{"maxupdateskew 1000000", true},
		{"maxupdateskew 1000000.000000000000001", false},
		{"maxupdateskew 1e-400", true},
		{"maxupdateskew -1e-400", false},
		{"makestep 1e-400 3", true},
		{"makestep -1e-400 3", false},
		{"makestep 0 3", false},
	} {
		t.Run(tc.directive, func(t *testing.T) {
			v, err := ParseSources([]byte(tc.directive + "\nserver time.example nts\n"))
			if tc.ok {
				if err != nil || !v.AllNTS || v.Count != 1 {
					t.Fatal("valid exact directive refused", err)
				}
			} else if !errors.Is(err, ErrUnavailable) || v.Count != 0 {
				t.Fatal("out-of-bound directive accepted", err)
			}
		})
	}
}
