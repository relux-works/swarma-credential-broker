package timeconf

import (
	"encoding/csv"
	"io"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

func rows(b []byte, fields int) ([][]string, error) {
	if len(b) == 0 || len(b) > 65536 || b[len(b)-1] != '\n' || strings.ContainsAny(string(b), "\r\x00\"") || strings.Contains(string(b), "\n\n") || b[0] == '\n' {
		return nil, ErrUnavailable
	}
	r := csv.NewReader(strings.NewReader(string(b)))
	r.FieldsPerRecord = fields
	var result [][]string
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, ErrUnavailable
		}
		for _, v := range row {
			if v == "" || strings.TrimSpace(v) != v {
				return nil, ErrUnavailable
			}
		}
		result = append(result, row)
	}
	if len(result) == 0 {
		return nil, ErrUnavailable
	}
	return result, nil
}
func number(s string) (float64, error) {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c == '.' || c == '+' || c == '-' || c == 'e' || c == 'E') {
			return 0, ErrUnavailable
		}
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || !finite(v) {
		return 0, ErrUnavailable
	}
	return v, nil
}
func epoch(s string) (time.Time, error) {
	parts := strings.Split(s, ".")
	if len(parts) > 2 || len(parts[0]) == 0 {
		return time.Time{}, ErrUnavailable
	}
	for _, c := range s {
		if c != '.' && (c < '0' || c > '9') {
			return time.Time{}, ErrUnavailable
		}
	}
	seconds, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || seconds <= 0 || seconds > 253402300799 {
		return time.Time{}, ErrUnavailable
	}
	var nanos int64
	if len(parts) == 2 {
		if len(parts[1]) == 0 || len(parts[1]) > 9 {
			return time.Time{}, ErrUnavailable
		}
		nanos, err = strconv.ParseInt(parts[1]+strings.Repeat("0", 9-len(parts[1])), 10, 64)
		if err != nil {
			return time.Time{}, ErrUnavailable
		}
	}
	return time.Unix(seconds, nanos).UTC(), nil
}

// ParseTracking supports the fixed 14-column chronyc CSV report, never raw
// diagnostic text. Source identities are retained in memory for correlation.
func ParseTracking(b []byte) (Tracking, error) {
	var t Tracking
	r, err := rows(b, 14)
	if err != nil || len(r) != 1 {
		return t, ErrUnavailable
	}
	v := r[0]
	ref, err := strconv.ParseUint(v[0], 16, 32)
	if err != nil || len(v[0]) != 8 || ref == 0 || strings.EqualFold(v[0], "7f7f0101") {
		return t, ErrUnavailable
	}
	identity, err := sourceIdentity(v[1])
	if err != nil {
		return t, ErrUnavailable
	}
	t.ReferenceID = v[0]
	t.Address = identity

	t.Stratum, err = strconv.Atoi(v[2])
	if err != nil || t.Stratum < 1 || t.Stratum > 15 {
		return Tracking{}, ErrUnavailable
	}
	t.Reference, err = epoch(v[3])
	if err != nil {
		return Tracking{}, err
	}
	fields := []*float64{&t.SystemOffset, &t.LastOffset, &t.RMSOffset, &t.Frequency, &t.ResidualFrequency, &t.Skew, &t.RootDelay, &t.RootDispersion, &t.UpdateInterval}
	for i, field := range fields {
		*field, err = number(v[i+4])
		if err != nil {
			return Tracking{}, err
		}
	}
	if t.RMSOffset < 0 || t.Skew < 0 || t.RootDelay < 0 || t.RootDispersion < 0 || t.UpdateInterval <= 0 || math.Abs(t.Frequency) > 1e6 || math.Abs(t.ResidualFrequency) > 1e6 || t.Skew > 1e6 {
		return Tracking{}, ErrUnavailable
	}
	t.Leap = v[13]
	switch t.Leap {
	case "Normal", "Insert second", "Delete second", "Not synchronised":
	default:
		return Tracking{}, ErrUnavailable
	}
	return t, nil
}

// ParseAuthData requires every reported association to be NTS, with negotiated
// keys/cookies and no reported NAK/failed establishment. Pool counts may differ
// from configuration counts; the selected tracking address is checked separately.
func ParseAuthData(b []byte) (Authentication, error) {
	out := Authentication{Addresses: map[string]bool{}}
	r, err := rows(b, 10)
	if err != nil {
		return Authentication{}, err
	}
	for _, v := range r {
		address, err := netip.ParseAddr(v[0])
		if err != nil || address.IsUnspecified() || address.Zone() != "" || out.Addresses[address.String()] || v[1] != "NTS" {
			return Authentication{}, ErrUnavailable
		}
		n := make([]uint64, 8)
		for i := range n {
			n[i], err = strconv.ParseUint(v[i+2], 10, 32)
			if err != nil {
				return Authentication{}, ErrUnavailable
			}
		}
		if !(n[1] == 15 && n[2] == 256 || n[1] == 30 && n[2] == 128) || n[4] > 1 || n[5] != 0 || n[6] == 0 || n[6] > 8 || n[7] == 0 || n[7] > 4096 {
			return Authentication{}, ErrUnavailable
		}
		out.Addresses[address.String()] = true
	}
	return out, nil
}

// ParseSources accepts an intentionally closed chrony configuration subset.
// Dynamic/include mechanisms and alternate clock sources are refused, rather
// than pretending a partial file list describes the daemon's entire authority.
func ParseSources(b []byte) (Sources, error) {
	var out Sources
	if len(b) > 65536 || strings.ContainsAny(string(b), "\x00\r\\\"'") {
		return out, ErrUnavailable
	}
	for _, line := range strings.Split(string(b), "\n") {
		line, _, _ = strings.Cut(line, "#")
		line, _, _ = strings.Cut(line, "!")
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "server", "pool":
			if len(f) < 3 || len(f[1]) > 253 || strings.HasPrefix(f[1], "-") {
				return Sources{}, ErrUnavailable
			}
			seen := map[string]bool{}
			nts := false
			for i := 2; i < len(f); i++ {
				option := f[i]
				if seen[option] {
					return Sources{}, ErrUnavailable
				}
				seen[option] = true
				switch option {
				case "nts":
					nts = true
				case "iburst", "burst", "prefer", "noselect", "offline":
				case "minpoll", "maxpoll", "maxsources", "ntsport", "port", "certset":
					i++
					if i >= len(f) {
						return Sources{}, ErrUnavailable
					}
					n, err := strconv.ParseUint(f[i], 10, 16)
					if err != nil || (option == "maxsources" || option == "port" || option == "ntsport") && n == 0 {
						return Sources{}, ErrUnavailable
					}
				default:
					return Sources{}, ErrUnavailable
				}
			}
			if !nts {
				return Sources{}, ErrUnavailable
			}
			identity, err := sourceIdentity(f[1])
			if err != nil {
				return Sources{}, ErrUnavailable
			}
			out.Entries = append(out.Entries, identity)
			out.Count++
		// These directives cannot add unauthenticated source associations. The
		// installed daemon and its complete file list remain operator-controlled.
		case "rtcsync", "rtconutc":
			if len(f) != 1 {
				return Sources{}, ErrUnavailable
			}
		case "driftfile", "logdir", "leapsectz", "ntsdumpdir", "keyfile", "bindcmdaddress", "user":
			if len(f) != 2 {
				return Sources{}, ErrUnavailable
			}
		case "leapsecmode":
			if len(f) != 2 || (f[1] != "system" && f[1] != "step" && f[1] != "slew" && f[1] != "ignore") {
				return Sources{}, ErrUnavailable
			}
		case "maxupdateskew":
			if len(f) != 2 {
				return Sources{}, ErrUnavailable
			}
			v, err := number(f[1])
			if err != nil || v <= 0 || v > 1e6 {
				return Sources{}, ErrUnavailable
			}
		case "port", "cmdport", "minsources":
			if len(f) != 2 {
				return Sources{}, ErrUnavailable
			}
			v, err := strconv.ParseUint(f[1], 10, 16)
			if err != nil || f[0] == "minsources" && v == 0 {
				return Sources{}, ErrUnavailable
			}
		case "makestep":
			if len(f) != 3 {
				return Sources{}, ErrUnavailable
			}
			v, err := number(f[1])
			if err != nil || v <= 0 {
				return Sources{}, ErrUnavailable
			}
			if _, err := strconv.ParseInt(f[2], 10, 32); err != nil {
				return Sources{}, ErrUnavailable
			}
		case "ntstrustedcerts":
			if len(f) != 2 && len(f) != 3 {
				return Sources{}, ErrUnavailable
			}
			if len(f) == 3 {
				if _, err := strconv.ParseUint(f[1], 10, 32); err != nil {
					return Sources{}, ErrUnavailable
				}
			}
		case "log":
			if len(f) < 2 {
				return Sources{}, ErrUnavailable
			}
			for _, v := range f[1:] {
				switch v {
				case "measurements", "statistics", "tracking", "rtc", "refclocks", "tempcomp", "rawmeasurements", "selection":
				default:
					return Sources{}, ErrUnavailable
				}
			}

		default:
			return Sources{}, ErrUnavailable
		}
	}
	out.AllNTS = true
	return out, nil
}

// sourceIdentity canonicalizes numeric addresses or original configured DNS
// names without a DNS lookup. Original names come from chronyd, never PTR data.
func sourceIdentity(s string) (string, error) {
	if a, err := netip.ParseAddr(s); err == nil {
		if a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.Zone() != "" {
			return "", ErrUnavailable
		}
		return a.Unmap().String(), nil
	}
	if strings.Contains(s, ":") {
		return "", ErrUnavailable
	}
	numeric := true
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c == '.') {
			numeric = false
		}
	}
	if numeric {
		return "", ErrUnavailable
	}
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	if len(s) == 0 || len(s) > 253 {
		return "", ErrUnavailable
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrUnavailable
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", ErrUnavailable
			}
		}
	}
	return s, nil
}
