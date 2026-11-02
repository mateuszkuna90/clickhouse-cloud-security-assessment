package exposure

import (
	"regexp"
	"strconv"
	"strings"
)

// Canonical protocol values (DESIGN.md 6.3).
const (
	ProtoAll     = "all"
	ProtoTCP     = "tcp"
	ProtoUDP     = "udp"
	ProtoICMP    = "icmp"
	ProtoICMPv6  = "icmpv6"
	ProtoESP     = "esp"
	ProtoAH      = "ah"
	ProtoSCTP    = "sctp"
	ProtoUnknown = "unknown"
)

// protocolNumbers maps IANA protocol numbers to the canonical names used in
// the report. Other numbers in 0-255 are kept as decimal strings.
var protocolNumbers = map[int]string{
	1:   ProtoICMP,
	6:   ProtoTCP,
	17:  ProtoUDP,
	50:  ProtoESP,
	51:  ProtoAH,
	58:  ProtoICMPv6,
	132: ProtoSCTP,
}

// protocolName accepts lower-case names such as "ipip" or "ipv6-icmp".
var protocolName = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// NormalizeProtocol maps a raw provider protocol value to its canonical
// form. ok is false when the value is empty or not a valid protocol (the
// canonical value is then "unknown"); the caller records a diagnostic, but
// the finding is still reported, because detection never depends on the
// protocol.
//
//	"-1", "all", "*"        -> "all"   (AWS, GCP, Azure wildcards)
//	"tcp", "6", "Tcp"       -> "tcp"   (and likewise for the table above)
//	"47", "047"             -> "47"    (other numbers 0-255)
//	"ipip"                  -> "ipip"  (other names, lower-cased)
//	"", "300", "-5", "t c p" -> "unknown", false
func NormalizeProtocol(raw string) (string, bool) {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch s {
	case "":
		return ProtoUnknown, false
	case "-1", "all", "*":
		return ProtoAll, true
	}
	if isDigits(s) || strings.HasPrefix(s, "-") {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 || n > 255 {
			return ProtoUnknown, false
		}
		if name, ok := protocolNumbers[n]; ok {
			return name, true
		}
		return strconv.Itoa(n), true
	}
	if protocolName.MatchString(s) {
		return s, true
	}
	return ProtoUnknown, false
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
