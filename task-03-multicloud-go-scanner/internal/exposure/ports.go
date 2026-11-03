package exposure

import (
	"strconv"
	"strings"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
)

const (
	minPort = 0
	maxPort = 65535
	// ICMP type and code are 8-bit values.
	maxICMPValue = 255
	// awsWildcard is AWS's "any" value for ICMP type/code.
	awsWildcard = -1
)

// PortFields are the port and ICMP fields of one finding (DESIGN.md 6.4).
// Port fields and ICMP fields are never mixed: ICMP type/code never appear
// in FromPort/ToPort. Fields that do not apply are nil (JSON null).
type PortFields struct {
	Port     string // "all" | "22" | "8000-8090" | "unknown"
	FromPort *int   // tcp/udp/sctp only
	ToPort   *int   // tcp/udp/sctp only
	ICMPType *int   // icmp/icmpv6 only; nil = any type
	ICMPCode *int   // icmp/icmpv6 only; nil = any code
}

// hasPorts reports whether a canonical protocol carries port numbers.
func hasPorts(proto string) bool {
	return proto == ProtoTCP || proto == ProtoUDP || proto == ProtoSCTP
}

func isICMP(proto string) bool {
	return proto == ProtoICMP || proto == ProtoICMPv6
}

func unknownPorts() PortFields { return PortFields{Port: model.PortUnknown} }

// rangeFields builds the fields for a valid inclusive port range.
func rangeFields(from, to int) PortFields {
	pf := PortFields{FromPort: intPtr(from), ToPort: intPtr(to)}
	switch {
	case from == minPort && to == maxPort:
		pf.Port = model.PortAll
	case from == to:
		pf.Port = strconv.Itoa(from)
	default:
		pf.Port = strconv.Itoa(from) + "-" + strconv.Itoa(to)
	}
	return pf
}

// FromPortRange converts a GCP or Azure port specification ("22",
// "8000-8090", "*", or "" for no restriction) for a canonical protocol.
//
//   - tcp, udp, sctp: the spec is a port range; no restriction is "all"
//     with from/to 0-65535.
//   - all protocols ("*" in Azure, "all" in GCP): a port restriction is
//     kept. Azure protocol "*" with destination port 443 allows tcp/443
//     and udp/443, not every port. Without a restriction the port is
//     "all" with null from/to, the same as AWS -1.
//   - other protocols (icmp, esp, ...): no port concept; "all", and the
//     raw value is kept only in provider_port.
//   - unknown protocol: "unknown" (the protocol diagnostic covers it).
//
// ok is false only when a spec that is used has an unparseable value.
func FromPortRange(proto, raw string) (PortFields, bool) {
	switch {
	case proto == ProtoUnknown:
		return unknownPorts(), true
	case proto != ProtoAll && !hasPorts(proto):
		return PortFields{Port: model.PortAll}, true
	}
	from, to, ok := parsePortSpec(raw)
	if !ok {
		return unknownPorts(), false
	}
	if proto == ProtoAll && from == minPort && to == maxPort {
		return PortFields{Port: model.PortAll}, true
	}
	return rangeFields(from, to), true
}

// parsePortSpec parses "", "*", "22" or "8000-8090". An empty spec or "*"
// means no restriction (0-65535).
func parsePortSpec(raw string) (from, to int, ok bool) {
	s := strings.TrimSpace(raw)
	if s == "" || s == "*" {
		return minPort, maxPort, true
	}
	lo, hi, found := strings.Cut(s, "-")
	if !found {
		hi = lo
	}
	from, okFrom := parsePort(lo)
	to, okTo := parsePort(hi)
	if !okFrom || !okTo || from > to {
		return 0, 0, false
	}
	return from, to, true
}

func parsePort(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if !isDigits(s) {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < minPort || n > maxPort {
		return 0, false
	}
	return n, true
}

// FromAWSPorts converts AWS IpPermission FromPort/ToPort for a canonical
// protocol.
//
//   - tcp/udp: FromPort-ToPort is a port range; 0-65535 is "all".
//   - icmp/icmpv6: FromPort is the ICMP type and ToPort the code; -1 means
//     any. A specific code with a wildcard type is invalid.
//   - icmpv6 only: the port range is optional; if both values are omitted,
//     all types and codes are allowed. (EC2 API reference, IpPermission:
//     "For icmpv6, the port range is optional; if you omit the port range,
//     traffic for all types and codes is allowed." For tcp, udp and icmp
//     the range is required.)
//   - "all" and every other protocol: AWS ignores the port fields and
//     allows all ports.
//
// ok is false when tcp/udp/icmp values are missing or out of range.
func FromAWSPorts(proto string, from, to *int32) (PortFields, bool) {
	if proto == ProtoICMPv6 && from == nil && to == nil {
		return PortFields{Port: model.PortAll}, true
	}
	switch {
	case proto == ProtoUnknown:
		return unknownPorts(), true
	case proto == ProtoTCP || proto == ProtoUDP:
		if from == nil || to == nil {
			return unknownPorts(), false
		}
		f, t := int(*from), int(*to)
		if f < minPort || t > maxPort || f > t {
			return unknownPorts(), false
		}
		return rangeFields(f, t), true
	case isICMP(proto):
		if from == nil || to == nil {
			return unknownPorts(), false
		}
		icmpType, okType := awsICMPValue(int(*from))
		icmpCode, okCode := awsICMPValue(int(*to))
		if !okType || !okCode || (icmpType == nil && icmpCode != nil) {
			return unknownPorts(), false
		}
		return PortFields{Port: model.PortAll, ICMPType: icmpType, ICMPCode: icmpCode}, true
	default:
		return PortFields{Port: model.PortAll}, true
	}
}

// awsICMPValue maps an AWS ICMP type or code: -1 is a wildcard (nil).
func awsICMPValue(v int) (*int, bool) {
	if v == awsWildcard {
		return nil, true
	}
	if v < 0 || v > maxICMPValue {
		return nil, false
	}
	return intPtr(v), true
}

// AWSProviderPort renders the raw AWS port fields for provider_port:
// "from-to" for port ranges, "type:code" for ICMP, "" when absent.
func AWSProviderPort(proto string, from, to *int32) string {
	if from == nil && to == nil {
		return ""
	}
	sep := "-"
	if isICMP(proto) {
		sep = ":"
	}
	return int32String(from) + sep + int32String(to)
}

func int32String(v *int32) string {
	if v == nil {
		return ""
	}
	return strconv.Itoa(int(*v))
}

func intPtr(v int) *int { return &v }
