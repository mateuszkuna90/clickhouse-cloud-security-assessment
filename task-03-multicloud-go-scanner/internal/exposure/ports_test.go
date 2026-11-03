package exposure

import (
	"strconv"
	"testing"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
)

func i32(v int32) *int32 { return &v }

func eqIntPtr(a, b *int) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func assertPorts(t *testing.T, got, want PortFields) {
	t.Helper()
	if got.Port != want.Port ||
		!eqIntPtr(got.FromPort, want.FromPort) || !eqIntPtr(got.ToPort, want.ToPort) ||
		!eqIntPtr(got.ICMPType, want.ICMPType) || !eqIntPtr(got.ICMPCode, want.ICMPCode) {
		t.Fatalf("ports = %s, want %s", fmtPorts(got), fmtPorts(want))
	}
}

func fmtPorts(p PortFields) string {
	s := func(v *int) string {
		if v == nil {
			return "nil"
		}
		return strconv.Itoa(*v)
	}
	return "{port=" + p.Port + " from=" + s(p.FromPort) + " to=" + s(p.ToPort) +
		" type=" + s(p.ICMPType) + " code=" + s(p.ICMPCode) + "}"
}

func rng(port string, from, to int) PortFields {
	return PortFields{Port: port, FromPort: intPtr(from), ToPort: intPtr(to)}
}

func TestFromPortRange(t *testing.T) {
	all := PortFields{Port: model.PortAll}
	unknown := PortFields{Port: model.PortUnknown}
	tests := []struct {
		name   string
		proto  string
		raw    string
		want   PortFields
		wantOK bool
	}{
		{"tcp single", ProtoTCP, "22", rng("22", 22, 22), true},
		{"tcp range", ProtoTCP, "8000-8090", rng("8000-8090", 8000, 8090), true},
		{"tcp full range is all", ProtoTCP, "0-65535", rng("all", 0, 65535), true},
		{"tcp star is all", ProtoTCP, "*", rng("all", 0, 65535), true},
		{"tcp empty is all", ProtoTCP, "", rng("all", 0, 65535), true},
		{"udp single", ProtoUDP, "123", rng("123", 123, 123), true},
		{"sctp range", ProtoSCTP, "1-2", rng("1-2", 1, 2), true},
		{"icmp has no ports", ProtoICMP, "*", all, true},
		{"icmp ignores a port value", ProtoICMP, "22", all, true},
		{"all protocols", ProtoAll, "*", all, true},
		// Regression (M1 review): Azure protocol "*" keeps its port limits.
		{"all protocols, port 443", ProtoAll, "443", rng("443", 443, 443), true},
		{"all protocols, range 80-443", ProtoAll, "80-443", rng("80-443", 80, 443), true},
		{"all protocols, empty spec", ProtoAll, "", all, true},
		{"all protocols, explicit 0-65535", ProtoAll, "0-65535", all, true},
		{"all protocols, malformed spec", ProtoAll, "https", unknown, false},
		{"other protocol", "47", "", all, true},
		{"unknown protocol", ProtoUnknown, "22", unknown, true},
		{"reversed range", ProtoTCP, "90-80", unknown, false},
		{"port too large", ProtoTCP, "65536", unknown, false},
		{"negative", ProtoTCP, "-1", unknown, false},
		{"text", ProtoTCP, "ssh", unknown, false},
		{"open range", ProtoTCP, "80-", unknown, false},
		{"three parts", ProtoTCP, "1-2-3", unknown, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := FromPortRange(tt.proto, tt.raw)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			assertPorts(t, got, tt.want)
		})
	}
}

func TestFromAWSPorts(t *testing.T) {
	all := PortFields{Port: model.PortAll}
	unknown := PortFields{Port: model.PortUnknown}
	icmp := func(typ, code *int) PortFields {
		return PortFields{Port: model.PortAll, ICMPType: typ, ICMPCode: code}
	}
	tests := []struct {
		name     string
		proto    string
		from, to *int32
		want     PortFields
		wantOK   bool
		wantRaw  string
	}{
		{"tcp 22", ProtoTCP, i32(22), i32(22), rng("22", 22, 22), true, "22-22"},
		{"tcp 443", ProtoTCP, i32(443), i32(443), rng("443", 443, 443), true, "443-443"},
		{"tcp all ports", ProtoTCP, i32(0), i32(65535), rng("all", 0, 65535), true, "0-65535"},
		{"udp 123", ProtoUDP, i32(123), i32(123), rng("123", 123, 123), true, "123-123"},
		{"all protocols, no ports", ProtoAll, nil, nil, all, true, ""},
		{"all protocols ignores ports on AWS", ProtoAll, i32(443), i32(443), all, true, "443-443"},
		// Regression (M1 review): icmpv6 port range is optional on AWS.
		{"icmpv6 omitted range is all types and codes", ProtoICMPv6, nil, nil, icmp(nil, nil), true, ""},
		{"icmpv6 -1/-1 is all types and codes", ProtoICMPv6, i32(-1), i32(-1), icmp(nil, nil), true, "-1:-1"},
		{"icmpv6 code without type is invalid", ProtoICMPv6, i32(-1), i32(0), unknown, false, "-1:0"},
		{"icmpv6 with only one value is invalid", ProtoICMPv6, i32(128), nil, unknown, false, "128:"},
		{"esp ignores ports", ProtoESP, nil, nil, all, true, ""},
		{"sctp on AWS allows all ports", ProtoSCTP, i32(1), i32(2), all, true, "1-2"},
		{"icmp all types", ProtoICMP, i32(-1), i32(-1), icmp(nil, nil), true, "-1:-1"},
		{"icmp echo request, any code", ProtoICMP, i32(8), i32(-1), icmp(intPtr(8), nil), true, "8:-1"},
		{"icmp type and code", ProtoICMP, i32(3), i32(4), icmp(intPtr(3), intPtr(4)), true, "3:4"},
		{"icmpv6 type", ProtoICMPv6, i32(128), i32(-1), icmp(intPtr(128), nil), true, "128:-1"},
		{"icmp code without type is invalid", ProtoICMP, i32(-1), i32(4), unknown, false, "-1:4"},
		{"icmp type out of range", ProtoICMP, i32(256), i32(-1), unknown, false, "256:-1"},
		{"icmp missing values", ProtoICMP, nil, nil, unknown, false, ""},
		{"tcp missing ports", ProtoTCP, nil, nil, unknown, false, ""},
		{"tcp reversed", ProtoTCP, i32(90), i32(80), unknown, false, "90-80"},
		{"tcp negative", ProtoTCP, i32(-1), i32(-1), unknown, false, "-1--1"},
		{"unknown protocol", ProtoUnknown, i32(1), i32(2), unknown, true, "1-2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := FromAWSPorts(tt.proto, tt.from, tt.to)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			assertPorts(t, got, tt.want)
			if raw := AWSProviderPort(tt.proto, tt.from, tt.to); raw != tt.wantRaw {
				t.Fatalf("AWSProviderPort = %q, want %q", raw, tt.wantRaw)
			}
		})
	}
}
