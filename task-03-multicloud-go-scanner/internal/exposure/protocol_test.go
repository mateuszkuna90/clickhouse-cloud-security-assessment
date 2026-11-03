package exposure

import "testing"

func TestNormalizeProtocol(t *testing.T) {
	tests := []struct {
		in     string
		want   string
		wantOK bool
	}{
		// Wildcards from each provider.
		{"-1", ProtoAll, true},
		{"all", ProtoAll, true},
		{"ALL", ProtoAll, true},
		{"*", ProtoAll, true},
		// Names, case-insensitive.
		{"tcp", ProtoTCP, true},
		{"Tcp", ProtoTCP, true},
		{"udp", ProtoUDP, true},
		{"Icmp", ProtoICMP, true},
		{"icmpv6", ProtoICMPv6, true},
		{"Esp", ProtoESP, true},
		{"Ah", ProtoAH, true},
		{"sctp", ProtoSCTP, true},
		// Numeric identifiers mapped to canonical names.
		{"6", ProtoTCP, true},
		{"17", ProtoUDP, true},
		{"1", ProtoICMP, true},
		{"58", ProtoICMPv6, true},
		{"50", ProtoESP, true},
		{"51", ProtoAH, true},
		{"132", ProtoSCTP, true},
		{"006", ProtoTCP, true},
		{" 6 ", ProtoTCP, true},
		// Other numbers kept as decimal strings.
		{"47", "47", true},
		{"047", "47", true},
		{"0", "0", true},
		{"255", "255", true},
		// Other names kept, lower-cased.
		{"ipip", "ipip", true},
		{"IPIP", "ipip", true},
		// Unknown.
		{"", ProtoUnknown, false},
		{"   ", ProtoUnknown, false},
		{"256", ProtoUnknown, false},
		{"300", ProtoUnknown, false},
		{"-5", ProtoUnknown, false},
		{"99999999999999999999", ProtoUnknown, false},
		{"t c p", ProtoUnknown, false},
		{"6.5", ProtoUnknown, false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, ok := NormalizeProtocol(tt.in)
			if got != tt.want || ok != tt.wantOK {
				t.Fatalf("NormalizeProtocol(%q) = (%q, %v), want (%q, %v)", tt.in, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}
