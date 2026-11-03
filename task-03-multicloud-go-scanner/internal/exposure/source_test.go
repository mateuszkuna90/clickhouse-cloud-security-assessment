package exposure

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
)

func TestClassifyAddress(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want SourceClass
	}{
		{"world", "0.0.0.0/0", ClassWorldIPv4},
		{"world with whitespace", "  0.0.0.0/0 ", ClassWorldIPv4},
		{"non-canonical world", "10.0.0.0/0", ClassWorldIPv4},
		{"private 10/8", "10.0.0.0/8", ClassNotWorld},
		{"private 172.16/12", "172.16.0.0/12", ClassNotWorld},
		{"private 192.168/16", "192.168.0.0/16", ClassNotWorld},
		{"single host", "203.0.113.10/32", ClassNotWorld},
		{"half the internet is not /0", "0.0.0.0/1", ClassNotWorld},
		{"plain address 0.0.0.0 is a host", "0.0.0.0", ClassNotWorld},
		{"plain address", "198.51.100.7", ClassNotWorld},
		{"ipv6 world is out of scope", "::/0", ClassNotWorld},
		{"ipv6 prefix", "2001:db8::/32", ClassNotWorld},
		{"ipv4-mapped ipv6 /0 is not ipv4", "::ffff:0.0.0.0/0", ClassNotWorld},
		{"empty", "", ClassMalformed},
		{"blank", "   ", ClassMalformed},
		{"octet out of range", "256.0.0.0/0", ClassMalformed},
		{"prefix too long", "10.0.0.0/33", ClassMalformed},
		{"negative prefix", "0.0.0.0/-1", ClassMalformed},
		{"missing prefix length", "0.0.0.0/", ClassMalformed},
		{"too few octets", "0.0.0/0", ClassMalformed},
		{"leading zeros", "000.0.0.0/0", ClassMalformed},
		{"text", "not-a-cidr", ClassMalformed},
		{"azure keyword is not an address", "*", ClassMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyAddress(tt.in)
			if got.Class != tt.want {
				t.Fatalf("ClassifyAddress(%q) = %v, want %v", tt.in, got.Class, tt.want)
			}
			if got.Class == ClassWorldIPv4 {
				if got.Source != WorldIPv4 || got.MatchReason != model.MatchIPv4WorldCIDR {
					t.Fatalf("world match = %+v", got)
				}
			} else if got.Source != "" || got.MatchReason != "" {
				t.Fatalf("non-world match carries world fields: %+v", got)
			}
		})
	}
}

func TestClassifyAzurePrefix(t *testing.T) {
	tests := []struct {
		in         string
		wantClass  SourceClass
		wantSource string
		wantReason string
	}{
		{"*", ClassWorldIPv4, WorldIPv4, model.MatchAzureAnyWildcard},
		{"Any", ClassWorldIPv4, WorldIPv4, model.MatchAzureAnyWildcard},
		{"any", ClassWorldIPv4, WorldIPv4, model.MatchAzureAnyWildcard},
		{"Internet", ClassWorldIPv4, "Internet", model.MatchAzureServiceTagInternet},
		{"INTERNET", ClassWorldIPv4, "Internet", model.MatchAzureServiceTagInternet},
		{"0.0.0.0/0", ClassWorldIPv4, WorldIPv4, model.MatchIPv4WorldCIDR},
		{"10.0.0.0/8", ClassNotWorld, "", ""},
		{"10.1.2.3", ClassNotWorld, "", ""},
		{"VirtualNetwork", ClassSelector, "", ""},
		{"AzureLoadBalancer", ClassSelector, "", ""},
		{"Storage.WestEurope", ClassSelector, "", ""},
		{"", ClassMalformed, "", ""},
		{"10.0.0.300", ClassMalformed, "", ""},
		{"Storage..WestEurope", ClassMalformed, "", ""},
		{"bad tag!", ClassMalformed, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := ClassifyAzurePrefix(tt.in)
			if got.Class != tt.wantClass || got.Source != tt.wantSource || got.MatchReason != tt.wantReason {
				t.Fatalf("ClassifyAzurePrefix(%q) = %+v, want class=%v source=%q reason=%q",
					tt.in, got, tt.wantClass, tt.wantSource, tt.wantReason)
			}
		})
	}
}

// FuzzClassifyAddress checks that classification never panics and that a
// world result always agrees with an independent reading of the prefix.
func FuzzClassifyAddress(f *testing.F) {
	for _, seed := range []string{"0.0.0.0/0", "10.0.0.0/0", "10.0.0.0/8", "::/0", "1.2.3.4", "", "x/0", "0.0.0.0/00"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		got := ClassifyAddress(in)
		p, err := netip.ParsePrefix(strings.TrimSpace(in))
		isWorld := err == nil && p.Addr().Is4() && p.Bits() == 0
		if (got.Class == ClassWorldIPv4) != isWorld {
			t.Fatalf("ClassifyAddress(%q) = %v, reference world=%v", in, got.Class, isWorld)
		}
	})
}
