// Package exposure is the provider-agnostic detection engine. It has no
// cloud SDK imports: provider packages translate SDK types into Rule values
// and call Evaluate (DESIGN.md section 6).
package exposure

import (
	"net/netip"
	"regexp"
	"strings"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
)

// SourceClass is the classification of one source value (DESIGN.md 6.1).
type SourceClass int

const (
	// ClassMalformed: empty or unparseable, and not a valid selector.
	ClassMalformed SourceClass = iota
	// ClassWorldIPv4: covers the whole IPv4 address space.
	ClassWorldIPv4
	// ClassNotWorld: a valid address or CIDR that is not IPv4 /0
	// (including IPv6 ::/0, which is out of scope in v1).
	ClassNotWorld
	// ClassSelector: a valid provider-specific non-address selector.
	ClassSelector
)

func (c SourceClass) String() string {
	switch c {
	case ClassWorldIPv4:
		return "world_ipv4"
	case ClassNotWorld:
		return "not_world"
	case ClassSelector:
		return "selector"
	default:
		return "malformed"
	}
}

// WorldIPv4 is the canonical text for an IPv4 world source.
const WorldIPv4 = "0.0.0.0/0"

// SourceMatch is the result of classifying one source value.
type SourceMatch struct {
	Class SourceClass
	// Source is the normalised source for world matches: "0.0.0.0/0", or
	// "Internet" for the Azure service tag. Empty otherwise.
	Source string
	// MatchReason is set for world matches (model.Match* constants).
	MatchReason string
}

// ClassifyAddress classifies a CIDR or a plain IP address, as found in AWS
// IpRanges and GCP sourceRanges.
//
// Any IPv4 prefix of length 0 is world-open, including non-canonical forms
// such as "10.0.0.0/0". A plain address without a prefix length is a single
// host, so it is not world-open.
func ClassifyAddress(raw string) SourceMatch {
	s := strings.TrimSpace(raw)
	if s == "" {
		return SourceMatch{Class: ClassMalformed}
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return SourceMatch{Class: ClassMalformed}
		}
		if p.Addr().Is4() && p.Bits() == 0 {
			return SourceMatch{Class: ClassWorldIPv4, Source: WorldIPv4, MatchReason: model.MatchIPv4WorldCIDR}
		}
		return SourceMatch{Class: ClassNotWorld}
	}
	if _, err := netip.ParseAddr(s); err != nil {
		return SourceMatch{Class: ClassMalformed}
	}
	return SourceMatch{Class: ClassNotWorld}
}

// azureServiceTag matches the documented service tag syntax: a name of
// letters and digits with an optional ".Region" suffix, for example
// "VirtualNetwork" or "Storage.WestEurope". (DESIGN.md 6.1 marks the exact
// syntax "verify"; this is deliberately strict so that typos surface as
// diagnostics rather than being silently accepted.)
var azureServiceTag = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*(\.[A-Za-z0-9]+)?$`)

// ClassifyAzurePrefix classifies an Azure NSG SourceAddressPrefix(es) value.
// Keywords are case-insensitive:
//
//	"*", "Any"  -> world, source "0.0.0.0/0", reason azure_any_wildcard
//	"Internet"  -> world, source "Internet", reason azure_service_tag_internet
//	CIDR / IP   -> as ClassifyAddress
//	service tag -> selector
func ClassifyAzurePrefix(raw string) SourceMatch {
	s := strings.TrimSpace(raw)
	switch strings.ToLower(s) {
	case "*", "any":
		return SourceMatch{Class: ClassWorldIPv4, Source: WorldIPv4, MatchReason: model.MatchAzureAnyWildcard}
	case "internet":
		return SourceMatch{Class: ClassWorldIPv4, Source: "Internet", MatchReason: model.MatchAzureServiceTagInternet}
	}
	if m := ClassifyAddress(s); m.Class != ClassMalformed {
		return m
	}
	if azureServiceTag.MatchString(s) {
		return SourceMatch{Class: ClassSelector}
	}
	return SourceMatch{Class: ClassMalformed}
}
