package exposure

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
)

// Rule builders shaped like each provider's conversion will produce them.
// All IDs are fake.

func awsRule(proto string, from, to *int32, cidrs ...string) Rule {
	r := Rule{
		Provider: model.ProviderAWS, Scope: "111111111111/eu-west-1", ResourceID: "sg-0fake0000000000001",
		RuleRef:   "fake-ref",
		Direction: DirectionInbound, Action: ActionAllow,
		Protocol: proto, PortStyle: PortsFromAWS, AWSFrom: from, AWSTo: to,
	}
	for _, c := range cidrs {
		r.Sources = append(r.Sources, Source{Kind: SourceAddress, Field: "IpRanges.CidrIp", Raw: c})
	}
	return r
}

func gcpRule(direction, proto string, ports []string, ranges ...string) Rule {
	r := Rule{
		Provider: model.ProviderGCP, Scope: "example-project-a",
		ResourceID: "projects/example-project-a/global/firewalls/fake-rule", RuleRef: "fake-rule",
		Direction: gcpDirection(direction), DirectionRaw: direction, Action: ActionAllow,
		Protocol: proto, PortRanges: ports,
	}
	for _, c := range ranges {
		r.Sources = append(r.Sources, Source{Kind: SourceAddress, Field: "sourceRanges", Raw: c})
	}
	return r
}

// gcpDirection mirrors the planned GCP mapping (DESIGN.md 6.2).
func gcpDirection(raw string) Direction {
	switch raw {
	case "INGRESS", "":
		return DirectionInbound
	case "EGRESS":
		return DirectionOutbound
	default:
		return DirectionUnknown
	}
}

func azureRule(proto string, ports []string, prefixes ...string) Rule {
	r := Rule{
		Provider: model.ProviderAzure, Scope: "00000000-0000-0000-0000-000000000000",
		ResourceID: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/example-rg/providers/Microsoft.Network/networkSecurityGroups/fake-nsg",
		RuleRef:    "fake-rule",
		Direction:  DirectionInbound, DirectionRaw: "Inbound", Action: ActionAllow, ActionRaw: "Allow",
		Protocol: proto, PortRanges: ports,
	}
	for _, p := range prefixes {
		r.Sources = append(r.Sources, Source{Kind: SourceAzurePrefix, Field: "sourceAddressPrefix", Raw: p})
	}
	return r
}

// summary renders the decision-relevant fields of a finding on one line.
func summary(f model.InsecureRule) string {
	p := func(v *int) string {
		if v == nil {
			return "-"
		}
		return fmt.Sprint(*v)
	}
	return fmt.Sprintf("%s %s from=%s to=%s type=%s code=%s src=%s reason=%s",
		f.Protocol, f.Port, p(f.FromPort), p(f.ToPort), p(f.ICMPType), p(f.ICMPCode), f.Source, f.MatchReason)
}

func diagSummary(d model.Diagnostic) string { return d.Code + "/" + d.Effect }

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name     string
		rule     Rule
		findings []string
		diags    []string
	}{
		// --- Required scenarios -------------------------------------------
		{
			name:     "world on tcp/22 (AWS)",
			rule:     awsRule("tcp", i32(22), i32(22), "0.0.0.0/0"),
			findings: []string{"tcp 22 from=22 to=22 type=- code=- src=0.0.0.0/0 reason=ipv4_world_cidr"},
		},
		{
			name:     "world on tcp/443 (GCP)",
			rule:     gcpRule("INGRESS", "tcp", []string{"443"}, "0.0.0.0/0"),
			findings: []string{"tcp 443 from=443 to=443 type=- code=- src=0.0.0.0/0 reason=ipv4_world_cidr"},
		},
		{
			name:     "wildcard protocol and port (AWS -1)",
			rule:     awsRule("-1", nil, nil, "0.0.0.0/0"),
			findings: []string{"all all from=- to=- type=- code=- src=0.0.0.0/0 reason=ipv4_world_cidr"},
		},
		{
			name:     "wildcard protocol and port (Azure * / * / *)",
			rule:     azureRule("*", []string{"*"}, "*"),
			findings: []string{"all all from=- to=- type=- code=- src=0.0.0.0/0 reason=azure_any_wildcard"},
		},
		// Regression (M1 review): Azure protocol "*" keeps destination ports.
		{
			name:     "Azure protocol * on port 443 keeps the port",
			rule:     azureRule("*", []string{"443"}, "*"),
			findings: []string{"all 443 from=443 to=443 type=- code=- src=0.0.0.0/0 reason=azure_any_wildcard"},
		},
		{
			name:     "Azure protocol * on range 80-443 keeps the range",
			rule:     azureRule("*", []string{"80-443"}, "Internet"),
			findings: []string{"all 80-443 from=80 to=443 type=- code=- src=Internet reason=azure_service_tag_internet"},
		},
		{
			name: "Azure protocol * with multiple destination port entries",
			rule: azureRule("*", []string{"443", "8000-8090", "22"}, "0.0.0.0/0"),
			findings: []string{
				"all 443 from=443 to=443 type=- code=- src=0.0.0.0/0 reason=ipv4_world_cidr",
				"all 8000-8090 from=8000 to=8090 type=- code=- src=0.0.0.0/0 reason=ipv4_world_cidr",
				"all 22 from=22 to=22 type=- code=- src=0.0.0.0/0 reason=ipv4_world_cidr",
			},
		},
		{
			name:     "Azure protocol * with malformed port is still a finding",
			rule:     azureRule("*", []string{"https"}, "*"),
			findings: []string{"all unknown from=- to=- type=- code=- src=0.0.0.0/0 reason=azure_any_wildcard"},
			diags:    []string{"port_malformed/finding_detail_unknown"},
		},
		{
			name:     "AWS -1 still means all ports even if ports are set",
			rule:     awsRule("-1", i32(443), i32(443), "0.0.0.0/0"),
			findings: []string{"all all from=- to=- type=- code=- src=0.0.0.0/0 reason=ipv4_world_cidr"},
		},
		// Regression (M1 review): AWS icmpv6 without a port range.
		{
			name:     "AWS icmpv6 with omitted range is all types and codes",
			rule:     awsRule("icmpv6", nil, nil, "0.0.0.0/0"),
			findings: []string{"icmpv6 all from=- to=- type=- code=- src=0.0.0.0/0 reason=ipv4_world_cidr"},
		},
		{
			name:     "AWS protocol 58 with omitted range is icmpv6, all types and codes",
			rule:     awsRule("58", nil, nil, "0.0.0.0/0"),
			findings: []string{"icmpv6 all from=- to=- type=- code=- src=0.0.0.0/0 reason=ipv4_world_cidr"},
		},
		{
			name:     "AWS icmp (v4) with omitted range is malformed",
			rule:     awsRule("icmp", nil, nil, "0.0.0.0/0"),
			findings: []string{"icmp unknown from=- to=- type=- code=- src=0.0.0.0/0 reason=ipv4_world_cidr"},
			diags:    []string{"port_malformed/finding_detail_unknown"},
		},
		{
			name:     "wildcard protocol (GCP all, no ports)",
			rule:     gcpRule("INGRESS", "all", nil, "0.0.0.0/0"),
			findings: []string{"all all from=- to=- type=- code=- src=0.0.0.0/0 reason=ipv4_world_cidr"},
		},
		{
			name:     "udp/123",
			rule:     awsRule("udp", i32(123), i32(123), "0.0.0.0/0"),
			findings: []string{"udp 123 from=123 to=123 type=- code=- src=0.0.0.0/0 reason=ipv4_world_cidr"},
		},
		{
			name:     "icmp all types (AWS)",
			rule:     awsRule("icmp", i32(-1), i32(-1), "0.0.0.0/0"),
			findings: []string{"icmp all from=- to=- type=- code=- src=0.0.0.0/0 reason=ipv4_world_cidr"},
		},
		{
			name:     "icmp echo request, any code (AWS)",
			rule:     awsRule("icmp", i32(8), i32(-1), "0.0.0.0/0"),
			findings: []string{"icmp all from=- to=- type=8 code=- src=0.0.0.0/0 reason=ipv4_world_cidr"},
		},
		{
			name:     "icmp on GCP has no type/code",
			rule:     gcpRule("INGRESS", "icmp", nil, "0.0.0.0/0"),
			findings: []string{"icmp all from=- to=- type=- code=- src=0.0.0.0/0 reason=ipv4_world_cidr"},
		},
		{
			name:     "numeric protocol 6 is tcp (AWS)",
			rule:     awsRule("6", i32(3389), i32(3389), "0.0.0.0/0"),
			findings: []string{"tcp 3389 from=3389 to=3389 type=- code=- src=0.0.0.0/0 reason=ipv4_world_cidr"},
		},
		{
			name:     "numeric protocol 17 is udp (GCP)",
			rule:     gcpRule("INGRESS", "17", []string{"53"}, "0.0.0.0/0"),
			findings: []string{"udp 53 from=53 to=53 type=- code=- src=0.0.0.0/0 reason=ipv4_world_cidr"},
		},
		{
			name:     "numeric protocol 1 is icmp (AWS)",
			rule:     awsRule("1", i32(-1), i32(-1), "0.0.0.0/0"),
			findings: []string{"icmp all from=- to=- type=- code=- src=0.0.0.0/0 reason=ipv4_world_cidr"},
		},
		{
			name:     "numeric protocol 47 (GRE) kept as number, all ports",
			rule:     awsRule("47", nil, nil, "0.0.0.0/0"),
			findings: []string{"47 all from=- to=- type=- code=- src=0.0.0.0/0 reason=ipv4_world_cidr"},
		},
		{
			name: "restricted private CIDRs produce nothing",
			rule: awsRule("tcp", i32(22), i32(22), "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"),
		},
		{
			name: "restricted single host produces nothing",
			rule: gcpRule("INGRESS", "tcp", []string{"22"}, "203.0.113.10/32"),
		},
		{
			name:  "malformed IPv4 source alone: no finding, scope incomplete",
			rule:  awsRule("tcp", i32(22), i32(22), "0.0.0.300/0"),
			diags: []string{"source_malformed/scope_incomplete"},
		},
		{
			name:  "malformed source next to a private CIDR: still incomplete",
			rule:  gcpRule("INGRESS", "tcp", []string{"22"}, "10.0.0.0/8", "not-a-cidr"),
			diags: []string{"source_malformed/scope_incomplete"},
		},
		{
			name:     "malformed source next to a world source: finding, detail diagnostic",
			rule:     gcpRule("INGRESS", "tcp", []string{"22"}, "not-a-cidr", "0.0.0.0/0"),
			findings: []string{"tcp 22 from=22 to=22 type=- code=- src=0.0.0.0/0 reason=ipv4_world_cidr"},
			diags:    []string{"source_malformed/finding_detail_unknown"},
		},
		{
			name:     "unknown protocol (empty) is still detected",
			rule:     gcpRule("INGRESS", "", []string{"22"}, "0.0.0.0/0"),
			findings: []string{"unknown unknown from=- to=- type=- code=- src=0.0.0.0/0 reason=ipv4_world_cidr"},
			diags:    []string{"protocol_unknown/finding_detail_unknown"},
		},
		{
			name:     "unknown protocol (out of range) is still detected",
			rule:     awsRule("300", i32(1), i32(2), "0.0.0.0/0"),
			findings: []string{"unknown unknown from=- to=- type=- code=- src=0.0.0.0/0 reason=ipv4_world_cidr"},
			diags:    []string{"protocol_unknown/finding_detail_unknown"},
		},
		{
			name:     "unrecognised protocol name is reported as-is, no diagnostic",
			rule:     gcpRule("INGRESS", "ipip", nil, "0.0.0.0/0"),
			findings: []string{"ipip all from=- to=- type=- code=- src=0.0.0.0/0 reason=ipv4_world_cidr"},
		},
		// --- Ports ----------------------------------------------------------
		{
			name: "multiple port specs give one finding each",
			rule: gcpRule("INGRESS", "tcp", []string{"22", "8000-8090"}, "0.0.0.0/0"),
			findings: []string{
				"tcp 22 from=22 to=22 type=- code=- src=0.0.0.0/0 reason=ipv4_world_cidr",
				"tcp 8000-8090 from=8000 to=8090 type=- code=- src=0.0.0.0/0 reason=ipv4_world_cidr",
			},
		},
		{
			name:     "malformed port is still a finding",
			rule:     azureRule("Tcp", []string{"ssh"}, "*"),
			findings: []string{"tcp unknown from=- to=- type=- code=- src=0.0.0.0/0 reason=azure_any_wildcard"},
			diags:    []string{"port_malformed/finding_detail_unknown"},
		},
		{
			name:     "malformed AWS ICMP code is still a finding",
			rule:     awsRule("icmp", i32(-1), i32(4), "0.0.0.0/0"),
			findings: []string{"icmp unknown from=- to=- type=- code=- src=0.0.0.0/0 reason=ipv4_world_cidr"},
			diags:    []string{"port_malformed/finding_detail_unknown"},
		},
		// --- Sources --------------------------------------------------------
		{
			name:     "non-canonical /0 is world",
			rule:     awsRule("tcp", i32(80), i32(80), "10.0.0.0/0"),
			findings: []string{"tcp 80 from=80 to=80 type=- code=- src=0.0.0.0/0 reason=ipv4_world_cidr"},
		},
		{
			name: "ipv6 ::/0 is out of scope",
			rule: awsRule("tcp", i32(22), i32(22), "::/0"),
		},
		{
			name:     "Azure Internet tag",
			rule:     azureRule("Tcp", []string{"3389"}, "Internet"),
			findings: []string{"tcp 3389 from=3389 to=3389 type=- code=- src=Internet reason=azure_service_tag_internet"},
		},
		{
			name: "Azure VirtualNetwork tag is a selector, not a diagnostic",
			rule: azureRule("Tcp", []string{"22"}, "VirtualNetwork"),
		},
		{
			name: "selectors only (security group reference) produce nothing",
			rule: func() Rule {
				r := awsRule("tcp", i32(22), i32(22))
				r.Sources = []Source{{Kind: SourceSelector, Field: "UserIdGroupPairs", Raw: "sg-0fake0000000000002"}}
				return r
			}(),
		},
		{
			name: "GCP source tags do not narrow a world range",
			rule: func() Rule {
				r := gcpRule("INGRESS", "tcp", []string{"22"}, "0.0.0.0/0")
				r.Sources = append(r.Sources, Source{Kind: SourceSelector, Field: "sourceTags", Raw: "fake-tag"})
				return r
			}(),
			findings: []string{"tcp 22 from=22 to=22 type=- code=- src=0.0.0.0/0 reason=ipv4_world_cidr"},
		},
		{
			name: "GCP rule with no source uses the default",
			rule: func() Rule {
				r := gcpRule("INGRESS", "tcp", []string{"22"})
				r.Sources = []Source{{Kind: SourceGCPDefault}}
				return r
			}(),
			findings: []string{"tcp 22 from=22 to=22 type=- code=- src=0.0.0.0/0 reason=gcp_default_source"},
		},
		{
			name:  "rule with no sources at all",
			rule:  azureRule("Tcp", []string{"22"}),
			diags: []string{"source_missing/scope_incomplete"},
		},
		// --- Direction and action -------------------------------------------
		{
			name:     "GCP empty direction is ingress",
			rule:     gcpRule("", "tcp", []string{"22"}, "0.0.0.0/0"),
			findings: []string{"tcp 22 from=22 to=22 type=- code=- src=0.0.0.0/0 reason=ipv4_world_cidr"},
		},
		{
			name: "GCP EGRESS is ignored without a diagnostic",
			rule: gcpRule("EGRESS", "all", nil, "0.0.0.0/0"),
		},
		{
			name:  "unknown direction blocks the decision",
			rule:  gcpRule("SIDEWAYS", "tcp", []string{"22"}, "0.0.0.0/0"),
			diags: []string{"direction_unrecognised/scope_incomplete"},
		},
		{
			name: "deny rule is ignored",
			rule: func() Rule {
				r := azureRule("*", []string{"*"}, "*")
				r.Action, r.ActionRaw = ActionDeny, "Deny"
				return r
			}(),
		},
		{
			name: "unknown access blocks the decision",
			rule: func() Rule {
				r := azureRule("*", []string{"*"}, "*")
				r.Action, r.ActionRaw = ActionUnknown, "Maybe"
				return r
			}(),
			diags: []string{"access_unrecognised/scope_incomplete"},
		},
		{
			name: "missing action blocks the decision",
			rule: func() Rule {
				r := gcpRule("INGRESS", "", nil, "0.0.0.0/0")
				r.Action = ActionMissing
				return r
			}(),
			diags: []string{"action_missing/scope_incomplete"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := Evaluate(tt.rule)
			var gotF, gotD []string
			for _, f := range res.Findings {
				gotF = append(gotF, summary(f))
				if f.Reachability != model.ReachabilityNotEvaluated {
					t.Errorf("reachability = %q", f.Reachability)
				}
				if f.ProviderProtocol != tt.rule.Protocol || f.RuleRef != tt.rule.RuleRef {
					t.Errorf("raw protocol or rule ref not preserved: %+v", f)
				}
			}
			for _, d := range res.Diagnostics {
				gotD = append(gotD, diagSummary(d))
			}
			if !slices.Equal(gotF, tt.findings) {
				t.Errorf("findings:\n got  %q\n want %q", gotF, tt.findings)
			}
			if !slices.Equal(gotD, tt.diags) {
				t.Errorf("diagnostics:\n got  %q\n want %q", gotD, tt.diags)
			}
		})
	}
}

// TestEvaluateMultipleRules checks a security group with several rules, as
// a provider would evaluate it: only the world-open ones are findings, and
// the scope status reflects the diagnostics.
func TestEvaluateMultipleRules(t *testing.T) {
	rules := []Rule{
		awsRule("tcp", i32(22), i32(22), "0.0.0.0/0"),       // finding
		awsRule("tcp", i32(443), i32(443), "0.0.0.0/0"),     // finding
		awsRule("tcp", i32(5432), i32(5432), "10.0.0.0/16"), // private: nothing
		awsRule("udp", i32(123), i32(123), "0.0.0.0/0"),     // finding
		awsRule("-1", nil, nil, "192.168.0.0/16"),           // private: nothing
	}
	var findings []model.InsecureRule
	var diags []model.Diagnostic
	for _, r := range rules {
		res := Evaluate(r)
		findings = append(findings, res.Findings...)
		diags = append(diags, res.Diagnostics...)
	}
	if len(findings) != 3 {
		t.Fatalf("got %d findings, want 3", len(findings))
	}
	if len(diags) != 0 || model.ScopeStatusFor(diags) != model.ScopeComplete {
		t.Fatalf("clean rules gave diagnostics %v", diags)
	}

	// Add one rule whose source cannot be read: the same scope is now
	// incomplete, and the earlier findings are kept.
	diags = append(diags, Evaluate(awsRule("tcp", i32(22), i32(22), "garbage")).Diagnostics...)
	if got := model.ScopeStatusFor(diags); got != model.ScopeIncomplete {
		t.Fatalf("scope status = %q, want incomplete", got)
	}
}

func TestEvaluateDiagnosticFields(t *testing.T) {
	long := strings.Repeat("é", 200) // 400 bytes, 2 bytes per rune
	res := Evaluate(gcpRule("INGRESS", "tcp", []string{"22"}, long))
	if len(res.Diagnostics) != 1 {
		t.Fatalf("diagnostics = %v", res.Diagnostics)
	}
	d := res.Diagnostics[0]
	if d.Provider != model.ProviderGCP || d.Scope != "example-project-a" || d.RuleRef != "fake-rule" || d.Field != "sourceRanges" {
		t.Fatalf("diagnostic context not filled: %+v", d)
	}
	if len(d.Value) > maxDiagnosticValue || !strings.HasPrefix(long, d.Value) || len(d.Value)%2 != 0 {
		t.Fatalf("value not truncated on a rune boundary: %d bytes", len(d.Value))
	}
}

func TestRuleNil(t *testing.T) {
	d := RuleNil(model.ProviderAzure, "sub", "nsg-id", "securityRules")
	if d.Code != model.CodeRuleNil || d.Effect != model.EffectScopeIncomplete {
		t.Fatalf("RuleNil = %+v", d)
	}
}
