package azure

import (
	"encoding/json"
	"slices"
	"strconv"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
)

// summary renders a finding as
// "ruleRef proto port from-to source providerSource reason prio=N".
func summary(f model.InsecureRule) string {
	ptr := func(p *int) string {
		if p == nil {
			return "null"
		}
		return strconv.Itoa(*p)
	}
	return f.RuleRef + " " + f.Protocol + " " + f.Port + " " + ptr(f.FromPort) + "-" + ptr(f.ToPort) +
		" " + f.Source + " " + f.ProviderSource + " " + f.MatchReason + " prio=" + ptr(f.Context.Priority)
}

func summaries(fs []model.InsecureRule) []string {
	out := []string{}
	for _, f := range fs {
		out = append(out, summary(f))
	}
	slices.Sort(out)
	return out
}

// convertOne converts an NSG with the given custom rules and the standard
// default rules.
func convertOne(t *testing.T, rules ...ruleSpec) nsgResult {
	t.Helper()
	return convertNSG(subA, nsgSpec{name: "example-nsg", rules: rules}.build(subA))
}

func TestConvert_SingleTCP22OpenToAll(t *testing.T) {
	r := convertOne(t, inAllow("ssh", "Tcp", "*", "22", 100))
	assertEqual(t, "findings", summaries(r.nsg.InsecureRules),
		[]string{"securityRules/ssh tcp 22 22-22 0.0.0.0/0 * azure_any_wildcard prio=100"})
	assertEqual(t, "diagnostics", diagCodes(r.diagnostics), []string{})
	assertEqual(t, "rules evaluated (1 custom + 6 default)", r.rulesEvaluated, 7)
	f := r.nsg.InsecureRules[0]
	assertEqual(t, "provider fields", []string{f.ProviderProtocol, f.ProviderPort, f.ProviderSource},
		[]string{"Tcp", "22", "*"})
	assertEqual(t, "reachability", f.Reachability, model.ReachabilityNotEvaluated)
	assertEqual(t, "nsg", []string{r.nsg.ID, r.nsg.Name, r.nsg.SubscriptionID},
		[]string{nsgID(subA, "example-nsg"), "example-nsg", subA})
}

func TestConvert_Sources(t *testing.T) {
	tests := []struct {
		name string
		rule ruleSpec
		want []string
	}{
		{"443 from literal 0.0.0.0/0", inAllow("https", "Tcp", "0.0.0.0/0", "443", 200),
			[]string{"securityRules/https tcp 443 443-443 0.0.0.0/0 0.0.0.0/0 ipv4_world_cidr prio=200"}},
		{"Any keyword", inAllow("any", "Tcp", "Any", "443", 200),
			[]string{"securityRules/any tcp 443 443-443 0.0.0.0/0 Any azure_any_wildcard prio=200"}},
		{"Internet tag is reported apart from 0.0.0.0/0", inAllow("inet", "Tcp", "Internet", "443", 200),
			[]string{"securityRules/inet tcp 443 443-443 Internet Internet azure_service_tag_internet prio=200"}},
		{"internet tag lower case", inAllow("inet", "Tcp", "internet", "443", 200),
			[]string{"securityRules/inet tcp 443 443-443 Internet internet azure_service_tag_internet prio=200"}},
		{"non-canonical /0", inAllow("odd", "Tcp", "10.0.0.0/0", "443", 200),
			[]string{"securityRules/odd tcp 443 443-443 0.0.0.0/0 10.0.0.0/0 ipv4_world_cidr prio=200"}},
		{"private CIDR", inAllow("priv", "Tcp", "10.0.0.0/8", "22", 200), []string{}},
		{"host address 0.0.0.0", inAllow("host", "Tcp", "0.0.0.0", "22", 200), []string{}},
		{"IPv6 ::/0 is out of scope", inAllow("v6", "Tcp", "::/0", "22", 200), []string{}},
		{"VirtualNetwork tag", inAllow("vnet", "Tcp", "VirtualNetwork", "22", 200), []string{}},
		{"regional service tag", inAllow("st", "Tcp", "Storage.WestEurope", "22", 200), []string{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := convertOne(t, tc.rule)
			assertEqual(t, "findings", summaries(r.nsg.InsecureRules), tc.want)
			assertEqual(t, "diagnostics", diagCodes(r.diagnostics), []string{})
		})
	}
}

func TestConvert_MultipleSourcePrefixes(t *testing.T) {
	rule := ruleSpec{
		name: "multi", direction: "Inbound", access: "Allow", protocol: "Tcp", priority: 300,
		srcList: []string{"10.0.0.0/8", "0.0.0.0/0", "Internet", "192.0.2.0/24"},
		srcPort: to.Ptr("*"), dstPort: to.Ptr("3389"),
	}
	r := convertOne(t, rule)
	assertEqual(t, "findings", summaries(r.nsg.InsecureRules), []string{
		"securityRules/multi tcp 3389 3389-3389 0.0.0.0/0 0.0.0.0/0 ipv4_world_cidr prio=300",
		"securityRules/multi tcp 3389 3389-3389 Internet Internet azure_service_tag_internet prio=300",
	})

	// The same world prefix in the single and plural fields is one source.
	dup := rule
	dup.name = "dup"
	dup.srcPrefix = to.Ptr("0.0.0.0/0")
	dup.srcList = []string{"0.0.0.0/0"}
	r = convertOne(t, dup)
	assertEqual(t, "merged", summaries(r.nsg.InsecureRules),
		[]string{"securityRules/dup tcp 3389 3389-3389 0.0.0.0/0 0.0.0.0/0 ipv4_world_cidr prio=300"})

	// Empty strings and nil entries carry no address.
	empty := rule
	empty.name = "empty"
	empty.srcPrefix = to.Ptr("")
	empty.srcList = []string{"", "0.0.0.0/0"}
	empty.nilSrcItem = true
	r = convertOne(t, empty)
	assertEqual(t, "empty entries", summaries(r.nsg.InsecureRules),
		[]string{"securityRules/empty tcp 3389 3389-3389 0.0.0.0/0 0.0.0.0/0 ipv4_world_cidr prio=300"})
	assertEqual(t, "no diagnostics", diagCodes(r.diagnostics), []string{})
}

func TestConvert_DestinationPorts(t *testing.T) {
	base := ruleSpec{name: "p", direction: "Inbound", access: "Allow", priority: 100,
		srcPrefix: to.Ptr("*"), srcPort: to.Ptr("*")}
	tests := []struct {
		name     string
		protocol string
		dstPort  *string
		dstPorts []string
		want     []string
	}{
		{"single range", "Tcp", to.Ptr("8000-8090"), nil,
			[]string{"securityRules/p tcp 8000-8090 8000-8090 0.0.0.0/0 * azure_any_wildcard prio=100"}},
		{"multiple ports", "Tcp", nil, []string{"22", "3389", "5985-5986"}, []string{
			"securityRules/p tcp 22 22-22 0.0.0.0/0 * azure_any_wildcard prio=100",
			"securityRules/p tcp 3389 3389-3389 0.0.0.0/0 * azure_any_wildcard prio=100",
			"securityRules/p tcp 5985-5986 5985-5986 0.0.0.0/0 * azure_any_wildcard prio=100",
		}},
		{"single and plural merged", "Udp", to.Ptr("53"), []string{"53", "123"}, []string{
			"securityRules/p udp 123 123-123 0.0.0.0/0 * azure_any_wildcard prio=100",
			"securityRules/p udp 53 53-53 0.0.0.0/0 * azure_any_wildcard prio=100",
		}},
		{"tcp any port", "Tcp", to.Ptr("*"), nil,
			[]string{"securityRules/p tcp all 0-65535 0.0.0.0/0 * azure_any_wildcard prio=100"}},
		{"protocol * keeps the port restriction", "*", to.Ptr("443"), nil,
			[]string{"securityRules/p all 443 443-443 0.0.0.0/0 * azure_any_wildcard prio=100"}},
		{"protocol * with several ports", "*", nil, []string{"80", "443"}, []string{
			"securityRules/p all 443 443-443 0.0.0.0/0 * azure_any_wildcard prio=100",
			"securityRules/p all 80 80-80 0.0.0.0/0 * azure_any_wildcard prio=100",
		}},
		{"protocol * any port", "*", to.Ptr("*"), nil,
			[]string{"securityRules/p all all null-null 0.0.0.0/0 * azure_any_wildcard prio=100"}},
		{"icmp has no port", "Icmp", to.Ptr("*"), nil,
			[]string{"securityRules/p icmp all null-null 0.0.0.0/0 * azure_any_wildcard prio=100"}},
		{"esp", "Esp", to.Ptr("*"), nil,
			[]string{"securityRules/p esp all null-null 0.0.0.0/0 * azure_any_wildcard prio=100"}},
		{"ah", "Ah", to.Ptr("*"), nil,
			[]string{"securityRules/p ah all null-null 0.0.0.0/0 * azure_any_wildcard prio=100"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rule := base
			rule.protocol, rule.dstPort, rule.dstPorts = tc.protocol, tc.dstPort, tc.dstPorts
			r := convertOne(t, rule)
			assertEqual(t, "findings", summaries(r.nsg.InsecureRules), tc.want)
			assertEqual(t, "diagnostics", diagCodes(r.diagnostics), []string{})
		})
	}
}

// Source ports never decide or describe the exposed port.
func TestConvert_SourcePortIsNotDestinationPort(t *testing.T) {
	rule := inAllow("sp", "Tcp", "*", "443", 100)
	rule.srcPort = to.Ptr("22")
	r := convertOne(t, rule)
	assertEqual(t, "findings", summaries(r.nsg.InsecureRules),
		[]string{"securityRules/sp tcp 443 443-443 0.0.0.0/0 * azure_any_wildcard prio=100"})
	assertEqual(t, "provider port", r.nsg.InsecureRules[0].ProviderPort, "443")
}

func TestConvert_MalformedAndMissingPorts(t *testing.T) {
	bad := inAllow("bad", "Tcp", "*", "22-x", 100)
	r := convertOne(t, bad)
	assertEqual(t, "malformed", summaries(r.nsg.InsecureRules),
		[]string{"securityRules/bad tcp unknown null-null 0.0.0.0/0 * azure_any_wildcard prio=100"})
	assertEqual(t, "diag", diagCodes(r.diagnostics),
		[]string{"securityRules/bad port_malformed port finding_detail_unknown"})

	missing := inAllow("missing", "Tcp", "*", "", 100)
	missing.dstPort = nil
	r = convertOne(t, missing)
	assertEqual(t, "missing", summaries(r.nsg.InsecureRules),
		[]string{"securityRules/missing tcp unknown null-null 0.0.0.0/0 * azure_any_wildcard prio=100"})
	assertEqual(t, "diag", diagCodes(r.diagnostics),
		[]string{"securityRules/missing port_malformed destinationPortRange finding_detail_unknown"})

	icmp := missing
	icmp.name, icmp.protocol = "icmp", "Icmp"
	r = convertOne(t, icmp)
	assertEqual(t, "icmp needs no port", summaries(r.nsg.InsecureRules),
		[]string{"securityRules/icmp icmp all null-null 0.0.0.0/0 * azure_any_wildcard prio=100"})
	assertEqual(t, "no diag", diagCodes(r.diagnostics), []string{})
}

func TestConvert_ProtocolValues(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"Tcp", "tcp"}, {"TCP", "tcp"}, {"Udp", "udp"}, {"*", "all"}, {"6", "tcp"}, {"47", "47"},
	} {
		r := convertOne(t, inAllow("p", tc.raw, "*", "443", 100))
		if len(r.nsg.InsecureRules) != 1 || r.nsg.InsecureRules[0].Protocol != tc.want ||
			r.nsg.InsecureRules[0].ProviderProtocol != tc.raw {
			t.Errorf("protocol %q: %v", tc.raw, summaries(r.nsg.InsecureRules))
		}
	}
	// A missing protocol still reports the finding, with a diagnostic.
	rule := inAllow("noproto", "", "*", "443", 100)
	r := convertOne(t, rule)
	assertEqual(t, "findings", summaries(r.nsg.InsecureRules),
		[]string{"securityRules/noproto unknown unknown null-null 0.0.0.0/0 * azure_any_wildcard prio=100"})
	assertEqual(t, "diag", diagCodes(r.diagnostics),
		[]string{"securityRules/noproto protocol_unknown protocol finding_detail_unknown"})
}

func TestConvert_ApplicationSecurityGroups(t *testing.T) {
	asg := "/subscriptions/" + subA + "/resourceGroups/example-rg/providers/Microsoft.Network/applicationSecurityGroups/example-asg"
	rule := ruleSpec{name: "asg", direction: "Inbound", access: "Allow", protocol: "Tcp", priority: 100,
		srcASGs: []string{asg}, srcPort: to.Ptr("*"), dstPort: to.Ptr("22")}
	r := convertOne(t, rule)
	assertEqual(t, "ASG only", summaries(r.nsg.InsecureRules), []string{})
	assertEqual(t, "no diagnostics", diagCodes(r.diagnostics), []string{})

	// An ASG entry with no ID is still a selector, not a missing source.
	sg := nsgSpec{name: "n", rules: []ruleSpec{rule}}.build(subA)
	sg.Properties.SecurityRules[0].Properties.SourceApplicationSecurityGroups =
		[]*armnetwork.ApplicationSecurityGroup{nil, {}}
	r = convertNSG(subA, sg)
	assertEqual(t, "nil ASG", summaries(r.nsg.InsecureRules), []string{})
	assertEqual(t, "nil ASG diagnostics", diagCodes(r.diagnostics), []string{})
}

func TestConvert_DirectionAndAccess(t *testing.T) {
	rule := func(dir, access string) ruleSpec {
		r := inAllow("r", "Tcp", "*", "22", 100)
		r.direction, r.access = dir, access
		return r
	}
	tests := []struct {
		name     string
		rule     ruleSpec
		findings int
		diags    []string
	}{
		{"inbound allow", rule("Inbound", "Allow"), 1, []string{}},
		{"case-insensitive", rule("inbound", "allow"), 1, []string{}},
		{"inbound deny", rule("Inbound", "Deny"), 0, []string{}},
		{"outbound allow", rule("Outbound", "Allow"), 0, []string{}},
		{"outbound deny", rule("Outbound", "Deny"), 0, []string{}},
		{"missing direction", rule("", "Allow"), 0,
			[]string{"securityRules/r direction_unrecognised direction scope_incomplete"}},
		{"unknown direction", rule("Sideways", "Allow"), 0,
			[]string{"securityRules/r direction_unrecognised direction scope_incomplete"}},
		{"missing access", rule("Inbound", ""), 0,
			[]string{"securityRules/r access_unrecognised access scope_incomplete"}},
		{"unknown access", rule("Inbound", "Maybe"), 0,
			[]string{"securityRules/r access_unrecognised access scope_incomplete"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := convertOne(t, tc.rule)
			assertEqual(t, "findings", len(r.nsg.InsecureRules), tc.findings)
			assertEqual(t, "diagnostics", diagCodes(r.diagnostics), tc.diags)
		})
	}
}

func TestConvert_DefaultRules(t *testing.T) {
	// The standard defaults never produce a finding: the inbound allows use
	// VirtualNetwork and AzureLoadBalancer, and the world rules are Deny or
	// Outbound.
	r := convertOne(t)
	assertEqual(t, "standard defaults", summaries(r.nsg.InsecureRules), []string{})
	assertEqual(t, "no diagnostics", diagCodes(r.diagnostics), []string{})
	assertEqual(t, "evaluated", r.rulesEvaluated, 6)

	// A world-open default rule (not something Azure ships, but the data is
	// evaluated the same way) is reported with its default-rule reference
	// and priority, and a custom rule with the same name stays separate.
	open := inAllow("AllowInternetInBound", "*", "*", "*", 65002)
	sg := nsgSpec{name: "n", rules: []ruleSpec{inAllow("AllowInternetInBound", "Tcp", "*", "22", 100)},
		defaults: append(defaultRules(), open)}.build(subA)
	r = convertNSG(subA, sg)
	assertEqual(t, "findings", summaries(r.nsg.InsecureRules), []string{
		"defaultSecurityRules/AllowInternetInBound all all null-null 0.0.0.0/0 * azure_any_wildcard prio=65002",
		"securityRules/AllowInternetInBound tcp 22 22-22 0.0.0.0/0 * azure_any_wildcard prio=100",
	})
}

// Priority is preserved even when a higher-priority Deny exists: no
// effective-reachability analysis is done (DESIGN.md 7).
func TestConvert_PriorityAndDenyOverride(t *testing.T) {
	deny := inAllow("deny-ssh", "Tcp", "*", "22", 100)
	deny.access = "Deny"
	r := convertOne(t, deny, inAllow("allow-ssh", "Tcp", "*", "22", 200))
	assertEqual(t, "findings", summaries(r.nsg.InsecureRules),
		[]string{"securityRules/allow-ssh tcp 22 22-22 0.0.0.0/0 * azure_any_wildcard prio=200"})
	assertEqual(t, "reachability", r.nsg.InsecureRules[0].Reachability, model.ReachabilityNotEvaluated)

	noPrio := inAllow("noprio", "Tcp", "*", "22", 0)
	r = convertOne(t, noPrio)
	if r.nsg.InsecureRules[0].Context.Priority != nil {
		t.Errorf("missing priority must stay null")
	}
}

func TestConvert_AttachedContext(t *testing.T) {
	for _, attached := range []bool{false, true} {
		sg := nsgSpec{name: "n", attached: attached, rules: []ruleSpec{inAllow("r", "Tcp", "*", "22", 100)}}.build(subA)
		r := convertNSG(subA, sg)
		ctx := r.nsg.InsecureRules[0].Context
		if ctx.Attached == nil || *ctx.Attached != attached || ctx.Targets != nil {
			t.Errorf("attached=%v: context %+v", attached, ctx)
		}
	}
	// A NIC association counts too.
	sg := nsgSpec{name: "n", rules: []ruleSpec{inAllow("r", "Tcp", "*", "22", 100)}}.build(subA)
	sg.Properties.NetworkInterfaces = []*armnetwork.Interface{{ID: to.Ptr("nic")}}
	if !*convertNSG(subA, sg).nsg.InsecureRules[0].Context.Attached {
		t.Errorf("NIC association not seen")
	}
}

func TestConvert_MalformedData(t *testing.T) {
	t.Run("rule with no source", func(t *testing.T) {
		rule := inAllow("nosrc", "Tcp", "*", "22", 100)
		rule.srcPrefix = nil
		r := convertOne(t, rule)
		assertEqual(t, "diag", diagCodes(r.diagnostics),
			[]string{"securityRules/nosrc source_missing source scope_incomplete"})
	})
	t.Run("malformed source alone", func(t *testing.T) {
		r := convertOne(t, inAllow("bad", "Tcp", "not a cidr!", "22", 100))
		assertEqual(t, "findings", len(r.nsg.InsecureRules), 0)
		assertEqual(t, "diag", diagCodes(r.diagnostics),
			[]string{"securityRules/bad source_malformed sourceAddressPrefix scope_incomplete"})
	})
	t.Run("malformed source next to a world source", func(t *testing.T) {
		rule := inAllow("mixed", "Tcp", "", "22", 100)
		rule.srcPrefix = nil
		rule.srcList = []string{"300.1.1.1/8", "*"}
		r := convertOne(t, rule)
		assertEqual(t, "findings", len(r.nsg.InsecureRules), 1)
		assertEqual(t, "diag", diagCodes(r.diagnostics),
			[]string{"securityRules/mixed source_malformed sourceAddressPrefixes finding_detail_unknown"})
	})
	t.Run("nil rules", func(t *testing.T) {
		sg := nsgSpec{name: "n"}.build(subA)
		sg.Properties.SecurityRules = []*armnetwork.SecurityRule{nil}
		sg.Properties.DefaultSecurityRules = append(sg.Properties.DefaultSecurityRules, nil)
		r := convertNSG(subA, sg)
		assertEqual(t, "diag", diagCodes(r.diagnostics), []string{
			" rule_nil defaultSecurityRules scope_incomplete",
			" rule_nil securityRules scope_incomplete",
		})
	})
	t.Run("rule without properties", func(t *testing.T) {
		r := convertOne(t, ruleSpec{name: "np", noProps: true})
		assertEqual(t, "diag", diagCodes(r.diagnostics),
			[]string{"securityRules/np properties_missing properties scope_incomplete"})
	})
	t.Run("NSG without properties", func(t *testing.T) {
		r := convertNSG(subA, nsgSpec{name: "n", noProps: true}.build(subA))
		assertEqual(t, "diag", diagCodes(r.diagnostics),
			[]string{" properties_missing properties scope_incomplete"})
		assertEqual(t, "evaluated", r.rulesEvaluated, 0)
	})
	t.Run("NSG and rule without names", func(t *testing.T) {
		sg := nsgSpec{name: "n", noID: true, rules: []ruleSpec{inAllow("", "Tcp", "*", "22", 100)}}.build(subA)
		r := convertNSG(subA, sg)
		assertEqual(t, "findings", len(r.nsg.InsecureRules), 1)
		assertEqual(t, "diag", diagCodes(r.diagnostics), []string{
			" resource_id_missing id finding_detail_unknown",
			"securityRules/ resource_id_missing name finding_detail_unknown",
		})
	})
}

// The converter only reads the SDK objects.
func TestConvert_DoesNotMutateInput(t *testing.T) {
	sg := nsgSpec{name: "n", attached: true, rules: []ruleSpec{
		inAllow("a", "Tcp", "*", "22", 100),
		{name: "b", direction: "Inbound", access: "Allow", protocol: "*", priority: 110,
			srcPrefix: to.Ptr(" 0.0.0.0/0 "), srcList: []string{"*", "Internet"}, dstPorts: []string{"80", " 443 ", "80"}},
		inAllow("missing", "Tcp", "*", "", 120),
	}}.build(subA)
	sg.Properties.SecurityRules[2].Properties.DestinationPortRange = nil
	before, err := json.Marshal(sg)
	if err != nil {
		t.Fatal(err)
	}
	r := convertNSG(subA, sg)
	after, _ := json.Marshal(sg)
	if string(before) != string(after) {
		t.Errorf("convertNSG modified its input")
	}
	if len(r.nsg.InsecureRules) == 0 {
		t.Fatal("expected findings")
	}
}

func TestTruncate(t *testing.T) {
	long := ""
	for len(long) < 300 {
		long += "é"
	}
	got := truncate(long)
	if len(got) > maxDiagnosticValue || !utf8Valid(got) {
		t.Errorf("truncate: %d bytes, valid=%v", len(got), utf8Valid(got))
	}
	assertEqual(t, "short", truncate("abc"), "abc")
}

func utf8Valid(s string) bool {
	for _, r := range s {
		if r == '�' {
			return false
		}
	}
	return true
}
