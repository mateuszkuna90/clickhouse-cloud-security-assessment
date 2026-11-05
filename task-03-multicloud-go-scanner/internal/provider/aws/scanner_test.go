package aws

import (
	"bytes"
	"context"
	"fmt"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/report"
)

const (
	euWest1  = "eu-west-1"
	usEast1  = "us-east-1"
	apEast1  = "ap-east-1"
	scopeEU  = fakeAccount + "/" + euWest1
	scopeUS  = fakeAccount + "/" + usEast1
	scopeAP  = fakeAccount + "/" + apEast1
	worldStr = "0.0.0.0/0"
)

// scanOne scans a single explicit region served by fake.
func scanOne(t *testing.T, fake *fakeEC2) model.ProviderResult {
	t.Helper()
	f := newFactory(map[string]*fakeEC2{euWest1: fake})
	return newTestScanner(Config{Regions: []string{euWest1}}, okSTS(), f).Scan(context.Background())
}

func onePage(groups ...types.SecurityGroup) *fakeEC2 {
	return &fakeEC2{pages: []page{{groups: groups}}}
}

// line renders the decision-relevant fields of a finding.
func line(f model.InsecureRule) string {
	p := func(v *int) string {
		if v == nil {
			return "-"
		}
		return fmt.Sprint(*v)
	}
	return fmt.Sprintf("%s %s from=%s to=%s type=%s code=%s src=%s raw=%s ref=%s",
		f.Protocol, f.Port, p(f.FromPort), p(f.ToPort), p(f.ICMPType), p(f.ICMPCode),
		f.Source, f.ProviderSource, f.RuleRef)
}

func lines(groups []model.AWSSecurityGroup) []string {
	var out []string
	for _, g := range groups {
		for _, f := range g.InsecureRules {
			out = append(out, g.ID+" "+line(f))
		}
	}
	slices.Sort(out)
	return out
}

func diagCodes(diags []model.Diagnostic) []string {
	var out []string
	for _, d := range diags {
		out = append(out, d.Code+"/"+d.Field+"/"+d.Effect)
	}
	slices.Sort(out)
	return out
}

func errorKinds(errs []model.ScanError) []string {
	var out []string
	for _, e := range errs {
		out = append(out, e.Scope+" "+e.Operation+" "+e.Kind)
	}
	slices.Sort(out)
	return out
}

func assertEqual[T any](t *testing.T, what string, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s:\n got  %v\n want %v", what, got, want)
	}
}

func TestScan_OneInsecureGroup(t *testing.T) {
	g := sg("sg-0fake0000000000001", "open-ssh", tcp(22, worldStr))
	g.IpPermissions[0].IpRanges[0].Description = awssdk.String("ssh from anywhere")
	res := scanOne(t, onePage(g))

	assertEqual(t, "status", res.Status, model.ProviderComplete)
	if len(res.AWSSecurityGroups) != 1 {
		t.Fatalf("groups = %d, want 1", len(res.AWSSecurityGroups))
	}
	got := res.AWSSecurityGroups[0]
	assertEqual(t, "group metadata",
		[]string{got.ID, got.Name, got.VPCID, got.AccountID, got.Region},
		[]string{"sg-0fake0000000000001", "open-ssh", "vpc-0fake000000000001", fakeAccount, euWest1})
	assertEqual(t, "findings", lines(res.AWSSecurityGroups),
		[]string{"sg-0fake0000000000001 tcp 22 from=22 to=22 type=- code=- src=0.0.0.0/0 raw=0.0.0.0/0 ref=tcp:22:22:0.0.0.0/0"})
	f := got.InsecureRules[0]
	assertEqual(t, "description", f.Description, "ssh from anywhere")
	assertEqual(t, "provider fields", []string{f.ProviderProtocol, f.ProviderPort, f.MatchReason, f.Reachability},
		[]string{"tcp", "22-22", model.MatchIPv4WorldCIDR, model.ReachabilityNotEvaluated})
	assertEqual(t, "scopes", res.Scopes, []model.ScopeResult{{
		Provider: model.ProviderAWS, Scope: scopeEU, Status: model.ScopeComplete,
		ResourcesScanned: 1, RulesEvaluated: 1,
	}})
	assertEqual(t, "diagnostics", len(res.Diagnostics), 0)
	assertEqual(t, "errors", len(res.Errors), 0)
}

func TestScan_MultipleInsecureRules(t *testing.T) {
	g := sg("sg-0fake0000000000001", "web",
		tcp(22, worldStr),
		tcp(443, worldStr),
		perm("udp", i32(123), i32(123), worldStr),
		perm("tcp", i32(8000), i32(8090), worldStr),
		tcp(5432, "10.0.0.0/8"), // private: not a finding
	)
	res := scanOne(t, onePage(g))
	assertEqual(t, "findings", lines(res.AWSSecurityGroups), []string{
		"sg-0fake0000000000001 tcp 22 from=22 to=22 type=- code=- src=0.0.0.0/0 raw=0.0.0.0/0 ref=tcp:22:22:0.0.0.0/0",
		"sg-0fake0000000000001 tcp 443 from=443 to=443 type=- code=- src=0.0.0.0/0 raw=0.0.0.0/0 ref=tcp:443:443:0.0.0.0/0",
		"sg-0fake0000000000001 tcp 8000-8090 from=8000 to=8090 type=- code=- src=0.0.0.0/0 raw=0.0.0.0/0 ref=tcp:8000:8090:0.0.0.0/0",
		"sg-0fake0000000000001 udp 123 from=123 to=123 type=- code=- src=0.0.0.0/0 raw=0.0.0.0/0 ref=udp:123:123:0.0.0.0/0",
	})
	assertEqual(t, "rules evaluated", res.Scopes[0].RulesEvaluated, 5)
}

func TestScan_DifferentIPv4Sources(t *testing.T) {
	p := perm("tcp", i32(443), i32(443),
		"10.0.0.0/8",     // private
		"0.0.0.0/0",      // world
		"10.1.2.0/0",     // non-canonical world: any IPv4 /0
		"192.0.2.10/32",  // host
		" 0.0.0.0/0 ",    // world with whitespace
		"203.0.113.0/24", // public, but not world
	)
	p.Ipv6Ranges = []types.Ipv6Range{{CidrIpv6: awssdk.String("::/0")}} // IPv6: out of v1 scope
	p.UserIdGroupPairs = []types.UserIdGroupPair{{GroupId: awssdk.String("sg-0fake0000000000009")}}
	p.PrefixListIds = []types.PrefixListId{{PrefixListId: awssdk.String("pl-0fake000000000001")}}
	res := scanOne(t, onePage(sg("sg-0fake0000000000001", "mixed", p)))

	assertEqual(t, "findings", lines(res.AWSSecurityGroups), []string{
		"sg-0fake0000000000001 tcp 443 from=443 to=443 type=- code=- src=0.0.0.0/0 raw= 0.0.0.0/0  ref=tcp:443:443: 0.0.0.0/0 ",
		"sg-0fake0000000000001 tcp 443 from=443 to=443 type=- code=- src=0.0.0.0/0 raw=0.0.0.0/0 ref=tcp:443:443:0.0.0.0/0",
		"sg-0fake0000000000001 tcp 443 from=443 to=443 type=- code=- src=0.0.0.0/0 raw=10.1.2.0/0 ref=tcp:443:443:10.1.2.0/0",
	})
	assertEqual(t, "prefix lists", res.Scopes[0].PrefixListRefsUnexpanded, 1)
	assertEqual(t, "status", res.Scopes[0].Status, model.ScopeComplete)
	assertEqual(t, "diagnostics", len(res.Diagnostics), 0)
}

func TestScan_IPv6OnlyRuleIsNotAFinding(t *testing.T) {
	p := types.IpPermission{
		IpProtocol: awssdk.String("tcp"), FromPort: i32(22), ToPort: i32(22),
		Ipv6Ranges: []types.Ipv6Range{{CidrIpv6: awssdk.String("::/0")}},
	}
	res := scanOne(t, onePage(sg("sg-0fake0000000000001", "v6", p)))
	assertEqual(t, "groups", len(res.AWSSecurityGroups), 0)
	assertEqual(t, "status", res.Status, model.ProviderComplete)
	assertEqual(t, "diagnostics", len(res.Diagnostics), 0)
}

func TestScan_SelectorOnlyRulesAreNotFindings(t *testing.T) {
	p := types.IpPermission{
		IpProtocol:       awssdk.String("-1"),
		UserIdGroupPairs: []types.UserIdGroupPair{{GroupId: awssdk.String("sg-0fake0000000000009")}},
	}
	q := types.IpPermission{
		IpProtocol: awssdk.String("tcp"), FromPort: i32(443), ToPort: i32(443),
		PrefixListIds: []types.PrefixListId{{PrefixListId: awssdk.String("pl-0fake000000000001")}},
	}
	res := scanOne(t, onePage(sg("sg-0fake0000000000001", "internal", p, q)))
	assertEqual(t, "groups", len(res.AWSSecurityGroups), 0)
	assertEqual(t, "scope", res.Scopes[0], model.ScopeResult{
		Provider: model.ProviderAWS, Scope: scopeEU, Status: model.ScopeComplete,
		ResourcesScanned: 1, RulesEvaluated: 2, PrefixListRefsUnexpanded: 1,
	})
}

func TestScan_EgressIsIgnored(t *testing.T) {
	g := sg("sg-0fake0000000000001", "default")
	g.IpPermissionsEgress = []types.IpPermission{perm("-1", nil, nil, worldStr)}
	res := scanOne(t, onePage(g))
	assertEqual(t, "groups", len(res.AWSSecurityGroups), 0)
	assertEqual(t, "rules evaluated", res.Scopes[0].RulesEvaluated, 0)
	assertEqual(t, "status", res.Status, model.ProviderComplete)
}

func TestScan_AllProtocols(t *testing.T) {
	// AWS ignores port fields for -1; the API returns none.
	res := scanOne(t, onePage(
		sg("sg-0fake0000000000001", "all-traffic", perm("-1", nil, nil, worldStr)),
		// Numeric protocol other than tcp/udp/icmp/icmpv6: all ports.
		sg("sg-0fake0000000000002", "gre", perm("47", nil, nil, worldStr)),
		// Numeric forms of tcp and udp.
		sg("sg-0fake0000000000003", "numeric", perm("6", i32(80), i32(80), worldStr), perm("17", i32(0), i32(65535), worldStr)),
	))
	assertEqual(t, "findings", lines(res.AWSSecurityGroups), []string{
		"sg-0fake0000000000001 all all from=- to=- type=- code=- src=0.0.0.0/0 raw=0.0.0.0/0 ref=-1:::0.0.0.0/0",
		"sg-0fake0000000000002 47 all from=- to=- type=- code=- src=0.0.0.0/0 raw=0.0.0.0/0 ref=47:::0.0.0.0/0",
		"sg-0fake0000000000003 tcp 80 from=80 to=80 type=- code=- src=0.0.0.0/0 raw=0.0.0.0/0 ref=6:80:80:0.0.0.0/0",
		"sg-0fake0000000000003 udp all from=0 to=65535 type=- code=- src=0.0.0.0/0 raw=0.0.0.0/0 ref=17:0:65535:0.0.0.0/0",
	})
	assertEqual(t, "diagnostics", len(res.Diagnostics), 0)
}

func TestScan_ICMP(t *testing.T) {
	res := scanOne(t, onePage(sg("sg-0fake0000000000001", "icmp",
		perm("icmp", i32(-1), i32(-1), worldStr), // all ICMP
		perm("icmp", i32(8), i32(-1), worldStr),  // echo request, any code
		perm("icmp", i32(3), i32(4), worldStr),   // frag needed
		perm("icmpv6", nil, nil, worldStr),       // icmpv6 without range: all
		perm("1", i32(0), i32(0), worldStr),      // numeric icmp, echo reply
	)))
	assertEqual(t, "findings", lines(res.AWSSecurityGroups), []string{
		"sg-0fake0000000000001 icmp all from=- to=- type=- code=- src=0.0.0.0/0 raw=0.0.0.0/0 ref=icmp:-1:-1:0.0.0.0/0",
		"sg-0fake0000000000001 icmp all from=- to=- type=0 code=0 src=0.0.0.0/0 raw=0.0.0.0/0 ref=1:0:0:0.0.0.0/0",
		"sg-0fake0000000000001 icmp all from=- to=- type=3 code=4 src=0.0.0.0/0 raw=0.0.0.0/0 ref=icmp:3:4:0.0.0.0/0",
		"sg-0fake0000000000001 icmp all from=- to=- type=8 code=- src=0.0.0.0/0 raw=0.0.0.0/0 ref=icmp:8:-1:0.0.0.0/0",
		"sg-0fake0000000000001 icmpv6 all from=- to=- type=- code=- src=0.0.0.0/0 raw=0.0.0.0/0 ref=icmpv6:::0.0.0.0/0",
	})
	for _, f := range res.AWSSecurityGroups[0].InsecureRules {
		if f.FromPort != nil || f.ToPort != nil {
			t.Errorf("ICMP values leaked into port fields: %s", line(f))
		}
	}
	assertEqual(t, "diagnostics", len(res.Diagnostics), 0)
}

func TestScan_MultiplePages(t *testing.T) {
	fake := &fakeEC2{pages: []page{
		{groups: []types.SecurityGroup{sg("sg-0fake0000000000001", "a", tcp(22, worldStr))}},
		{}, // empty page that still carries a NextToken
		{groups: []types.SecurityGroup{
			sg("sg-0fake0000000000002", "b", tcp(443, worldStr)),
			sg("sg-0fake0000000000003", "c", tcp(443, "10.0.0.0/8")),
		}},
	}}
	res := scanOne(t, fake)

	assertEqual(t, "calls", fake.sgCalls(), 3)
	var tokens []string
	for _, in := range fake.sgInputs {
		tokens = append(tokens, awssdk.ToString(in.NextToken))
		if awssdk.ToInt32(in.MaxResults) != pageSize {
			t.Errorf("MaxResults = %v, want %d", in.MaxResults, pageSize)
		}
		if len(in.GroupIds) != 0 || len(in.GroupNames) != 0 || len(in.Filters) != 0 {
			t.Errorf("request must not filter server-side: %+v", in)
		}
	}
	assertEqual(t, "tokens", tokens, []string{"", "p1", "p2"})
	assertEqual(t, "resources", res.Scopes[0].ResourcesScanned, 3)
	assertEqual(t, "groups with findings", len(res.AWSSecurityGroups), 2)
	assertEqual(t, "status", res.Status, model.ProviderComplete)
}

func TestScan_EmptyResults(t *testing.T) {
	cases := map[string]*fakeEC2{
		"no pages":      {},
		"empty page":    {pages: []page{{}}},
		"empty group":   onePage(sg("sg-0fake0000000000001", "empty")),
		"private rules": onePage(sg("sg-0fake0000000000001", "private", tcp(22, "10.0.0.0/8"))),
	}
	for name, fake := range cases {
		t.Run(name, func(t *testing.T) {
			res := scanOne(t, fake)
			assertEqual(t, "status", res.Status, model.ProviderComplete)
			assertEqual(t, "scope status", res.Scopes[0].Status, model.ScopeComplete)
			if res.AWSSecurityGroups == nil || len(res.AWSSecurityGroups) != 0 {
				t.Errorf("groups = %#v, want empty non-nil", res.AWSSecurityGroups)
			}
			if res.Diagnostics == nil || res.Errors == nil {
				t.Error("nil slices in result")
			}
		})
	}
}

func TestScan_MultipleRegions(t *testing.T) {
	f := newFactory(map[string]*fakeEC2{
		euWest1: onePage(sg("sg-0fake0000000000001", "eu", tcp(22, worldStr))),
		usEast1: onePage(sg("sg-0fake0000000000002", "us", tcp(443, worldStr))),
	})
	res := newTestScanner(Config{Regions: []string{usEast1, euWest1, " eu-west-1 "}}, okSTS(), f).
		Scan(context.Background())

	assertEqual(t, "status", res.Status, model.ProviderComplete)
	var scopes []string
	for _, s := range res.Scopes {
		scopes = append(scopes, s.Scope+" "+string(s.Status))
	}
	assertEqual(t, "scopes (sorted, de-duplicated)", scopes,
		[]string{scopeEU + " complete", scopeUS + " complete"})
	regions := map[string]string{}
	for _, g := range res.AWSSecurityGroups {
		regions[g.ID] = g.Region
	}
	assertEqual(t, "regions", regions, map[string]string{
		"sg-0fake0000000000001": euWest1, "sg-0fake0000000000002": usEast1,
	})
}

func TestScan_RegionDiscovery(t *testing.T) {
	boot := &fakeEC2{regions: []types.Region{
		{RegionName: awssdk.String(usEast1), OptInStatus: awssdk.String("opt-in-not-required")},
		{RegionName: awssdk.String(euWest1), OptInStatus: awssdk.String("opt-in-not-required")},
		{RegionName: awssdk.String(apEast1), OptInStatus: awssdk.String("opted-in")},
	}}
	// The bootstrap client is eu-west-1, which is also scanned.
	boot.pages = []page{{groups: []types.SecurityGroup{sg("sg-0fake0000000000001", "eu", tcp(22, worldStr))}}}
	f := newFactory(map[string]*fakeEC2{
		euWest1: boot,
		usEast1: onePage(),
		apEast1: onePage(),
	})
	res := newTestScanner(Config{BootstrapRegion: euWest1}, okSTS(), f).Scan(context.Background())

	if len(boot.regionInputs) != 1 {
		t.Fatalf("DescribeRegions calls = %d, want 1", len(boot.regionInputs))
	}
	if all := boot.regionInputs[0].AllRegions; all == nil || *all {
		t.Errorf("AllRegions = %v, want explicit false (enabled regions only)", all)
	}
	assertEqual(t, "status", res.Status, model.ProviderComplete)
	var scopes []string
	for _, s := range res.Scopes {
		scopes = append(scopes, s.Scope)
	}
	assertEqual(t, "scopes", scopes, []string{scopeAP, scopeEU, scopeUS})
	assertEqual(t, "findings", len(lines(res.AWSSecurityGroups)), 1)
}

func TestScan_ExplicitRegionsSkipDiscovery(t *testing.T) {
	boot := onePage()
	f := newFactory(map[string]*fakeEC2{euWest1: boot, usEast1: onePage()})
	res := newTestScanner(Config{BootstrapRegion: euWest1, Regions: []string{usEast1}}, okSTS(), f).
		Scan(context.Background())
	assertEqual(t, "DescribeRegions calls", len(boot.regionInputs), 0)
	assertEqual(t, "bootstrap region scanned", boot.sgCalls(), 0)
	assertEqual(t, "status", res.Status, model.ProviderComplete)
	assertEqual(t, "scopes", len(res.Scopes), 1)
}

func TestScan_DisabledOrUnavailableRegion(t *testing.T) {
	disabled := &fakeEC2{pages: []page{{err: apiError("OptInRequired",
		"You are not subscribed to this service. Please go to http://aws.amazon.com to subscribe.")}}}
	f := newFactory(map[string]*fakeEC2{
		euWest1: onePage(sg("sg-0fake0000000000001", "eu", tcp(22, worldStr))),
		apEast1: disabled,
		// "me-south-1" has no fake: the factory fails it like an unknown endpoint.
	})
	res := newTestScanner(Config{Regions: []string{euWest1, apEast1, "me-south-1"}}, okSTS(), f).
		Scan(context.Background())

	assertEqual(t, "status", res.Status, model.ProviderPartial)
	statuses := map[string]model.ScopeStatus{}
	for _, s := range res.Scopes {
		statuses[s.Scope] = s.Status
	}
	assertEqual(t, "scope statuses", statuses, map[string]model.ScopeStatus{
		scopeAP: model.ScopeFailed, scopeEU: model.ScopeComplete, fakeAccount + "/me-south-1": model.ScopeFailed,
	})
	assertEqual(t, "errors", errorKinds(res.Errors), []string{
		scopeAP + " ec2:DescribeSecurityGroups permission_denied",
		fakeAccount + "/me-south-1 ec2:DescribeSecurityGroups other",
	})
	// Findings from the healthy region are still reported.
	assertEqual(t, "findings", len(lines(res.AWSSecurityGroups)), 1)
}

func TestScan_InvalidRegionNameIsAFailedScope(t *testing.T) {
	f := newFactory(map[string]*fakeEC2{euWest1: onePage()})
	res := newTestScanner(Config{Regions: []string{euWest1, "evil.example.com#", ""}}, okSTS(), f).
		Scan(context.Background())
	assertEqual(t, "status", res.Status, model.ProviderPartial)
	assertEqual(t, "errors", errorKinds(res.Errors), []string{
		fakeAccount + "/ config other",
		fakeAccount + "/evil.example.com# config other",
	})
	// No client is ever built for an invalid name.
	assertEqual(t, "clients built", f.asked, []string{euWest1})
}

func TestScan_PaginationFailureDiscardsScope(t *testing.T) {
	fake := &fakeEC2{pages: []page{
		{groups: []types.SecurityGroup{sg("sg-0fake0000000000001", "page1", tcp(22, worldStr))}},
		{err: apiError("InternalError", "fake internal error")},
	}}
	res := scanOne(t, fake)
	assertEqual(t, "status", res.Status, model.ProviderFailed)
	assertEqual(t, "scope", res.Scopes[0], model.ScopeResult{
		Provider: model.ProviderAWS, Scope: scopeEU, Status: model.ScopeFailed,
	})
	assertEqual(t, "page 1 findings discarded", len(res.AWSSecurityGroups), 0)
	assertEqual(t, "errors", errorKinds(res.Errors), []string{scopeEU + " ec2:DescribeSecurityGroups other"})
	if !strings.Contains(res.Errors[0].Message, "page 2") {
		t.Errorf("message %q should name the failing page", res.Errors[0].Message)
	}
}

func TestScan_RepeatedNextTokenFailsScope(t *testing.T) {
	fake := &fakeEC2{pages: []page{
		{groups: []types.SecurityGroup{sg("sg-0fake0000000000001", "a", tcp(22, worldStr))}},
		{next: awssdk.String("p1")}, // points back to itself
	}}
	res := scanOne(t, fake)
	assertEqual(t, "status", res.Status, model.ProviderFailed)
	// Page 0 returns "p1"; page 1 returns "p1" again and is rejected.
	assertEqual(t, "calls", fake.sgCalls(), 2)
	assertEqual(t, "groups", len(res.AWSSecurityGroups), 0)
}

func TestScan_NilOutputFailsScope(t *testing.T) {
	res := scanOne(t, &fakeEC2{pages: []page{{nilOutput: true}}})
	assertEqual(t, "status", res.Status, model.ProviderFailed)
	assertEqual(t, "errors", errorKinds(res.Errors), []string{scopeEU + " ec2:DescribeSecurityGroups other"})
}

func TestScan_AccessDenied(t *testing.T) {
	denied := &fakeEC2{pages: []page{{err: apiError("UnauthorizedOperation",
		"You are not authorized to perform this operation.")}}}
	f := newFactory(map[string]*fakeEC2{euWest1: denied, usEast1: denied})
	res := newTestScanner(Config{Regions: []string{euWest1, usEast1}}, okSTS(), f).Scan(context.Background())
	assertEqual(t, "status (every scope failed)", res.Status, model.ProviderFailed)
	assertEqual(t, "errors", errorKinds(res.Errors), []string{
		scopeEU + " ec2:DescribeSecurityGroups permission_denied",
		scopeUS + " ec2:DescribeSecurityGroups permission_denied",
	})
}

func TestScan_SetupFailures(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name      string
		cfg       Config
		sts       *fakeSTS
		boot      *fakeEC2
		wantErr   []string
		wantDiags []string
	}{
		{
			name: "invalid bootstrap region", cfg: Config{BootstrapRegion: "not a region"},
			sts: okSTS(), boot: onePage(),
			wantErr: []string{" config other"},
		},
		{
			name: "GetCallerIdentity denied", sts: &fakeSTS{err: opError("GetCallerIdentity",
				&smithy.GenericAPIError{Code: "InvalidClientTokenId", Message: "The security token included in the request is invalid."})},
			boot:    onePage(),
			wantErr: []string{" sts:GetCallerIdentity auth"},
		},
		{
			name: "GetCallerIdentity without account", sts: &fakeSTS{},
			boot:    onePage(),
			wantErr: []string{" sts:GetCallerIdentity other"},
		},
		{
			name: "DescribeRegions denied", sts: okSTS(),
			boot:    &fakeEC2{regionsErr: apiError("UnauthorizedOperation", "not authorized")},
			wantErr: []string{fakeAccount + " ec2:DescribeRegions permission_denied"},
		},
		{
			name: "zero regions discovered", sts: okSTS(), boot: &fakeEC2{},
			wantDiags: []string{model.CodeNoScopesDiscovered + "/Regions/" + model.EffectProviderFailed},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFactory(map[string]*fakeEC2{euWest1: tc.boot})
			res := newTestScanner(tc.cfg, tc.sts, f).Scan(ctx)
			assertEqual(t, "status", res.Status, model.ProviderFailed)
			assertEqual(t, "errors", errorKinds(res.Errors), tc.wantErr)
			assertEqual(t, "diagnostics", diagCodes(res.Diagnostics), tc.wantDiags)
			assertEqual(t, "scopes", len(res.Scopes), 0)
			assertEqual(t, "no SG reads", tc.boot.sgCalls(), 0)
		})
	}
}

func TestScan_DiscoveredRegionWithoutNameMakesProviderPartial(t *testing.T) {
	boot := &fakeEC2{regions: []types.Region{
		{RegionName: awssdk.String(euWest1)},
		{RegionName: nil},
	}}
	f := newFactory(map[string]*fakeEC2{euWest1: boot})
	res := newTestScanner(Config{}, okSTS(), f).Scan(context.Background())
	assertEqual(t, "status", res.Status, model.ProviderPartial)
	assertEqual(t, "scope status", res.Scopes[0].Status, model.ScopeComplete)
	assertEqual(t, "errors", errorKinds(res.Errors), []string{fakeAccount + " ec2:DescribeRegions other"})
}

func TestScan_ScopeTimeout(t *testing.T) {
	f := newFactory(map[string]*fakeEC2{
		euWest1: {block: true},
		usEast1: onePage(sg("sg-0fake0000000000002", "us", tcp(443, worldStr))),
	})
	cfg := Config{Regions: []string{euWest1, usEast1}, ScopeTimeout: 20 * time.Millisecond}
	res := newTestScanner(cfg, okSTS(), f).Scan(context.Background())
	assertEqual(t, "status", res.Status, model.ProviderPartial)
	assertEqual(t, "errors", errorKinds(res.Errors), []string{scopeEU + " ec2:DescribeSecurityGroups timeout"})
	assertEqual(t, "other region still reported", len(lines(res.AWSSecurityGroups)), 1)
}

func TestScan_ContextCancelledMidScan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// With one worker, whichever region starts first interrupts the run
	// during its call; the other region must not be started.
	a := &fakeEC2{onCall: cancel}
	b := &fakeEC2{onCall: cancel}
	f := newFactory(map[string]*fakeEC2{euWest1: a, usEast1: b})
	res := newTestScanner(Config{Regions: []string{usEast1, euWest1}, Concurrency: 1}, okSTS(), f).Scan(ctx)

	assertEqual(t, "status", res.Status, model.ProviderFailed)
	assertEqual(t, "errors", errorKinds(res.Errors), []string{
		scopeEU + " ec2:DescribeSecurityGroups timeout",
		scopeUS + " ec2:DescribeSecurityGroups timeout",
	})
	assertEqual(t, "API calls", a.sgCalls()+b.sgCalls(), 1)
	assertEqual(t, "every region has a scope", len(res.Scopes), 2)
}

func TestScan_ContextCancelledBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := newFactory(map[string]*fakeEC2{euWest1: onePage()})
	res := newTestScanner(Config{Regions: []string{euWest1}}, okSTS(), f).Scan(ctx)
	assertEqual(t, "status", res.Status, model.ProviderFailed)
	assertEqual(t, "errors", errorKinds(res.Errors), []string{" sts:GetCallerIdentity timeout"})
}

func TestScan_MalformedFields(t *testing.T) {
	noID := sg("", "no-id", tcp(22, worldStr))
	noID.GroupId = nil
	noID.VpcId = nil

	noProto := sg("sg-0fake0000000000002", "no-proto", types.IpPermission{
		IpRanges: []types.IpRange{{CidrIp: awssdk.String(worldStr)}},
	})
	tcpNoPorts := sg("sg-0fake0000000000003", "tcp-no-ports", perm("tcp", nil, nil, worldStr))
	badICMP := sg("sg-0fake0000000000004", "bad-icmp", perm("icmp", i32(-1), i32(4), worldStr))
	// Missing CidrIp next to a world CIDR: finding, detail diagnostic.
	nilCIDRWithWorld := sg("sg-0fake0000000000005", "nil-cidr-world", types.IpPermission{
		IpProtocol: awssdk.String("tcp"), FromPort: i32(80), ToPort: i32(80),
		IpRanges: []types.IpRange{{CidrIp: nil}, {CidrIp: awssdk.String(worldStr)}},
	})
	otherOwner := sg("sg-0fake0000000000006", "shared-vpc", tcp(3389, worldStr))
	otherOwner.OwnerId = awssdk.String(otherAcct)
	noOwner := sg("sg-0fake0000000000007", "no-owner", tcp(25, worldStr))
	noOwner.OwnerId = nil

	res := scanOne(t, onePage(noID, noProto, tcpNoPorts, badICMP, nilCIDRWithWorld, otherOwner, noOwner))

	assertEqual(t, "findings", lines(res.AWSSecurityGroups), []string{
		" tcp 22 from=22 to=22 type=- code=- src=0.0.0.0/0 raw=0.0.0.0/0 ref=tcp:22:22:0.0.0.0/0",
		"sg-0fake0000000000002 unknown unknown from=- to=- type=- code=- src=0.0.0.0/0 raw=0.0.0.0/0 ref=:::0.0.0.0/0",
		"sg-0fake0000000000003 tcp unknown from=- to=- type=- code=- src=0.0.0.0/0 raw=0.0.0.0/0 ref=tcp:::0.0.0.0/0",
		"sg-0fake0000000000004 icmp unknown from=- to=- type=- code=- src=0.0.0.0/0 raw=0.0.0.0/0 ref=icmp:-1:4:0.0.0.0/0",
		"sg-0fake0000000000005 tcp 80 from=80 to=80 type=- code=- src=0.0.0.0/0 raw=0.0.0.0/0 ref=tcp:80:80:0.0.0.0/0",
		"sg-0fake0000000000006 tcp 3389 from=3389 to=3389 type=- code=- src=0.0.0.0/0 raw=0.0.0.0/0 ref=tcp:3389:3389:0.0.0.0/0",
		"sg-0fake0000000000007 tcp 25 from=25 to=25 type=- code=- src=0.0.0.0/0 raw=0.0.0.0/0 ref=tcp:25:25:0.0.0.0/0",
	})
	assertEqual(t, "diagnostics", diagCodes(res.Diagnostics), []string{
		model.CodePortMalformed + "/port/" + model.EffectFindingDetailUnknown, // bad icmp
		model.CodePortMalformed + "/port/" + model.EffectFindingDetailUnknown, // tcp no ports
		model.CodeProtocolUnknown + "/protocol/" + model.EffectFindingDetailUnknown,
		model.CodeResourceIDMissing + "/GroupId/" + model.EffectFindingDetailUnknown,
		model.CodeSourceMalformed + "/IpRanges.CidrIp/" + model.EffectFindingDetailUnknown,
	})
	// Every rule could be decided, so the scope stays complete.
	assertEqual(t, "scope status", res.Scopes[0].Status, model.ScopeComplete)

	owners := map[string]string{}
	for _, g := range res.AWSSecurityGroups {
		owners[g.Name] = g.AccountID + "|" + g.VPCID
	}
	assertEqual(t, "valid metadata preserved", owners["no-id"], fakeAccount+"|")
	assertEqual(t, "shared VPC owner", owners["shared-vpc"], otherAcct+"|vpc-0fake000000000001")
	assertEqual(t, "missing owner", owners["no-owner"], fakeAccount+"|vpc-0fake000000000001")
}

func TestScan_UndecidableRuleMakesScopeIncomplete(t *testing.T) {
	tests := map[string]types.IpPermission{
		"missing CidrIp": {IpProtocol: awssdk.String("tcp"), FromPort: i32(22), ToPort: i32(22),
			IpRanges: []types.IpRange{{CidrIp: nil}}},
		"unparseable CidrIp": tcp(22, "not-a-cidr"),
		"no sources":         {IpProtocol: awssdk.String("tcp"), FromPort: i32(22), ToPort: i32(22)},
	}
	for name, p := range tests {
		t.Run(name, func(t *testing.T) {
			res := scanOne(t, onePage(sg("sg-0fake0000000000001", "x", p)))
			assertEqual(t, "groups", len(res.AWSSecurityGroups), 0)
			assertEqual(t, "scope status", res.Scopes[0].Status, model.ScopeIncomplete)
			assertEqual(t, "provider status", res.Status, model.ProviderPartial)
			if len(res.Diagnostics) != 1 || res.Diagnostics[0].Effect != model.EffectScopeIncomplete {
				t.Errorf("diagnostics = %+v, want one scope_incomplete", res.Diagnostics)
			}
		})
	}
}

// TestScan_DeterministicOutput feeds the same inventory in shuffled page
// and group order with concurrency, and requires byte-identical reports.
func TestScan_DeterministicOutput(t *testing.T) {
	groups := []types.SecurityGroup{
		sg("sg-0fake0000000000001", "a", tcp(22, worldStr), tcp(443, worldStr), perm("-1", nil, nil, worldStr)),
		sg("sg-0fake0000000000002", "b", perm("icmp", i32(8), i32(-1), worldStr, "10.0.0.0/0")),
		sg("sg-0fake0000000000003", "c", perm("udp", i32(53), i32(53), "not-a-cidr")),
		sg("sg-0fake0000000000004", "d", tcp(80, "10.0.0.0/8")),
	}
	build := func(seed uint64) []byte {
		rng := rand.New(rand.NewPCG(seed, seed))
		fakes := map[string]*fakeEC2{}
		for _, region := range []string{euWest1, usEast1, apEast1} {
			gs := slices.Clone(groups)
			rng.Shuffle(len(gs), func(i, j int) { gs[i], gs[j] = gs[j], gs[i] })
			// Split into one page per group, so page order varies too.
			var pages []page
			for _, g := range gs {
				pages = append(pages, page{groups: []types.SecurityGroup{g}})
			}
			fakes[region] = &fakeEC2{pages: pages}
		}
		regions := []string{usEast1, apEast1, euWest1}
		rng.Shuffle(len(regions), func(i, j int) { regions[i], regions[j] = regions[j], regions[i] })
		res := newTestScanner(Config{Regions: regions, Concurrency: 8}, okSTS(), newFactory(fakes)).
			Scan(context.Background())
		out, err := report.Encode(report.Build([]model.ProviderResult{res}, report.Options{ToolVersion: "test"}))
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	want := build(1)
	for seed := uint64(2); seed < 30; seed++ {
		if got := build(seed); !bytes.Equal(got, want) {
			t.Fatalf("seed %d: output differs\n--- got\n%s\n--- want\n%s", seed, got, want)
		}
	}
	for _, s := range []string{`"findings": 15`, `"status": "incomplete"`, `"aws": "partial"`} {
		if !bytes.Contains(want, []byte(s)) {
			t.Errorf("report missing %s:\n%s", s, want)
		}
	}
}

// TestReadOnlyInterfaces guards the code-level read-only guarantee: the
// interfaces the scanner depends on expose only Describe*/Get* calls.
func TestReadOnlyInterfaces(t *testing.T) {
	for _, iface := range []reflect.Type{
		reflect.TypeFor[EC2API](),
		reflect.TypeFor[STSAPI](),
	} {
		for m := range iface.Methods() {
			if !strings.HasPrefix(m.Name, "Describe") && !strings.HasPrefix(m.Name, "Get") {
				t.Errorf("%s.%s is not a read-only operation", iface.Name(), m.Name)
			}
		}
	}
}
