package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/exposure"
	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
)

var update = flag.Bool("update", false, "rewrite golden files")

const goldenPath = "../../testdata/golden/example-report.json"

func i32(v int32) *int32 { return &v }

// evalAll runs the detection engine over rules and returns the findings
// and diagnostics, as a provider scanner will.
func evalAll(t *testing.T, rules ...exposure.Rule) ([]model.InsecureRule, []model.Diagnostic) {
	t.Helper()
	var f []model.InsecureRule
	var d []model.Diagnostic
	for _, r := range rules {
		res := exposure.Evaluate(r)
		f = append(f, res.Findings...)
		d = append(d, res.Diagnostics...)
	}
	return f, d
}

// fixtureResults builds a small fake inventory across all three providers,
// using the detection engine. All IDs are fake.
func fixtureResults(t *testing.T) []model.ProviderResult {
	t.Helper()

	awsScope := "111111111111/eu-west-1"
	aws := func(proto string, from, to *int32, cidr, ref string) exposure.Rule {
		return exposure.Rule{
			Provider: model.ProviderAWS, Scope: awsScope, ResourceID: "sg-0fake0000000000001", RuleRef: ref,
			Direction: exposure.DirectionInbound, Action: exposure.ActionAllow,
			Protocol: proto, PortStyle: exposure.PortsFromAWS, AWSFrom: from, AWSTo: to,
			Sources: []exposure.Source{{Kind: exposure.SourceAddress, Field: "IpRanges.CidrIp", Raw: cidr}},
		}
	}
	awsFindings, awsDiags := evalAll(t,
		aws("tcp", i32(8080), i32(8080), "0.0.0.0/0", "tcp:8080:8080:0.0.0.0/0"),
		aws("icmp", i32(8), i32(-1), "0.0.0.0/0", "icmp:8:-1:0.0.0.0/0"),
		aws("tcp", i32(22), i32(22), "10.0.0.0/8", "tcp:22:22:10.0.0.0/8"),
	)

	gcpScope := "example-project-a"
	gcpRule := exposure.Rule{
		Provider: model.ProviderGCP, Scope: gcpScope,
		ResourceID: "projects/example-project-a/global/firewalls/allow-all", RuleRef: "allow-all",
		Direction: exposure.DirectionInbound, DirectionRaw: "INGRESS", Action: exposure.ActionAllow,
		Protocol: "icmp",
		Sources:  []exposure.Source{{Kind: exposure.SourceAddress, Field: "sourceRanges", Raw: "0.0.0.0/0"}},
		Context:  model.RuleContext{Priority: new(int), Targets: []string{"all_instances"}},
	}
	*gcpRule.Context.Priority = 1000
	badGCP := gcpRule
	badGCP.ResourceID, badGCP.RuleRef = "projects/example-project-a/global/firewalls/fake-rule", "fake-rule"
	badGCP.Sources = []exposure.Source{{Kind: exposure.SourceAddress, Field: "sourceRanges", Raw: "not-a-cidr"}}
	gcpFindings, gcpDiags := evalAll(t, gcpRule, badGCP)

	azScope := "00000000-0000-0000-0000-000000000000"
	attached := true
	azRule := exposure.Rule{
		Provider: model.ProviderAzure, Scope: azScope,
		ResourceID: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/example-rg/providers/Microsoft.Network/networkSecurityGroups/open-nsg",
		RuleRef:    "allow-any",
		Direction:  exposure.DirectionInbound, Action: exposure.ActionAllow,
		Protocol: "*", PortRanges: []string{"*"},
		// "*" and "0.0.0.0/0" in the same rule normalise to one finding.
		Sources: []exposure.Source{
			{Kind: exposure.SourceAzurePrefix, Field: "sourceAddressPrefix", Raw: "*"},
			{Kind: exposure.SourceAzurePrefix, Field: "sourceAddressPrefixes", Raw: "0.0.0.0/0"},
		},
		Description: "<fake> & description",
		Context:     model.RuleContext{Priority: new(int), Attached: &attached},
	}
	*azRule.Context.Priority = 100
	azFindings, azDiags := evalAll(t, azRule)

	enabled := "Enabled"
	return []model.ProviderResult{
		{
			Provider: model.ProviderAWS, Status: model.ProviderComplete,
			Scopes: []model.ScopeResult{{
				Provider: model.ProviderAWS, Scope: awsScope, Status: model.ScopeStatusFor(awsDiags),
				ResourcesScanned: 1, RulesEvaluated: 3,
			}},
			AWSSecurityGroups: []model.AWSSecurityGroup{
				{ID: "sg-0fake0000000000001", Name: "open-sg", VPCID: "vpc-0fake000000000001",
					AccountID: "111111111111", Region: "eu-west-1", InsecureRules: awsFindings},
				{ID: "sg-0fake0000000000002", Name: "closed-sg", VPCID: "vpc-0fake000000000001",
					AccountID: "111111111111", Region: "eu-west-1"}, // no findings: omitted
			},
			Diagnostics: awsDiags,
		},
		{
			Provider: model.ProviderGCP, Status: model.ProviderPartial,
			Scopes: []model.ScopeResult{
				{Provider: model.ProviderGCP, Scope: gcpScope, Status: model.ScopeStatusFor(gcpDiags),
					ResourcesScanned: 2, RulesEvaluated: 2},
				{Provider: model.ProviderGCP, Scope: "example-project-b", Status: model.ScopeFailed},
			},
			GCPFirewallRules: []model.GCPFirewallRule{
				{Name: "allow-all", Network: "default", Project: gcpScope, ID: "1234567890", Direction: "INGRESS",
					InsecureRules: gcpFindings},
			},
			Diagnostics: gcpDiags,
			Errors: []model.ScanError{{
				Provider: model.ProviderGCP, Scope: "example-project-b", Operation: "compute.firewalls.list",
				Kind: model.ErrorKindPermissionDenied, Message: "fake 403",
			}},
		},
		{
			Provider: model.ProviderAzure, Status: model.ProviderComplete,
			Scopes: []model.ScopeResult{{
				Provider: model.ProviderAzure, Scope: azScope, Status: model.ScopeStatusFor(azDiags),
				ResourcesScanned: 1, RulesEvaluated: 1, SubscriptionState: &enabled,
			}},
			AzureNSGs: []model.AzureNSG{
				{ID: azRule.ResourceID, Name: "open-nsg", SubscriptionID: azScope, InsecureRules: azFindings},
			},
			Diagnostics: azDiags,
		},
	}
}

func TestGolden(t *testing.T) {
	got, err := Encode(Build(fixtureResults(t), Options{ToolVersion: "0.1.0-test"}))
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden file (run with -update to create it): %v", err)
	}
	// Git on Windows may check the file out with CRLF line endings.
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(got, want) {
		t.Fatalf("report differs from %s; run `go test ./internal/report -update` and review the diff.\n got:\n%s", goldenPath, got)
	}
}

// shuffled returns a deep-enough copy of results with every slice order
// randomised, simulating API pages and goroutines finishing in any order.
func shuffled(rng *rand.Rand, in []model.ProviderResult) []model.ProviderResult {
	out := slices.Clone(in)
	rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	for i := range out {
		p := &out[i]
		p.Scopes = shuffle(rng, p.Scopes)
		p.Diagnostics = shuffle(rng, p.Diagnostics)
		p.Errors = shuffle(rng, p.Errors)
		p.AWSSecurityGroups = shuffle(rng, p.AWSSecurityGroups)
		for j := range p.AWSSecurityGroups {
			p.AWSSecurityGroups[j].InsecureRules = shuffle(rng, p.AWSSecurityGroups[j].InsecureRules)
		}
		p.GCPFirewallRules = shuffle(rng, p.GCPFirewallRules)
		for j := range p.GCPFirewallRules {
			p.GCPFirewallRules[j].InsecureRules = shuffle(rng, p.GCPFirewallRules[j].InsecureRules)
		}
		p.AzureNSGs = shuffle(rng, p.AzureNSGs)
		for j := range p.AzureNSGs {
			p.AzureNSGs[j].InsecureRules = shuffle(rng, p.AzureNSGs[j].InsecureRules)
		}
	}
	return out
}

func shuffle[T any](rng *rand.Rand, in []T) []T {
	out := slices.Clone(in)
	rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

func TestDeterministicOutput(t *testing.T) {
	base := fixtureResults(t)
	want, err := Encode(Build(base, Options{}))
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewPCG(1, 2)) // fixed seed: the test itself is reproducible
	for i := 0; i < 50; i++ {
		got, err := Encode(Build(shuffled(rng, base), Options{}))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("run %d: output depends on input order", i)
		}
	}
}

func TestBuildDoesNotModifyInput(t *testing.T) {
	base := fixtureResults(t)
	before := base[2].AzureNSGs[0].InsecureRules
	n := len(before)
	Build(base, Options{})
	if len(base[2].AzureNSGs[0].InsecureRules) != n {
		t.Fatal("Build changed the input slice")
	}
}

func TestDeduplication(t *testing.T) {
	r := Build(fixtureResults(t), Options{})
	if len(r.Azure.NSGs) != 1 || len(r.Azure.NSGs[0].InsecureRules) != 1 {
		t.Fatalf("Azure '*' and '0.0.0.0/0' in one rule should merge into one finding: %+v", r.Azure.NSGs)
	}
	if got := r.Azure.NSGs[0].InsecureRules[0].ProviderSource; got != "*" {
		t.Fatalf("kept provider_source %q, want the first in sort order (\"*\")", got)
	}
	// Different rule refs are not duplicates.
	f := model.InsecureRule{Protocol: "tcp", Port: "22", Source: "0.0.0.0/0", RuleRef: "a"}
	g := f
	g.RuleRef = "b"
	if got := normaliseRules([]model.InsecureRule{f, g, f}); len(got) != 2 {
		t.Fatalf("normaliseRules kept %d rules, want 2", len(got))
	}
}

// Regression (M1 review): Azure protocol "*" findings with different
// destination ports must not be merged.
func TestDeduplicationKeepsDistinctAzurePorts(t *testing.T) {
	nsgID := "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/example-rg/providers/Microsoft.Network/networkSecurityGroups/fake-nsg"
	azure := func(ref string, ports ...string) exposure.Rule {
		return exposure.Rule{
			Provider: model.ProviderAzure, Scope: "sub", ResourceID: nsgID, RuleRef: ref,
			Direction: exposure.DirectionInbound, Action: exposure.ActionAllow,
			Protocol: "*", PortRanges: ports,
			Sources: []exposure.Source{{Kind: exposure.SourceAzurePrefix, Raw: "*"}},
		}
	}
	findings, _ := evalAll(t,
		azure("allow-443", "443"),
		azure("allow-80", "80"),
		azure("allow-web", "443", "80-443", "443"), // one duplicate entry
	)
	r := Build([]model.ProviderResult{{
		Provider: model.ProviderAzure, Status: model.ProviderComplete,
		AzureNSGs: []model.AzureNSG{{ID: nsgID, Name: "fake-nsg", SubscriptionID: "sub", InsecureRules: findings}},
	}}, Options{})

	var got []string
	for _, f := range r.Azure.NSGs[0].InsecureRules {
		got = append(got, f.RuleRef+" "+f.Protocol+"/"+f.Port)
	}
	want := []string{
		"allow-80 all/80",
		"allow-web all/80-443",
		"allow-443 all/443",
		"allow-web all/443",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("findings:\n got  %q\n want %q", got, want)
	}
}

// Regression (M1 review): nested target lists are canonical in the output.
func TestTargetsAreCanonical(t *testing.T) {
	gcpResult := func(targets []string) []model.ProviderResult {
		return []model.ProviderResult{{
			Provider: model.ProviderGCP, Status: model.ProviderComplete,
			GCPFirewallRules: []model.GCPFirewallRule{{
				Name: "fake-rule", Network: "default", Project: "example-project-a", ID: "1",
				InsecureRules: []model.InsecureRule{
					{Protocol: "tcp", Port: "22", Source: "0.0.0.0/0", RuleRef: "fake-rule",
						Context: model.RuleContext{Targets: targets}},
				},
			}},
		}}
	}
	encode := func(targets []string) []byte {
		t.Helper()
		out, err := Encode(Build(gcpResult(targets), Options{}))
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	sorted := []string{"fake-sa@example-project-a.iam.gserviceaccount.com", "fake-tag-a", "fake-tag-b", "fake-tag-c"}
	want := encode(sorted)

	reversed := slices.Clone(sorted)
	slices.Reverse(reversed)
	if got := encode(reversed); !bytes.Equal(got, want) {
		t.Fatalf("reversed targets changed the output:\n%s", got)
	}

	withDupes := append(slices.Clone(reversed), "fake-tag-a", "fake-tag-c")
	if got := encode(withDupes); !bytes.Equal(got, want) {
		t.Fatalf("duplicate targets changed the output:\n%s", got)
	}

	rng := rand.New(rand.NewPCG(3, 4))
	for i := 0; i < 50; i++ {
		in := shuffle(rng, withDupes)
		before := slices.Clone(in)
		if got := encode(in); !bytes.Equal(got, want) {
			t.Fatalf("run %d: target order %q changed the output", i, in)
		}
		if !slices.Equal(in, before) {
			t.Fatalf("run %d: Build modified the caller's target slice", i)
		}
	}

	// nil means "not applicable" (null); an empty list stays an empty list.
	if out := encode(nil); !bytes.Contains(out, []byte(`"targets": null`)) {
		t.Fatalf("nil targets not encoded as null:\n%s", out)
	}
	if out := encode([]string{}); !bytes.Contains(out, []byte(`"targets": []`)) {
		t.Fatalf("empty targets not encoded as []:\n%s", out)
	}
}

// Findings that differ only in target order are the same finding, so they
// merge after canonicalisation.
func TestDeduplicationUsesCanonicalTargets(t *testing.T) {
	f := model.InsecureRule{Protocol: "tcp", Port: "22", Source: "0.0.0.0/0", RuleRef: "r",
		Context: model.RuleContext{Targets: []string{"b", "a"}}}
	g := f
	g.Context.Targets = []string{"a", "b", "a"}
	got := normaliseRules([]model.InsecureRule{f, g})
	if len(got) != 1 || !slices.Equal(got[0].Context.Targets, []string{"a", "b"}) {
		t.Fatalf("normaliseRules = %+v", got)
	}
	if !slices.Equal(f.Context.Targets, []string{"b", "a"}) {
		t.Fatal("input targets were modified")
	}
}

func TestBuildCountsAndOmissions(t *testing.T) {
	r := Build(fixtureResults(t), Options{})
	// AWS: tcp/8080 + icmp; GCP: icmp; Azure: one merged finding.
	if r.Scan.Findings != 4 {
		t.Fatalf("findings = %d, want 4", r.Scan.Findings)
	}
	if len(r.AWS.SecurityGroups) != 1 {
		t.Fatalf("security group without findings was not omitted")
	}
	if r.Scan.Providers != (model.ProviderStatuses{AWS: "complete", GCP: "partial", Azure: "complete"}) {
		t.Fatalf("providers = %+v", r.Scan.Providers)
	}
	if len(r.Diagnostics) != 1 || r.Diagnostics[0].Code != model.CodeSourceMalformed {
		t.Fatalf("diagnostics = %+v", r.Diagnostics)
	}
}

func TestEmptyReportUsesEmptyArrays(t *testing.T) {
	out, err := Encode(Build(nil, Options{ToolVersion: "test"}))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "null") {
		t.Fatalf("empty report contains null:\n%s", s)
	}
	for _, key := range []string{`"scopes": []`, `"security_groups": []`, `"firewall_rules": []`, `"nsgs": []`, `"diagnostics": []`, `"errors": []`} {
		if !strings.Contains(s, key) {
			t.Errorf("missing %s", key)
		}
	}
	for _, key := range []string{`"aws": "not_selected"`, `"gcp": "not_selected"`, `"azure": "not_selected"`} {
		if !strings.Contains(s, key) {
			t.Errorf("missing %s", key)
		}
	}
	if strings.Contains(s, "started_at") || !strings.HasSuffix(s, "}\n") {
		t.Fatalf("unexpected timestamp or missing trailing newline:\n%s", s)
	}
}

func TestTimestampsOnlyWhenRequested(t *testing.T) {
	start := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	r := Build(nil, Options{StartedAt: start, FinishedAt: start.Add(time.Minute)})
	if r.Scan.StartedAt != "2026-11-02T10:00:00Z" || r.Scan.FinishedAt != "2026-11-02T10:01:00Z" {
		t.Fatalf("timestamps = %q %q", r.Scan.StartedAt, r.Scan.FinishedAt)
	}
}

func TestEncodeIsValidJSONAndKeepsHTMLCharacters(t *testing.T) {
	out, err := Encode(Build(fixtureResults(t), Options{}))
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if !bytes.Contains(out, []byte(`"<fake> & description"`)) {
		t.Fatal("HTML characters were escaped")
	}
}

func TestExitCode(t *testing.T) {
	st := func(aws, gcp, azure model.ProviderStatus, findings int) model.Report {
		var r model.Report
		r.Scan.Providers = model.ProviderStatuses{AWS: aws, GCP: gcp, Azure: azure}
		r.Scan.Findings = findings
		return r
	}
	const (
		c  = model.ProviderComplete
		p  = model.ProviderPartial
		f  = model.ProviderFailed
		ns = model.ProviderNotSelected
	)
	tests := []struct {
		name string
		r    model.Report
		want int
	}{
		{"clean", st(c, c, c, 0), ExitClean},
		{"findings", st(c, c, c, 3), ExitFindings},
		{"not selected is fine", st(c, ns, ns, 0), ExitClean},
		{"partial without findings", st(c, p, c, 0), ExitIncomplete},
		{"incomplete outranks findings", st(c, p, c, 3), ExitIncomplete},
		{"failed provider", st(f, c, c, 1), ExitIncomplete},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExitCode(tt.r); got != tt.want {
				t.Fatalf("got %d, want %d", got, tt.want)
			}
		})
	}
	// The fixture has a failed GCP project.
	if got := ExitCode(Build(fixtureResults(t), Options{})); got != ExitIncomplete {
		t.Fatalf("fixture exit = %d, want %d", got, ExitIncomplete)
	}
}
