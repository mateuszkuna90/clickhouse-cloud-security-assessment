package gcp

import (
	"bytes"
	"context"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	compute "google.golang.org/api/compute/v1"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/report"
)

// completeScope is the expected scope of a fully evaluated project.
func completeScope(project string, resources, evaluated, disabled int) []model.ScopeResult {
	return []model.ScopeResult{{
		Provider: model.ProviderGCP, Scope: project, Status: model.ScopeComplete,
		ResourcesScanned: resources, RulesEvaluated: evaluated, DisabledRulesSkipped: disabled,
	}}
}

// assertClean checks a complete result with no diagnostics or errors.
func assertClean(t *testing.T, res model.ProviderResult) {
	t.Helper()
	assertEqual(t, "status", res.Status, model.ProviderComplete)
	assertEqual(t, "diagnostics", diagCodes(res.Diagnostics), []string(nil))
	assertEqual(t, "errors", errorKinds(res.Errors), []string(nil))
}

func TestScan_WorldOpenSSHAndHTTPS(t *testing.T) {
	ssh := ingress("allow-ssh", world(), tcp("22"))
	ssh.Description = "ssh from anywhere"
	ssh.TargetTags = []string{"bastion"}
	ssh.TargetServiceAccounts = []string{"vm@example-project-a.iam.gserviceaccount.com"}
	p := 900
	ssh.Priority = &p
	https := ingress("allow-https", world(), tcp("443"))

	res := scanOne(t, ssh, https)
	assertClean(t, res)
	assertEqual(t, "scopes", res.Scopes, completeScope(projA, 2, 2, 0))
	assertEqual(t, "findings", lines(res.GCPFirewallRules), []string{
		projA + " allow-https tcp 443 from=443 to=443 type=- code=- src=0.0.0.0/0 raw=tcp/443/0.0.0.0/0 reason=ipv4_world_cidr",
		projA + " allow-ssh tcp 22 from=22 to=22 type=- code=- src=0.0.0.0/0 raw=tcp/22/0.0.0.0/0 reason=ipv4_world_cidr",
	})

	var got model.GCPFirewallRule
	for _, r := range res.GCPFirewallRules {
		if r.Name == "allow-ssh" {
			got = r
		}
	}
	assertEqual(t, "rule metadata",
		[]string{got.Name, got.ID, got.Network, got.Project, got.Direction},
		[]string{"allow-ssh", ssh.ID, netURL, projA, "INGRESS"})
	f := got.InsecureRules[0]
	assertEqual(t, "rule ref", f.RuleRef, "allow-ssh")
	assertEqual(t, "description", f.Description, "ssh from anywhere")
	assertEqual(t, "priority", ptr(f.Context.Priority), "900")
	assertEqual(t, "targets", f.Context.Targets,
		[]string{"tag:bastion", "serviceAccount:vm@example-project-a.iam.gserviceaccount.com"})
	assertEqual(t, "attached", f.Context.Attached, (*bool)(nil))
	assertEqual(t, "reachability", f.Reachability, model.ReachabilityNotEvaluated)

	for _, r := range res.GCPFirewallRules {
		if r.Name == "allow-https" {
			assertEqual(t, "no targets -> all instances", r.InsecureRules[0].Context.Targets,
				[]string{"all_instances"})
		}
	}
}

func TestScan_ProtocolsAndPorts(t *testing.T) {
	tests := []struct {
		name    string
		allowed []entry
		want    []string
	}{
		{"udp single port", []entry{udp("53")},
			[]string{"udp 53 from=53 to=53 type=- code=- src=0.0.0.0/0 raw=udp/53/0.0.0.0/0 reason=ipv4_world_cidr"}},
		{"icmp has no ports or type/code", []entry{allow("icmp")},
			[]string{"icmp all from=- to=- type=- code=- src=0.0.0.0/0 raw=icmp//0.0.0.0/0 reason=ipv4_world_cidr"}},
		{"all protocols", []entry{allow("all")},
			[]string{"all all from=- to=- type=- code=- src=0.0.0.0/0 raw=all//0.0.0.0/0 reason=ipv4_world_cidr"}},
		{"tcp without ports is every port", []entry{tcp()},
			[]string{"tcp all from=0 to=65535 type=- code=- src=0.0.0.0/0 raw=tcp//0.0.0.0/0 reason=ipv4_world_cidr"}},
		{"port range", []entry{tcp("8000-8090")},
			[]string{"tcp 8000-8090 from=8000 to=8090 type=- code=- src=0.0.0.0/0 raw=tcp/8000-8090/0.0.0.0/0 reason=ipv4_world_cidr"}},
		{"numeric tcp, udp, icmp, gre", []entry{allow("6", "22"), allow("17", "500"), allow("1"), allow("47")},
			[]string{
				"47 all from=- to=- type=- code=- src=0.0.0.0/0 raw=47//0.0.0.0/0 reason=ipv4_world_cidr",
				"icmp all from=- to=- type=- code=- src=0.0.0.0/0 raw=1//0.0.0.0/0 reason=ipv4_world_cidr",
				"tcp 22 from=22 to=22 type=- code=- src=0.0.0.0/0 raw=6/22/0.0.0.0/0 reason=ipv4_world_cidr",
				"udp 500 from=500 to=500 type=- code=- src=0.0.0.0/0 raw=17/500/0.0.0.0/0 reason=ipv4_world_cidr",
			}},
		{"named non-port protocols", []entry{allow("esp"), allow("ah"), allow("sctp", "9000"), allow("ipip")},
			[]string{
				"ah all from=- to=- type=- code=- src=0.0.0.0/0 raw=ah//0.0.0.0/0 reason=ipv4_world_cidr",
				"esp all from=- to=- type=- code=- src=0.0.0.0/0 raw=esp//0.0.0.0/0 reason=ipv4_world_cidr",
				"ipip all from=- to=- type=- code=- src=0.0.0.0/0 raw=ipip//0.0.0.0/0 reason=ipv4_world_cidr",
				"sctp 9000 from=9000 to=9000 type=- code=- src=0.0.0.0/0 raw=sctp/9000/0.0.0.0/0 reason=ipv4_world_cidr",
			}},
		{"multiple ports in one entry", []entry{tcp("22", "80", "8000-8090")},
			[]string{
				"tcp 22 from=22 to=22 type=- code=- src=0.0.0.0/0 raw=tcp/22/0.0.0.0/0 reason=ipv4_world_cidr",
				"tcp 80 from=80 to=80 type=- code=- src=0.0.0.0/0 raw=tcp/80/0.0.0.0/0 reason=ipv4_world_cidr",
				"tcp 8000-8090 from=8000 to=8090 type=- code=- src=0.0.0.0/0 raw=tcp/8000-8090/0.0.0.0/0 reason=ipv4_world_cidr",
			}},
		{"multiple allowed entries", []entry{tcp("443"), udp("443"), allow("icmp")},
			[]string{
				"icmp all from=- to=- type=- code=- src=0.0.0.0/0 raw=icmp//0.0.0.0/0 reason=ipv4_world_cidr",
				"tcp 443 from=443 to=443 type=- code=- src=0.0.0.0/0 raw=tcp/443/0.0.0.0/0 reason=ipv4_world_cidr",
				"udp 443 from=443 to=443 type=- code=- src=0.0.0.0/0 raw=udp/443/0.0.0.0/0 reason=ipv4_world_cidr",
			}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := scanOne(t, ingress("r", world(), tc.allowed...))
			assertClean(t, res)
			var want []string
			for _, w := range tc.want {
				want = append(want, projA+" r "+w)
			}
			assertEqual(t, "findings", lines(res.GCPFirewallRules), want)
		})
	}
}

func TestScan_SourceSemantics(t *testing.T) {
	sa := "app@example-project-a.iam.gserviceaccount.com"
	tests := []struct {
		name string
		edit func(*fw)
		want []string // finding source/raw/reason triples; nil = no finding
	}{
		{"explicit 0.0.0.0/0", func(f *fw) {},
			[]string{"0.0.0.0/0 0.0.0.0/0 ipv4_world_cidr"}},
		{"noncanonical IPv4 /0", func(f *fw) { f.SourceRanges = []string{"10.0.0.0/0"} },
			[]string{"0.0.0.0/0 10.0.0.0/0 ipv4_world_cidr"}},
		{"restricted CIDR", func(f *fw) { f.SourceRanges = []string{"203.0.113.0/24"} }, nil},
		{"single host", func(f *fw) { f.SourceRanges = []string{"0.0.0.0"} }, nil},
		{"IPv6 ::/0 is out of scope", func(f *fw) { f.SourceRanges = []string{"::/0"} }, nil},
		{"multiple CIDRs, one world", func(f *fw) {
			f.SourceRanges = []string{"203.0.113.0/24", "0.0.0.0/0", "198.51.100.7/32"}
		}, []string{"0.0.0.0/0 0.0.0.0/0 ipv4_world_cidr"}},
		{"multiple CIDRs, none world", func(f *fw) {
			f.SourceRanges = []string{"203.0.113.0/24", "198.51.100.0/24", "2001:db8::/32"}
		}, nil},
		{"two world forms", func(f *fw) { f.SourceRanges = []string{"0.0.0.0/0", "10.0.0.0/0"} },
			[]string{"0.0.0.0/0 0.0.0.0/0 ipv4_world_cidr", "0.0.0.0/0 10.0.0.0/0 ipv4_world_cidr"}},
		{"sourceTags only", func(f *fw) { f.SourceRanges, f.SourceTags = nil, []string{"web"} }, nil},
		{"sourceServiceAccounts only", func(f *fw) {
			f.SourceRanges, f.SourceServiceAccounts = nil, []string{sa}
		}, nil},
		{"world range OR source tag", func(f *fw) { f.SourceTags = []string{"web"} },
			[]string{"0.0.0.0/0 0.0.0.0/0 ipv4_world_cidr"}},
		{"world range OR source service account", func(f *fw) { f.SourceServiceAccounts = []string{sa} },
			[]string{"0.0.0.0/0 0.0.0.0/0 ipv4_world_cidr"}},
		{"restricted range OR source tag", func(f *fw) {
			f.SourceRanges, f.SourceTags = []string{"10.0.0.0/8"}, []string{"web"}
		}, nil},
		{"no source selector: GCP default", func(f *fw) { f.SourceRanges = nil },
			[]string{"0.0.0.0/0  gcp_default_source"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := ingress("r", world(), tcp("22"))
			tc.edit(&f)
			res := scanOne(t, f)
			assertClean(t, res)
			var got []string
			for _, r := range res.GCPFirewallRules {
				for _, x := range r.InsecureRules {
					got = append(got, x.Source+" "+x.ProviderSource+" "+x.MatchReason)
				}
			}
			slices.Sort(got)
			assertEqual(t, "sources", got, tc.want)
		})
	}
}

func TestScan_RuleSelection(t *testing.T) {
	disabled := ingress("disabled-world", world(), tcp("22"))
	tr := true
	disabled.Disabled = &tr
	egress := ingress("egress-world", nil, tcp("443"))
	egress.Direction = "EGRESS"
	egress.SourceRanges = nil
	egressWithRanges := ingress("egress-odd", world(), allow("all"))
	egressWithRanges.Direction = "EGRESS"
	deny := ingress("deny-world", world())
	deny.Denied = []entry{allow("all")}
	noDirection := ingress("no-direction", world(), tcp("80"))
	noDirection.Direction = ""

	t.Run("disabled rule is skipped and counted", func(t *testing.T) {
		res := scanOne(t, disabled)
		assertClean(t, res)
		assertEqual(t, "findings", len(res.GCPFirewallRules), 0)
		assertEqual(t, "scopes", res.Scopes, completeScope(projA, 1, 0, 1))
	})
	t.Run("EGRESS is ignored without a diagnostic", func(t *testing.T) {
		res := scanOne(t, egress, egressWithRanges)
		assertClean(t, res)
		assertEqual(t, "findings", len(res.GCPFirewallRules), 0)
		assertEqual(t, "scopes", res.Scopes, completeScope(projA, 2, 2, 0))
		js := encode(t, res)
		if !bytes.Contains(js, []byte(`"findings": 0`)) || report.ExitCode(build(res)) != report.ExitClean {
			t.Errorf("egress-only project should be clean (exit 0):\n%s", js)
		}
	})
	t.Run("EGRESS mixed with one INGRESS finding is exit 1, not 2", func(t *testing.T) {
		res := scanOne(t, egress, egressWithRanges, ingress("ssh", world(), tcp("22")))
		assertClean(t, res)
		assertEqual(t, "exit", report.ExitCode(build(res)), report.ExitFindings)
		assertEqual(t, "findings", len(lines(res.GCPFirewallRules)), 1)
	})
	t.Run("DENY-only rule has no finding", func(t *testing.T) {
		res := scanOne(t, deny)
		assertClean(t, res)
		assertEqual(t, "findings", len(res.GCPFirewallRules), 0)
		assertEqual(t, "scopes", res.Scopes, completeScope(projA, 1, 1, 0))
	})
	t.Run("empty direction is INGRESS", func(t *testing.T) {
		res := scanOne(t, noDirection)
		assertClean(t, res)
		assertEqual(t, "findings", lines(res.GCPFirewallRules), []string{
			projA + " no-direction tcp 80 from=80 to=80 type=- code=- src=0.0.0.0/0 raw=tcp/80/0.0.0.0/0 reason=ipv4_world_cidr",
		})
		assertEqual(t, "raw direction kept", res.GCPFirewallRules[0].Direction, "")
	})
}

func TestScan_UndecidableRulesMakeScopeIncomplete(t *testing.T) {
	sideways := ingress("sideways", world(), tcp("22"), udp("53"))
	sideways.Direction = "SIDEWAYS"
	lower := ingress("lowercase", world(), tcp("22"))
	lower.Direction = "ingress"
	noAction := ingress("no-action", world())
	badSource := ingress("bad-source", []string{"not-a-cidr"}, tcp("22"), tcp("443"))

	tests := []struct {
		name string
		rule fw
		want []string
	}{
		{"unknown direction, reported once per rule", sideways,
			[]string{"sideways direction_unrecognised/direction/SIDEWAYS/scope_incomplete"}},
		{"direction is case-sensitive", lower,
			[]string{"lowercase direction_unrecognised/direction/ingress/scope_incomplete"}},
		{"neither allowed nor denied", noAction,
			[]string{"no-action action_missing/action//scope_incomplete"}},
		{"only a malformed source, reported once", badSource,
			[]string{"bad-source source_malformed/sourceRanges/not-a-cidr/scope_incomplete"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := scanOne(t, tc.rule)
			assertEqual(t, "findings", len(res.GCPFirewallRules), 0)
			assertEqual(t, "diagnostics", diagCodes(res.Diagnostics), tc.want)
			assertEqual(t, "scope", res.Scopes[0].Status, model.ScopeIncomplete)
			assertEqual(t, "provider", res.Status, model.ProviderPartial)
			assertEqual(t, "exit", report.ExitCode(build(res)), report.ExitIncomplete)
			assertEqual(t, "resource id", res.Diagnostics[0].ResourceID,
				"projects/"+projA+"/global/firewalls/"+tc.rule.Name)
		})
	}
}

func TestScan_FindingDetailDiagnosticsKeepScopeComplete(t *testing.T) {
	mixed := ingress("mixed", []string{"not-a-cidr", worldStr}, tcp("22"), tcp("443"))
	noProto := ingress("no-proto", world(), allow(""))
	badPort := ingress("bad-port", world(), tcp("99999"))
	noName := ingress("", world(), tcp("22"))

	res := scanOne(t, mixed, noProto, badPort, noName)
	assertEqual(t, "status", res.Status, model.ProviderComplete)
	assertEqual(t, "scope", res.Scopes[0].Status, model.ScopeComplete)
	assertEqual(t, "diagnostics", diagCodes(res.Diagnostics), []string{
		" resource_id_missing/name/" + noName.ID + "/finding_detail_unknown",
		"bad-port port_malformed/port/99999/finding_detail_unknown",
		"mixed source_malformed/sourceRanges/not-a-cidr/finding_detail_unknown",
		"no-proto protocol_unknown/protocol//finding_detail_unknown",
	})
	assertEqual(t, "findings", lines(res.GCPFirewallRules), []string{
		projA + "  tcp 22 from=22 to=22 type=- code=- src=0.0.0.0/0 raw=tcp/22/0.0.0.0/0 reason=ipv4_world_cidr",
		projA + " bad-port tcp unknown from=- to=- type=- code=- src=0.0.0.0/0 raw=tcp/99999/0.0.0.0/0 reason=ipv4_world_cidr",
		projA + " mixed tcp 22 from=22 to=22 type=- code=- src=0.0.0.0/0 raw=tcp/22/0.0.0.0/0 reason=ipv4_world_cidr",
		projA + " mixed tcp 443 from=443 to=443 type=- code=- src=0.0.0.0/0 raw=tcp/443/0.0.0.0/0 reason=ipv4_world_cidr",
		projA + " no-proto unknown unknown from=- to=- type=- code=- src=0.0.0.0/0 raw=//0.0.0.0/0 reason=ipv4_world_cidr",
	})
}

func TestScan_EmptyProjects(t *testing.T) {
	res, _ := scanServer(t, map[string][]page{
		projA: {{}}, // "items": []
		projB: {{body: `{"kind":"compute#firewallList","id":"projects/example-project-b/global/firewalls"}`}},
	}, Config{})
	assertClean(t, res)
	assertEqual(t, "scopes", res.Scopes, append(completeScope(projA, 0, 0, 0), completeScope(projB, 0, 0, 0)...))
	assertEqual(t, "rules", res.GCPFirewallRules, []model.GCPFirewallRule{})
}

func TestScan_MultipleProjects(t *testing.T) {
	res, f := scanServer(t, map[string][]page{
		projA: onePage(t, ingress("a-ssh", world(), tcp("22"))),
		projB: {errorPage(403, "forbidden", "Required 'compute.firewalls.list' permission for 'projects/example-project-b'")},
		projC: onePage(t, ingress("c-rdp", world(), tcp("3389")), ingress("c-internal", []string{"10.0.0.0/8"}, tcp())),
	}, Config{Projects: []string{projC, projA, " " + projB + " ", projA}})

	assertEqual(t, "status", res.Status, model.ProviderPartial)
	assertEqual(t, "scopes", res.Scopes, []model.ScopeResult{
		completeScope(projA, 1, 1, 0)[0],
		{Provider: model.ProviderGCP, Scope: projB, Status: model.ScopeFailed},
		completeScope(projC, 2, 2, 0)[0],
	})
	assertEqual(t, "errors", errorKinds(res.Errors), []string{projB + " compute.firewalls.list permission_denied"})
	assertEqual(t, "findings", lines(res.GCPFirewallRules), []string{
		projA + " a-ssh tcp 22 from=22 to=22 type=- code=- src=0.0.0.0/0 raw=tcp/22/0.0.0.0/0 reason=ipv4_world_cidr",
		projC + " c-rdp tcp 3389 from=3389 to=3389 type=- code=- src=0.0.0.0/0 raw=tcp/3389/0.0.0.0/0 reason=ipv4_world_cidr",
	})
	reqs := f.requestLog()
	slices.Sort(reqs)
	assertEqual(t, "one request per distinct project", reqs, []string{projA + " ", projB + " ", projC + " "})
}

func TestScan_Pagination(t *testing.T) {
	t.Run("three pages are all read", func(t *testing.T) {
		p1 := onePage(t, ingress("r1", world(), tcp("22")))[0]
		p2 := onePage(t, ingress("r2", world(), tcp("80")), ingress("r3", []string{"10.0.0.0/8"}, tcp("80")))[0]
		p3 := onePage(t, ingress("r4", world(), tcp("443")))[0]
		res, f := scanServer(t, map[string][]page{projA: {p1, p2, p3}}, Config{})
		assertClean(t, res)
		assertEqual(t, "requests", f.requestLog(), []string{projA + " ", projA + " p1", projA + " p2"})
		assertEqual(t, "scopes", res.Scopes, completeScope(projA, 4, 4, 0))
		assertEqual(t, "finding count", len(lines(res.GCPFirewallRules)), 3)
	})
	t.Run("empty page with a token is followed", func(t *testing.T) {
		res, f := scanServer(t, map[string][]page{projA: {
			{}, onePage(t, ingress("late", world(), tcp("22")))[0],
		}}, Config{})
		assertClean(t, res)
		assertEqual(t, "requests", len(f.requestLog()), 2)
		assertEqual(t, "finding count", len(lines(res.GCPFirewallRules)), 1)
	})
	t.Run("failure on page 2 discards page 1", func(t *testing.T) {
		res, _ := scanServer(t, map[string][]page{projA: {
			onePage(t, ingress("r1", world(), tcp("22")))[0],
			errorPage(500, "backendError", "Internal error"),
		}}, Config{})
		assertEqual(t, "status", res.Status, model.ProviderFailed)
		assertEqual(t, "scopes", res.Scopes, []model.ScopeResult{
			{Provider: model.ProviderGCP, Scope: projA, Status: model.ScopeFailed}})
		assertEqual(t, "rules", res.GCPFirewallRules, []model.GCPFirewallRule{})
		assertEqual(t, "errors", errorKinds(res.Errors), []string{projA + " compute.firewalls.list other"})
		assertEqual(t, "message", res.Errors[0].Message,
			"compute.firewalls.list failed: unexpected error (page 2) [HTTP 500] [reason: backendError]")
	})
	t.Run("repeated nextPageToken fails the scope", func(t *testing.T) {
		loop := "p1"
		res, _ := scanServer(t, map[string][]page{projA: {
			onePage(t, ingress("r1", world(), tcp("22")))[0],
			{items: []string{ingress("r2", world(), tcp("80")).json(t)}, next: &loop},
		}}, Config{ScopeTimeout: 10 * time.Second})
		assertEqual(t, "scope", res.Scopes[0].Status, model.ScopeFailed)
		assertEqual(t, "rules", res.GCPFirewallRules, []model.GCPFirewallRule{})
		if !strings.Contains(res.Errors[0].Message, string(errRepeatedToken)) {
			t.Errorf("message = %q", res.Errors[0].Message)
		}
	})
}

func TestScan_APIErrors(t *testing.T) {
	tests := []struct {
		name string
		page page
		kind string
		msg  string
	}{
		{"permission denied", errorPage(403, "forbidden", "Required 'compute.firewalls.list' permission"),
			model.ErrorKindPermissionDenied,
			"compute.firewalls.list failed: permission denied, or the Compute Engine API is not enabled for the project (page 1) [HTTP 403] [reason: forbidden]"},
		{"API not enabled", errorPage(403, "accessNotConfigured", "Compute Engine API has not been used in project"),
			model.ErrorKindPermissionDenied,
			"compute.firewalls.list failed: permission denied, or the Compute Engine API is not enabled for the project (page 1) [HTTP 403] [reason: accessNotConfigured]"},
		{"403 rate limit", errorPage(403, "rateLimitExceeded", "Rate Limit Exceeded"),
			model.ErrorKindThrottled,
			"compute.firewalls.list failed: request rate-limited or quota exceeded (page 1) [HTTP 403] [reason: rateLimitExceeded]"},
		{"429", errorPage(429, "rateLimitExceeded", "Quota exceeded"), model.ErrorKindThrottled,
			"compute.firewalls.list failed: request rate-limited or quota exceeded (page 1) [HTTP 429] [reason: rateLimitExceeded]"},
		{"401 invalid credentials", errorPage(401, "authError", "Invalid Credentials"), model.ErrorKindAuth,
			"compute.firewalls.list failed: Google credentials could not be resolved or were rejected (page 1) [HTTP 401] [reason: authError]"},
		{"unknown reason is dropped", errorPage(403, "someNewReason", "x"), model.ErrorKindPermissionDenied,
			"compute.firewalls.list failed: permission denied, or the Compute Engine API is not enabled for the project (page 1) [HTTP 403]"},
		{"non-JSON error body", page{status: 502, body: "<html>bad gateway</html>"}, model.ErrorKindOther,
			"compute.firewalls.list failed: unexpected error (page 1) [HTTP 502]"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, _ := scanServer(t, map[string][]page{projA: {tc.page}}, Config{})
			assertEqual(t, "status", res.Status, model.ProviderFailed)
			assertEqual(t, "errors", errorKinds(res.Errors), []string{projA + " compute.firewalls.list " + tc.kind})
			assertEqual(t, "message", res.Errors[0].Message, tc.msg)
		})
	}
	t.Run("project not found", func(t *testing.T) {
		res, _ := scanServer(t, map[string][]page{projA: onePage(t)}, Config{Projects: []string{projA, "example-missing"}})
		assertEqual(t, "status", res.Status, model.ProviderPartial)
		assertEqual(t, "errors", errorKinds(res.Errors), []string{"example-missing compute.firewalls.list not_found"})
	})
}

func TestScan_MalformedAPIResponses(t *testing.T) {
	bodies := map[string]string{
		"not JSON":             `this is not json`,
		"truncated JSON":       `{"items":[{"name":"r1"`,
		"items is not a list":  `{"items":"oops"}`,
		"id is not a number":   `{"items":[{"name":"r1","id":"not-a-number"}]}`,
		"allowed wrong type":   `{"items":[{"name":"r1","allowed":"tcp"}]}`,
		"sourceRanges number":  `{"items":[{"name":"r1","sourceRanges":[5]}]}`,
		"disabled is a string": `{"items":[{"name":"r1","disabled":"yes"}]}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			res, _ := scanServer(t, map[string][]page{projA: {{body: body}}}, Config{})
			assertEqual(t, "scope", res.Scopes[0].Status, model.ScopeFailed)
			assertEqual(t, "errors", errorKinds(res.Errors), []string{projA + " compute.firewalls.list other"})
			assertEqual(t, "message", res.Errors[0].Message, "compute.firewalls.list failed: unexpected error (page 1)")
		})
	}
	t.Run("unknown fields are ignored", func(t *testing.T) {
		body := `{"kind":"compute#firewallList","futureField":{"x":1},"items":[{"name":"r1","id":"7",` +
			`"direction":"INGRESS","sourceRanges":["0.0.0.0/0"],"allowed":[{"IPProtocol":"tcp","ports":["22"],"newField":true}],` +
			`"params":{"resourceManagerTags":{}},"someNewField":"v"}]}`
		res, _ := scanServer(t, map[string][]page{projA: {{body: body}}}, Config{})
		assertClean(t, res)
		assertEqual(t, "findings", len(lines(res.GCPFirewallRules)), 1)
	})
}

func TestScan_NilEntries(t *testing.T) {
	// The REST decoder never yields nil entries; the lister contract still
	// allows them, so they are reported rather than skipped.
	lister := &fakeLister{result: map[string][]*compute.Firewall{projA: {
		nil,
		{Name: "nil-allowed", Direction: "INGRESS",
			SourceRanges: []string{worldStr},
			Allowed:      []*compute.FirewallAllowed{nil, {IPProtocol: "tcp", Ports: []string{"22"}}}},
	}}}
	res := NewScanner(Config{Projects: []string{projA}}, lister).Scan(context.Background())
	assertEqual(t, "diagnostics", diagCodes(res.Diagnostics), []string{
		" rule_nil/items//scope_incomplete",
		"nil-allowed rule_nil/allowed//scope_incomplete",
	})
	assertEqual(t, "scope", res.Scopes[0].Status, model.ScopeIncomplete)
	assertEqual(t, "findings still reported", len(lines(res.GCPFirewallRules)), 1)
	assertEqual(t, "resources", res.Scopes[0].ResourcesScanned, 2)
}

func TestScan_InvalidProjectsFailWithoutARequest(t *testing.T) {
	bad := []string{"", "p/../x", "example-project-a?x=1", "Example-Project", "ab", "-bad-project", "example-project-", "../.."}
	res, f := scanServer(t, map[string][]page{projA: onePage(t)}, Config{Projects: append([]string{projA}, bad...)})
	assertEqual(t, "requests", f.requestLog(), []string{projA + " "})
	assertEqual(t, "status", res.Status, model.ProviderPartial)
	failed := 0
	for _, s := range res.Scopes {
		if s.Status == model.ScopeFailed {
			failed++
		}
	}
	assertEqual(t, "failed scopes", failed, len(bad))
	for _, e := range res.Errors {
		assertEqual(t, "op", e.Operation, OpConfig)
		assertEqual(t, "message", e.Message, "config failed: unexpected error; invalid project ID")
	}
}

func TestScan_SetupFailures(t *testing.T) {
	t.Run("no projects", func(t *testing.T) {
		res := NewScanner(Config{}, &fakeLister{}).Scan(context.Background())
		assertEqual(t, "status", res.Status, model.ProviderFailed)
		assertEqual(t, "errors", errorKinds(res.Errors), []string{" config other"})
		assertEqual(t, "scopes", res.Scopes, []model.ScopeResult{})
	})
	t.Run("no client", func(t *testing.T) {
		res := NewScanner(Config{Projects: []string{projA}}, nil).Scan(context.Background())
		assertEqual(t, "status", res.Status, model.ProviderFailed)
		assertEqual(t, "message", res.Errors[0].Message, "config failed: unexpected error; no Compute API client")
	})
}

func TestScan_ScopeTimeout(t *testing.T) {
	f, srv := newFakeCompute(t, map[string][]page{projA: onePage(t)})
	f.block = true
	start := time.Now()
	res := NewScanner(Config{Projects: []string{projA}, ScopeTimeout: 200 * time.Millisecond},
		realClient(t, srv, staticToken{})).Scan(context.Background())
	// The request carries the scope context, so the deadline aborts it and
	// the server sees the client go away.
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("scan took %v; the scope timeout did not stop the hung request", d)
	}
	f.waitIdle(t, 1)
	assertEqual(t, "errors", errorKinds(res.Errors), []string{projA + " compute.firewalls.list timeout"})
	assertEqual(t, "message", res.Errors[0].Message, "compute.firewalls.list failed: timed out or cancelled (page 1)")
	assertEqual(t, "status", res.Status, model.ProviderFailed)
}

func TestScan_ContextCancelled(t *testing.T) {
	t.Run("mid-scan", func(t *testing.T) {
		f, srv := newFakeCompute(t, map[string][]page{projA: onePage(t), projB: onePage(t)})
		f.block = true
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			for len(f.requestLog()) < 2 {
				time.Sleep(5 * time.Millisecond)
			}
			cancel()
		}()
		res := NewScanner(Config{Projects: []string{projA, projB}}, realClient(t, srv, staticToken{})).Scan(ctx)
		f.waitIdle(t, 2)
		assertEqual(t, "requests", len(f.requestLog()), 2)
		assertEqual(t, "errors", errorKinds(res.Errors), []string{
			projA + " compute.firewalls.list timeout", projB + " compute.firewalls.list timeout"})
		assertEqual(t, "status", res.Status, model.ProviderFailed)
	})
	t.Run("before start: no request", func(t *testing.T) {
		f, srv := newFakeCompute(t, map[string][]page{projA: onePage(t)})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		res := NewScanner(Config{Projects: []string{projA}}, realClient(t, srv, staticToken{})).Scan(ctx)
		assertEqual(t, "requests", len(f.requestLog()), 0)
		assertEqual(t, "errors", errorKinds(res.Errors), []string{projA + " compute.firewalls.list timeout"})
		assertEqual(t, "message", res.Errors[0].Message,
			"compute.firewalls.list failed: timed out or cancelled; project not scanned before the run ended")
	})
}

func TestScan_SendsReadOnlyAuthenticatedGET(t *testing.T) {
	_, f := scanServer(t, map[string][]page{projA: onePage(t)}, Config{})
	f.mu.Lock()
	defer f.mu.Unlock()
	assertEqual(t, "authorization", f.auth, []string{"Bearer " + fakeToken})
}

// TestScan_DeterministicOutput feeds the same inventory in shuffled page,
// rule, entry and project order with concurrency, and requires
// byte-identical reports.
func TestScan_DeterministicOutput(t *testing.T) {
	mk := func() []fw {
		a := ingress("ssh", world(), tcp("22"))
		a.ID = "11"
		b := ingress("web", []string{"10.0.0.0/0", "0.0.0.0/0", "203.0.113.0/24"}, tcp("443", "80"), udp("443"), allow("icmp"))
		b.ID, b.TargetTags = "12", []string{"web", "frontend", "web"}
		c := ingress("default-src", nil, allow("all"))
		c.ID = "13"
		d := ingress("bad", []string{"not-a-cidr"}, tcp("22"))
		d.ID = "14"
		e := ingress("egress", nil, allow("all"))
		e.ID, e.Direction = "15", "EGRESS"
		return []fw{a, b, c, d, e}
	}
	build := func(seed uint64) []byte {
		rng := rand.New(rand.NewPCG(seed, seed))
		projects := map[string][]page{}
		for _, p := range []string{projA, projB, projC} {
			fws := mk()
			rng.Shuffle(len(fws), func(i, j int) { fws[i], fws[j] = fws[j], fws[i] })
			var pages []page
			for _, f := range fws {
				rng.Shuffle(len(f.Allowed), func(i, j int) { f.Allowed[i], f.Allowed[j] = f.Allowed[j], f.Allowed[i] })
				pages = append(pages, page{items: []string{f.json(t)}})
			}
			projects[p] = pages
		}
		order := []string{projA, projB, projC}
		rng.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
		res, _ := scanServer(t, projects, Config{Projects: order, Concurrency: 8})
		return encode(t, res)
	}
	want := build(1)
	for seed := uint64(2); seed < 15; seed++ {
		if got := build(seed); !bytes.Equal(got, want) {
			t.Fatalf("seed %d: output differs\n--- got\n%s\n--- want\n%s", seed, got, want)
		}
	}
	// Per project: ssh 1 + web (tcp/443, tcp/80, udp/443, icmp; the two
	// world forms merge) 4 + default-src 1 = 6.
	for _, s := range []string{`"findings": 18`, `"status": "incomplete"`, `"gcp": "partial"`,
		`"targets": [` + "\n" + `                "tag:frontend",` + "\n" + `                "tag:web"` + "\n"} {
		if !bytes.Contains(want, []byte(s)) {
			t.Errorf("report missing %q:\n%s", s, want)
		}
	}
}

// TestReadOnlyInterface guards the code-level read-only guarantee.
func TestReadOnlyInterface(t *testing.T) {
	for m := range reflect.TypeFor[FirewallLister]().Methods() {
		if !strings.HasPrefix(m.Name, "List") {
			t.Errorf("FirewallLister.%s is not a read-only operation", m.Name)
		}
	}
}

func build(res model.ProviderResult) model.Report {
	return report.Build([]model.ProviderResult{res}, report.Options{ToolVersion: "test"})
}

func encode(t *testing.T, res model.ProviderResult) []byte {
	t.Helper()
	out, err := report.Encode(build(res))
	if err != nil {
		t.Fatal(err)
	}
	return out
}
