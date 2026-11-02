package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/provider/aws"
	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/provider/azure"
	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/provider/gcp"
	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/report"
)

var update = flag.Bool("update", false, "rewrite golden files")

const allProviders = "aws,gcp,azure"

// allArgs selects every provider with explicit scopes.
func allArgs(extra ...string) []string {
	return append([]string{
		"--providers", allProviders,
		"--aws-regions", regionEU,
		"--gcp-projects", projA,
		"--azure-subscriptions", subA,
	}, extra...)
}

// ---- 1. complete scan, no findings: exit 0 --------------------------------

func TestE2E_CleanScanExit0(t *testing.T) {
	r := run(t, cleanCloud(), allArgs()...)
	assertEqual(t, "exit", r.code, report.ExitClean)
	rep := decode(t, r.stdout)
	assertEqual(t, "findings", rep.Scan.Findings, 0)
	assertEqual(t, "aws", rep.Scan.Providers.AWS, model.ProviderComplete)
	assertEqual(t, "gcp", rep.Scan.Providers.GCP, model.ProviderComplete)
	assertEqual(t, "azure", rep.Scan.Providers.Azure, model.ProviderComplete)
	assertEqual(t, "scopes", len(rep.Scan.Scopes), 3)
	if !strings.Contains(r.stderr, "exit=0") || strings.Contains(r.stdout, "cloudfw-scan:") {
		t.Errorf("summary must go to stderr only:\nstdout=%s\nstderr=%s", r.stdout, r.stderr)
	}
	// Empty sections are [] (not null), and there is no timestamp.
	for _, want := range []string{`"security_groups": []`, `"firewall_rules": []`, `"nsgs": []`, `"errors": []`} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("missing %s", want)
		}
	}
	if strings.Contains(r.stdout, "started_at") {
		t.Errorf("timestamps must be opt-in")
	}
}

// ---- 2-4. one insecure rule per provider: exit 1 ---------------------------

func TestE2E_OneFindingPerProvider(t *testing.T) {
	t.Run("aws", func(t *testing.T) {
		c := cleanCloud()
		c.ec2[regionEU].groups = append(c.ec2[regionEU].groups,
			sg("sg-0fake0000000000002", "open-ssh", perm("tcp", 22, 22, "0.0.0.0/0")))
		r := run(t, c, "--providers", "aws", "--aws-regions", regionEU)
		assertEqual(t, "exit", r.code, report.ExitFindings)
		rep := decode(t, r.stdout)
		assertEqual(t, "findings", rep.Scan.Findings, 1)
		g := rep.AWS.SecurityGroups[0]
		f := g.InsecureRules[0]
		assertEqual(t, "group", g.ID+" "+g.Region+" "+g.AccountID, "sg-0fake0000000000002 "+regionEU+" "+account)
		assertEqual(t, "finding", f.Protocol+" "+f.Port+" "+f.Source+" "+f.RuleRef, "tcp 22 0.0.0.0/0 tcp:22:22:0.0.0.0/0")
		assertEqual(t, "gcp not selected", rep.Scan.Providers.GCP, model.ProviderNotSelected)
		assertEqual(t, "azure not selected", rep.Scan.Providers.Azure, model.ProviderNotSelected)
		assertEqual(t, "only aws built", fmt.Sprint(c.builtProviders()), "[aws]")
	})
	t.Run("gcp", func(t *testing.T) {
		c := cleanCloud()
		c.firewalls.byProject[projA] = append(c.firewalls.byProject[projA],
			firewall("allow-rdp-world", []string{"0.0.0.0/0"}, allowed("tcp", "3389")))
		r := run(t, c, "--providers", "gcp", "--gcp-projects", projA)
		assertEqual(t, "exit", r.code, report.ExitFindings)
		rep := decode(t, r.stdout)
		fw := rep.GCP.FirewallRules[0]
		f := fw.InsecureRules[0]
		assertEqual(t, "rule", fw.Project+" "+fw.Name, projA+" allow-rdp-world")
		assertEqual(t, "finding", f.Protocol+" "+f.Port+" "+f.Source, "tcp 3389 0.0.0.0/0")
		assertEqual(t, "only gcp built", fmt.Sprint(c.builtProviders()), "[gcp]")
	})
	t.Run("azure", func(t *testing.T) {
		c := cleanCloud()
		c.nsgs.bySub[subA] = append(c.nsgs.bySub[subA],
			nsg(subA, "web", nsgRule("https", "Inbound", "Allow", "Tcp", "*", 100, "443")))
		r := run(t, c, "--providers", "azure", "--azure-subscriptions", subA)
		assertEqual(t, "exit", r.code, report.ExitFindings)
		rep := decode(t, r.stdout)
		n := rep.Azure.NSGs[0]
		f := n.InsecureRules[0]
		assertEqual(t, "nsg", n.Name+" "+n.SubscriptionID, "web "+subA)
		assertEqual(t, "finding", f.Protocol+" "+f.Port+" "+f.Source+" "+f.RuleRef,
			"tcp 443 0.0.0.0/0 securityRules/https")
		assertEqual(t, "explicit subscription has null state", rep.Scan.Scopes[0].SubscriptionState == nil, true)
	})
}

// ---- 5-6. combined findings, ports and ranges: golden file ----------------

// combinedCloud has findings in all three providers, with single ports,
// ranges, multiple ports, ICMP, protocol "all", the Azure Internet tag, and
// rules that must not be reported (egress, deny, outbound, private).
func combinedCloud() *cloud {
	c := cleanCloud()
	icmp := perm("icmp", 8, -1, "0.0.0.0/0")
	c.ec2[regionEU].groups = append(c.ec2[regionEU].groups,
		sg("sg-0fake0000000000002", "open-web",
			perm("tcp", 22, 22, "0.0.0.0/0"),
			perm("tcp", 8000, 8090, "0.0.0.0/0", "10.0.0.0/8"),
			perm("udp", 53, 53, "10.0.0.0/0"),
			icmp,
		))
	egress := firewall("egress-world", []string{"0.0.0.0/0"}, allowed("all"))
	egress.Direction = "EGRESS"
	c.firewalls.byProject[projA] = append(c.firewalls.byProject[projA],
		firewall("allow-ssh-world", []string{"0.0.0.0/0"}, allowed("tcp", "22", "3389"), allowed("udp", "500-600")),
		egress,
	)
	c.nsgs.bySub[subA] = append(c.nsgs.bySub[subA], nsg(subA, "web",
		nsgRule("https", "Inbound", "Allow", "Tcp", "*", 100, "443"),
		nsgRule("http-alt", "Inbound", "Allow", "*", "Internet", 110, "80", "8080-8090"),
		nsgRule("deny-ssh", "Inbound", "Deny", "Tcp", "*", 120, "22"),
		nsgRule("out-all", "Outbound", "Allow", "*", "*", 130, "*"),
	))
	return c
}

func TestE2E_CombinedFindingsGolden(t *testing.T) {
	r := run(t, combinedCloud(), allArgs()...)
	assertEqual(t, "exit", r.code, report.ExitFindings)
	rep := decode(t, r.stdout)
	assertEqual(t, "findings", rep.Scan.Findings, 4+3+3)
	golden := filepath.Join("..", "..", "testdata", "golden", "example-cli-combined.json")
	if *update {
		if err := os.WriteFile(golden, []byte(r.stdout), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if string(want) != r.stdout {
		t.Errorf("report differs from %s (run with -update after checking the diff):\n%s", golden, r.stdout)
	}
}

// ---- 7. deterministic output ----------------------------------------------

func TestE2E_DeterministicAcrossShuffledInputs(t *testing.T) {
	build := func(seed uint64) string {
		rng := rand.New(rand.NewPCG(seed, 7))
		c := combinedCloud()
		c.ec2[regionUS] = &fakeEC2{groups: []types.SecurityGroup{
			sg("sg-0fake0000000000003", "us", perm("tcp", 443, 443, "0.0.0.0/0")),
		}}
		c.firewalls.byProject[projB] = []*compute.Firewall{firewall("b", []string{"0.0.0.0/0"}, allowed("all"))}
		c.nsgs.bySub[subB] = []*armnetwork.SecurityGroup{nsg(subB, "b", nsgRule("r", "Inbound", "Allow", "Udp", "Any", 100, "*"))}
		shuffle := func(n int, swap func(i, j int)) { rng.Shuffle(n, swap) }
		g := c.ec2[regionEU].groups
		shuffle(len(g), func(i, j int) { g[i], g[j] = g[j], g[i] })
		for _, grp := range g {
			p := grp.IpPermissions
			shuffle(len(p), func(i, j int) { p[i], p[j] = p[j], p[i] })
		}
		fws := c.firewalls.byProject[projA]
		shuffle(len(fws), func(i, j int) { fws[i], fws[j] = fws[j], fws[i] })
		ns := c.nsgs.bySub[subA]
		shuffle(len(ns), func(i, j int) { ns[i], ns[j] = ns[j], ns[i] })
		regions := []string{regionEU, regionUS}
		projects := []string{projA, projB}
		subs := []string{subA, subB}
		shuffle(2, func(i, j int) { regions[i], regions[j] = regions[j], regions[i] })
		shuffle(2, func(i, j int) { projects[i], projects[j] = projects[j], projects[i] })
		shuffle(2, func(i, j int) { subs[i], subs[j] = subs[j], subs[i] })
		r := run(t, c, "--providers", "azure,gcp,aws",
			"--aws-regions", strings.Join(regions, ","),
			"--gcp-projects", strings.Join(projects, ","),
			"--azure-subscriptions", strings.Join(subs, ","),
			"--concurrency", "8")
		assertEqual(t, "exit", r.code, report.ExitFindings)
		return r.stdout
	}
	first := build(1)
	decode(t, first)
	for seed := uint64(2); seed < 15; seed++ {
		if got := build(seed); got != first {
			t.Fatalf("seed %d: output differs", seed)
		}
	}
}

// ---- 8-10. partial failures: exit 2, findings kept --------------------------

func TestE2E_PartialFailuresKeepFindings(t *testing.T) {
	t.Run("aws region", func(t *testing.T) {
		c := combinedCloud()
		c.ec2[regionUS] = &fakeEC2{err: &smithy.GenericAPIError{Code: "UnauthorizedOperation", Message: markerPayload}}
		r := run(t, c, "--providers", "aws", "--aws-regions", regionEU+","+regionUS)
		assertEqual(t, "exit", r.code, report.ExitIncomplete)
		rep := decode(t, r.stdout)
		assertEqual(t, "status", rep.Scan.Providers.AWS, model.ProviderPartial)
		assertEqual(t, "findings kept", rep.Scan.Findings, 4)
		assertEqual(t, "errors", fmt.Sprint(errorSummary(rep)),
			"[aws "+account+"/"+regionUS+" ec2:DescribeSecurityGroups permission_denied]")
		assertNoMarkers(t, "stdout", r.stdout)
		assertNoMarkers(t, "stderr", r.stderr)
	})
	t.Run("gcp project", func(t *testing.T) {
		c := combinedCloud()
		c.firewalls.errs = map[string]error{projB: &googleapi.Error{Code: 403, Message: markerPayload, Body: markBody,
			Errors: []googleapi.ErrorItem{{Reason: "forbidden", Message: markSecret}}}}
		r := run(t, c, "--providers", "gcp", "--gcp-projects", projA+","+projB)
		assertEqual(t, "exit", r.code, report.ExitIncomplete)
		rep := decode(t, r.stdout)
		assertEqual(t, "status", rep.Scan.Providers.GCP, model.ProviderPartial)
		assertEqual(t, "findings kept", rep.Scan.Findings, 3)
		assertEqual(t, "errors", fmt.Sprint(errorSummary(rep)), "[gcp "+projB+" compute.firewalls.list permission_denied]")
		assertNoMarkers(t, "stdout", r.stdout)
	})
	t.Run("azure subscription", func(t *testing.T) {
		c := combinedCloud()
		c.nsgs.errs = map[string]error{subB: &azcore.ResponseError{StatusCode: http.StatusForbidden, ErrorCode: "AuthorizationFailed"}}
		r := run(t, c, "--providers", "azure", "--azure-subscriptions", subA+","+subB)
		assertEqual(t, "exit", r.code, report.ExitIncomplete)
		rep := decode(t, r.stdout)
		assertEqual(t, "status", rep.Scan.Providers.Azure, model.ProviderPartial)
		assertEqual(t, "findings kept", rep.Scan.Findings, 3)
		assertEqual(t, "errors", fmt.Sprint(errorSummary(rep)),
			"[azure "+subB+" Microsoft.Network/networkSecurityGroups/read permission_denied]")
	})
	t.Run("one provider fails entirely, the others complete", func(t *testing.T) {
		c := combinedCloud()
		c.subs = fakeSubs{err: &azcore.ResponseError{StatusCode: 401, ErrorCode: "InvalidAuthenticationToken"}}
		r := run(t, c, "--providers", allProviders, "--aws-regions", regionEU, "--gcp-projects", projA)
		assertEqual(t, "exit", r.code, report.ExitIncomplete)
		rep := decode(t, r.stdout)
		assertEqual(t, "azure", rep.Scan.Providers.Azure, model.ProviderFailed)
		assertEqual(t, "aws", rep.Scan.Providers.AWS, model.ProviderComplete)
		assertEqual(t, "gcp", rep.Scan.Providers.GCP, model.ProviderComplete)
		assertEqual(t, "findings from aws+gcp", rep.Scan.Findings, 7)
	})
	t.Run("azure discovery with a Deleted subscription", func(t *testing.T) {
		c := combinedCloud()
		c.subs = fakeSubs{subs: []azure.Subscription{
			{ID: subA, State: azure.StateEnabled, HasState: true},
			{ID: subB, State: azure.StateDeleted, HasState: true},
		}}
		r := run(t, c, "--providers", "azure")
		assertEqual(t, "exit (skipped does not raise 2)", r.code, report.ExitFindings)
		rep := decode(t, r.stdout)
		var states []string
		for _, s := range rep.Scan.Scopes {
			states = append(states, s.Scope+" "+string(s.Status)+" "+*s.SubscriptionState)
		}
		assertEqual(t, "scopes", fmt.Sprint(states), "["+subA+" complete Enabled "+subB+" skipped Deleted]")
	})
}

// ---- 11. authentication failures -------------------------------------------

func TestE2E_AuthenticationFailures(t *testing.T) {
	t.Run("API rejects the credentials", func(t *testing.T) {
		c := combinedCloud()
		c.stsErr = &smithy.GenericAPIError{Code: "InvalidClientTokenId", Message: markerPayload}
		c.firewalls.errs = map[string]error{projA: &googleapi.Error{Code: 401, Body: markerPayload}}
		c.nsgs.errs = map[string]error{subA: &azcore.ResponseError{StatusCode: 401, ErrorCode: "ExpiredAuthenticationToken"}}
		r := run(t, c, allArgs()...)
		assertEqual(t, "exit", r.code, report.ExitIncomplete)
		rep := decode(t, r.stdout)
		assertEqual(t, "errors", fmt.Sprint(errorSummary(rep)), "[aws  sts:GetCallerIdentity auth "+
			"azure "+subA+" Microsoft.Network/networkSecurityGroups/read auth gcp "+projA+" compute.firewalls.list auth]")
		for _, s := range []model.ProviderStatus{rep.Scan.Providers.AWS, rep.Scan.Providers.GCP, rep.Scan.Providers.Azure} {
			assertEqual(t, "status", s, model.ProviderFailed)
		}
		assertNoMarkers(t, "stdout", r.stdout)
		assertNoMarkers(t, "stderr", r.stderr)
	})
	t.Run("credential chain cannot be set up", func(t *testing.T) {
		c := combinedCloud()
		c.initErr = map[model.Provider]error{
			model.ProviderAWS:   aws.ErrConfigLoad,
			model.ProviderGCP:   gcp.ErrCredentials,
			model.ProviderAzure: fmt.Errorf("%s: %w", markerPayload, azure.ErrCredentials),
		}
		r := run(t, c, allArgs()...)
		assertEqual(t, "exit", r.code, report.ExitIncomplete)
		rep := decode(t, r.stdout)
		assertEqual(t, "errors", fmt.Sprint(errorSummary(rep)), "[aws  init auth azure  init auth gcp  init auth]")
		for _, e := range rep.Errors {
			if e.Message == "" {
				t.Errorf("empty message: %+v", e)
			}
		}
		assertNoMarkers(t, "stdout", r.stdout)
		assertNoMarkers(t, "stderr", r.stderr)
	})
	t.Run("unknown init error is reported with fixed text", func(t *testing.T) {
		c := cleanCloud()
		c.initErr = map[model.Provider]error{model.ProviderGCP: errors.New(markerPayload)}
		r := run(t, c, "--providers", "gcp,azure", "--gcp-projects", projA, "--azure-subscriptions", subA)
		assertEqual(t, "exit", r.code, report.ExitIncomplete)
		rep := decode(t, r.stdout)
		assertEqual(t, "gcp", rep.Scan.Providers.GCP, model.ProviderFailed)
		assertEqual(t, "azure still scanned", rep.Scan.Providers.Azure, model.ProviderComplete)
		assertEqual(t, "message", rep.Errors[0].Message, "gcp scanner could not be initialised")
		assertNoMarkers(t, "stdout", r.stdout)
	})
}

// ---- 12. cancellation and timeouts -------------------------------------------

func TestE2E_GlobalTimeoutStillWritesReport(t *testing.T) {
	c := combinedCloud()
	c.ec2[regionEU].block = true
	c.firewalls.block = true
	c.nsgs.block = true
	start := time.Now()
	r := run(t, c, allArgs("--timeout", "200ms")...)
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("run took %v", d)
	}
	assertEqual(t, "exit", r.code, report.ExitIncomplete)
	rep := decode(t, r.stdout)
	assertEqual(t, "errors", fmt.Sprint(errorSummary(rep)), "[aws "+account+"/"+regionEU+
		" ec2:DescribeSecurityGroups timeout azure "+subA+" Microsoft.Network/networkSecurityGroups/read timeout "+
		"gcp "+projA+" compute.firewalls.list timeout]")
}

func TestE2E_ScopeTimeoutFailsOnlySlowScope(t *testing.T) {
	c := combinedCloud()
	c.ec2[regionUS] = &fakeEC2{block: true}
	r := run(t, c, "--providers", "aws", "--aws-regions", regionEU+","+regionUS, "--scope-timeout", "100ms")
	assertEqual(t, "exit", r.code, report.ExitIncomplete)
	rep := decode(t, r.stdout)
	assertEqual(t, "findings kept", rep.Scan.Findings, 4)
	assertEqual(t, "errors", fmt.Sprint(errorSummary(rep)),
		"[aws "+account+"/"+regionUS+" ec2:DescribeSecurityGroups timeout]")
}

func TestE2E_CancelledContext(t *testing.T) {
	c := combinedCloud()
	c.ec2[regionEU].block = true
	c.firewalls.block = true
	c.nsgs.block = true
	env, stdout, _ := testEnv(c, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- Run(ctx, allArgs(), env) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case code := <-done:
		assertEqual(t, "exit", code, report.ExitIncomplete)
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
	rep := decode(t, stdout.String())
	for _, e := range rep.Errors {
		assertEqual(t, "kind", e.Kind, model.ErrorKindTimeout)
	}
}

// ---- 13-15. invalid arguments and configuration: exit 3, nothing scanned ---

func TestE2E_InvalidArgumentsExit3(t *testing.T) {
	tests := []struct {
		name string
		args []string
		env  map[string]string
		want string // part of the stderr message
	}{
		{"no arguments", nil, nil, "--providers is required"},
		{"empty providers", []string{"--providers", ""}, nil, "--providers is empty"},
		{"unknown provider", []string{"--providers", "aws,oracle"}, nil, `unknown provider "oracle"`},
		{"upper-case provider", []string{"--providers", "AWS"}, nil, "unknown provider"},
		{"empty entry", []string{"--providers", "aws,,gcp", "--gcp-projects", projA}, nil, "empty entry"},
		{"unknown flag", []string{"--providers", "aws", "--regions", "x"}, nil, "invalid arguments"},
		{"positional argument", []string{"--providers", "aws", "extra"}, nil, `unexpected argument "extra"`},
		{"aws flag without aws", []string{"--providers", "gcp", "--gcp-projects", projA, "--aws-regions", regionEU}, nil,
			`--aws-regions needs "aws"`},
		{"gcp flag without gcp", []string{"--providers", "aws", "--gcp-projects", projA}, nil, `--gcp-projects needs "gcp"`},
		{"azure flag without azure", []string{"--providers", "aws", "--azure-subscriptions", subA}, nil,
			`--azure-subscriptions needs "azure"`},
		{"bootstrap without aws", []string{"--providers", "gcp", "--gcp-projects", projA, "--aws-bootstrap-region", regionEU}, nil,
			`--aws-bootstrap-region needs "aws"`},
		{"invalid region", []string{"--providers", "aws", "--aws-regions", "eu-west-1,evil.example#"}, nil,
			`invalid AWS region "evil.example#"`},
		{"invalid bootstrap region", []string{"--providers", "aws", "--aws-bootstrap-region", "EU"}, nil, "invalid AWS region"},
		{"empty region list", []string{"--providers", "aws", "--aws-regions", " "}, nil, "--aws-regions is empty"},
		{"invalid project", []string{"--providers", "gcp", "--gcp-projects", "p/../x"}, nil, `invalid GCP project ID "p/../x"`},
		{"invalid subscription", []string{"--providers", "azure", "--azure-subscriptions", "not-a-guid"}, nil,
			`invalid Azure subscription ID "not-a-guid"`},
		{"gcp without project", []string{"--providers", "gcp"}, nil, "no project"},
		{"invalid GOOGLE_CLOUD_PROJECT", []string{"--providers", "gcp"}, map[string]string{gcp.EnvProject: "Bad_Project"},
			"invalid GCP project ID"},
		{"zero timeout", []string{"--providers", "aws", "--timeout", "0s"}, nil, "--timeout must be positive"},
		{"negative scope timeout", []string{"--providers", "aws", "--scope-timeout", "-1s"}, nil, "--scope-timeout must be positive"},
		{"bad duration", []string{"--providers", "aws", "--timeout", "soon"}, nil, "invalid arguments"},
		{"concurrency 0", []string{"--providers", "aws", "--concurrency", "0"}, nil, "--concurrency must be between 1 and 64"},
		{"concurrency too high", []string{"--providers", "aws", "--concurrency", "1000"}, nil, "--concurrency"},
		{"empty output", []string{"--providers", "aws", "--output", " "}, nil, "--output is empty"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := cleanCloud()
			env, stdout, stderr := testEnv(c, tc.env)
			code := Run(context.Background(), tc.args, env)
			assertEqual(t, "exit", code, report.ExitUsage)
			assertEqual(t, "stdout", stdout.String(), "")
			if !strings.Contains(stderr.String(), tc.want) {
				t.Errorf("stderr %q does not contain %q", stderr.String(), tc.want)
			}
			assertEqual(t, "nothing built", len(c.builtProviders()), 0)
		})
	}
}

func TestE2E_GCPProjectFromEnvironment(t *testing.T) {
	c := combinedCloud()
	env, stdout, _ := testEnv(c, map[string]string{gcp.EnvProject: projA})
	code := Run(context.Background(), []string{"--providers", "gcp"}, env)
	assertEqual(t, "exit", code, report.ExitFindings)
	rep := decode(t, stdout.String())
	assertEqual(t, "scope", rep.Scan.Scopes[0].Scope, projA)
}

// The real AWS factory with no region anywhere: exit 3 before any other
// provider is built and before any request. Offline: config loading reads
// only the (empty) files named here.
func TestE2E_MissingAWSBootstrapRegionExit3(t *testing.T) {
	dir := t.TempDir()
	for _, k := range []string{"AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE", "AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "fake-config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "fake-credentials"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	c := cleanCloud()
	env, stdout, stderr := testEnv(c, nil)
	f := c.factories()
	f.AWS = SDKFactories().AWS
	env.Factories = f
	code := Run(context.Background(), []string{"--providers", "aws,azure", "--azure-subscriptions", subA}, env)
	assertEqual(t, "exit", code, report.ExitUsage)
	assertEqual(t, "stdout", stdout.String(), "")
	if !strings.Contains(stderr.String(), "no AWS bootstrap region") {
		t.Errorf("stderr: %s", stderr.String())
	}
	assertEqual(t, "azure not built", len(c.builtProviders()), 0)
}

func TestE2E_HelpExit0(t *testing.T) {
	r := run(t, cleanCloud(), "-h")
	assertEqual(t, "exit", r.code, report.ExitClean)
	assertEqual(t, "stdout", r.stdout, "")
	for _, want := range []string{"--providers", "--aws-regions", "--output", "Exit codes:"} {
		if !strings.Contains(r.stderr, strings.TrimPrefix(want, "-")) {
			t.Errorf("help misses %s", want)
		}
	}
}

// ---- 16-17. output file ------------------------------------------------------

func TestE2E_OutputFile(t *testing.T) {
	t.Run("written to a new file, nothing on stdout", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "example-report.json")
		r := run(t, combinedCloud(), allArgs("--output", path)...)
		assertEqual(t, "exit", r.code, report.ExitFindings)
		assertEqual(t, "stdout", r.stdout, "")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		decode(t, string(data))
		if !strings.Contains(r.stderr, "report=") {
			t.Errorf("summary misses the path: %s", r.stderr)
		}
		if info, _ := os.Stat(path); info.Mode().Perm()&0o077 != 0 && !isWindows() {
			t.Errorf("mode %v is readable by others", info.Mode().Perm())
		}
	})
	t.Run("existing file: exit 3, unchanged, nothing scanned", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "example-existing.json")
		if err := os.WriteFile(path, []byte("keep me"), 0o600); err != nil {
			t.Fatal(err)
		}
		c := combinedCloud()
		env, stdout, stderr := testEnv(c, nil)
		code := Run(context.Background(), allArgs("--output", path), env)
		assertEqual(t, "exit", code, report.ExitUsage)
		assertEqual(t, "stdout", stdout.String(), "")
		data, _ := os.ReadFile(path)
		assertEqual(t, "file unchanged", string(data), "keep me")
		assertEqual(t, "nothing built", len(c.builtProviders()), 0)
		if !strings.Contains(stderr.String(), "already exists") {
			t.Errorf("stderr: %s", stderr.String())
		}
	})
	t.Run("existing directory or missing parent: exit 3", func(t *testing.T) {
		dir := t.TempDir()
		for _, p := range []string{dir, filepath.Join(dir, "missing", "example-report.json")} {
			r := run(t, cleanCloud(), allArgs("--output", p)...)
			assertEqual(t, "exit "+p, r.code, report.ExitUsage)
		}
	})
	t.Run("file appears during the scan: exit 4, file untouched", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "example-race.json")
		c := combinedCloud()
		env, stdout, _ := testEnv(c, nil)
		env.CreateFile = func(p string) (OutputFile, error) {
			if err := os.WriteFile(p, []byte("someone else's"), 0o600); err != nil {
				t.Fatal(err)
			}
			return createExclusive(p)
		}
		code := Run(context.Background(), allArgs("--output", path), env)
		assertEqual(t, "exit", code, report.ExitWriteFailed)
		assertEqual(t, "stdout", stdout.String(), "")
		data, _ := os.ReadFile(path)
		assertEqual(t, "other file kept", string(data), "someone else's")
	})
	t.Run("partial write: exit 4, partial file removed", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "example-partial.json")
		env, _, stderr := testEnv(combinedCloud(), nil)
		env.CreateFile = func(p string) (OutputFile, error) {
			f, err := createExclusive(p)
			if err != nil {
				return nil, err
			}
			return &shortFile{OutputFile: f, limit: 100}, nil
		}
		code := Run(context.Background(), allArgs("--output", path), env)
		assertEqual(t, "exit", code, report.ExitWriteFailed)
		assertEqual(t, "partial file removed", fileExists(path), false)
		if !strings.Contains(stderr.String(), "partial file was removed") {
			t.Errorf("stderr: %s", stderr.String())
		}
	})
	t.Run("sync failure: exit 4, file removed", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "example-sync.json")
		env, _, _ := testEnv(combinedCloud(), nil)
		env.CreateFile = func(p string) (OutputFile, error) {
			f, err := createExclusive(p)
			if err != nil {
				return nil, err
			}
			return &shortFile{OutputFile: f, limit: -1, syncErr: errors.New("disk full")}, nil
		}
		code := Run(context.Background(), allArgs("--output", path), env)
		assertEqual(t, "exit", code, report.ExitWriteFailed)
		assertEqual(t, "file removed", fileExists(path), false)
	})
	t.Run("stdout write failure: exit 4 outranks 2", func(t *testing.T) {
		c := combinedCloud()
		c.firewalls.errs = map[string]error{projA: errors.New("x")}
		env, _, _ := testEnv(c, nil)
		env.Stdout = failingWriter{}
		code := Run(context.Background(), allArgs(), env)
		assertEqual(t, "exit", code, report.ExitWriteFailed)
	})
}

type shortFile struct {
	OutputFile
	limit   int // bytes accepted before failing; -1 = no limit
	syncErr error
}

func (f *shortFile) Write(p []byte) (int, error) {
	if f.limit >= 0 && len(p) > f.limit {
		n, _ := f.OutputFile.Write(p[:f.limit])
		return n, errors.New("no space left on device")
	}
	return f.OutputFile.Write(p)
}

func (f *shortFile) Sync() error {
	if f.syncErr != nil {
		return f.syncErr
	}
	return f.OutputFile.Sync()
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func isWindows() bool { return os.PathSeparator == '\\' }

// ---- 18. exit code precedence -------------------------------------------------

func TestE2E_ExitCodePrecedence(t *testing.T) {
	// 2 outranks 1: findings and an incomplete provider.
	c := combinedCloud()
	c.firewalls.errs = map[string]error{projA: errors.New("x")}
	r := run(t, c, allArgs()...)
	assertEqual(t, "2 over 1", r.code, report.ExitIncomplete)
	rep := decode(t, r.stdout)
	if rep.Scan.Findings == 0 {
		t.Errorf("findings must still be reported with exit 2")
	}
	// An incomplete scope (rule could not be evaluated) is exit 2, never 0.
	c = cleanCloud()
	c.firewalls.byProject[projA] = append(c.firewalls.byProject[projA],
		firewall("weird", []string{"0.0.0.0/0"}, allowed("tcp", "22")))
	c.firewalls.byProject[projA][1].Direction = "SIDEWAYS"
	r = run(t, c, "--providers", "gcp", "--gcp-projects", projA)
	assertEqual(t, "incomplete scope", r.code, report.ExitIncomplete)
	// 3 outranks everything that would follow: no scan happens.
	r = run(t, combinedCloud(), "--providers", "aws", "--aws-regions", "bad region")
	assertEqual(t, "3", r.code, report.ExitUsage)
}

// ---- 19. no secrets anywhere ---------------------------------------------------

func TestE2E_NoSecretsInReportOrLogs(t *testing.T) {
	c := combinedCloud()
	c.ec2[regionUS] = &fakeEC2{err: &smithy.GenericAPIError{Code: markSecret, Message: markerPayload}}
	c.firewalls.errs = map[string]error{projB: &googleapi.Error{Code: 500, Body: markerPayload,
		Header: http.Header{"X-Echo": {markToken}}, Errors: []googleapi.ErrorItem{{Reason: markSecret}}}}
	c.nsgs.errs = map[string]error{subB: &azcore.ResponseError{StatusCode: 400, ErrorCode: markSecret}}
	path := filepath.Join(t.TempDir(), "example-report.json")
	r := run(t, c, "--providers", allProviders,
		"--aws-regions", regionEU+","+regionUS, "--gcp-projects", projA+","+projB,
		"--azure-subscriptions", subA+","+subB, "--output", path)
	assertEqual(t, "exit", r.code, report.ExitIncomplete)
	data, _ := os.ReadFile(path)
	assertNoMarkers(t, "report file", string(data))
	assertNoMarkers(t, "stderr", r.stderr)
	assertNoMarkers(t, "stdout", r.stdout)
	rep := decode(t, string(data))
	assertEqual(t, "errors", len(rep.Errors), 3)
}

// ---- determinism details ---------------------------------------------------------

func TestE2E_TimestampsOptIn(t *testing.T) {
	r := run(t, cleanCloud(), allArgs("--include-timestamps")...)
	rep := decode(t, r.stdout)
	assertEqual(t, "started", rep.Scan.StartedAt, "2026-01-02T03:04:05Z")
	assertEqual(t, "finished", rep.Scan.FinishedAt, "2026-01-02T03:04:05Z")
}

func TestE2E_DuplicateScopesAndProviders(t *testing.T) {
	r := run(t, combinedCloud(), "--providers", "gcp,gcp", "--gcp-projects", projA+", "+projA)
	assertEqual(t, "exit", r.code, report.ExitFindings)
	rep := decode(t, r.stdout)
	assertEqual(t, "one scope", len(rep.Scan.Scopes), 1)
	var scopes []string
	for _, s := range rep.Scan.Scopes {
		scopes = append(scopes, s.Scope)
	}
	if !slices.Equal(scopes, []string{projA}) {
		t.Errorf("scopes %v", scopes)
	}
}
