package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	compute "google.golang.org/api/compute/v1"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/provider/aws"
	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/provider/azure"
	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/provider/gcp"
	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/runner"
)

// The end-to-end tests run cli.Run with the real collectors (internal
// provider packages), the real detection engine and the real report
// builder. Only the SDK adapters are faked: each provider package's own
// narrow interface (aws.EC2API / aws.STSAPI, gcp.FirewallLister,
// azure.SubscriptionLister / azure.NSGLister). Nothing reaches a network.

// Fake identifiers. None of these exist.
const (
	account  = "111111111111"
	projA    = "example-project-a"
	projB    = "example-project-b"
	subA     = "00000000-0000-0000-0000-00000000000a"
	subB     = "00000000-0000-0000-0000-00000000000b"
	regionEU = "eu-west-1"
	regionUS = "us-east-1"
)

// Dummy markers placed in error payloads. They are not credentials.
const (
	markSecret = "DUMMY_CLIENT_SECRET_MARKER_8B2E"
	markToken  = "DUMMY_SESSION_TOKEN_MARKER_4A7C"
	markBody   = "DUMMY_RESPONSE_BODY_MARKER_6C3A"
)

var allMarkers = []string{markSecret, markToken, markBody}

const markerPayload = markSecret + " " + markToken + " " + markBody

func assertNoMarkers(t *testing.T, where, data string) {
	t.Helper()
	for _, m := range allMarkers {
		if strings.Contains(strings.ToUpper(data), m) {
			t.Errorf("%s contains marker %s:\n%s", where, m, data)
		}
	}
}

// ---- AWS ------------------------------------------------------------------

type fakeSTS struct{ err error }

func (f fakeSTS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput,
	...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &sts.GetCallerIdentityOutput{Account: awssdk.String(account)}, nil
}

// fakeEC2 serves one region.
type fakeEC2 struct {
	groups  []types.SecurityGroup
	err     error
	block   bool
	regions []string
}

func (f *fakeEC2) DescribeSecurityGroups(ctx context.Context, _ *ec2.DescribeSecurityGroupsInput,
	_ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	if f.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if f.err != nil {
		return nil, f.err
	}
	return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: f.groups}, nil
}

func (f *fakeEC2) DescribeRegions(context.Context, *ec2.DescribeRegionsInput,
	...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
	out := &ec2.DescribeRegionsOutput{}
	for _, r := range f.regions {
		out.Regions = append(out.Regions, types.Region{RegionName: awssdk.String(r)})
	}
	return out, nil
}

func sg(id, name string, perms ...types.IpPermission) types.SecurityGroup {
	return types.SecurityGroup{
		GroupId: awssdk.String(id), GroupName: awssdk.String(name),
		VpcId: awssdk.String("vpc-0fake000000000001"), OwnerId: awssdk.String(account),
		IpPermissions: perms,
	}
}

func perm(proto string, from, to int32, cidrs ...string) types.IpPermission {
	p := types.IpPermission{IpProtocol: awssdk.String(proto), FromPort: awssdk.Int32(from), ToPort: awssdk.Int32(to)}
	for _, c := range cidrs {
		p.IpRanges = append(p.IpRanges, types.IpRange{CidrIp: awssdk.String(c)})
	}
	return p
}

// ---- GCP ------------------------------------------------------------------

type fakeFirewalls struct {
	byProject map[string][]*compute.Firewall
	errs      map[string]error
	block     bool
}

func (f *fakeFirewalls) ListFirewalls(ctx context.Context, project string) ([]*compute.Firewall, error) {
	if f.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if err := f.errs[project]; err != nil {
		return nil, err
	}
	return f.byProject[project], nil
}

func firewall(name string, ranges []string, allowed ...*compute.FirewallAllowed) *compute.Firewall {
	return &compute.Firewall{
		Name: name, Id: uint64(len(name)) + 1000, Direction: "INGRESS", Priority: 1000,
		Network:      "https://www.googleapis.com/compute/v1/projects/" + projA + "/global/networks/default",
		SourceRanges: ranges, Allowed: allowed,
	}
}

func allowed(proto string, ports ...string) *compute.FirewallAllowed {
	return &compute.FirewallAllowed{IPProtocol: proto, Ports: ports}
}

// ---- Azure ----------------------------------------------------------------

type fakeSubs struct {
	subs []azure.Subscription
	err  error
}

func (f fakeSubs) ListSubscriptions(context.Context) ([]azure.Subscription, error) {
	return f.subs, f.err
}

type fakeNSGs struct {
	bySub map[string][]*armnetwork.SecurityGroup
	errs  map[string]error
	block bool
}

func (f *fakeNSGs) ListNSGs(ctx context.Context, sub string) ([]*armnetwork.SecurityGroup, error) {
	if f.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if err := f.errs[sub]; err != nil {
		return nil, err
	}
	return f.bySub[sub], nil
}

func nsg(sub, name string, rules ...*armnetwork.SecurityRule) *armnetwork.SecurityGroup {
	return &armnetwork.SecurityGroup{
		ID:   to.Ptr("/subscriptions/" + sub + "/resourceGroups/example-rg/providers/Microsoft.Network/networkSecurityGroups/" + name),
		Name: to.Ptr(name),
		Properties: &armnetwork.SecurityGroupPropertiesFormat{
			SecurityRules: rules,
			DefaultSecurityRules: []*armnetwork.SecurityRule{
				nsgRule("DenyAllInBound", "Inbound", "Deny", "*", "*", 65500, "*"),
			},
		},
	}
}

func nsgRule(name, dir, access, proto, src string, prio int32, ports ...string) *armnetwork.SecurityRule {
	p := &armnetwork.SecurityRulePropertiesFormat{
		Direction:           to.Ptr(armnetwork.SecurityRuleDirection(dir)),
		Access:              to.Ptr(armnetwork.SecurityRuleAccess(access)),
		Protocol:            to.Ptr(armnetwork.SecurityRuleProtocol(proto)),
		Priority:            to.Ptr(prio),
		SourceAddressPrefix: to.Ptr(src),
		SourcePortRange:     to.Ptr("*"),
	}
	if len(ports) == 1 {
		p.DestinationPortRange = to.Ptr(ports[0])
	} else {
		for _, port := range ports {
			p.DestinationPortRanges = append(p.DestinationPortRanges, to.Ptr(port))
		}
	}
	return &armnetwork.SecurityRule{Name: to.Ptr(name), Properties: p}
}

// ---- the fake cloud --------------------------------------------------------

// cloud is a complete fake inventory for all three providers. Factories
// returns cli Factories that build the real collectors on it and record
// which providers were built.
type cloud struct {
	stsErr    error
	ec2       map[string]*fakeEC2 // by region
	firewalls *fakeFirewalls
	subs      fakeSubs
	nsgs      *fakeNSGs

	// initErr makes a factory fail as the real credential chain would.
	initErr map[model.Provider]error

	mu    sync.Mutex
	built []model.Provider
}

func (c *cloud) record(p model.Provider) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.built = append(c.built, p)
}

func (c *cloud) builtProviders() []model.Provider {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]model.Provider(nil), c.built...)
}

func (c *cloud) factories() Factories {
	return Factories{
		AWS: func(_ context.Context, bootstrap string, cfg aws.Config) (runner.Scanner, func(), error) {
			c.record(model.ProviderAWS)
			if err := c.initErr[model.ProviderAWS]; err != nil {
				return nil, nil, err
			}
			if bootstrap == "" {
				bootstrap = regionEU // as if AWS_REGION were set
			}
			cfg.BootstrapRegion = bootstrap
			clients := func(region string) aws.EC2API {
				if e, ok := c.ec2[region]; ok {
					return e
				}
				return &fakeEC2{err: errors.New("fake: no such region")}
			}
			return aws.NewScanner(cfg, fakeSTS{err: c.stsErr}, clients), nil, nil
		},
		GCP: func(_ context.Context, cfg gcp.Config) (runner.Scanner, func(), error) {
			c.record(model.ProviderGCP)
			if err := c.initErr[model.ProviderGCP]; err != nil {
				return nil, nil, err
			}
			return gcp.NewScanner(cfg, c.firewalls), func() {}, nil
		},
		Azure: func(_ context.Context, cfg azure.Config) (runner.Scanner, func(), error) {
			c.record(model.ProviderAzure)
			if err := c.initErr[model.ProviderAzure]; err != nil {
				return nil, nil, err
			}
			return azure.NewScanner(cfg, c.subs, c.nsgs), nil, nil
		},
	}
}

// cleanCloud has one quiet resource per provider: no findings.
func cleanCloud() *cloud {
	return &cloud{
		ec2: map[string]*fakeEC2{
			regionEU: {regions: []string{regionEU}, groups: []types.SecurityGroup{
				sg("sg-0fake0000000000001", "internal", perm("tcp", 22, 22, "10.0.0.0/8")),
			}},
		},
		firewalls: &fakeFirewalls{byProject: map[string][]*compute.Firewall{
			projA: {firewall("allow-internal", []string{"10.128.0.0/9"}, allowed("tcp", "22"))},
		}},
		subs: fakeSubs{subs: []azure.Subscription{{ID: subA, State: azure.StateEnabled, HasState: true}}},
		nsgs: &fakeNSGs{bySub: map[string][]*armnetwork.SecurityGroup{
			subA: {nsg(subA, "quiet", nsgRule("vnet-ssh", "Inbound", "Allow", "Tcp", "VirtualNetwork", 100, "22"))},
		}},
	}
}

// ---- running the command ----------------------------------------------------

type result struct {
	code   int
	stdout string
	stderr string
}

// testEnv runs the command on the fake cloud with in-memory stdout and
// stderr, the real file system and a fixed clock.
func testEnv(c *cloud, env map[string]string) (Env, *bytes.Buffer, *bytes.Buffer) {
	var stdout, stderr bytes.Buffer
	return Env{
		Stdout:     &stdout,
		Stderr:     &stderr,
		Getenv:     func(k string) string { return env[k] },
		Factories:  c.factories(),
		CreateFile: createExclusive,
		RemoveFile: os.Remove,
		Lstat:      os.Lstat,
		Now:        func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) },
	}, &stdout, &stderr
}

func run(t *testing.T, c *cloud, args ...string) result {
	t.Helper()
	env, stdout, stderr := testEnv(c, nil)
	code := Run(context.Background(), args, env)
	return result{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

// decode parses stdout as the report, failing the test if it is not one
// valid JSON document.
func decode(t *testing.T, out string) model.Report {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(out))
	dec.DisallowUnknownFields()
	var rep model.Report
	if err := dec.Decode(&rep); err != nil {
		t.Fatalf("stdout is not a valid report: %v\n%s", err, out)
	}
	if dec.More() {
		t.Fatalf("stdout has more than one JSON value:\n%s", out)
	}
	return rep
}

func assertEqual[T comparable](t *testing.T, what string, got, want T) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %v, want %v", what, got, want)
	}
}

// fileExists reports whether path exists.
func fileExists(path string) bool {
	_, err := os.Lstat(path)
	return !errors.Is(err, fs.ErrNotExist)
}

// errorSummary renders report errors as "provider scope operation kind".
func errorSummary(rep model.Report) []string {
	var out []string
	for _, e := range rep.Errors {
		out = append(out, string(e.Provider)+" "+e.Scope+" "+e.Operation+" "+e.Kind)
	}
	return out
}
