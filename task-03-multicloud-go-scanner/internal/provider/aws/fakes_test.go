package aws

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

// TestMain makes sure no test can reach a real AWS account: credential
// variables are cleared, shared config files point nowhere, and the
// instance metadata service is disabled. The tests use fakes only.
func TestMain(m *testing.M) {
	for _, k := range []string{
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
		"AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE",
		"AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
		"AWS_REGION", "AWS_DEFAULT_REGION",
	} {
		os.Unsetenv(k)
	}
	os.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	os.Setenv("AWS_CONFIG_FILE", os.DevNull)
	os.Setenv("AWS_SHARED_CREDENTIALS_FILE", os.DevNull)
	os.Exit(m.Run())
}

// Fake identifiers. None of these exist.
const (
	fakeAccount = "111111111111"
	otherAcct   = "222222222222"
)

// page is one DescribeSecurityGroups response.
type page struct {
	groups []types.SecurityGroup
	err    error
	// next overrides the generated NextToken ("p<i+1>" unless last page).
	next *string
	// nilOutput returns (nil, nil).
	nilOutput bool
}

// fakeEC2 serves DescribeSecurityGroups pages by token: no token is page 0,
// token "p<i>" is page i. It records every call.
type fakeEC2 struct {
	mu         sync.Mutex
	pages      []page
	regions    []types.Region
	regionsErr error
	// block makes DescribeSecurityGroups wait for ctx to end.
	block bool
	// onCall runs at the start of each DescribeSecurityGroups call.
	onCall func()

	sgInputs     []ec2.DescribeSecurityGroupsInput
	regionInputs []ec2.DescribeRegionsInput
}

func (f *fakeEC2) DescribeSecurityGroups(ctx context.Context, in *ec2.DescribeSecurityGroupsInput,
	_ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	f.mu.Lock()
	f.sgInputs = append(f.sgInputs, *in)
	f.mu.Unlock()
	if f.onCall != nil {
		f.onCall()
	}
	if f.block {
		<-ctx.Done()
		return nil, opError("DescribeSecurityGroups", ctx.Err())
	}
	if err := ctx.Err(); err != nil {
		return nil, opError("DescribeSecurityGroups", err)
	}
	i := 0
	if tok := awssdk.ToString(in.NextToken); tok != "" {
		n, err := strconv.Atoi(strings.TrimPrefix(tok, "p"))
		if err != nil || n >= len(f.pages) {
			return nil, fmt.Errorf("fake: unknown token %q", tok)
		}
		i = n
	}
	if len(f.pages) == 0 {
		return &ec2.DescribeSecurityGroupsOutput{}, nil
	}
	p := f.pages[i]
	if p.err != nil {
		return nil, p.err
	}
	if p.nilOutput {
		return nil, nil
	}
	out := &ec2.DescribeSecurityGroupsOutput{SecurityGroups: p.groups}
	switch {
	case p.next != nil:
		out.NextToken = p.next
	case i+1 < len(f.pages):
		out.NextToken = awssdk.String("p" + strconv.Itoa(i+1))
	}
	return out, nil
}

func (f *fakeEC2) DescribeRegions(ctx context.Context, in *ec2.DescribeRegionsInput,
	_ ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
	f.mu.Lock()
	f.regionInputs = append(f.regionInputs, *in)
	f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, opError("DescribeRegions", err)
	}
	if f.regionsErr != nil {
		return nil, f.regionsErr
	}
	return &ec2.DescribeRegionsOutput{Regions: f.regions}, nil
}

func (f *fakeEC2) sgCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sgInputs)
}

// fakeSTS returns a fixed identity or error.
type fakeSTS struct {
	account *string
	err     error
	calls   int
}

func (f *fakeSTS) GetCallerIdentity(ctx context.Context, _ *sts.GetCallerIdentityInput,
	_ ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	f.calls++
	if err := ctx.Err(); err != nil {
		return nil, opError("GetCallerIdentity", err)
	}
	if f.err != nil {
		return nil, f.err
	}
	return &sts.GetCallerIdentityOutput{Account: f.account}, nil
}

func okSTS() *fakeSTS { return &fakeSTS{account: awssdk.String(fakeAccount)} }

// factory maps regions to fakes. A region without a fake gets a client
// that fails like an unknown endpoint would.
type factory struct {
	mu      sync.Mutex
	clients map[string]*fakeEC2
	asked   []string
}

func newFactory(clients map[string]*fakeEC2) *factory {
	return &factory{clients: clients}
}

func (f *factory) client(region string) EC2API {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, region)
	if c, ok := f.clients[region]; ok {
		return c
	}
	return &fakeEC2{pages: []page{{err: apiError("UnknownEndpoint", "fake: no such region")}}}
}

// apiError mimics an EC2 API error as the SDK returns it: a smithy API
// error wrapped in an operation error.
func apiError(code, msg string) error {
	return opError("DescribeSecurityGroups", &smithy.GenericAPIError{Code: code, Message: msg})
}

func opError(op string, err error) error {
	return &smithy.OperationError{ServiceID: "EC2", OperationName: op, Err: err}
}

// Builders for SDK types.

func sg(id, name string, perms ...types.IpPermission) types.SecurityGroup {
	return types.SecurityGroup{
		GroupId:       awssdk.String(id),
		GroupName:     awssdk.String(name),
		VpcId:         awssdk.String("vpc-0fake000000000001"),
		OwnerId:       awssdk.String(fakeAccount),
		IpPermissions: perms,
	}
}

func perm(proto string, from, to *int32, cidrs ...string) types.IpPermission {
	p := types.IpPermission{IpProtocol: awssdk.String(proto), FromPort: from, ToPort: to}
	for _, c := range cidrs {
		p.IpRanges = append(p.IpRanges, types.IpRange{CidrIp: awssdk.String(c)})
	}
	return p
}

func i32(v int32) *int32 { return &v }

func tcp(port int32, cidrs ...string) types.IpPermission {
	return perm("tcp", i32(port), i32(port), cidrs...)
}

func newTestScanner(cfg Config, s STSAPI, f *factory) *Scanner {
	if cfg.BootstrapRegion == "" {
		cfg.BootstrapRegion = "eu-west-1"
	}
	return NewScanner(cfg, s, f.client)
}
