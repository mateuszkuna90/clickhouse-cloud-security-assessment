package aws

import (
	"context"
	"fmt"
	"sync"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
)

// Defaults (DESIGN.md 5.7).
const (
	DefaultConcurrency  = 8
	DefaultScopeTimeout = 2 * time.Minute
	// pageSize is the DescribeSecurityGroups MaxResults value (5-1000).
	pageSize = 1000
)

// Config selects what the scanner covers.
type Config struct {
	// BootstrapRegion is used for sts:GetCallerIdentity and, without
	// Regions, for ec2:DescribeRegions. It decides the partition. Required.
	BootstrapRegion string
	// Regions is an explicit region list. When empty, the regions enabled
	// for the account are discovered. Entries are trimmed and de-duplicated.
	Regions []string
	// Concurrency is the number of regions scanned in parallel.
	Concurrency int
	// ScopeTimeout bounds the scan of one region.
	ScopeTimeout time.Duration
}

// Scanner scans EC2 Security Groups of one account in one partition.
type Scanner struct {
	cfg     Config
	sts     STSAPI
	clients ClientFactory
}

// NewScanner returns a scanner. stsClient must be bound to the bootstrap
// region; clients returns an EC2 client for any region.
func NewScanner(cfg Config, stsClient STSAPI, clients ClientFactory) *Scanner {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = DefaultConcurrency
	}
	if cfg.ScopeTimeout <= 0 {
		cfg.ScopeTimeout = DefaultScopeTimeout
	}
	return &Scanner{cfg: cfg, sts: stsClient, clients: clients}
}

// Provider returns model.ProviderAWS.
func (s *Scanner) Provider() model.Provider { return model.ProviderAWS }

// Scan never returns an error: every failure is recorded in the result and
// lowers its status (DESIGN.md 3, principle 3).
//
// Status rules:
//   - setup failure (bootstrap region, GetCallerIdentity, DescribeRegions)
//     or zero regions: provider failed;
//   - otherwise from the region scopes (model.ProviderStatusFor), lowered
//     to partial if discovery returned regions that could not be scanned.
func (s *Scanner) Scan(ctx context.Context) model.ProviderResult {
	res := model.ProviderResult{Provider: model.ProviderAWS}
	failSetup := func(scope, op string, err error) model.ProviderResult {
		res.Status = model.ProviderFailed
		res.Errors = append(res.Errors, scanError(scope, op, err))
		return finish(res)
	}

	bootstrap := s.cfg.BootstrapRegion
	if !ValidRegion(bootstrap) {
		return failSetup("", OpConfig, errInvalidBootstrapRegion)
	}

	account, err := s.callerAccount(ctx)
	if err != nil {
		return failSetup("", OpGetCallerIdentity, err)
	}

	regions := normalizeRegions(s.cfg.Regions)
	unnamed := 0
	if len(regions) == 0 {
		client := s.clients(bootstrap)
		if client == nil {
			return failSetup(account, OpDescribeRegions, errNoClient)
		}
		d, err := discoverRegions(ctx, client)
		if err != nil {
			return failSetup(account, OpDescribeRegions, err)
		}
		regions, unnamed = d.names, d.unnamed
		for range unnamed {
			res.Errors = append(res.Errors, scanError(account, OpDescribeRegions, errNoRegionName))
		}
	}
	if len(regions) == 0 {
		res.Status = model.ProviderFailed
		res.Diagnostics = append(res.Diagnostics, model.Diagnostic{
			Provider: model.ProviderAWS, Scope: account,
			Code: model.CodeNoScopesDiscovered, Field: "Regions",
			Effect: model.EffectProviderFailed,
		})
		return finish(res)
	}

	outcomes := s.scanRegions(ctx, account, regions)
	for _, o := range outcomes {
		res.Scopes = append(res.Scopes, o.scope)
		res.Diagnostics = append(res.Diagnostics, o.diagnostics...)
		res.Errors = append(res.Errors, o.errors...)
		res.AWSSecurityGroups = append(res.AWSSecurityGroups, o.groups...)
	}
	res.Status = model.ProviderStatusFor(res.Scopes)
	if unnamed > 0 && res.Status == model.ProviderComplete {
		res.Status = model.ProviderPartial
	}
	return finish(res)
}

// finish replaces nil slices with empty ones so callers never see nil.
func finish(r model.ProviderResult) model.ProviderResult {
	if r.Scopes == nil {
		r.Scopes = []model.ScopeResult{}
	}
	if r.AWSSecurityGroups == nil {
		r.AWSSecurityGroups = []model.AWSSecurityGroup{}
	}
	if r.Diagnostics == nil {
		r.Diagnostics = []model.Diagnostic{}
	}
	if r.Errors == nil {
		r.Errors = []model.ScanError{}
	}
	return r
}

func (s *Scanner) callerAccount(ctx context.Context) (string, error) {
	if s.sts == nil {
		return "", errNoSTSClient
	}
	out, err := s.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}
	if out == nil || deref(out.Account) == "" {
		return "", errNoAccount
	}
	return *out.Account, nil
}

// regionOutcome is the result of one region scope.
type regionOutcome struct {
	scope       model.ScopeResult
	groups      []model.AWSSecurityGroup // only groups with findings
	diagnostics []model.Diagnostic
	errors      []model.ScanError
}

// scanRegions scans regions in a bounded worker pool. Every region gets an
// outcome, in input order; a failure never cancels another region. Regions
// not started before ctx ends are failed with kind timeout, without an API
// call.
func (s *Scanner) scanRegions(ctx context.Context, account string, regions []string) []regionOutcome {
	outcomes := make([]regionOutcome, len(regions))
	sem := make(chan struct{}, s.cfg.Concurrency)
	var wg sync.WaitGroup
	for i, region := range regions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
			}
			if err := ctx.Err(); err != nil {
				outcomes[i] = failedRegion(account, region, OpDescribeSecurityGroups,
					fmt.Errorf("%w: %w", errNotStarted, err))
				return
			}
			outcomes[i] = s.scanRegion(ctx, account, region)
		}()
	}
	wg.Wait()
	return outcomes
}

func scopeName(account, region string) string { return account + "/" + region }

func failedRegion(account, region, op string, err error) regionOutcome {
	scope := scopeName(account, region)
	return regionOutcome{
		scope:  model.ScopeResult{Provider: model.ProviderAWS, Scope: scope, Status: model.ScopeFailed},
		errors: []model.ScanError{scanError(scope, op, err)},
	}
}

// scanRegion reads every security group of one region and evaluates it.
//
// All pages are read before any group is evaluated. An error on any page
// fails the whole scope and discards the pages already read, so a partial
// listing is never reported as coverage (DESIGN.md 5.6).
func (s *Scanner) scanRegion(ctx context.Context, account, region string) regionOutcome {
	if !ValidRegion(region) {
		return failedRegion(account, region, OpConfig, errInvalidRegion)
	}
	client := s.clients(region)
	if client == nil {
		return failedRegion(account, region, OpConfig, errNoClient)
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.ScopeTimeout)
	defer cancel()

	groups, err := listSecurityGroups(ctx, client)
	if err != nil {
		return failedRegion(account, region, OpDescribeSecurityGroups, err)
	}

	scope := scopeName(account, region)
	out := regionOutcome{scope: model.ScopeResult{
		Provider:         model.ProviderAWS,
		Scope:            scope,
		ResourcesScanned: len(groups),
	}}
	for _, sg := range groups {
		g := convertGroup(scope, account, region, sg)
		out.scope.RulesEvaluated += g.rulesEvaluated
		out.scope.PrefixListRefsUnexpanded += g.prefixListRefs
		out.diagnostics = append(out.diagnostics, g.diagnostics...)
		if len(g.group.InsecureRules) > 0 {
			out.groups = append(out.groups, g.group)
		}
	}
	out.scope.Status = model.ScopeStatusFor(out.diagnostics)
	return out
}

// listSecurityGroups follows NextToken with the SDK paginator until the
// last page. A token that repeats is an error rather than a silent stop
// (the paginator's StopOnDuplicateToken would end the listing early
// without telling the caller).
func listSecurityGroups(ctx context.Context, client EC2API) ([]types.SecurityGroup, error) {
	p := ec2.NewDescribeSecurityGroupsPaginator(nonNilOutput{client},
		&ec2.DescribeSecurityGroupsInput{MaxResults: awssdk.Int32(pageSize)})
	var groups []types.SecurityGroup
	seen := map[string]bool{}
	for page := 1; p.HasMorePages(); page++ {
		out, err := p.NextPage(ctx)
		if err != nil {
			return nil, &pageError{page: page, err: err}
		}
		groups = append(groups, out.SecurityGroups...)
		if tok := deref(out.NextToken); tok != "" {
			if seen[tok] {
				return nil, &pageError{page: page, err: errRepeatedToken}
			}
			seen[tok] = true
		}
	}
	return groups, nil
}

// nonNilOutput turns a (nil, nil) response into an error, so the SDK
// paginator never dereferences a nil output.
type nonNilOutput struct{ EC2API }

func (c nonNilOutput) DescribeSecurityGroups(ctx context.Context, in *ec2.DescribeSecurityGroupsInput,
	opts ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	out, err := c.EC2API.DescribeSecurityGroups(ctx, in, opts...)
	if err == nil && out == nil {
		return nil, errNoOutput
	}
	return out, err
}
