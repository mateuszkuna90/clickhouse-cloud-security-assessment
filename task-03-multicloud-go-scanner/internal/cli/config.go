package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/provider/aws"
	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/provider/azure"
	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/provider/gcp"
)

// Flag names (DESIGN.md 5.2-5.7). --providers is not named in DESIGN.md;
// it selects the clouds explicitly so that a run never scans a cloud the
// user did not ask for just because credentials happen to be present.
const (
	flagProviders          = "providers"
	flagAWSRegions         = "aws-regions"
	flagAWSBootstrapRegion = "aws-bootstrap-region"
	flagGCPProjects        = "gcp-projects"
	flagAzureSubscriptions = "azure-subscriptions"
	flagOutput             = "output"
	flagTimeout            = "timeout"
	flagScopeTimeout       = "scope-timeout"
	flagConcurrency        = "concurrency"
	flagIncludeTimestamps  = "include-timestamps"
)

// Defaults (DESIGN.md 5.7) and limits.
const (
	DefaultTimeout      = 10 * time.Minute
	DefaultScopeTimeout = 2 * time.Minute
	DefaultConcurrency  = 8
	MaxConcurrency      = 64
)

// usageError is a configuration or argument error: exit 3, no scan. Its
// text may quote values the user supplied, never secrets or SDK output.
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

func usagef(format string, a ...any) error { return &usageError{msg: fmt.Sprintf(format, a...)} }

// config is the validated command line.
type config struct {
	providers          []model.Provider // sorted, de-duplicated
	awsRegions         []string
	awsBootstrapRegion string
	gcpProjects        []string
	azureSubscriptions []string
	output             string
	timeout            time.Duration
	scopeTimeout       time.Duration
	concurrency        int
	includeTimestamps  bool
}

func (c config) selected(p model.Provider) bool { return slices.Contains(c.providers, p) }

const usageText = `Usage: cloudfw-scan --providers LIST [options]

Scans AWS Security Groups, GCP VPC firewall rules and Azure NSGs for
inbound rules open to 0.0.0.0/0 and writes a JSON report (stdout by
default). Read-only; credentials come from each cloud's standard chain.

Options:
`

const exitText = `
Exit codes:
  0  complete scan, no findings
  1  complete scan, at least one finding
  2  scan not complete (a provider is partial or failed); report still written
  3  invalid arguments or configuration; nothing scanned
  4  the report could not be written
`

// parseArgs parses and validates the command line. It returns
// flag.ErrHelp for -h/--help, a *usageError for anything invalid, and
// never touches the network or a cloud credential.
func parseArgs(args []string, getenv func(string) string, stderr io.Writer) (config, error) {
	cfg := config{}
	fs := flag.NewFlagSet("cloudfw-scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), usageText)
		fs.PrintDefaults()
		fmt.Fprint(fs.Output(), exitText)
	}
	providers := fs.String(flagProviders, "", "comma-separated clouds to scan: aws, gcp, azure (required)")
	awsRegions := fs.String(flagAWSRegions, "", "comma-separated AWS regions (default: every region enabled for the account)")
	fs.StringVar(&cfg.awsBootstrapRegion, flagAWSBootstrapRegion, "",
		"AWS region for STS and region discovery; also selects the partition (default: AWS_REGION / profile region)")
	gcpProjects := fs.String(flagGCPProjects, "", "comma-separated GCP project IDs (default: "+gcp.EnvProject+")")
	azureSubs := fs.String(flagAzureSubscriptions, "",
		"comma-separated Azure subscription IDs (default: every subscription the identity can list, except Deleted)")
	fs.StringVar(&cfg.output, flagOutput, "", "write the report to this new file instead of stdout; never overwrites")
	fs.DurationVar(&cfg.timeout, flagTimeout, DefaultTimeout, "deadline for the whole run")
	fs.DurationVar(&cfg.scopeTimeout, flagScopeTimeout, DefaultScopeTimeout, "deadline for one region, project or subscription")
	fs.IntVar(&cfg.concurrency, flagConcurrency, DefaultConcurrency, "scopes scanned in parallel per provider (1-64)")
	fs.BoolVar(&cfg.includeTimestamps, flagIncludeTimestamps, false, "add started_at / finished_at to the report")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return config{}, flag.ErrHelp
		}
		// The flag package has already printed the problem.
		return config{}, usagef("invalid arguments")
	}
	if fs.NArg() > 0 {
		return config{}, usagef("unexpected argument %q (all options are flags)", fs.Arg(0))
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	var err error
	if !set[flagProviders] {
		return config{}, usagef("--%s is required (aws, gcp, azure)", flagProviders)
	}
	if cfg.providers, err = parseProviders(*providers); err != nil {
		return config{}, err
	}

	// Provider-specific flags are only allowed with their provider, so a
	// typo in --providers cannot silently drop a scope the user listed.
	for _, dep := range []struct {
		flag     string
		provider model.Provider
	}{
		{flagAWSRegions, model.ProviderAWS},
		{flagAWSBootstrapRegion, model.ProviderAWS},
		{flagGCPProjects, model.ProviderGCP},
		{flagAzureSubscriptions, model.ProviderAzure},
	} {
		if set[dep.flag] && !cfg.selected(dep.provider) {
			return config{}, usagef("--%s needs %q in --%s", dep.flag, dep.provider, flagProviders)
		}
	}

	if set[flagAWSRegions] {
		if cfg.awsRegions, err = parseList(flagAWSRegions, *awsRegions, aws.ValidRegion, "AWS region"); err != nil {
			return config{}, err
		}
	}
	if set[flagAWSBootstrapRegion] && !aws.ValidRegion(cfg.awsBootstrapRegion) {
		return config{}, usagef("--%s: invalid AWS region %q", flagAWSBootstrapRegion, cfg.awsBootstrapRegion)
	}
	if set[flagAzureSubscriptions] {
		if cfg.azureSubscriptions, err = parseList(flagAzureSubscriptions, *azureSubs,
			azure.ValidSubscriptionID, "Azure subscription ID"); err != nil {
			return config{}, err
		}
	}
	if cfg.selected(model.ProviderGCP) {
		if set[flagGCPProjects] {
			if cfg.gcpProjects, err = parseList(flagGCPProjects, *gcpProjects, gcp.ValidProject, "GCP project ID"); err != nil {
				return config{}, err
			}
		} else {
			cfg.gcpProjects = gcp.ResolveProjects(nil, getenv)
			if len(cfg.gcpProjects) == 0 {
				return config{}, usagef("gcp selected but no project: set --%s or %s", flagGCPProjects, gcp.EnvProject)
			}
			if !gcp.ValidProject(cfg.gcpProjects[0]) {
				return config{}, usagef("%s: invalid GCP project ID %q", gcp.EnvProject, cfg.gcpProjects[0])
			}
		}
	}

	switch {
	case cfg.timeout <= 0:
		return config{}, usagef("--%s must be positive", flagTimeout)
	case cfg.scopeTimeout <= 0:
		return config{}, usagef("--%s must be positive", flagScopeTimeout)
	case cfg.concurrency < 1 || cfg.concurrency > MaxConcurrency:
		return config{}, usagef("--%s must be between 1 and %d", flagConcurrency, MaxConcurrency)
	}
	if set[flagOutput] && strings.TrimSpace(cfg.output) == "" {
		return config{}, usagef("--%s is empty", flagOutput)
	}
	return cfg, nil
}

func parseProviders(raw string) ([]model.Provider, error) {
	items, err := splitList(flagProviders, raw)
	if err != nil {
		return nil, err
	}
	var out []model.Provider
	for _, it := range items {
		switch p := model.Provider(it); p {
		case model.ProviderAWS, model.ProviderGCP, model.ProviderAzure:
			out = append(out, p)
		default:
			return nil, usagef("--%s: unknown provider %q (use aws, gcp, azure)", flagProviders, it)
		}
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// parseList splits a comma-separated flag value, rejects empty lists and
// empty entries, and checks every entry's syntax. Whether a well-formed
// region, project or subscription exists is found out when it is scanned
// (a failed scope, exit 2).
func parseList(name, raw string, valid func(string) bool, what string) ([]string, error) {
	items, err := splitList(name, raw)
	if err != nil {
		return nil, err
	}
	for _, it := range items {
		if !valid(it) {
			return nil, usagef("--%s: invalid %s %q", name, what, it)
		}
	}
	return items, nil
}

func splitList(name, raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, usagef("--%s is empty", name)
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			return nil, usagef("--%s has an empty entry", name)
		}
		out = append(out, p)
	}
	return out, nil
}
