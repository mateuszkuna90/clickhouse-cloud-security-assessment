// Package cli is the cloudfw-scan command: it validates the command line,
// builds the selected provider scanners on the standard credential chains,
// runs them (internal/runner), builds the JSON report (internal/report),
// writes it, and returns the exit code (DESIGN.md sections 5 and 8).
//
// Everything the command touches outside the process (stdout, stderr,
// environment, file system, cloud clients) comes through Env, so the whole
// command can be tested offline with fake cloud adapters.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/provider/aws"
	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/provider/azure"
	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/provider/gcp"
	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/report"
	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/runner"
)

// Version is the tool version written into the report.
const Version = "0.1.0"

// Factories build one provider scanner each. close, if non-nil, is called
// after the scan to release idle connections. An error means the scanner
// could not be built (see buildScanners for how each error is reported).
type Factories struct {
	AWS   func(ctx context.Context, bootstrapRegion string, cfg aws.Config) (runner.Scanner, func(), error)
	GCP   func(ctx context.Context, cfg gcp.Config) (runner.Scanner, func(), error)
	Azure func(ctx context.Context, cfg azure.Config) (runner.Scanner, func(), error)
}

// Env is everything the command uses from the outside world.
type Env struct {
	Stdout     io.Writer // the JSON report only
	Stderr     io.Writer // usage errors, the one-line summary
	Getenv     func(string) string
	Factories  Factories
	CreateFile func(path string) (OutputFile, error)
	RemoveFile func(path string) error
	Lstat      func(path string) (fs.FileInfo, error)
	Now        func() time.Time
}

// DefaultEnv uses the real process streams, environment, file system and
// cloud SDKs.
func DefaultEnv() Env {
	return Env{
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
		Getenv:     os.Getenv,
		Factories:  SDKFactories(),
		CreateFile: createExclusive,
		RemoveFile: os.Remove,
		Lstat:      os.Lstat,
		Now:        time.Now,
	}
}

// SDKFactories builds scanners on the official SDKs and the standard
// credential chains (DESIGN.md 5.1). No credential value is passed, read
// or logged here.
func SDKFactories() Factories {
	return Factories{
		AWS: func(ctx context.Context, bootstrap string, cfg aws.Config) (runner.Scanner, func(), error) {
			c, err := aws.LoadConfig(ctx, bootstrap)
			if err != nil {
				return nil, nil, err
			}
			return aws.NewScannerFromConfig(c, cfg), nil, nil
		},
		GCP: func(ctx context.Context, cfg gcp.Config) (runner.Scanner, func(), error) {
			c, err := gcp.NewClient(ctx)
			if err != nil {
				return nil, nil, err
			}
			return gcp.NewScanner(cfg, c), func() { _ = c.Close() }, nil
		},
		Azure: func(_ context.Context, cfg azure.Config) (runner.Scanner, func(), error) {
			c, err := azure.NewClient()
			if err != nil {
				return nil, nil, err
			}
			return azure.NewScanner(cfg, c, c), nil, nil
		},
	}
}

// Operation recorded for a provider whose scanner could not be built.
const OpInit = "init"

// Run is the whole command. It returns the exit code (DESIGN.md 5.8):
//
//	4  the report could not be written            (highest)
//	3  invalid arguments or configuration; no scan
//	2  a selected provider is not complete
//	1  complete, with findings
//	0  complete, no findings                      (lowest)
//
// stdout receives only the JSON report; everything else goes to stderr.
func Run(ctx context.Context, args []string, env Env) int {
	cfg, err := parseArgs(args, env.Getenv, env.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return report.ExitClean
	}
	if err != nil {
		fmt.Fprintf(env.Stderr, "cloudfw-scan: %v\n", err)
		fmt.Fprintln(env.Stderr, "Run 'cloudfw-scan -h' for usage.")
		return report.ExitUsage
	}
	if cfg.output != "" {
		if err := checkOutputPath(cfg.output, env.Lstat); err != nil {
			fmt.Fprintf(env.Stderr, "cloudfw-scan: --%s %q: %v\n", flagOutput, cfg.output, err)
			return report.ExitUsage
		}
	}

	started := env.Now()
	runCtx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()

	scanners, failed, closers, err := buildScanners(runCtx, cfg, env.Factories)
	defer func() {
		for _, c := range closers {
			c()
		}
	}()
	if err != nil {
		fmt.Fprintf(env.Stderr, "cloudfw-scan: %v\n", err)
		return report.ExitUsage
	}

	results := append(runner.Run(runCtx, scanners), failed...)
	cancel()

	opts := report.Options{ToolVersion: Version}
	if cfg.includeTimestamps {
		opts.StartedAt, opts.FinishedAt = started, env.Now()
	}
	rep := report.Build(results, opts)
	code := report.ExitCode(rep)
	data, err := report.Encode(rep)
	if err != nil {
		fmt.Fprintln(env.Stderr, "cloudfw-scan: the report could not be encoded")
		return report.ExitWriteFailed
	}

	if cfg.output != "" {
		err = writeFile(cfg.output, data, env.CreateFile, env.RemoveFile)
	} else {
		err = writeStdout(env.Stdout, data)
	}
	if err != nil {
		fmt.Fprintf(env.Stderr, "cloudfw-scan: %v\n", err)
		return report.ExitWriteFailed
	}
	fmt.Fprintln(env.Stderr, summary(rep, cfg.output, code))
	return code
}

// buildScanners builds a scanner for every selected provider, in a fixed
// order (aws, azure, gcp). AWS is first because its bootstrap region can
// still turn out to be missing (a usage error), and the run must stop with
// exit 3 before any other provider touches the network.
//
// A provider whose scanner cannot be built for any other reason (its
// credential chain cannot be set up) is not a usage error: it becomes a
// failed provider result, and the other providers still run.
func buildScanners(ctx context.Context, cfg config, f Factories) (
	scanners []runner.Scanner, failed []model.ProviderResult, closers []func(), err error) {
	add := func(s runner.Scanner, closeFn func()) {
		scanners = append(scanners, s)
		if closeFn != nil {
			closers = append(closers, closeFn)
		}
	}
	if cfg.selected(model.ProviderAWS) {
		s, c, berr := f.AWS(ctx, cfg.awsBootstrapRegion, aws.Config{
			BootstrapRegion: cfg.awsBootstrapRegion,
			Regions:         cfg.awsRegions,
			Concurrency:     cfg.concurrency,
			ScopeTimeout:    cfg.scopeTimeout,
		})
		switch {
		case errors.Is(berr, aws.ErrNoBootstrapRegion), errors.Is(berr, aws.ErrInvalidBootstrapRegion):
			return nil, nil, closers, &usageError{msg: berr.Error()}
		case berr != nil:
			failed = append(failed, initFailed(model.ProviderAWS, berr))
		default:
			add(s, c)
		}
	}
	if cfg.selected(model.ProviderAzure) {
		s, c, berr := f.Azure(ctx, azure.Config{
			Subscriptions: cfg.azureSubscriptions,
			Concurrency:   cfg.concurrency,
			ScopeTimeout:  cfg.scopeTimeout,
		})
		if berr != nil {
			failed = append(failed, initFailed(model.ProviderAzure, berr))
		} else {
			add(s, c)
		}
	}
	if cfg.selected(model.ProviderGCP) {
		s, c, berr := f.GCP(ctx, gcp.Config{
			Projects:     cfg.gcpProjects,
			Concurrency:  cfg.concurrency,
			ScopeTimeout: cfg.scopeTimeout,
		})
		if berr != nil {
			failed = append(failed, initFailed(model.ProviderGCP, berr))
		} else {
			add(s, c)
		}
	}
	return scanners, failed, closers, nil
}

// initFailed turns a scanner construction error into a failed provider.
// Only the providers' own sentinel errors, whose text is fixed in this
// repository, are quoted; anything else gets a generic sentence.
func initFailed(p model.Provider, err error) model.ProviderResult {
	for _, known := range []struct {
		err  error
		kind string
	}{
		{aws.ErrConfigLoad, model.ErrorKindAuth},
		{aws.ErrCredentialProcessChain, model.ErrorKindAuth},
		{gcp.ErrCredentials, model.ErrorKindAuth},
		{gcp.ErrClientInit, model.ErrorKindOther},
		{azure.ErrCredentials, model.ErrorKindAuth},
	} {
		if errors.Is(err, known.err) {
			return runner.Failed(p, OpInit, known.kind, known.err.Error())
		}
	}
	kind := model.ErrorKindOther
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		kind = model.ErrorKindTimeout
	}
	return runner.Failed(p, OpInit, kind, string(p)+" scanner could not be initialised")
}

// summary is the one-line stderr summary. It contains only statuses and
// counts.
func summary(rep model.Report, output string, code int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "cloudfw-scan: aws=%s gcp=%s azure=%s findings=%d diagnostics=%d errors=%d exit=%d",
		rep.Scan.Providers.AWS, rep.Scan.Providers.GCP, rep.Scan.Providers.Azure,
		rep.Scan.Findings, len(rep.Diagnostics), len(rep.Errors), code)
	if output != "" {
		fmt.Fprintf(&b, " report=%q", output)
	}
	return b.String()
}
