package gcp

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/exposure"
	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
)

// Defaults (DESIGN.md 5.7).
const (
	DefaultConcurrency  = 8
	DefaultScopeTimeout = 2 * time.Minute
)

// Config selects what the scanner covers.
type Config struct {
	// Projects is the explicit project list (see ResolveProjects). Entries
	// are trimmed and de-duplicated; each one is a scope. Required.
	Projects []string
	// Concurrency is the number of projects scanned in parallel.
	Concurrency int
	// ScopeTimeout bounds the scan of one project.
	ScopeTimeout time.Duration
}

// Scanner scans the VPC firewall rules of a list of GCP projects.
type Scanner struct {
	cfg    Config
	lister FirewallLister
}

// NewScanner returns a scanner that reads firewall rules through lister.
func NewScanner(cfg Config, lister FirewallLister) *Scanner {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = DefaultConcurrency
	}
	if cfg.ScopeTimeout <= 0 {
		cfg.ScopeTimeout = DefaultScopeTimeout
	}
	return &Scanner{cfg: cfg, lister: lister}
}

// Provider returns model.ProviderGCP.
func (s *Scanner) Provider() model.Provider { return model.ProviderGCP }

// Scan never returns an error: every failure is recorded in the result and
// lowers its status (DESIGN.md 3, principle 3).
//
// Status rules:
//   - no projects, or no client: provider failed;
//   - otherwise from the project scopes (model.ProviderStatusFor): one
//     failed project makes the provider partial, and the other projects
//     are still scanned.
func (s *Scanner) Scan(ctx context.Context) model.ProviderResult {
	res := model.ProviderResult{Provider: model.ProviderGCP}
	projects := normalizeProjects(s.cfg.Projects)
	switch {
	case len(projects) == 0:
		res.Status = model.ProviderFailed
		res.Errors = append(res.Errors, scanError("", OpConfig, errNoProjects))
		return finish(res)
	case s.lister == nil:
		res.Status = model.ProviderFailed
		res.Errors = append(res.Errors, scanError("", OpConfig, errNoLister))
		return finish(res)
	}

	for _, o := range s.scanProjects(ctx, projects) {
		res.Scopes = append(res.Scopes, o.scope)
		res.Diagnostics = append(res.Diagnostics, o.diagnostics...)
		res.Errors = append(res.Errors, o.errors...)
		res.GCPFirewallRules = append(res.GCPFirewallRules, o.rules...)
	}
	res.Status = model.ProviderStatusFor(res.Scopes)
	return finish(res)
}

// finish replaces nil slices with empty ones so callers never see nil.
func finish(r model.ProviderResult) model.ProviderResult {
	if r.Scopes == nil {
		r.Scopes = []model.ScopeResult{}
	}
	if r.GCPFirewallRules == nil {
		r.GCPFirewallRules = []model.GCPFirewallRule{}
	}
	if r.Diagnostics == nil {
		r.Diagnostics = []model.Diagnostic{}
	}
	if r.Errors == nil {
		r.Errors = []model.ScanError{}
	}
	return r
}

// projectOutcome is the result of one project scope.
type projectOutcome struct {
	scope       model.ScopeResult
	rules       []model.GCPFirewallRule // only rules with findings
	diagnostics []model.Diagnostic
	errors      []model.ScanError
}

// scanProjects scans projects in a bounded worker pool. Every project gets
// an outcome, in input order; a failure never cancels another project.
// Projects not started before ctx ends are failed with kind timeout,
// without an API call.
func (s *Scanner) scanProjects(ctx context.Context, projects []string) []projectOutcome {
	outcomes := make([]projectOutcome, len(projects))
	sem := make(chan struct{}, s.cfg.Concurrency)
	var wg sync.WaitGroup
	for i, project := range projects {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
			}
			if err := ctx.Err(); err != nil {
				outcomes[i] = failedProject(project, OpListFirewalls,
					fmt.Errorf("%w: %w", errNotStarted, err))
				return
			}
			outcomes[i] = s.scanProject(ctx, project)
		}()
	}
	wg.Wait()
	return outcomes
}

func failedProject(project, op string, err error) projectOutcome {
	return projectOutcome{
		scope:  model.ScopeResult{Provider: model.ProviderGCP, Scope: project, Status: model.ScopeFailed},
		errors: []model.ScanError{scanError(project, op, err)},
	}
}

// scanProject reads every firewall rule of one project and evaluates it.
// The lister returns all pages or an error; on error nothing from the
// project is kept (DESIGN.md 5.6).
func (s *Scanner) scanProject(ctx context.Context, project string) projectOutcome {
	if !ValidProject(project) {
		return failedProject(project, OpConfig, errInvalidProject)
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.ScopeTimeout)
	defer cancel()

	firewalls, err := s.lister.ListFirewalls(ctx, project)
	if err != nil {
		return failedProject(project, OpListFirewalls, err)
	}

	out := projectOutcome{scope: model.ScopeResult{
		Provider:         model.ProviderGCP,
		Scope:            project,
		ResourcesScanned: len(firewalls),
	}}
	for _, fw := range firewalls {
		if fw == nil {
			out.diagnostics = append(out.diagnostics,
				exposure.RuleNil(model.ProviderGCP, project, "", fieldItems))
			continue
		}
		r := convertFirewall(project, fw)
		if r.disabled {
			out.scope.DisabledRulesSkipped++
		}
		if r.evaluated {
			out.scope.RulesEvaluated++
		}
		out.diagnostics = append(out.diagnostics, r.diagnostics...)
		if len(r.rule.InsecureRules) > 0 {
			out.rules = append(out.rules, r.rule)
		}
	}
	out.scope.Status = model.ScopeStatusFor(out.diagnostics)
	return out
}
