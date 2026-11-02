package azure

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
	// Subscriptions is the explicit subscription ID list
	// (--azure-subscriptions). When empty, subscriptions are discovered
	// with SubscriptionLister. Entries are trimmed and de-duplicated; each
	// one is a scope and is always scanned.
	Subscriptions []string
	// Concurrency is the number of subscriptions scanned in parallel.
	Concurrency int
	// ScopeTimeout bounds subscription discovery and the scan of one
	// subscription.
	ScopeTimeout time.Duration
}

// Scanner scans the NSGs of a set of Azure subscriptions.
type Scanner struct {
	cfg  Config
	subs SubscriptionLister
	nsgs NSGLister
}

// NewScanner returns a scanner. subs is used only when cfg.Subscriptions
// is empty and may then be nil.
func NewScanner(cfg Config, subs SubscriptionLister, nsgs NSGLister) *Scanner {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = DefaultConcurrency
	}
	if cfg.ScopeTimeout <= 0 {
		cfg.ScopeTimeout = DefaultScopeTimeout
	}
	return &Scanner{cfg: cfg, subs: subs, nsgs: nsgs}
}

// Provider returns model.ProviderAzure.
func (s *Scanner) Provider() model.Provider { return model.ProviderAzure }

// Scan never returns an error: every failure is recorded in the result and
// lowers its status (DESIGN.md 3, principle 3).
//
// Status rules (DESIGN.md 5.5):
//   - no NSG client, no subscription client (discovery only), or a failed
//     discovery: provider failed;
//   - discovery returning zero subscriptions: provider failed with
//     no_scopes_discovered;
//   - otherwise from the subscription scopes (model.ProviderStatusFor):
//     a failed subscription, including a discovered record with a missing
//     or invalid ID, makes the provider partial, and the other
//     subscriptions are still scanned. A skipped (Deleted) subscription
//     does not lower the status.
func (s *Scanner) Scan(ctx context.Context) model.ProviderResult {
	res := model.ProviderResult{Provider: model.ProviderAzure}
	failSetup := func(op string, err error) model.ProviderResult {
		res.Status = model.ProviderFailed
		res.Errors = append(res.Errors, scanError("", op, err))
		return finish(res)
	}
	if s.nsgs == nil {
		return failSetup(OpConfig, errNoNSGLister)
	}

	var targets []Subscription
	if len(s.cfg.Subscriptions) > 0 {
		targets = explicitSubscriptions(s.cfg.Subscriptions)
	} else {
		if s.subs == nil {
			return failSetup(OpConfig, errNoSubscriptionLister)
		}
		dctx, cancel := context.WithTimeout(ctx, s.cfg.ScopeTimeout)
		discovered, err := s.subs.ListSubscriptions(dctx)
		cancel()
		if err != nil {
			return failSetup(OpListSubscriptions, err)
		}
		targets = normalizeSubscriptions(discovered)
		if len(targets) == 0 {
			res.Status = model.ProviderFailed
			res.Diagnostics = append(res.Diagnostics, model.Diagnostic{
				Provider: model.ProviderAzure,
				Code:     model.CodeNoScopesDiscovered, Field: "subscriptions",
				Effect: model.EffectProviderFailed,
			})
			return finish(res)
		}
	}

	for _, o := range s.scanSubscriptions(ctx, targets) {
		res.Scopes = append(res.Scopes, o.scope)
		res.Diagnostics = append(res.Diagnostics, o.diagnostics...)
		res.Errors = append(res.Errors, o.errors...)
		res.AzureNSGs = append(res.AzureNSGs, o.nsgs...)
	}
	res.Status = model.ProviderStatusFor(res.Scopes)
	return finish(res)
}

// finish replaces nil slices with empty ones so callers never see nil.
func finish(r model.ProviderResult) model.ProviderResult {
	if r.Scopes == nil {
		r.Scopes = []model.ScopeResult{}
	}
	if r.AzureNSGs == nil {
		r.AzureNSGs = []model.AzureNSG{}
	}
	if r.Diagnostics == nil {
		r.Diagnostics = []model.Diagnostic{}
	}
	if r.Errors == nil {
		r.Errors = []model.ScanError{}
	}
	return r
}

// subscriptionOutcome is the result of one subscription scope.
type subscriptionOutcome struct {
	scope       model.ScopeResult
	nsgs        []model.AzureNSG // only NSGs with findings
	diagnostics []model.Diagnostic
	errors      []model.ScanError
}

// baseScope is the scope record of a subscription: its ID and, for
// discovered subscriptions, the raw API state (null for explicit entries).
// A record without an ID is still listed, with an empty scope name. The ID
// is truncated because a discovered value comes from the API.
func baseScope(sub Subscription) model.ScopeResult {
	sr := model.ScopeResult{Provider: model.ProviderAzure, Scope: truncate(sub.ID)}
	if sub.HasState {
		st := string(sub.State)
		sr.SubscriptionState = &st
	}
	return sr
}

func failedSubscription(sub Subscription, op string, err error) subscriptionOutcome {
	sr := baseScope(sub)
	sr.Status = model.ScopeFailed
	return subscriptionOutcome{scope: sr, errors: []model.ScanError{scanError(sr.Scope, op, err)}}
}

// scanSubscriptions scans subscriptions in a bounded worker pool. Every
// subscription gets an outcome, in input order; a failure never cancels
// another subscription.
//
// Decided without an API call, in this order: a missing or invalid ID
// fails the scope, whatever the record's state (a record that cannot be
// identified is never trusted to be Deleted); a valid ID the API reports as
// Deleted is skipped; a subscription not started before ctx ends fails
// with kind timeout.
func (s *Scanner) scanSubscriptions(ctx context.Context, subs []Subscription) []subscriptionOutcome {
	outcomes := make([]subscriptionOutcome, len(subs))
	sem := make(chan struct{}, s.cfg.Concurrency)
	var wg sync.WaitGroup
	for i, sub := range subs {
		switch {
		case sub.ID == "" && sub.HasState:
			outcomes[i] = failedSubscription(sub, OpListSubscriptions, errNoSubscriptionID)
			continue
		case !ValidSubscriptionID(sub.ID):
			outcomes[i] = failedSubscription(sub, OpConfig, errInvalidSubscriptionID)
			continue
		case !shouldScan(sub):
			sr := baseScope(sub)
			sr.Status = model.ScopeSkipped
			outcomes[i] = subscriptionOutcome{scope: sr}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
			}
			if err := ctx.Err(); err != nil {
				outcomes[i] = failedSubscription(sub, OpListNSGs, fmt.Errorf("%w: %w", errNotStarted, err))
				return
			}
			outcomes[i] = s.scanSubscription(ctx, sub)
		}()
	}
	wg.Wait()
	return outcomes
}

// scanSubscription reads every NSG of one subscription and evaluates it.
// The lister returns all pages or an error; on error nothing from the
// subscription is kept (DESIGN.md 5.6).
func (s *Scanner) scanSubscription(ctx context.Context, sub Subscription) subscriptionOutcome {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.ScopeTimeout)
	defer cancel()

	groups, err := s.nsgs.ListNSGs(ctx, sub.ID)
	if err != nil {
		return failedSubscription(sub, OpListNSGs, err)
	}

	out := subscriptionOutcome{scope: baseScope(sub)}
	out.scope.ResourcesScanned = len(groups)
	for _, sg := range groups {
		if sg == nil {
			out.diagnostics = append(out.diagnostics,
				exposure.RuleNil(model.ProviderAzure, sub.ID, "", fieldValue))
			continue
		}
		r := convertNSG(sub.ID, sg)
		out.scope.RulesEvaluated += r.rulesEvaluated
		out.diagnostics = append(out.diagnostics, r.diagnostics...)
		if len(r.nsg.InsecureRules) > 0 {
			out.nsgs = append(out.nsgs, r.nsg)
		}
	}
	out.scope.Status = model.ScopeStatusFor(out.diagnostics)
	return out
}
