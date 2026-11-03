// Package runner runs the selected provider scanners concurrently under one
// context and collects their results (DESIGN.md sections 3 and 5.7).
//
// Each provider scanner already bounds its own scopes (worker pool,
// per-scope timeout) and never returns a Go error. The runner adds only:
//
//   - concurrency across providers: one provider's failure or slowness
//     never stops another;
//   - a recover guard, so that a bug in one provider becomes a failed
//     provider result instead of a crash with no report;
//   - a deterministic result order (by provider name).
//
// Run returns only when every scanner has returned, so no scanner
// goroutine outlives it. Cancellation and the global deadline are carried
// by ctx, which every scanner passes to its SDK calls.
package runner

import (
	"cmp"
	"context"
	"slices"
	"sync"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
)

// Scanner scans one cloud provider (DESIGN.md section 4). Scan never
// returns an error: failures are recorded in the result.
type Scanner interface {
	Provider() model.Provider
	Scan(ctx context.Context) model.ProviderResult
}

// Operation and message used when a scanner panics. The panic value is not
// reported: it could contain anything.
const (
	OpInternal      = "internal"
	panicMessage    = "internal error: the provider scanner stopped unexpectedly; its results were discarded"
	providerMissing = "internal error: the provider scanner returned no provider name"
)

// Run scans with every scanner concurrently and returns their results
// sorted by provider. A nil entry is ignored.
func Run(ctx context.Context, scanners []Scanner) []model.ProviderResult {
	results := make([]model.ProviderResult, len(scanners))
	var wg sync.WaitGroup
	for i, s := range scanners {
		if s == nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = scanOne(ctx, s)
		}()
	}
	wg.Wait()

	out := make([]model.ProviderResult, 0, len(results))
	for i, r := range results {
		if scanners[i] != nil {
			out = append(out, r)
		}
	}
	slices.SortStableFunc(out, func(a, b model.ProviderResult) int {
		return cmp.Compare(a.Provider, b.Provider)
	})
	return out
}

// scanOne runs one scanner and turns a panic into a failed result.
func scanOne(ctx context.Context, s Scanner) (res model.ProviderResult) {
	p := s.Provider()
	defer func() {
		if recover() != nil {
			res = Failed(p, OpInternal, model.ErrorKindOther, panicMessage)
		}
	}()
	res = s.Scan(ctx)
	if res.Provider == "" {
		return Failed(p, OpInternal, model.ErrorKindOther, providerMissing)
	}
	// The scanner's own provider name is authoritative for the report.
	res.Provider = p
	return res
}

// Failed builds the result of a provider that could not run at all, with
// one error. message must be fixed text: it goes into the report as is.
func Failed(p model.Provider, op, kind, message string) model.ProviderResult {
	return model.ProviderResult{
		Provider:          p,
		Status:            model.ProviderFailed,
		Scopes:            []model.ScopeResult{},
		AWSSecurityGroups: []model.AWSSecurityGroup{},
		GCPFirewallRules:  []model.GCPFirewallRule{},
		AzureNSGs:         []model.AzureNSG{},
		Diagnostics:       []model.Diagnostic{},
		Errors: []model.ScanError{{
			Provider: p, Operation: op, Kind: kind, Message: message,
		}},
	}
}
