// Package report assembles provider results into the JSON report, with a
// total sort order so that output does not depend on API or goroutine order
// (DESIGN.md sections 5.8, 6.6 and 8).
package report

import (
	"bytes"
	"cmp"
	"encoding/json"
	"slices"
	"time"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
)

// ToolName is the CLI name written into the report.
const ToolName = "cloudfw-scan"

// Exit codes (DESIGN.md 5.8). 3 and 4 are decided by the CLI.
const (
	ExitClean       = 0
	ExitFindings    = 1
	ExitIncomplete  = 2
	ExitUsage       = 3
	ExitWriteFailed = 4
)

// Options for Build.
type Options struct {
	ToolVersion string
	// StartedAt and FinishedAt are written only when non-zero
	// (--include-timestamps). Zero values keep the output byte-stable.
	StartedAt  time.Time
	FinishedAt time.Time
}

// Build merges provider results into a report. Providers without a result
// are "not_selected". Input slices are not modified.
func Build(results []model.ProviderResult, opts Options) model.Report {
	r := model.Report{
		SchemaVersion: model.SchemaVersion,
		Tool:          model.Tool{Name: ToolName, Version: opts.ToolVersion},
		Scan: model.Scan{
			Providers: model.ProviderStatuses{
				AWS:   model.ProviderNotSelected,
				GCP:   model.ProviderNotSelected,
				Azure: model.ProviderNotSelected,
			},
			Scopes: []model.ScopeResult{},
		},
		AWS:         model.AWSSection{SecurityGroups: []model.AWSSecurityGroup{}},
		GCP:         model.GCPSection{FirewallRules: []model.GCPFirewallRule{}},
		Azure:       model.AzureSection{NSGs: []model.AzureNSG{}},
		Diagnostics: []model.Diagnostic{},
		Errors:      []model.ScanError{},
	}
	if !opts.StartedAt.IsZero() {
		r.Scan.StartedAt = opts.StartedAt.UTC().Format(time.RFC3339)
	}
	if !opts.FinishedAt.IsZero() {
		r.Scan.FinishedAt = opts.FinishedAt.UTC().Format(time.RFC3339)
	}

	for _, pr := range results {
		switch pr.Provider {
		case model.ProviderAWS:
			r.Scan.Providers.AWS = pr.Status
		case model.ProviderGCP:
			r.Scan.Providers.GCP = pr.Status
		case model.ProviderAzure:
			r.Scan.Providers.Azure = pr.Status
		}
		r.Scan.Scopes = append(r.Scan.Scopes, pr.Scopes...)
		r.Diagnostics = append(r.Diagnostics, pr.Diagnostics...)
		r.Errors = append(r.Errors, pr.Errors...)
		for _, sg := range pr.AWSSecurityGroups {
			if sg.InsecureRules = normaliseRules(sg.InsecureRules); len(sg.InsecureRules) > 0 {
				r.AWS.SecurityGroups = append(r.AWS.SecurityGroups, sg)
			}
		}
		for _, fw := range pr.GCPFirewallRules {
			if fw.InsecureRules = normaliseRules(fw.InsecureRules); len(fw.InsecureRules) > 0 {
				r.GCP.FirewallRules = append(r.GCP.FirewallRules, fw)
			}
		}
		for _, nsg := range pr.AzureNSGs {
			if nsg.InsecureRules = normaliseRules(nsg.InsecureRules); len(nsg.InsecureRules) > 0 {
				r.Azure.NSGs = append(r.Azure.NSGs, nsg)
			}
		}
	}

	slices.SortFunc(r.Scan.Scopes, compareScopes)
	slices.SortFunc(r.AWS.SecurityGroups, func(a, b model.AWSSecurityGroup) int {
		return cmp.Or(cmp.Compare(a.AccountID, b.AccountID), cmp.Compare(a.Region, b.Region),
			cmp.Compare(a.ID, b.ID), cmp.Compare(a.Name, b.Name), cmp.Compare(a.VPCID, b.VPCID))
	})
	slices.SortFunc(r.GCP.FirewallRules, func(a, b model.GCPFirewallRule) int {
		return cmp.Or(cmp.Compare(a.Project, b.Project), cmp.Compare(a.Name, b.Name),
			cmp.Compare(a.ID, b.ID), cmp.Compare(a.Network, b.Network))
	})
	slices.SortFunc(r.Azure.NSGs, func(a, b model.AzureNSG) int {
		return cmp.Or(cmp.Compare(a.SubscriptionID, b.SubscriptionID), cmp.Compare(a.ID, b.ID),
			cmp.Compare(a.Name, b.Name))
	})
	slices.SortFunc(r.Diagnostics, compareDiagnostics)
	slices.SortFunc(r.Errors, compareErrors)

	for _, sg := range r.AWS.SecurityGroups {
		r.Scan.Findings += len(sg.InsecureRules)
	}
	for _, fw := range r.GCP.FirewallRules {
		r.Scan.Findings += len(fw.InsecureRules)
	}
	for _, nsg := range r.Azure.NSGs {
		r.Scan.Findings += len(nsg.InsecureRules)
	}
	return r
}

// normaliseRules returns a sorted copy of rules with duplicates merged.
// Two findings are duplicates when they share rule ref, protocol, port,
// port range, ICMP fields and source (DESIGN.md 6.6); the first in sort
// order is kept. The key fields lead the sort order, so duplicates are
// adjacent after sorting.
func normaliseRules(in []model.InsecureRule) []model.InsecureRule {
	out := slices.Clone(in)
	for i := range out {
		out[i].Context.Targets = canonicalTargets(out[i].Context.Targets)
	}
	slices.SortFunc(out, compareRules)
	return slices.CompactFunc(out, func(a, b model.InsecureRule) bool {
		return compareRuleKey(a, b) == 0
	})
}

// canonicalTargets returns a sorted copy of a target list with duplicate
// entries removed, so that equivalent target sets encode identically. The
// caller's slice is never modified. nil stays nil (JSON null: targets not
// applicable); an empty list stays empty (JSON []).
func canonicalTargets(in []string) []string {
	if in == nil {
		return nil
	}
	out := slices.Clone(in)
	slices.Sort(out)
	return slices.Compact(out)
}

func compareRuleKey(a, b model.InsecureRule) int {
	return cmp.Or(
		cmp.Compare(a.Protocol, b.Protocol),
		compareIntPtr(a.FromPort, b.FromPort),
		compareIntPtr(a.ToPort, b.ToPort),
		compareIntPtr(a.ICMPType, b.ICMPType),
		compareIntPtr(a.ICMPCode, b.ICMPCode),
		cmp.Compare(a.Port, b.Port),
		cmp.Compare(a.Source, b.Source),
		cmp.Compare(a.RuleRef, b.RuleRef),
	)
}

func compareRules(a, b model.InsecureRule) int {
	return cmp.Or(
		compareRuleKey(a, b),
		cmp.Compare(a.ProviderSource, b.ProviderSource),
		cmp.Compare(a.ProviderProtocol, b.ProviderProtocol),
		cmp.Compare(a.ProviderPort, b.ProviderPort),
		cmp.Compare(a.MatchReason, b.MatchReason),
		cmp.Compare(a.Description, b.Description),
		compareIntPtr(a.Context.Priority, b.Context.Priority),
		compareTargets(a.Context.Targets, b.Context.Targets),
		compareBoolPtr(a.Context.Attached, b.Context.Attached),
		cmp.Compare(a.Reachability, b.Reachability),
	)
}

func compareScopes(a, b model.ScopeResult) int {
	return cmp.Or(
		cmp.Compare(a.Provider, b.Provider),
		cmp.Compare(a.Scope, b.Scope),
		cmp.Compare(a.Status, b.Status),
		cmp.Compare(a.ResourcesScanned, b.ResourcesScanned),
		cmp.Compare(a.RulesEvaluated, b.RulesEvaluated),
		cmp.Compare(a.DisabledRulesSkipped, b.DisabledRulesSkipped),
		cmp.Compare(a.PrefixListRefsUnexpanded, b.PrefixListRefsUnexpanded),
		compareStringPtr(a.SubscriptionState, b.SubscriptionState),
	)
}

func compareDiagnostics(a, b model.Diagnostic) int {
	return cmp.Or(
		cmp.Compare(a.Provider, b.Provider),
		cmp.Compare(a.Scope, b.Scope),
		cmp.Compare(a.ResourceID, b.ResourceID),
		cmp.Compare(a.RuleRef, b.RuleRef),
		cmp.Compare(a.Code, b.Code),
		cmp.Compare(a.Field, b.Field),
		cmp.Compare(a.Value, b.Value),
		cmp.Compare(a.Effect, b.Effect),
	)
}

func compareErrors(a, b model.ScanError) int {
	return cmp.Or(
		cmp.Compare(a.Provider, b.Provider),
		cmp.Compare(a.Scope, b.Scope),
		cmp.Compare(a.Operation, b.Operation),
		cmp.Compare(a.Kind, b.Kind),
		cmp.Compare(a.Message, b.Message),
	)
}

// compareTargets orders canonical target lists: nil before empty, then
// element by element.
func compareTargets(a, b []string) int {
	if (a == nil) != (b == nil) {
		if a == nil {
			return -1
		}
		return 1
	}
	return slices.Compare(a, b)
}

// nil sorts before any value.
func compareIntPtr(a, b *int) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1
	case b == nil:
		return 1
	}
	return cmp.Compare(*a, *b)
}

func compareStringPtr(a, b *string) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1
	case b == nil:
		return 1
	}
	return cmp.Compare(*a, *b)
}

func compareBoolPtr(a, b *bool) int {
	toInt := func(p *bool) int {
		switch {
		case p == nil:
			return 0
		case !*p:
			return 1
		default:
			return 2
		}
	}
	return cmp.Compare(toInt(a), toInt(b))
}

// ExitCode returns 0, 1 or 2 for a built report (DESIGN.md 5.8). Exit 2
// (scan not fully evaluated) outranks exit 1 (findings).
func ExitCode(r model.Report) int {
	for _, s := range []model.ProviderStatus{r.Scan.Providers.AWS, r.Scan.Providers.GCP, r.Scan.Providers.Azure} {
		if s != model.ProviderComplete && s != model.ProviderNotSelected {
			return ExitIncomplete
		}
	}
	if r.Scan.Findings > 0 {
		return ExitFindings
	}
	return ExitClean
}

// Encode renders the report as indented JSON with a trailing newline.
// HTML escaping is off so that values such as "<" stay readable; the
// output is still valid, fully escaped JSON.
func Encode(r model.Report) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
