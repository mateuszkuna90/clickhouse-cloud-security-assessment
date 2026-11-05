package gcp

import (
	"strconv"

	compute "google.golang.org/api/compute/v1"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/exposure"
	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
)

// Firewall direction values. They are compared case-sensitively: the API
// returns these exact strings, and anything else is reported rather than
// guessed (DESIGN.md 6.2).
const (
	directionIngress = "INGRESS"
	directionEgress  = "EGRESS"
)

// Provider field names used in diagnostics.
const (
	fieldSourceRanges          = "sourceRanges"
	fieldSourceTags            = "sourceTags"
	fieldSourceServiceAccounts = "sourceServiceAccounts"
	fieldAllowed               = "allowed"
	fieldItems                 = "items"
	fieldName                  = "name"
)

// Prefixes that keep the two kinds of target apart in context.targets.
// The "serviceAccount:" form matches Google's IAM member syntax.
const (
	targetAllInstances = "all_instances"
	targetTagPrefix    = "tag:"
	targetSAPrefix     = "serviceAccount:"
)

// firewallResult is the evaluation of one firewall rule.
type firewallResult struct {
	rule        model.GCPFirewallRule // InsecureRules may be empty
	evaluated   bool                  // false for disabled rules
	disabled    bool
	diagnostics []model.Diagnostic
}

// convertFirewall evaluates one VPC firewall rule.
//
// Rule selection (DESIGN.md 6.2):
//
//   - disabled: true  -> not evaluated; counted as skipped. A disabled rule
//     allows nothing.
//   - direction INGRESS or empty (the API default) -> evaluated;
//     EGRESS -> valid and out of scope: no finding, no diagnostic;
//     any other value -> direction_unrecognised, scope incomplete.
//   - allowed[] non-empty -> allow rule; only denied[] -> deny rule (no
//     finding); neither -> action_missing, scope incomplete.
//
// Sources: sourceRanges are OR-ed with sourceTags and sourceServiceAccounts.
// A world range is world-open whatever tags are also listed; tags and
// service accounts alone are selectors and never world-open. Only a rule
// with no source of any kind gets the API default source 0.0.0.0/0.
//
// Each allowed[] entry is one exposure.Rule (its protocol and ports), with
// the firewall's sources. Findings are not a reachability verdict.
func convertFirewall(project string, fw *compute.Firewall) firewallResult {
	name := fw.Name
	resourceID := "projects/" + project + "/global/firewalls/" + name
	res := firewallResult{
		rule: model.GCPFirewallRule{
			Name:          name,
			Network:       fw.Network,
			Project:       project,
			ID:            firewallID(fw),
			Direction:     fw.Direction,
			InsecureRules: []model.InsecureRule{},
		},
	}
	if name == "" {
		resourceID = ""
		res.diagnostics = append(res.diagnostics, model.Diagnostic{
			Provider: model.ProviderGCP, Scope: project,
			Code: model.CodeResourceIDMissing, Field: fieldName,
			Value:  res.rule.ID,
			Effect: model.EffectFindingDetailUnknown,
		})
	}

	if fw.Disabled {
		res.disabled = true
		return res
	}
	res.evaluated = true

	base := exposure.Rule{
		Provider:     model.ProviderGCP,
		Scope:        project,
		ResourceID:   resourceID,
		RuleRef:      name,
		DirectionRaw: fw.Direction,
		PortStyle:    exposure.PortsFromRanges,
		Sources:      firewallSources(fw),
		Description:  fw.Description,
		Context:      firewallContext(fw),
	}
	switch fw.Direction {
	case directionIngress, "":
		base.Direction = exposure.DirectionInbound
	case directionEgress:
		base.Direction = exposure.DirectionOutbound
	default:
		base.Direction = exposure.DirectionUnknown
	}
	switch {
	case len(fw.Allowed) > 0:
		base.Action = exposure.ActionAllow
		base.ActionRaw = fieldAllowed
	case len(fw.Denied) > 0:
		base.Action = exposure.ActionDeny
		base.ActionRaw = "denied"
	default:
		base.Action = exposure.ActionMissing
	}

	// Direction and action are properties of the whole firewall rule, so
	// anything other than an inbound allow is decided once, not once per
	// allowed entry.
	if base.Direction != exposure.DirectionInbound || base.Action != exposure.ActionAllow {
		res.diagnostics = append(res.diagnostics, exposure.Evaluate(base).Diagnostics...)
		return res
	}

	seen := map[model.Diagnostic]bool{}
	addDiag := func(d model.Diagnostic) {
		if !seen[d] {
			seen[d] = true
			res.diagnostics = append(res.diagnostics, d)
		}
	}
	for _, a := range fw.Allowed {
		if a == nil {
			d := exposure.RuleNil(model.ProviderGCP, project, resourceID, fieldAllowed)
			d.RuleRef = name
			addDiag(d)
			continue
		}
		rule := base
		rule.Protocol = a.IPProtocol
		rule.PortRanges = a.Ports
		ev := exposure.Evaluate(rule)
		res.rule.InsecureRules = append(res.rule.InsecureRules, ev.Findings...)
		// Source diagnostics are the same for every allowed entry; report
		// each once.
		for _, d := range ev.Diagnostics {
			addDiag(d)
		}
	}
	return res
}

// firewallSources lists every source selector of the rule. With none at
// all, the rule gets the GCP default source (0.0.0.0/0 for ingress).
func firewallSources(fw *compute.Firewall) []exposure.Source {
	var out []exposure.Source
	for _, r := range fw.SourceRanges {
		out = append(out, exposure.Source{Kind: exposure.SourceAddress, Field: fieldSourceRanges, Raw: r})
	}
	for _, t := range fw.SourceTags {
		out = append(out, exposure.Source{Kind: exposure.SourceSelector, Field: fieldSourceTags, Raw: t})
	}
	for _, sa := range fw.SourceServiceAccounts {
		out = append(out, exposure.Source{Kind: exposure.SourceSelector, Field: fieldSourceServiceAccounts, Raw: sa})
	}
	if len(out) == 0 {
		out = append(out, exposure.Source{Kind: exposure.SourceGCPDefault, Field: fieldSourceRanges})
	}
	return out
}

// firewallContext copies the triage facts already in the API response
// (DESIGN.md 7): priority, and the targets the rule applies to. A rule with
// no target tags or service accounts applies to every instance in the
// network.
func firewallContext(fw *compute.Firewall) model.RuleContext {
	ctx := model.RuleContext{}
	// The REST type cannot tell a missing priority from priority 0 (a valid
	// value). The API always returns the field (default 1000), so it is
	// always copied.
	p := int(fw.Priority)
	ctx.Priority = &p
	targets := []string{}
	for _, t := range fw.TargetTags {
		targets = append(targets, targetTagPrefix+t)
	}
	for _, sa := range fw.TargetServiceAccounts {
		targets = append(targets, targetSAPrefix+sa)
	}
	if len(targets) == 0 {
		targets = append(targets, targetAllInstances)
	}
	ctx.Targets = targets
	return ctx
}

// firewallID renders the numeric rule ID; "" if the API gave none (rule IDs
// are never 0).
func firewallID(fw *compute.Firewall) string {
	if fw.Id == 0 {
		return ""
	}
	return strconv.FormatUint(fw.Id, 10)
}
