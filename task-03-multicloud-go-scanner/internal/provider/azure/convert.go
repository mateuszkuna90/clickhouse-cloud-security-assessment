package azure

import (
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/exposure"
	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
)

// Provider field names used in diagnostics and rule references. They are
// the JSON property names of the ARM resource.
const (
	fieldValue                 = "value"
	fieldID                    = "id"
	fieldName                  = "name"
	fieldProperties            = "properties"
	fieldSecurityRules         = "securityRules"
	fieldDefaultSecurityRules  = "defaultSecurityRules"
	fieldSourceAddressPrefix   = "sourceAddressPrefix"
	fieldSourceAddressPrefixes = "sourceAddressPrefixes"
	fieldSourceASGs            = "sourceApplicationSecurityGroups"
	fieldDestinationPortRange  = "destinationPortRange"
)

// nsgResult is the evaluation of one NSG.
type nsgResult struct {
	nsg            model.AzureNSG // InsecureRules may be empty
	rulesEvaluated int
	diagnostics    []model.Diagnostic
}

// convertNSG evaluates every custom and default rule of one NSG.
//
// Rule references are the rule's ARM child path, "securityRules/<name>" or
// "defaultSecurityRules/<name>", so a finding always says whether it came
// from a default rule, and a custom rule can never be confused with a
// default rule of the same name.
//
// Each finding carries the rule priority and whether the NSG is associated
// with any subnet or network interface (context.attached). These are
// triage hints; no effective-reachability analysis is done (DESIGN.md 7):
// a higher-priority Deny may still block the traffic.
//
// The SDK object is only read, never modified.
func convertNSG(subscriptionID string, sg *armnetwork.SecurityGroup) nsgResult {
	id := deref(sg.ID)
	res := nsgResult{nsg: model.AzureNSG{
		ID:             id,
		Name:           deref(sg.Name),
		SubscriptionID: subscriptionID,
		InsecureRules:  []model.InsecureRule{},
	}}
	if id == "" {
		res.diagnostics = append(res.diagnostics, model.Diagnostic{
			Provider: model.ProviderAzure, Scope: subscriptionID,
			Code: model.CodeResourceIDMissing, Field: fieldID,
			Value:  truncate(res.nsg.Name),
			Effect: model.EffectFindingDetailUnknown,
		})
	}
	props := sg.Properties
	if props == nil {
		// Without properties no rule (not even the default rules) could be
		// read, so the NSG was not evaluated.
		res.diagnostics = append(res.diagnostics, model.Diagnostic{
			Provider: model.ProviderAzure, Scope: subscriptionID, ResourceID: id,
			Code: model.CodePropertiesMissing, Field: fieldProperties,
			Effect: model.EffectScopeIncomplete,
		})
		return res
	}
	attached := len(props.Subnets) > 0 || len(props.NetworkInterfaces) > 0

	for _, set := range []struct {
		field string
		rules []*armnetwork.SecurityRule
	}{
		{fieldSecurityRules, props.SecurityRules},
		{fieldDefaultSecurityRules, props.DefaultSecurityRules},
	} {
		for _, rule := range set.rules {
			if rule == nil {
				res.diagnostics = append(res.diagnostics,
					exposure.RuleNil(model.ProviderAzure, subscriptionID, id, set.field))
				continue
			}
			res.rulesEvaluated++
			findings, diags := convertRule(subscriptionID, id, set.field, attached, rule)
			res.nsg.InsecureRules = append(res.nsg.InsecureRules, findings...)
			res.diagnostics = append(res.diagnostics, diags...)
		}
	}
	return res
}

// convertRule evaluates one security rule.
//
// Rule selection (DESIGN.md 6.2): only direction Inbound with access Allow
// can produce a finding. Valid Outbound or Deny rules are ignored without a
// diagnostic. A missing or unrecognised direction or access gives a
// diagnostic and makes the scope incomplete. Enum values are compared
// case-insensitively, as ARM does.
//
// Sources are SourceAddressPrefix, SourceAddressPrefixes and
// SourceApplicationSecurityGroups (selectors, never world-open). Source
// ports are not read: they say nothing about which service is exposed.
// Destination ports come from DestinationPortRange and
// DestinationPortRanges, and are kept even when the protocol is "*".
func convertRule(subscriptionID, nsgID, field string, attached bool,
	rule *armnetwork.SecurityRule) ([]model.InsecureRule, []model.Diagnostic) {
	name := deref(rule.Name)
	ref := field + "/" + name
	var diags []model.Diagnostic
	if name == "" {
		diags = append(diags, model.Diagnostic{
			Provider: model.ProviderAzure, Scope: subscriptionID, ResourceID: nsgID,
			RuleRef: ref, Code: model.CodeResourceIDMissing, Field: fieldName,
			Value:  truncate(deref(rule.ID)),
			Effect: model.EffectFindingDetailUnknown,
		})
	}
	p := rule.Properties
	if p == nil {
		diags = append(diags, model.Diagnostic{
			Provider: model.ProviderAzure, Scope: subscriptionID, ResourceID: nsgID,
			RuleRef: ref, Code: model.CodePropertiesMissing, Field: fieldProperties,
			Effect: model.EffectScopeIncomplete,
		})
		return nil, diags
	}

	r := exposure.Rule{
		Provider:    model.ProviderAzure,
		Scope:       subscriptionID,
		ResourceID:  nsgID,
		RuleRef:     ref,
		Protocol:    string(deref(p.Protocol)),
		PortStyle:   exposure.PortsFromRanges,
		Sources:     ruleSources(p),
		Description: deref(p.Description),
		Context:     ruleContext(p, attached),
	}
	r.Direction, r.DirectionRaw = ruleDirection(p.Direction)
	r.Action, r.ActionRaw = ruleAccess(p.Access)
	ports := destinationPorts(p)
	r.PortRanges = ports

	ev := exposure.Evaluate(r)
	diags = append(diags, ev.Diagnostics...)
	if len(ports) == 0 && len(ev.Findings) > 0 {
		// No destination port field at all. The engine would read that as
		// "no restriction"; it is reported as unknown instead.
		diags = append(diags, markPortsUnknown(ev.Findings, r)...)
	}
	return ev.Findings, diags
}

func ruleDirection(d *armnetwork.SecurityRuleDirection) (exposure.Direction, string) {
	raw := string(deref(d))
	switch {
	case strings.EqualFold(raw, string(armnetwork.SecurityRuleDirectionInbound)):
		return exposure.DirectionInbound, raw
	case strings.EqualFold(raw, string(armnetwork.SecurityRuleDirectionOutbound)):
		return exposure.DirectionOutbound, raw
	}
	return exposure.DirectionUnknown, raw
}

func ruleAccess(a *armnetwork.SecurityRuleAccess) (exposure.Action, string) {
	raw := string(deref(a))
	switch {
	case strings.EqualFold(raw, string(armnetwork.SecurityRuleAccessAllow)):
		return exposure.ActionAllow, raw
	case strings.EqualFold(raw, string(armnetwork.SecurityRuleAccessDeny)):
		return exposure.ActionDeny, raw
	}
	return exposure.ActionUnknown, raw
}

// ruleSources lists the source values of a rule. Empty strings carry no
// address and are skipped; identical prefixes from the single and plural
// fields are listed once. A rule left with no source at all gets the
// engine's source_missing diagnostic.
func ruleSources(p *armnetwork.SecurityRulePropertiesFormat) []exposure.Source {
	var out []exposure.Source
	seen := map[string]bool{}
	addPrefix := func(field string, v *string) {
		s := strings.TrimSpace(deref(v))
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, exposure.Source{Kind: exposure.SourceAzurePrefix, Field: field, Raw: s})
	}
	addPrefix(fieldSourceAddressPrefix, p.SourceAddressPrefix)
	for _, v := range p.SourceAddressPrefixes {
		addPrefix(fieldSourceAddressPrefixes, v)
	}
	// An application security group is a set of NICs, never an address
	// range, so it is a selector even if its ID is missing.
	for _, asg := range p.SourceApplicationSecurityGroups {
		var raw string
		if asg != nil {
			raw = deref(asg.ID)
		}
		out = append(out, exposure.Source{Kind: exposure.SourceSelector, Field: fieldSourceASGs, Raw: raw})
	}
	return out
}

// destinationPorts returns the destination port specs of a rule, trimmed
// and without duplicates. Empty values and nil entries carry no port.
func destinationPorts(p *armnetwork.SecurityRulePropertiesFormat) []string {
	var out []string
	seen := map[string]bool{}
	add := func(v *string) {
		s := strings.TrimSpace(deref(v))
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	add(p.DestinationPortRange)
	for _, v := range p.DestinationPortRanges {
		add(v)
	}
	return out
}

// markPortsUnknown rewrites findings of a rule with no destination port
// field: for protocols that carry ports the port is "unknown", not "all".
// It returns one port_malformed diagnostic if any finding was changed.
// Protocols without ports (icmp, esp, ah) keep "all".
func markPortsUnknown(findings []model.InsecureRule, r exposure.Rule) []model.Diagnostic {
	changed := false
	for i := range findings {
		switch findings[i].Protocol {
		case exposure.ProtoTCP, exposure.ProtoUDP, exposure.ProtoSCTP, exposure.ProtoAll:
			findings[i].Port = model.PortUnknown
			findings[i].FromPort = nil
			findings[i].ToPort = nil
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return []model.Diagnostic{{
		Provider: r.Provider, Scope: r.Scope, ResourceID: r.ResourceID, RuleRef: r.RuleRef,
		Code: model.CodePortMalformed, Field: fieldDestinationPortRange,
		Effect: model.EffectFindingDetailUnknown,
	}}
}

// ruleContext copies the triage facts already in the API response
// (DESIGN.md 7): rule priority and whether the NSG is associated with
// anything. NSG rules have no target list.
func ruleContext(p *armnetwork.SecurityRulePropertiesFormat, attached bool) model.RuleContext {
	ctx := model.RuleContext{Attached: &attached}
	if p.Priority != nil {
		v := int(*p.Priority)
		ctx.Priority = &v
	}
	return ctx
}

// maxDiagnosticValue bounds untrusted values copied into diagnostics here
// (the engine applies the same bound to its own diagnostics).
const maxDiagnosticValue = 256

func truncate(s string) string {
	if len(s) <= maxDiagnosticValue {
		return s
	}
	cut := maxDiagnosticValue
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut]
}
