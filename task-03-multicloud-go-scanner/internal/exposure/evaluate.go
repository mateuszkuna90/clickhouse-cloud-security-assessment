package exposure

import (
	"unicode/utf8"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
)

// Direction of a rule, as decided by the provider package. Each provider
// maps its own values (AWS IpPermissions = inbound, GCP INGRESS/EGRESS/"",
// Azure Inbound/Outbound) and uses DirectionUnknown for anything else.
type Direction int

const (
	DirectionUnknown Direction = iota
	DirectionInbound
	DirectionOutbound
)

// Action of a rule, as decided by the provider package.
type Action int

const (
	// ActionUnknown: an action value is present but not recognised.
	ActionUnknown Action = iota
	ActionAllow
	ActionDeny
	// ActionMissing: no action at all (e.g. GCP rule with neither allowed
	// nor denied entries).
	ActionMissing
)

// SourceKind tells Evaluate how to interpret Source.Raw.
type SourceKind int

const (
	// SourceAddress: a CIDR or IP (AWS IpRanges/Ipv6Ranges, GCP sourceRanges).
	SourceAddress SourceKind = iota
	// SourceAzurePrefix: an Azure address prefix, which may also be "*",
	// "Any", or a service tag.
	SourceAzurePrefix
	// SourceSelector: a valid non-address selector (AWS security group
	// reference or prefix list, GCP source tag or service account, Azure
	// application security group). Never world-open, never a diagnostic.
	SourceSelector
	// SourceGCPDefault: a GCP ingress rule with no source at all, which the
	// API treats as 0.0.0.0/0.
	SourceGCPDefault
)

// Source is one source value of a rule.
type Source struct {
	Kind  SourceKind
	Field string // provider field name for diagnostics, e.g. "sourceRanges"
	Raw   string
}

// PortStyle selects how port values are interpreted.
type PortStyle int

const (
	// PortsFromRanges: GCP/Azure string specs in Rule.PortRanges.
	PortsFromRanges PortStyle = iota
	// PortsFromAWS: AWS FromPort/ToPort integers (ICMP type/code for ICMP).
	PortsFromAWS
)

// Rule is the provider-neutral form of one firewall rule. Provider packages
// build it from SDK types; Evaluate never sees an SDK type.
type Rule struct {
	Provider   model.Provider
	Scope      string
	ResourceID string
	RuleRef    string

	Direction    Direction
	DirectionRaw string
	Action       Action
	ActionRaw    string

	Protocol string // raw provider value

	PortStyle  PortStyle
	PortRanges []string // PortsFromRanges: raw specs; empty = no restriction
	AWSFrom    *int32   // PortsFromAWS
	AWSTo      *int32   // PortsFromAWS

	Sources     []Source
	Description string
	Context     model.RuleContext
}

// Result of evaluating one rule.
type Result struct {
	Findings    []model.InsecureRule
	Diagnostics []model.Diagnostic
}

// maxDiagnosticValue bounds untrusted values copied into diagnostics.
const maxDiagnosticValue = 256

// Evaluate decides whether a rule allows inbound traffic from 0.0.0.0/0
// and returns one finding per (world source, port spec).
//
// Detection depends only on direction, action and source. Protocol and
// port values describe a finding but never decide whether it is reported:
// an unknown protocol or malformed port still produces a finding, with
// "unknown" values and a finding_detail_unknown diagnostic.
//
// If the rule cannot be classified (unknown direction or action, no
// source, or only malformed sources), Evaluate returns no finding and a
// scope_incomplete diagnostic, so the scan is not reported as complete.
func Evaluate(r Rule) Result {
	var res Result
	diag := func(code, field, value, effect string) {
		res.Diagnostics = append(res.Diagnostics, model.Diagnostic{
			Provider:   r.Provider,
			Scope:      r.Scope,
			ResourceID: r.ResourceID,
			RuleRef:    r.RuleRef,
			Code:       code,
			Field:      field,
			Value:      truncate(value, maxDiagnosticValue),
			Effect:     effect,
		})
	}

	switch r.Direction {
	case DirectionInbound:
	case DirectionOutbound:
		return res // valid, out of scope: no finding, no diagnostic
	default:
		diag(model.CodeDirectionUnrecognised, "direction", r.DirectionRaw, model.EffectScopeIncomplete)
		return res
	}

	switch r.Action {
	case ActionAllow:
	case ActionDeny:
		return res
	case ActionMissing:
		diag(model.CodeActionMissing, "action", r.ActionRaw, model.EffectScopeIncomplete)
		return res
	default:
		diag(model.CodeAccessUnrecognised, "access", r.ActionRaw, model.EffectScopeIncomplete)
		return res
	}

	if len(r.Sources) == 0 {
		diag(model.CodeSourceMissing, "source", "", model.EffectScopeIncomplete)
		return res
	}

	type worldSource struct {
		match SourceMatch
		raw   string
	}
	var world []worldSource
	var malformed []Source
	for _, s := range r.Sources {
		var m SourceMatch
		switch s.Kind {
		case SourceSelector:
			continue
		case SourceGCPDefault:
			m = SourceMatch{Class: ClassWorldIPv4, Source: WorldIPv4, MatchReason: model.MatchGCPDefaultSource}
		case SourceAzurePrefix:
			m = ClassifyAzurePrefix(s.Raw)
		default:
			m = ClassifyAddress(s.Raw)
		}
		switch m.Class {
		case ClassWorldIPv4:
			world = append(world, worldSource{match: m, raw: s.Raw})
		case ClassMalformed:
			malformed = append(malformed, s)
		}
	}

	// A malformed source blocks the decision only if no other source of
	// the same rule is already world-open.
	effect := model.EffectScopeIncomplete
	if len(world) > 0 {
		effect = model.EffectFindingDetailUnknown
	}
	for _, s := range malformed {
		field := s.Field
		if field == "" {
			field = "source"
		}
		diag(model.CodeSourceMalformed, field, s.Raw, effect)
	}
	if len(world) == 0 {
		return res
	}

	proto, ok := NormalizeProtocol(r.Protocol)
	if !ok {
		diag(model.CodeProtocolUnknown, "protocol", r.Protocol, model.EffectFindingDetailUnknown)
	}

	type portSpec struct {
		fields PortFields
		raw    string
	}
	var ports []portSpec
	if r.PortStyle == PortsFromAWS {
		raw := AWSProviderPort(proto, r.AWSFrom, r.AWSTo)
		pf, ok := FromAWSPorts(proto, r.AWSFrom, r.AWSTo)
		if !ok {
			diag(model.CodePortMalformed, "port", raw, model.EffectFindingDetailUnknown)
		}
		ports = append(ports, portSpec{fields: pf, raw: raw})
	} else {
		specs := r.PortRanges
		if len(specs) == 0 {
			specs = []string{""}
		}
		for _, spec := range specs {
			pf, ok := FromPortRange(proto, spec)
			if !ok {
				diag(model.CodePortMalformed, "port", spec, model.EffectFindingDetailUnknown)
			}
			ports = append(ports, portSpec{fields: pf, raw: spec})
		}
	}

	for _, w := range world {
		for _, p := range ports {
			res.Findings = append(res.Findings, model.InsecureRule{
				Protocol:         proto,
				Port:             p.fields.Port,
				FromPort:         p.fields.FromPort,
				ToPort:           p.fields.ToPort,
				ICMPType:         p.fields.ICMPType,
				ICMPCode:         p.fields.ICMPCode,
				Source:           w.match.Source,
				ProviderProtocol: r.Protocol,
				ProviderPort:     p.raw,
				ProviderSource:   w.raw,
				RuleRef:          r.RuleRef,
				MatchReason:      w.match.MatchReason,
				Description:      r.Description,
				Context:          r.Context,
				Reachability:     model.ReachabilityNotEvaluated,
			})
		}
	}
	return res
}

// RuleNil returns the diagnostic for a nil entry in a provider rule list.
func RuleNil(provider model.Provider, scope, resourceID, field string) model.Diagnostic {
	return model.Diagnostic{
		Provider:   provider,
		Scope:      scope,
		ResourceID: resourceID,
		Code:       model.CodeRuleNil,
		Field:      field,
		Effect:     model.EffectScopeIncomplete,
	}
}

// truncate cuts s to at most n bytes without splitting a UTF-8 sequence.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
