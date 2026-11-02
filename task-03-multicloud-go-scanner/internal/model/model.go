// Package model holds the report types shared by the scanner, the detection
// engine and the JSON encoder (DESIGN.md sections 5.8, 6.5, 6.6 and 8).
//
// The JSON field order is fixed by struct field order. Collections are
// slices, never maps, so encoding is deterministic.
package model

// Provider identifies a cloud provider.
type Provider string

const (
	ProviderAWS   Provider = "aws"
	ProviderGCP   Provider = "gcp"
	ProviderAzure Provider = "azure"
)

// ScopeStatus is the result of scanning one region, project or subscription.
type ScopeStatus string

const (
	// ScopeComplete: every rule in the scope was read and evaluated.
	ScopeComplete ScopeStatus = "complete"
	// ScopeIncomplete: the scope was read, but at least one rule could not
	// be evaluated (a diagnostic with EffectScopeIncomplete).
	ScopeIncomplete ScopeStatus = "incomplete"
	// ScopeFailed: an API error or timeout stopped the scope.
	ScopeFailed ScopeStatus = "failed"
	// ScopeSkipped: deliberately not scanned (only an API-reported Deleted
	// Azure subscription).
	ScopeSkipped ScopeStatus = "skipped"
)

// ProviderStatus summarises all scopes of one provider.
type ProviderStatus string

const (
	ProviderComplete    ProviderStatus = "complete"
	ProviderPartial     ProviderStatus = "partial"
	ProviderFailed      ProviderStatus = "failed"
	ProviderNotSelected ProviderStatus = "not_selected"
)

// Diagnostic codes (DESIGN.md section 6.5).
const (
	CodeSourceMalformed       = "source_malformed"
	CodeSourceMissing         = "source_missing"
	CodeDirectionUnrecognised = "direction_unrecognised"
	CodeAccessUnrecognised    = "access_unrecognised"
	CodeActionMissing         = "action_missing"
	CodeRuleNil               = "rule_nil"
	CodeProtocolUnknown       = "protocol_unknown"
	CodePortMalformed         = "port_malformed"
	CodeNoScopesDiscovered    = "no_scopes_discovered"
)

// Diagnostic effects.
const (
	// EffectScopeIncomplete: the tool could not decide whether a rule is a
	// world-open inbound allow. The scope becomes incomplete (exit 2).
	EffectScopeIncomplete = "scope_incomplete"
	// EffectFindingDetailUnknown: the finding was emitted, but a descriptive
	// field (protocol, port, an extra source) could not be read.
	EffectFindingDetailUnknown = "finding_detail_unknown"
	// EffectProviderFailed: used with CodeNoScopesDiscovered.
	EffectProviderFailed = "provider_failed"
)

// Match reasons explain why a source counts as open to the internet.
const (
	MatchIPv4WorldCIDR           = "ipv4_world_cidr"
	MatchAzureAnyWildcard        = "azure_any_wildcard"
	MatchAzureServiceTagInternet = "azure_service_tag_internet"
	MatchGCPDefaultSource        = "gcp_default_source"
)

// ReachabilityNotEvaluated is the only reachability value in v1: findings
// are configuration findings, not proof of internet reachability.
const ReachabilityNotEvaluated = "not_evaluated"

// Canonical port values.
const (
	PortAll     = "all"
	PortUnknown = "unknown"
)

// Diagnostic records a rule the tool could not fully evaluate.
type Diagnostic struct {
	Provider   Provider `json:"provider"`
	Scope      string   `json:"scope"`
	ResourceID string   `json:"resource_id"`
	RuleRef    string   `json:"rule_ref"`
	Code       string   `json:"code"`
	Field      string   `json:"field"`
	Value      string   `json:"value"`
	Effect     string   `json:"effect"`
}

// ScanError records an API or setup failure.
type ScanError struct {
	Provider  Provider `json:"provider"`
	Scope     string   `json:"scope"`
	Operation string   `json:"operation"`
	Kind      string   `json:"kind"`
	Message   string   `json:"message"`
}

// Error kinds for ScanError.Kind.
const (
	ErrorKindAuth             = "auth"
	ErrorKindPermissionDenied = "permission_denied"
	ErrorKindThrottled        = "throttled"
	ErrorKindTimeout          = "timeout"
	ErrorKindNotFound         = "not_found"
	ErrorKindOther            = "other"
)

// RuleContext copies configuration facts that matter for reachability
// triage. They are hints, not a reachability verdict (DESIGN.md section 7).
type RuleContext struct {
	Priority *int     `json:"priority"`
	Targets  []string `json:"targets"`
	Attached *bool    `json:"attached"`
}

// InsecureRule is one world-open inbound allow entry.
type InsecureRule struct {
	Protocol         string      `json:"protocol"`
	Port             string      `json:"port"`
	FromPort         *int        `json:"from_port"`
	ToPort           *int        `json:"to_port"`
	ICMPType         *int        `json:"icmp_type"`
	ICMPCode         *int        `json:"icmp_code"`
	Source           string      `json:"source"`
	ProviderProtocol string      `json:"provider_protocol"`
	ProviderPort     string      `json:"provider_port"`
	ProviderSource   string      `json:"provider_source"`
	RuleRef          string      `json:"rule_ref"`
	MatchReason      string      `json:"match_reason"`
	Description      string      `json:"description"`
	Context          RuleContext `json:"context"`
	Reachability     string      `json:"reachability"`
}

// AWSSecurityGroup is an EC2 security group with at least one finding.
type AWSSecurityGroup struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	VPCID         string         `json:"vpc_id"`
	AccountID     string         `json:"account_id"`
	Region        string         `json:"region"`
	InsecureRules []InsecureRule `json:"insecure_rules"`
}

// GCPFirewallRule is a VPC firewall rule with at least one finding.
type GCPFirewallRule struct {
	Name          string         `json:"name"`
	Network       string         `json:"network"`
	Project       string         `json:"project"`
	ID            string         `json:"id"`
	InsecureRules []InsecureRule `json:"insecure_rules"`
}

// AzureNSG is a network security group with at least one finding.
type AzureNSG struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	SubscriptionID string         `json:"subscription_id"`
	InsecureRules  []InsecureRule `json:"insecure_rules"`
}

// ScopeResult describes the coverage of one scanned scope.
type ScopeResult struct {
	Provider                 Provider    `json:"provider"`
	Scope                    string      `json:"scope"`
	Status                   ScopeStatus `json:"status"`
	ResourcesScanned         int         `json:"resources_scanned"`
	RulesEvaluated           int         `json:"rules_evaluated"`
	DisabledRulesSkipped     int         `json:"disabled_rules_skipped"`
	PrefixListRefsUnexpanded int         `json:"prefix_list_refs_unexpanded"`
	// SubscriptionState is the raw Azure state for discovered subscriptions
	// and null everywhere else.
	SubscriptionState *string `json:"subscription_state"`
}

// ProviderResult is what one provider scanner returns. Scanners never
// return Go errors; failures are recorded in Errors and Status.
type ProviderResult struct {
	Provider          Provider
	Status            ProviderStatus
	Scopes            []ScopeResult
	AWSSecurityGroups []AWSSecurityGroup
	GCPFirewallRules  []GCPFirewallRule
	AzureNSGs         []AzureNSG
	Diagnostics       []Diagnostic
	Errors            []ScanError
}

// Report is the JSON document written by the tool.
type Report struct {
	SchemaVersion string       `json:"schema_version"`
	Tool          Tool         `json:"tool"`
	Scan          Scan         `json:"scan"`
	AWS           AWSSection   `json:"aws"`
	GCP           GCPSection   `json:"gcp"`
	Azure         AzureSection `json:"azure"`
	Diagnostics   []Diagnostic `json:"diagnostics"`
	Errors        []ScanError  `json:"errors"`
}

// SchemaVersion of the JSON report.
const SchemaVersion = "1.0"

type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Scan struct {
	Providers ProviderStatuses `json:"providers"`
	Scopes    []ScopeResult    `json:"scopes"`
	Findings  int              `json:"findings"`
	// Timestamps are present only with --include-timestamps, so that the
	// default output is byte-stable.
	StartedAt  string `json:"started_at,omitempty"`
	FinishedAt string `json:"finished_at,omitempty"`
}

// ProviderStatuses is a struct, not a map, so the key order is fixed.
type ProviderStatuses struct {
	AWS   ProviderStatus `json:"aws"`
	GCP   ProviderStatus `json:"gcp"`
	Azure ProviderStatus `json:"azure"`
}

type AWSSection struct {
	SecurityGroups []AWSSecurityGroup `json:"security_groups"`
}

type GCPSection struct {
	FirewallRules []GCPFirewallRule `json:"firewall_rules"`
}

type AzureSection struct {
	NSGs []AzureNSG `json:"nsgs"`
}
