package aws

import (
	"strconv"

	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/exposure"
	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
)

// Provider field names used in diagnostics.
const (
	fieldCidrIp     = "IpRanges.CidrIp"
	fieldCidrIpv6   = "Ipv6Ranges.CidrIpv6"
	fieldGroupPair  = "UserIdGroupPairs"
	fieldPrefixList = "PrefixListIds"
	fieldGroupID    = "GroupId"
)

// groupResult is the evaluation of one security group.
type groupResult struct {
	group          model.AWSSecurityGroup // InsecureRules may be empty
	rulesEvaluated int
	prefixListRefs int
	diagnostics    []model.Diagnostic
}

// convertGroup evaluates the ingress rules of one security group.
//
// Only IpPermissions (ingress) are read; IpPermissionsEgress is ignored.
// Each IpPermission is one exposure.Rule with these sources:
//
//   - IpRanges[].CidrIp: address, classified by the engine (world if IPv4 /0).
//   - Ipv6Ranges[].CidrIpv6: address; never world in v1 (IPv6 out of scope).
//   - UserIdGroupPairs, PrefixListIds: selectors, never world. Prefix lists
//     are counted because their contents are not expanded.
//
// callerAccount is used when the group has no OwnerId.
func convertGroup(scope, callerAccount, region string, sg types.SecurityGroup) groupResult {
	id := deref(sg.GroupId)
	owner := deref(sg.OwnerId)
	if owner == "" {
		owner = callerAccount
	}
	res := groupResult{
		group: model.AWSSecurityGroup{
			ID:            id,
			Name:          deref(sg.GroupName),
			VPCID:         deref(sg.VpcId),
			AccountID:     owner,
			Region:        region,
			InsecureRules: []model.InsecureRule{},
		},
	}
	if id == "" {
		res.diagnostics = append(res.diagnostics, model.Diagnostic{
			Provider: model.ProviderAWS, Scope: scope,
			Code: model.CodeResourceIDMissing, Field: fieldGroupID,
			Value:  deref(sg.GroupName),
			Effect: model.EffectFindingDetailUnknown,
		})
	}

	for _, perm := range sg.IpPermissions {
		res.rulesEvaluated++
		ref := permissionRef(perm)
		rule := exposure.Rule{
			Provider:   model.ProviderAWS,
			Scope:      scope,
			ResourceID: id,
			RuleRef:    ref,
			Direction:  exposure.DirectionInbound, // IpPermissions is the ingress list
			Action:     exposure.ActionAllow,      // security groups have allow rules only
			Protocol:   deref(perm.IpProtocol),
			PortStyle:  exposure.PortsFromAWS,
			AWSFrom:    perm.FromPort,
			AWSTo:      perm.ToPort,
			// AWS Security Groups have no priority or targets; attachment
			// is not known without extra API calls (DESIGN.md 7).
			Context: model.RuleContext{},
		}
		// Descriptions belong to individual IP ranges, not the permission.
		descriptions := make(map[string]string, len(perm.IpRanges))
		for _, r := range perm.IpRanges {
			cidr := deref(r.CidrIp)
			rule.Sources = append(rule.Sources, exposure.Source{
				Kind: exposure.SourceAddress, Field: fieldCidrIp, Raw: cidr,
			})
			if _, seen := descriptions[cidr]; !seen {
				descriptions[cidr] = deref(r.Description)
			}
		}
		for _, r := range perm.Ipv6Ranges {
			rule.Sources = append(rule.Sources, exposure.Source{
				Kind: exposure.SourceAddress, Field: fieldCidrIpv6, Raw: deref(r.CidrIpv6),
			})
		}
		for _, p := range perm.UserIdGroupPairs {
			rule.Sources = append(rule.Sources, exposure.Source{
				Kind: exposure.SourceSelector, Field: fieldGroupPair, Raw: deref(p.GroupId),
			})
		}
		for _, p := range perm.PrefixListIds {
			res.prefixListRefs++
			rule.Sources = append(rule.Sources, exposure.Source{
				Kind: exposure.SourceSelector, Field: fieldPrefixList, Raw: deref(p.PrefixListId),
			})
		}

		ev := exposure.Evaluate(rule)
		for _, f := range ev.Findings {
			// SG rules have no ID in DescribeSecurityGroups, so the rule
			// ref names the permission and the world CIDR (DESIGN.md 6.6).
			f.RuleRef = ref + ":" + f.ProviderSource
			f.Description = descriptions[f.ProviderSource]
			res.group.InsecureRules = append(res.group.InsecureRules, f)
		}
		res.diagnostics = append(res.diagnostics, ev.Diagnostics...)
	}
	return res
}

// permissionRef renders "<protocol>:<from>:<to>" from the raw values; an
// absent value is empty, e.g. "-1::" for all traffic.
func permissionRef(p types.IpPermission) string {
	return deref(p.IpProtocol) + ":" + int32Text(p.FromPort) + ":" + int32Text(p.ToPort)
}

func int32Text(v *int32) string {
	if v == nil {
		return ""
	}
	return strconv.Itoa(int(*v))
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
