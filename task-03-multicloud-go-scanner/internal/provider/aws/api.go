// Package aws collects EC2 Security Group ingress rules with the AWS SDK for
// Go v2, converts them to exposure.Rule values and evaluates them with the
// provider-neutral detection engine (DESIGN.md sections 4, 5.3, 5.6, 6.2).
//
// The package is read-only by construction: the scanner depends only on the
// narrow interfaces below, which expose Describe*/Get* operations and nothing
// that can change a cloud resource.
package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// EC2API is the subset of the EC2 client the scanner uses. It satisfies
// ec2.DescribeSecurityGroupsAPIClient, so the real SDK paginator runs
// against fakes in tests.
type EC2API interface {
	DescribeSecurityGroups(ctx context.Context, in *ec2.DescribeSecurityGroupsInput,
		opts ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	DescribeRegions(ctx context.Context, in *ec2.DescribeRegionsInput,
		opts ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error)
}

// STSAPI is the subset of the STS client the scanner uses. GetCallerIdentity
// needs no IAM permission.
type STSAPI interface {
	GetCallerIdentity(ctx context.Context, in *sts.GetCallerIdentityInput,
		opts ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// ClientFactory returns an EC2 client bound to one region.
type ClientFactory func(region string) EC2API

// Compile-time checks: the real SDK clients satisfy the interfaces, and
// EC2API is usable with the SDK paginator.
var (
	_ EC2API                              = (*ec2.Client)(nil)
	_ STSAPI                              = (*sts.Client)(nil)
	_ ec2.DescribeSecurityGroupsAPIClient = EC2API(nil)
)
