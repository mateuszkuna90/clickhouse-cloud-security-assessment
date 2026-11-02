package aws

import (
	"context"
	"regexp"
	"slices"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// regionPattern accepts AWS region names in every partition, e.g.
// "eu-west-1", "us-gov-west-1", "cn-north-1", "us-isob-east-1".
//
// A region name becomes part of the endpoint host name, so it is checked
// before any client is built: a value such as "evil.example#" never reaches
// the SDK's endpoint resolver.
var regionPattern = regexp.MustCompile(`^[a-z]{2,}(-[a-z0-9]+)+-[0-9]+$`)

// ValidRegion reports whether s looks like an AWS region name. It checks
// syntax only: whether the region exists or is enabled is found out when
// it is scanned.
func ValidRegion(s string) bool { return regionPattern.MatchString(s) }

// normalizeRegions trims, de-duplicates and sorts an explicit region list.
// Empty entries are kept as "" so that the scanner reports them as failed
// scopes rather than dropping them.
func normalizeRegions(in []string) []string {
	out := make([]string, 0, len(in))
	for _, r := range in {
		out = append(out, strings.TrimSpace(r))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// discoveredRegions is the outcome of DescribeRegions.
type discoveredRegions struct {
	names []string // valid-looking, sorted, de-duplicated
	// unnamed counts entries that had no RegionName. They cannot be
	// scanned and make the provider partial.
	unnamed int
}

// discoverRegions lists the regions enabled for the account.
//
// AllRegions=false returns only regions that are enabled for the account
// ("opt-in-not-required" or "opted-in"), so regions that are not opted in
// are not scanned and not reported. DescribeRegions only returns regions
// of the client's partition, so a run covers exactly the partition of the
// bootstrap region.
func discoverRegions(ctx context.Context, client EC2API) (discoveredRegions, error) {
	out, err := client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		AllRegions: awssdk.Bool(false),
	})
	if err != nil {
		return discoveredRegions{}, err
	}
	if out == nil {
		return discoveredRegions{}, errNoOutput
	}
	var d discoveredRegions
	for _, r := range out.Regions {
		name := strings.TrimSpace(deref(r.RegionName))
		if name == "" {
			d.unnamed++
			continue
		}
		d.names = append(d.names, name)
	}
	slices.Sort(d.names)
	d.names = slices.Compact(d.names)
	return d, nil
}
