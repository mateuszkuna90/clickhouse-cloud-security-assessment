// Package gcp collects VPC firewall rules with the official Compute Engine
// REST client for Go (google.golang.org/api/compute/v1), converts them to
// exposure.Rule values and evaluates them with the provider-neutral
// detection engine (DESIGN.md sections 4, 5.4, 5.6, 6.2).
//
// The package is read-only by construction: the scanner depends only on the
// FirewallLister interface below, which exposes a single List operation.
// The SDK adapter calls only Firewalls.List, and its credentials are
// requested with the compute.readonly OAuth scope.
package gcp

import (
	"context"

	compute "google.golang.org/api/compute/v1"
)

// FirewallLister is what the scanner needs from the Compute API. The
// adapter requests every page and returns the complete list, or an error if
// any page failed (DESIGN.md 4, 5.6).
type FirewallLister interface {
	ListFirewalls(ctx context.Context, project string) ([]*compute.Firewall, error)
}

// Compile-time check: the SDK adapter satisfies the interface.
var _ FirewallLister = (*Client)(nil)
