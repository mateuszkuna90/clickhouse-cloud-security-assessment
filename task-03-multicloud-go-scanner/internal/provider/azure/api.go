// Package azure collects Network Security Groups with the official Azure SDK
// for Go (armnetwork, armsubscriptions, azidentity), converts their rules to
// exposure.Rule values and evaluates them with the provider-neutral
// detection engine (DESIGN.md sections 4, 5.5, 5.6, 6.2).
//
// The package is read-only by construction:
//
//   - the scanner depends only on the NSGLister and SubscriptionLister
//     interfaces below, which expose list operations only;
//   - the SDK adapter calls only SecurityGroupsClient.NewListAllPager and
//     armsubscriptions Client.NewListPager;
//   - the adapter's HTTP pipeline refuses any request that is not a GET to
//     the Azure Resource Manager host (requestGuard), and the SDK's
//     automatic resource provider registration (a POST) is disabled.
package azure

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
)

// NSGLister is what the scanner needs from the Network API. The adapter
// requests every page and returns the complete list, or an error if any
// page failed (DESIGN.md 4, 5.6).
type NSGLister interface {
	ListNSGs(ctx context.Context, subscriptionID string) ([]*armnetwork.SecurityGroup, error)
}

// SubscriptionState holds the raw state string from the API, unchanged.
// The scanner compares it case-insensitively with the known values below.
// Any other value, including an empty one, means "unknown" and the
// subscription is scanned (DESIGN.md 4, 5.5).
//
// The armsubscriptions SDK enum has no "Expired" value; the raw string is
// kept so that values outside the enum are still reported as they are.
type SubscriptionState string

const (
	StateEnabled  SubscriptionState = "Enabled"
	StateWarned   SubscriptionState = "Warned"
	StatePastDue  SubscriptionState = "PastDue"
	StateDisabled SubscriptionState = "Disabled"
	StateExpired  SubscriptionState = "Expired"
	StateDeleted  SubscriptionState = "Deleted"
)

// Subscription is one subscription to consider for scanning.
type Subscription struct {
	ID string
	// State is the raw API state; "" when the API gave none.
	State SubscriptionState
	// HasState is true for discovered subscriptions (the API answered,
	// even if without a state) and false for explicit-list entries.
	HasState bool
}

// SubscriptionLister discovers the subscriptions the identity can see.
type SubscriptionLister interface {
	// ListSubscriptions returns every subscription the identity can see,
	// with its state, following the armsubscriptions pager to the end.
	ListSubscriptions(ctx context.Context) ([]Subscription, error)
}

// Compile-time checks: the SDK adapter satisfies both interfaces.
var (
	_ NSGLister          = (*Client)(nil)
	_ SubscriptionLister = (*Client)(nil)
)
