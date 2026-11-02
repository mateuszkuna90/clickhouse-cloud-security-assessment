package azure

import (
	"cmp"
	"regexp"
	"slices"
	"strings"
)

// subscriptionIDPattern accepts a subscription ID: a GUID.
//
// The ID becomes part of the request URL path. The SDK escapes it, but it
// is still checked before any request is built, so a value such as
// "x/../y" or "x?y" never reaches the SDK.
var subscriptionIDPattern = regexp.MustCompile(
	`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)

// ValidSubscriptionID reports whether s is a syntactically valid
// subscription ID. Whether it exists, and whether the identity can read
// it, is found out when it is scanned.
func ValidSubscriptionID(s string) bool { return subscriptionIDPattern.MatchString(s) }

// shouldScan is the single subscription policy (DESIGN.md 5.5): every
// subscription is scanned except one the API itself reports as Deleted.
// Explicit-list entries (HasState false) are always scanned, and an empty
// or unknown state is never treated as empty or deleted.
func shouldScan(s Subscription) bool {
	return !(s.HasState && strings.EqualFold(string(s.State), string(StateDeleted)))
}

// explicitSubscriptions turns an explicit ID list into subscriptions with
// no state. Entries are trimmed; invalid ones are kept so that they fail as
// scopes rather than being dropped.
func explicitSubscriptions(ids []string) []Subscription {
	out := make([]Subscription, 0, len(ids))
	for _, id := range ids {
		out = append(out, Subscription{ID: strings.TrimSpace(id)})
	}
	return normalizeSubscriptions(out)
}

// normalizeSubscriptions returns a sorted copy of subs with duplicate IDs
// merged (IDs are GUIDs, compared case-insensitively). Records with an
// empty ID are all kept: each is reported as a failed scope.
//
// When the API lists the same ID twice with different states, the record
// that will be scanned wins over a Deleted one, so a duplicate can never
// hide a subscription. The input is not modified.
func normalizeSubscriptions(in []Subscription) []Subscription {
	out := slices.Clone(in)
	for i := range out {
		out[i].ID = strings.TrimSpace(out[i].ID)
	}
	slices.SortFunc(out, func(a, b Subscription) int {
		return cmp.Or(
			cmp.Compare(strings.ToLower(a.ID), strings.ToLower(b.ID)),
			cmp.Compare(boolInt(!shouldScan(a)), boolInt(!shouldScan(b))),
			cmp.Compare(a.ID, b.ID),
			cmp.Compare(a.State, b.State),
			cmp.Compare(boolInt(a.HasState), boolInt(b.HasState)),
		)
	})
	return slices.CompactFunc(out, func(a, b Subscription) bool {
		return a.ID != "" && strings.EqualFold(a.ID, b.ID)
	})
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
