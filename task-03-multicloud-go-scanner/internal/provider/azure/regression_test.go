package azure

import (
	"context"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/report"
)

// Regression tests for the M4 review (Low): a discovery record marked
// Deleted but with a missing or malformed subscription ID was skipped
// before its ID was checked, so a record the scanner could not identify was
// trusted to be deleted and did not lower completeness.
//
// These drive the real armsubscriptions pager over the fake ARM transport.

func TestRegression_DeletedRecordsWithBadIDsFailTheScope(t *testing.T) {
	f := newFakeARM(map[string][]armPage{
		subsPath(): {
			{items: []string{
				subJSON(subA, "Enabled"),
				subJSON(subB, "Deleted"), // valid and Deleted: skipped
			}},
			{items: []string{
				`{"displayName":"no id","state":"Deleted"}`,              // missing ID
				`{"subscriptionId":"not-a-guid","state":"Deleted"}`,      // malformed ID
				`{"subscriptionId":"../` + subC + `","state":"deleted"}`, // path-like ID
				`{"id":"/subscriptions/garbage","state":"Deleted"}`,      // id field not a GUID
				`{"subscriptionId":"` + subD + `/x","state":"Deleted"}`,  // GUID with suffix
				`{"subscriptionId":"","id":"","state":"Deleted"}`,        // empty strings
			}},
		},
		nsgPath(subA): {{}},
	})
	c := realClient(t, f, staticCred{})
	res := NewScanner(Config{}, c, c).Scan(context.Background())

	assertEqual(t, "scopes", scopeStatuses(res.Scopes), []string{
		" failed Deleted",
		" failed Deleted",
		" failed Deleted",
		"../" + subC + " failed deleted",
		subA + " complete Enabled",
		subB + " skipped Deleted",
		subD + "/x failed Deleted",
		"not-a-guid failed Deleted",
	})
	assertEqual(t, "errors", errorKinds(res.Errors), []string{
		" " + OpListSubscriptions + " other",
		" " + OpListSubscriptions + " other",
		" " + OpListSubscriptions + " other",
		"../" + subC + " config other",
		subD + "/x config other",
		"not-a-guid config other",
	})
	assertEqual(t, "status", res.Status, model.ProviderPartial)
	rep := report.Build([]model.ProviderResult{res}, report.Options{})
	assertEqual(t, "exit", report.ExitCode(rep), report.ExitIncomplete)

	// Only the valid, non-Deleted subscription was read.
	for _, r := range f.requestLog() {
		if strings.Contains(r.url, "/providers/Microsoft.Network/") && !strings.Contains(r.url, subA) {
			t.Errorf("unexpected NSG read: %s", r.url)
		}
	}
}

// A valid Deleted subscription alone is still skipped without lowering the
// status (the M4 behaviour is preserved).
func TestRegression_ValidDeletedStillSkipped(t *testing.T) {
	f := newFakeARM(map[string][]armPage{subsPath(): {
		{items: []string{subJSON(subA, "Deleted"), subJSON(subB, "Enabled")}},
	}, nsgPath(subB): {{}}})
	c := realClient(t, f, staticCred{})
	res := NewScanner(Config{}, c, c).Scan(context.Background())
	assertEqual(t, "scopes", scopeStatuses(res.Scopes), []string{
		subA + " skipped Deleted", subB + " complete Enabled",
	})
	assertEqual(t, "status", res.Status, model.ProviderComplete)
	assertEqual(t, "errors", res.Errors, []model.ScanError{})
}

// The unit-level form, with a fake lister: every bad-ID record fails,
// whatever its state, and a Deleted state never hides it.
func TestRegression_StateNeverHidesBadID(t *testing.T) {
	for _, state := range []SubscriptionState{StateDeleted, "DELETED", StateEnabled, ""} {
		subs := &fakeSubs{subs: []Subscription{
			{ID: "", State: state, HasState: true},
			{ID: "bad", State: state, HasState: true},
		}}
		nsgs := &fakeNSGs{bySub: map[string][]*armnetwork.SecurityGroup{}}
		res := NewScanner(Config{}, subs, nsgs).Scan(context.Background())
		for _, sc := range res.Scopes {
			if sc.Status != model.ScopeFailed {
				t.Errorf("state %q: scope %q is %s, want failed", state, sc.Scope, sc.Status)
			}
		}
		assertEqual(t, "status", res.Status, model.ProviderFailed)
		assertEqual(t, "no reads", len(nsgs.called()), 0)
	}
}
