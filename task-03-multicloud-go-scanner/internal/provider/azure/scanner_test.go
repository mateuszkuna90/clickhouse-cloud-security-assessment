package azure

import (
	"bytes"
	"context"
	"errors"
	"math/rand/v2"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/report"
)

// openNSG is an NSG with one world-open SSH rule.
func openNSG(sub, name string) *armnetwork.SecurityGroup {
	return nsgSpec{name: name, rules: []ruleSpec{inAllow("ssh", "Tcp", "*", "22", 100)}}.build(sub)
}

func respErr(status int, code string) error {
	return &azcore.ResponseError{StatusCode: status, ErrorCode: code}
}

func TestScan_SubscriptionStateMatrix(t *testing.T) {
	subs := &fakeSubs{subs: []Subscription{
		{ID: subA, State: StateEnabled, HasState: true},
		{ID: subB, State: StateWarned, HasState: true},
		{ID: subC, State: StatePastDue, HasState: true},
		{ID: subD, State: StateDisabled, HasState: true},
		{ID: subE, State: StateExpired, HasState: true},
		{ID: subF, State: StateDeleted, HasState: true},
		{ID: subG, State: "", HasState: true},          // API gave no state
		{ID: subH, State: "Suspended", HasState: true}, // unknown value
		{ID: "00000000-0000-0000-0000-000000000012", State: "deleted", HasState: true},
	}}
	nsgs := &fakeNSGs{bySub: map[string][]*armnetwork.SecurityGroup{}}
	for _, s := range []string{subA, subB, subC, subD, subE, subG, subH} {
		nsgs.bySub[s] = []*armnetwork.SecurityGroup{openNSG(s, "nsg")}
	}
	res := NewScanner(Config{}, subs, nsgs).Scan(context.Background())

	assertEqual(t, "NSG reads (Deleted never read)", nsgs.called(),
		[]string{subA, subB, subC, subD, subE, subG, subH})
	assertEqual(t, "scopes", scopeStatuses(res.Scopes), []string{
		subA + " complete Enabled",
		subB + " complete Warned",
		subC + " complete PastDue",
		subD + " complete Disabled",
		subE + " complete Expired",
		subF + " skipped Deleted",
		subG + " complete ",
		subH + " complete Suspended",
		"00000000-0000-0000-0000-000000000012 skipped deleted",
	})
	assertEqual(t, "status", res.Status, model.ProviderComplete)
	assertEqual(t, "NSGs with findings", len(res.AzureNSGs), 7)
	assertEqual(t, "errors", res.Errors, []model.ScanError{})
}

func TestScan_DisabledOrExpiredReadFailures(t *testing.T) {
	subs := &fakeSubs{subs: []Subscription{
		{ID: subA, State: StateEnabled, HasState: true},
		{ID: subD, State: StateDisabled, HasState: true},
		{ID: subE, State: StateExpired, HasState: true},
	}}
	nsgs := &fakeNSGs{
		bySub: map[string][]*armnetwork.SecurityGroup{subA: {openNSG(subA, "nsg")}},
		errs: map[string]error{
			subD: &pageError{page: 1, err: respErr(http.StatusForbidden, "AuthorizationFailed")},
			subE: &pageError{page: 1, err: respErr(http.StatusConflict, "ReadOnlyDisabledSubscription")},
		},
	}
	res := NewScanner(Config{}, subs, nsgs).Scan(context.Background())
	assertEqual(t, "scopes", scopeStatuses(res.Scopes), []string{
		subA + " complete Enabled", subD + " failed Disabled", subE + " failed Expired",
	})
	assertEqual(t, "errors", errorKinds(res.Errors), []string{
		subD + " " + OpListNSGs + " permission_denied",
		subE + " " + OpListNSGs + " permission_denied",
	})
	assertEqual(t, "status", res.Status, model.ProviderPartial)
	assertEqual(t, "findings kept for the readable subscription", len(res.AzureNSGs), 1)
	rep := report.Build([]model.ProviderResult{res}, report.Options{})
	assertEqual(t, "exit", report.ExitCode(rep), report.ExitIncomplete)
}

func TestScan_ExplicitSubscriptions(t *testing.T) {
	subs := &fakeSubs{err: errors.New("must not be called")}
	nsgs := &fakeNSGs{
		bySub: map[string][]*armnetwork.SecurityGroup{subA: {openNSG(subA, "nsg")}, subB: {}},
		errs:  map[string]error{subC: respErr(http.StatusNotFound, "SubscriptionNotFound")},
	}
	cfg := Config{Subscriptions: []string{" " + subB + " ", subA, subC, subA, "not-a-guid", ""}}
	res := NewScanner(cfg, subs, nsgs).Scan(context.Background())

	assertEqual(t, "discovery not called", subs.calls, 0)
	assertEqual(t, "NSG reads", nsgs.called(), []string{subA, subB, subC})
	assertEqual(t, "scopes (state null for explicit entries)", scopeStatuses(res.Scopes), []string{
		" failed <null>",
		subA + " complete <null>",
		subB + " complete <null>",
		subC + " failed <null>",
		"not-a-guid failed <null>",
	})
	assertEqual(t, "errors", errorKinds(res.Errors), []string{
		" config other",
		subC + " " + OpListNSGs + " not_found",
		"not-a-guid config other",
	})
	assertEqual(t, "status", res.Status, model.ProviderPartial)
}

// An explicit list is never filtered by state: no state is looked up.
func TestScan_ExplicitSubscriptionWithoutStateIsAlwaysScanned(t *testing.T) {
	nsgs := &fakeNSGs{bySub: map[string][]*armnetwork.SecurityGroup{subA: {}}}
	res := NewScanner(Config{Subscriptions: []string{subA}}, nil, nsgs).Scan(context.Background())
	assertEqual(t, "scopes", scopeStatuses(res.Scopes), []string{subA + " complete <null>"})
	assertEqual(t, "status", res.Status, model.ProviderComplete)
	assertEqual(t, "resources", res.Scopes[0].ResourcesScanned, 0)
}

func TestScan_DiscoveryFailures(t *testing.T) {
	t.Run("list error", func(t *testing.T) {
		subs := &fakeSubs{err: &pageError{page: 2, err: respErr(http.StatusUnauthorized, "InvalidAuthenticationToken")}}
		nsgs := &fakeNSGs{}
		res := NewScanner(Config{}, subs, nsgs).Scan(context.Background())
		assertEqual(t, "status", res.Status, model.ProviderFailed)
		assertEqual(t, "errors", errorKinds(res.Errors), []string{" " + OpListSubscriptions + " auth"})
		assertEqual(t, "no NSG reads", len(nsgs.called()), 0)
		assertEqual(t, "message", res.Errors[0].Message,
			OpListSubscriptions+" failed: Azure credentials could not be resolved or were rejected (page 2) "+
				"[HTTP 401] [code: InvalidAuthenticationToken]")
	})
	t.Run("zero subscriptions", func(t *testing.T) {
		res := NewScanner(Config{}, &fakeSubs{}, &fakeNSGs{}).Scan(context.Background())
		assertEqual(t, "status", res.Status, model.ProviderFailed)
		assertEqual(t, "diag", diagCodes(res.Diagnostics),
			[]string{" no_scopes_discovered subscriptions provider_failed"})
		rep := report.Build([]model.ProviderResult{res}, report.Options{})
		assertEqual(t, "exit", report.ExitCode(rep), report.ExitIncomplete)
	})
	t.Run("records without or with invalid IDs", func(t *testing.T) {
		subs := &fakeSubs{subs: []Subscription{
			{ID: subA, State: StateEnabled, HasState: true},
			{ID: "", State: StateEnabled, HasState: true},
			{ID: "", HasState: true},
			{ID: "../../evil", State: StateEnabled, HasState: true},
		}}
		nsgs := &fakeNSGs{bySub: map[string][]*armnetwork.SecurityGroup{subA: {}}}
		res := NewScanner(Config{}, subs, nsgs).Scan(context.Background())
		assertEqual(t, "NSG reads", nsgs.called(), []string{subA})
		assertEqual(t, "scopes", scopeStatuses(res.Scopes), []string{
			" failed ", " failed Enabled", "../../evil failed Enabled", subA + " complete Enabled",
		})
		assertEqual(t, "errors", errorKinds(res.Errors), []string{
			" " + OpListSubscriptions + " other",
			" " + OpListSubscriptions + " other",
			"../../evil config other",
		})
		assertEqual(t, "status", res.Status, model.ProviderPartial)
	})
	t.Run("only Deleted subscriptions", func(t *testing.T) {
		subs := &fakeSubs{subs: []Subscription{{ID: subA, State: StateDeleted, HasState: true}}}
		nsgs := &fakeNSGs{}
		res := NewScanner(Config{}, subs, nsgs).Scan(context.Background())
		assertEqual(t, "no NSG reads", len(nsgs.called()), 0)
		assertEqual(t, "scopes", scopeStatuses(res.Scopes), []string{subA + " skipped Deleted"})
		assertEqual(t, "status (skipped does not raise exit 2)", res.Status, model.ProviderComplete)
	})
	t.Run("duplicate records: a scannable one wins over Deleted", func(t *testing.T) {
		upper := "00000000-0000-0000-0000-00000000000A"
		subs := &fakeSubs{subs: []Subscription{
			{ID: subA, State: StateDeleted, HasState: true},
			{ID: upper, State: StateEnabled, HasState: true},
		}}
		nsgs := &fakeNSGs{bySub: map[string][]*armnetwork.SecurityGroup{upper: {}}}
		res := NewScanner(Config{}, subs, nsgs).Scan(context.Background())
		assertEqual(t, "scopes", scopeStatuses(res.Scopes), []string{upper + " complete Enabled"})
	})
	t.Run("no clients", func(t *testing.T) {
		res := NewScanner(Config{}, nil, &fakeNSGs{}).Scan(context.Background())
		assertEqual(t, "no subs client", errorKinds(res.Errors), []string{" config other"})
		assertEqual(t, "status", res.Status, model.ProviderFailed)
		res = NewScanner(Config{Subscriptions: []string{subA}}, nil, nil).Scan(context.Background())
		assertEqual(t, "no NSG client", errorKinds(res.Errors), []string{" config other"})
		assertEqual(t, "status", res.Status, model.ProviderFailed)
	})
}

func TestScan_MultipleNSGsAndRules(t *testing.T) {
	quiet := nsgSpec{name: "quiet", rules: []ruleSpec{inAllow("vnet", "Tcp", "VirtualNetwork", "22", 100)}}.build(subA)
	multi := nsgSpec{name: "web", attached: true, rules: []ruleSpec{
		inAllow("https", "Tcp", "0.0.0.0/0", "443", 100),
		inAllow("http", "Tcp", "Internet", "80", 110),
		inAllow("deny-all", "*", "*", "*", 4096),
	}}.build(subA)
	multi.Properties.SecurityRules[2].Properties.Access = ptr(armnetwork.SecurityRuleAccessDeny)
	nsgs := &fakeNSGs{bySub: map[string][]*armnetwork.SecurityGroup{
		subA: {quiet, openNSG(subA, "ssh"), multi, nil},
	}}
	res := NewScanner(Config{Subscriptions: []string{subA}}, nil, nsgs).Scan(context.Background())
	assertEqual(t, "NSGs with findings", len(res.AzureNSGs), 2)
	sc := res.Scopes[0]
	assertEqual(t, "resources (nil entry counted)", sc.ResourcesScanned, 4)
	assertEqual(t, "rules evaluated", sc.RulesEvaluated, 1+6+1+6+3+6)
	assertEqual(t, "nil NSG is a blocking diagnostic", diagCodes(res.Diagnostics),
		[]string{" rule_nil value scope_incomplete"})
	assertEqual(t, "scope", sc.Status, model.ScopeIncomplete)
	assertEqual(t, "status", res.Status, model.ProviderPartial)
}

func ptr[T any](v T) *T { return &v }

func TestScan_Timeouts(t *testing.T) {
	t.Run("scope timeout fails only the slow subscription", func(t *testing.T) {
		nsgs := &fakeNSGs{
			bySub: map[string][]*armnetwork.SecurityGroup{subA: {openNSG(subA, "n")}},
			block: map[string]bool{subB: true},
		}
		cfg := Config{Subscriptions: []string{subA, subB}, ScopeTimeout: 50 * time.Millisecond}
		res := NewScanner(cfg, nil, nsgs).Scan(context.Background())
		assertEqual(t, "scopes", scopeStatuses(res.Scopes), []string{
			subA + " complete <null>", subB + " failed <null>",
		})
		assertEqual(t, "errors", errorKinds(res.Errors), []string{subB + " " + OpListNSGs + " timeout"})
		assertEqual(t, "status", res.Status, model.ProviderPartial)
	})
	t.Run("cancelled run: nothing started, every scope failed, no call", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		nsgs := &fakeNSGs{}
		res := NewScanner(Config{Subscriptions: []string{subA, subB}}, nil, nsgs).Scan(ctx)
		assertEqual(t, "no calls", len(nsgs.called()), 0)
		assertEqual(t, "errors", errorKinds(res.Errors), []string{
			subA + " " + OpListNSGs + " timeout", subB + " " + OpListNSGs + " timeout",
		})
		assertEqual(t, "status", res.Status, model.ProviderFailed)
	})
	t.Run("cancelled discovery", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		subs := &fakeSubs{err: &pageError{page: 1, err: context.Canceled}}
		res := NewScanner(Config{}, subs, &fakeNSGs{}).Scan(ctx)
		assertEqual(t, "errors", errorKinds(res.Errors), []string{" " + OpListSubscriptions + " timeout"})
		assertEqual(t, "status", res.Status, model.ProviderFailed)
	})
}

// The same inventory, shuffled and scanned with concurrency, always encodes
// to the same bytes.
func TestScan_DeterministicJSON(t *testing.T) {
	ids := []string{subA, subB, subC, subD, subE}
	build := func(seed uint64) []byte {
		rng := rand.New(rand.NewPCG(seed, 1))
		nsgs := &fakeNSGs{bySub: map[string][]*armnetwork.SecurityGroup{}}
		var subs []Subscription
		for _, id := range ids {
			groups := []*armnetwork.SecurityGroup{
				openNSG(id, "a"),
				nsgSpec{name: "b", rules: []ruleSpec{
					inAllow("x", "*", "*", "443", 100),
					{name: "y", direction: "Inbound", access: "Allow", protocol: "Tcp", priority: 120,
						srcList: []string{"Internet", "0.0.0.0/0", "*"}, dstPorts: []string{"22", "80-90"}},
				}}.build(id),
			}
			rng.Shuffle(len(groups), func(i, j int) { groups[i], groups[j] = groups[j], groups[i] })
			for _, g := range groups {
				rs := g.Properties.SecurityRules
				rng.Shuffle(len(rs), func(i, j int) { rs[i], rs[j] = rs[j], rs[i] })
			}
			nsgs.bySub[id] = groups
			subs = append(subs, Subscription{ID: id, State: StateEnabled, HasState: true})
		}
		subs = append(subs, Subscription{ID: subF, State: StateDeleted, HasState: true})
		rng.Shuffle(len(subs), func(i, j int) { subs[i], subs[j] = subs[j], subs[i] })
		res := NewScanner(Config{Concurrency: 8}, &fakeSubs{subs: subs}, nsgs).Scan(context.Background())
		js, err := report.Encode(report.Build([]model.ProviderResult{res}, report.Options{ToolVersion: "test"}))
		if err != nil {
			t.Fatal(err)
		}
		return js
	}
	first := build(1)
	for seed := uint64(2); seed < 20; seed++ {
		if got := build(seed); !bytes.Equal(got, first) {
			t.Fatalf("seed %d: output differs", seed)
		}
	}
	if !bytes.Contains(first, []byte(`"subscription_state": "Deleted"`)) ||
		!bytes.Contains(first, []byte(`"source": "Internet"`)) {
		t.Errorf("report misses expected content:\n%s", first)
	}
}

// The scanner does not modify the subscriptions the lister returned or the
// explicit list it was given.
func TestScan_DoesNotMutateInputs(t *testing.T) {
	discovered := []Subscription{
		{ID: " " + subB + " ", State: StateEnabled, HasState: true},
		{ID: subA, State: StateDeleted, HasState: true},
	}
	orig := slices.Clone(discovered)
	nsgs := &fakeNSGs{bySub: map[string][]*armnetwork.SecurityGroup{subB: {}}}
	NewScanner(Config{}, &fakeSubs{subs: discovered}, nsgs).Scan(context.Background())
	assertEqual(t, "discovered", discovered, orig)

	explicit := []string{subB, " " + subA}
	origE := slices.Clone(explicit)
	NewScanner(Config{Subscriptions: explicit}, nil, nsgs).Scan(context.Background())
	assertEqual(t, "explicit", explicit, origE)
}

func TestShouldScan(t *testing.T) {
	for _, tc := range []struct {
		s    Subscription
		want bool
	}{
		{Subscription{ID: subA}, true},
		{Subscription{ID: subA, State: StateDeleted}, true}, // no state metadata: never skipped
		{Subscription{ID: subA, State: StateDeleted, HasState: true}, false},
		{Subscription{ID: subA, State: "DELETED", HasState: true}, false},
		{Subscription{ID: subA, State: "Deleted ", HasState: true}, true}, // not an exact state
		{Subscription{ID: subA, State: "", HasState: true}, true},
	} {
		if got := shouldScan(tc.s); got != tc.want {
			t.Errorf("shouldScan(%+v) = %v, want %v", tc.s, got, tc.want)
		}
	}
}

func TestValidSubscriptionID(t *testing.T) {
	for _, s := range []string{subA, "ABCDEF01-2345-6789-ABCD-EF0123456789"} {
		if !ValidSubscriptionID(s) {
			t.Errorf("%q should be valid", s)
		}
	}
	for _, s := range []string{"", "x", subA + "/", "../" + subA, subA + "?x=1", " " + subA,
		"00000000-0000-0000-0000-00000000000g", "00000000000000000000000000000000"} {
		if ValidSubscriptionID(s) {
			t.Errorf("%q should be invalid", s)
		}
	}
}

func TestProvider(t *testing.T) {
	assertEqual(t, "provider", NewScanner(Config{}, nil, nil).Provider(), model.ProviderAzure)
}

// In the final report the Internet service tag stays a separate finding from
// a literal 0.0.0.0/0, while "*" and "0.0.0.0/0" on the same rule and port
// describe the same exposure and are merged (DESIGN.md 6.1, 6.6).
func TestReport_InternetTagNotConflatedWithWorldCIDR(t *testing.T) {
	sg := nsgSpec{name: "n", rules: []ruleSpec{{
		name: "web", direction: "Inbound", access: "Allow", protocol: "Tcp", priority: 100,
		srcList: []string{"*", "0.0.0.0/0", "Internet"}, dstPorts: []string{"443"},
	}}}.build(subA)
	nsgs := &fakeNSGs{bySub: map[string][]*armnetwork.SecurityGroup{subA: {sg}}}
	res := NewScanner(Config{Subscriptions: []string{subA}}, nil, nsgs).Scan(context.Background())
	rep := report.Build([]model.ProviderResult{res}, report.Options{})
	if len(rep.Azure.NSGs) != 1 {
		t.Fatalf("NSGs = %d", len(rep.Azure.NSGs))
	}
	var got []string
	for _, f := range rep.Azure.NSGs[0].InsecureRules {
		got = append(got, f.Source+" "+f.MatchReason)
	}
	assertEqual(t, "findings", got, []string{
		"0.0.0.0/0 azure_any_wildcard",
		"Internet azure_service_tag_internet",
	})
	assertEqual(t, "count", rep.Scan.Findings, 2)
	assertEqual(t, "exit", report.ExitCode(rep), report.ExitFindings)
}
