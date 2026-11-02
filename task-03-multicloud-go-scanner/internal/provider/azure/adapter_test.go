package azure

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
)

// ---- subscriptions through the real SDK ----------------------------------

func TestListSubscriptions_PagesAndStates(t *testing.T) {
	f := newFakeARM(map[string][]armPage{subsPath(): {
		{items: []string{subJSON(subA, "Enabled"), subJSON(subB, "Warned")}},
		{}, // an empty page in the middle
		{items: []string{subJSON(subC, "Expired"), subJSON(subD, ""), subJSON(subE, "Deleted")}},
		{items: []string{
			`{"id":"/subscriptions/` + subF + `","state":"Disabled"}`, // no subscriptionId field
			`{"displayName":"no id at all","state":"Enabled"}`,
			`null`,
		}},
	}})
	c := realClient(t, f, staticCred{})
	got, err := c.ListSubscriptions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, "subscriptions", got, []Subscription{
		{ID: subA, State: StateEnabled, HasState: true},
		{ID: subB, State: StateWarned, HasState: true},
		{ID: subC, State: StateExpired, HasState: true},
		{ID: subD, State: "", HasState: true},
		{ID: subE, State: StateDeleted, HasState: true},
		{ID: subF, State: StateDisabled, HasState: true},
		{ID: "", State: StateEnabled, HasState: true},
		{ID: "", HasState: true},
	})
	reqs := f.requestLog()
	assertEqual(t, "requests (one per page)", len(reqs), 4)
	for _, r := range reqs {
		if r.method != http.MethodGet || r.auth != "Bearer "+fakeToken {
			t.Errorf("request %+v", r)
		}
	}
}

func TestListSubscriptions_ErrorOnLaterPageDiscardsEverything(t *testing.T) {
	f := newFakeARM(map[string][]armPage{subsPath(): {
		{items: []string{subJSON(subA, "Enabled")}},
		armError(http.StatusForbidden, "AuthorizationFailed", "denied"),
	}})
	got, err := realClient(t, f, staticCred{}).ListSubscriptions(context.Background())
	var pe *pageError
	if got != nil || !errors.As(err, &pe) || pe.page != 2 {
		t.Fatalf("ListSubscriptions = %v, %v", got, err)
	}
	assertEqual(t, "kind", classify(err), model.ErrorKindPermissionDenied)
}

// ---- NSGs through the real SDK -------------------------------------------

func TestListNSGs_MultiplePages(t *testing.T) {
	f := newFakeARM(map[string][]armPage{nsgPath(subA): {
		{items: []string{nsgJSON(t, subA, nsgSpec{name: "a", rules: []ruleSpec{inAllow("ssh", "Tcp", "*", "22", 100)}})}},
		{},
		{items: []string{nsgJSON(t, subA, nsgSpec{name: "b"}), nsgJSON(t, subA, nsgSpec{name: "c"})}},
	}})
	c := realClient(t, f, staticCred{})
	got, err := c.ListNSGs(context.Background(), subA)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, g := range got {
		names = append(names, *g.Name)
	}
	assertEqual(t, "names", names, []string{"a", "b", "c"})
	assertEqual(t, "rules decoded", len(got[0].Properties.SecurityRules), 1)
	assertEqual(t, "default rules decoded", len(got[0].Properties.DefaultSecurityRules), 6)
	reqs := f.requestLog()
	assertEqual(t, "requests", len(reqs), 3)
	if u, _ := url.Parse(reqs[0].url); u.Query().Get("api-version") == "" || u.Path != nsgPath(subA) {
		t.Errorf("first request %s", reqs[0].url)
	}
}

func TestListNSGs_EmptySubscription(t *testing.T) {
	f := newFakeARM(map[string][]armPage{nsgPath(subA): {{}}})
	got, err := realClient(t, f, staticCred{}).ListNSGs(context.Background(), subA)
	if err != nil || len(got) != 0 {
		t.Fatalf("ListNSGs = %v, %v", got, err)
	}
}

func TestListNSGs_Failures(t *testing.T) {
	tests := []struct {
		name     string
		pages    []armPage
		page     int
		kind     string
		requests int // including retries
	}{
		{"403 on page 1", []armPage{armError(403, "AuthorizationFailed", "x")}, 1, model.ErrorKindPermissionDenied, 1},
		{"409 disabled subscription", []armPage{armError(409, "ReadOnlyDisabledSubscription", "x")}, 1,
			model.ErrorKindPermissionDenied, 1},
		{"404 subscription", []armPage{armError(404, "SubscriptionNotFound", "x")}, 1, model.ErrorKindNotFound, 1},
		{"401 token", []armPage{armError(401, "ExpiredAuthenticationToken", "x")}, 1, model.ErrorKindAuth, 1},
		{"429 retried then reported", []armPage{armError(429, "SubscriptionRequestsThrottled", "x")}, 1,
			model.ErrorKindThrottled, 3},
		{"500 on page 2 discards page 1", []armPage{
			{items: []string{nsgJSON(t, subA, nsgSpec{name: "a"})}},
			armError(500, "InternalServerError", "x"),
		}, 2, model.ErrorKindOther, 1 + 3},
		{"malformed body", []armPage{{body: `{"value":[{"id":`}}, 1, model.ErrorKindOther, 1},
		{"409 MissingSubscriptionRegistration is not auto-registered", []armPage{
			armError(409, "MissingSubscriptionRegistration", "x")}, 1, model.ErrorKindOther, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeARM(map[string][]armPage{nsgPath(subA): tc.pages})
			got, err := realClient(t, f, staticCred{}).ListNSGs(context.Background(), subA)
			var pe *pageError
			if got != nil || !errors.As(err, &pe) || pe.page != tc.page {
				t.Fatalf("ListNSGs = %v, %v", got, err)
			}
			assertEqual(t, "kind", classify(err), tc.kind)
			reqs := f.requestLog()
			assertEqual(t, "requests", len(reqs), tc.requests)
			for _, r := range reqs {
				if r.method != http.MethodGet {
					t.Errorf("non-GET request sent: %+v", r)
				}
			}
		})
	}
}

func TestListNSGs_RepeatedNextLink(t *testing.T) {
	self := pageURL(nsgPath(subA), "p1")
	f := newFakeARM(map[string][]armPage{nsgPath(subA): {
		{items: []string{nsgJSON(t, subA, nsgSpec{name: "a"})}},
		{next: &self},
	}})
	got, err := realClient(t, f, staticCred{}).ListNSGs(context.Background(), subA)
	var pe *pageError
	if got != nil || !errors.As(err, &pe) || pe.page != 2 || !errors.Is(err, errRepeatedNextLink) {
		t.Fatalf("ListNSGs = %v, %v", got, err)
	}
	assertEqual(t, "requests", len(f.requestLog()), 2)
}

// A nextLink to another host, or plain HTTP, never receives a request and
// so never receives the bearer token.
func TestListNSGs_NextLinkToForeignHostIsRefused(t *testing.T) {
	for _, link := range []string{
		"https://attacker.example/subscriptions/x?$skiptoken=p1",
		"http://" + armHost + nsgPath(subA) + "?$skiptoken=p1",
		"https://" + armHost + ".attacker.example" + nsgPath(subA) + "?$skiptoken=p1",
	} {
		t.Run(link, func(t *testing.T) {
			f := newFakeARM(map[string][]armPage{nsgPath(subA): {
				{items: []string{nsgJSON(t, subA, nsgSpec{name: "a"})}, next: to.Ptr(link)},
				{},
			}})
			got, err := realClient(t, f, staticCred{}).ListNSGs(context.Background(), subA)
			if got != nil || !errors.Is(err, errUnexpectedHost) {
				t.Fatalf("ListNSGs = %v, %v", got, err)
			}
			reqs := f.requestLog()
			assertEqual(t, "only the first page was requested", len(reqs), 1)
		})
	}
}

func TestRequestGuard(t *testing.T) {
	f := newFakeARM(nil)
	pl := runtime.NewPipeline("test", "v0", runtime.PipelineOptions{}, &policy.ClientOptions{
		Transport:       f,
		PerCallPolicies: []policy.Policy{requestGuard{host: armHost}},
		Retry:           policy.RetryOptions{MaxRetries: -1},
	})
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		req, err := runtime.NewRequest(context.Background(), m, "https://"+armHost+"/subscriptions")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pl.Do(req); !errors.Is(err, errNonReadRequest) {
			t.Errorf("%s: err = %v", m, err)
		}
	}
	req, _ := runtime.NewRequest(context.Background(), http.MethodGet, "https://"+armHost+"/subscriptions")
	if _, err := pl.Do(req); err != nil {
		t.Errorf("GET refused: %v", err)
	}
	assertEqual(t, "only the GET reached the transport", len(f.requestLog()), 1)
}

func TestListNSGs_ChecksInputBeforeAnyRequest(t *testing.T) {
	f := newFakeARM(map[string][]armPage{nsgPath(subA): {{}}})
	c := realClient(t, f, staticCred{})
	for _, id := range []string{"", "x/../y", subA + "/resourceGroups"} {
		if _, err := c.ListNSGs(context.Background(), id); !errors.Is(err, errInvalidSubscriptionID) {
			t.Errorf("%q: err = %v", id, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.ListNSGs(ctx, subA); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: err = %v", err)
	}
	assertEqual(t, "requests", len(f.requestLog()), 0)
}

// Cancelling while a request is in flight stops it; no further page is
// requested, and nothing keeps running after ListNSGs returns.
func TestListNSGs_CancelInFlight(t *testing.T) {
	f := newFakeARM(map[string][]armPage{nsgPath(subA): {{}, {}}})
	f.hold = make(chan struct{})
	f.started = make(chan string, 4)
	c := realClient(t, f, staticCred{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := c.ListNSGs(ctx, subA)
		done <- err
	}()
	<-f.started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || classify(err) != model.ErrorKindTimeout {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ListNSGs did not return after cancel")
	}
	close(f.hold)
	assertEqual(t, "requests", len(f.requestLog()), 1)
}

func TestScan_EndToEndThroughSDK(t *testing.T) {
	f := newFakeARM(map[string][]armPage{
		subsPath(): {
			{items: []string{subJSON(subA, "Enabled"), subJSON(subB, "Disabled")}},
			{items: []string{subJSON(subC, "Deleted"), subJSON(subD, "PastDue")}},
		},
		nsgPath(subA): {
			{items: []string{nsgJSON(t, subA, nsgSpec{name: "ssh", attached: true,
				rules: []ruleSpec{inAllow("ssh", "Tcp", "*", "22", 100)}})}},
			{items: []string{nsgJSON(t, subA, nsgSpec{name: "web",
				rules: []ruleSpec{inAllow("https", "Tcp", "0.0.0.0/0", "443", 100)}})}},
		},
		nsgPath(subB): {armError(403, "AuthorizationFailed", "denied")},
		nsgPath(subD): {{}},
	})
	c := realClient(t, f, staticCred{})
	res := NewScanner(Config{}, c, c).Scan(context.Background())
	assertEqual(t, "scopes", scopeStatuses(res.Scopes), []string{
		subA + " complete Enabled", subB + " failed Disabled", subC + " skipped Deleted", subD + " complete PastDue",
	})
	assertEqual(t, "errors", errorKinds(res.Errors), []string{subB + " " + OpListNSGs + " permission_denied"})
	assertEqual(t, "message", res.Errors[0].Message, OpListNSGs+" failed: permission denied, or the subscription "+
		"does not allow this read in its current state (page 1) [HTTP 403] [code: AuthorizationFailed]")
	assertEqual(t, "NSGs", len(res.AzureNSGs), 2)
	assertEqual(t, "status", res.Status, model.ProviderPartial)
	for _, r := range f.requestLog() {
		if strings.Contains(r.url, subC) {
			t.Errorf("Deleted subscription was read: %s", r.url)
		}
	}
}

// ---- collectPages with the real azcore Pager -----------------------------

type fakeResp struct {
	items []int
	next  *string
}

func scriptedPager(pages []fakeResp, errAt int, err error, calls *int, during func(n int)) *runtime.Pager[fakeResp] {
	return runtime.NewPager(runtime.PagingHandler[fakeResp]{
		More: func(p fakeResp) bool { return p.next != nil && *p.next != "" },
		Fetcher: func(ctx context.Context, _ *fakeResp) (fakeResp, error) {
			*calls++
			n := *calls
			if during != nil {
				during(n)
			}
			if n == errAt {
				return fakeResp{}, err
			}
			if n > len(pages) {
				return fakeResp{}, errors.New("no more scripted pages")
			}
			return pages[n-1], nil
		},
	})
}

func items(p fakeResp) ([]int, *string) { return p.items, p.next }

func TestCollectPages(t *testing.T) {
	ctx := context.Background()
	link := func(s string) *string { return &s }
	t.Run("all pages, including empty ones", func(t *testing.T) {
		calls := 0
		p := scriptedPager([]fakeResp{{next: link("a")}, {items: []int{1}, next: link("b")}, {items: []int{2, 3}}},
			0, nil, &calls, nil)
		got, err := collectPages(ctx, maxPages, p, items)
		if err != nil || len(got) != 3 || calls != 3 {
			t.Fatalf("got %v, %v, %d calls", got, err, calls)
		}
	})
	t.Run("cycle", func(t *testing.T) {
		calls := 0
		p := scriptedPager([]fakeResp{{next: link("a")}, {next: link("b")}, {next: link("a")}}, 0, nil, &calls, nil)
		got, err := collectPages(ctx, maxPages, p, items)
		if got != nil || !errors.Is(err, errRepeatedNextLink) || calls != 3 {
			t.Fatalf("got %v, %v, %d calls", got, err, calls)
		}
	})
	t.Run("page limit", func(t *testing.T) {
		var pages []fakeResp
		for i := range 10 {
			pages = append(pages, fakeResp{next: link(strconv.Itoa(i))})
		}
		calls := 0
		got, err := collectPages(ctx, 3, scriptedPager(pages, 0, nil, &calls, nil), items)
		var pe *pageError
		if got != nil || !errors.Is(err, errTooManyPages) || !errors.As(err, &pe) || pe.page != 4 || calls != 3 {
			t.Fatalf("got %v, %v, %d calls", got, err, calls)
		}
	})
	t.Run("error discards earlier pages", func(t *testing.T) {
		calls := 0
		boom := errors.New("boom")
		p := scriptedPager([]fakeResp{{items: []int{1}, next: link("a")}}, 2, boom, &calls, nil)
		got, err := collectPages(ctx, maxPages, p, items)
		if got != nil || !errors.Is(err, boom) {
			t.Fatalf("got %v, %v", got, err)
		}
	})
	t.Run("cancelled between pages: no further request", func(t *testing.T) {
		cctx, cancel := context.WithCancel(ctx)
		defer cancel()
		calls := 0
		p := scriptedPager([]fakeResp{{items: []int{1}, next: link("a")}, {}}, 0, nil, &calls,
			func(n int) {
				if n == 1 {
					cancel()
				}
			})
		got, err := collectPages(cctx, maxPages, p, items)
		if got != nil || !errors.Is(err, context.Canceled) || calls != 1 {
			t.Fatalf("got %v, %v, %d calls", got, err, calls)
		}
	})
	t.Run("a failure after cancellation reports the cancellation", func(t *testing.T) {
		cctx, cancel := context.WithCancel(ctx)
		defer cancel()
		calls := 0
		p := scriptedPager(nil, 1, errors.New("connection reset"), &calls, func(int) { cancel() })
		_, err := collectPages(cctx, maxPages, p, items)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v", err)
		}
	})
}

// ---- errors --------------------------------------------------------------

type fakeNetTimeout struct{}

func (fakeNetTimeout) Error() string   { return "i/o timeout" }
func (fakeNetTimeout) Timeout() bool   { return true }
func (fakeNetTimeout) Temporary() bool { return true }

func TestClassify(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"deadline", fmt.Errorf("x: %w", context.DeadlineExceeded), model.ErrorKindTimeout},
		{"canceled in url.Error", &url.Error{Op: "Get", URL: "u", Err: context.Canceled}, model.ErrorKindTimeout},
		{"net timeout", &url.Error{Op: "Get", URL: "u", Err: fakeNetTimeout{}}, model.ErrorKindTimeout},
		{"credentials", fmt.Errorf("wrapped: %w", &credentialsError{}), model.ErrorKindAuth},
		{"credentials timeout", &credentialsError{ctxErr: context.DeadlineExceeded}, model.ErrorKindTimeout},
		{"401", respErr(401, ""), model.ErrorKindAuth},
		{"403", respErr(403, ""), model.ErrorKindPermissionDenied},
		{"403 throttling code", respErr(403, "TenantRequestsThrottled"), model.ErrorKindThrottled},
		{"404", respErr(404, ""), model.ErrorKindNotFound},
		{"409 read-only", respErr(409, "ReadOnlyDisabledSubscription"), model.ErrorKindPermissionDenied},
		{"409 other", respErr(409, "Conflict"), model.ErrorKindOther},
		{"429", respErr(429, ""), model.ErrorKindThrottled},
		{"400 subscription id", respErr(400, "InvalidSubscriptionId"), model.ErrorKindNotFound},
		{"500", respErr(500, "InternalServerError"), model.ErrorKindOther},
		{"plain", errors.New("x"), model.ErrorKindOther},
		{"safe", errInvalidSubscriptionID, model.ErrorKindOther},
	}
	for _, tc := range tests {
		if got := classify(tc.err); got != tc.want {
			t.Errorf("%s: classify = %q, want %q", tc.name, got, tc.want)
		}
	}
	for _, k := range []string{model.ErrorKindAuth, model.ErrorKindPermissionDenied, model.ErrorKindThrottled,
		model.ErrorKindTimeout, model.ErrorKindNotFound, model.ErrorKindOther} {
		if kindText[k] == "" {
			t.Errorf("no text for kind %q", k)
		}
	}
}

func TestSafeMessage_UnlistedCodeIsDropped(t *testing.T) {
	e := scanError(subA, OpListNSGs, &pageError{page: 3, err: respErr(400, "SECRET_CODE_VALUE")})
	assertEqual(t, "message", e.Message, OpListNSGs+" failed: unexpected error (page 3) [HTTP 400]")
	assertEqual(t, "page error text", (&pageError{page: 2, err: errRepeatedNextLink}).Error(),
		"page 2: "+string(errRepeatedNextLink))
}

// ---- credentials ---------------------------------------------------------

func TestGuardCredential(t *testing.T) {
	ctx := context.Background()
	tok, err := guardCredential(staticCred{}).GetToken(ctx, policy.TokenRequestOptions{})
	if err != nil || tok.Token != fakeToken {
		t.Fatalf("GetToken = %v, %v", tok, err)
	}
	secret := errors.New(markerPayload)
	_, err = guardCredential(failingCred{err: secret}).GetToken(ctx, policy.TokenRequestOptions{})
	var ce *credentialsError
	if !errors.As(err, &ce) || errors.Is(err, secret) {
		t.Fatalf("err = %v", err)
	}
	assertNoMarkers(t, "error", err.Error())
	_, err = guardCredential(failingCred{err: fmt.Errorf("%s: %w", markSecret, context.DeadlineExceeded)}).
		GetToken(ctx, policy.TokenRequestOptions{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("context state lost: %v", err)
	}
	if _, err := guardCredential(nil).GetToken(ctx, policy.TokenRequestOptions{}); err == nil {
		t.Errorf("nil credential must fail")
	}
}

// NewClient builds DefaultAzureCredential without requesting a token, so it
// needs no network and no account. Its pipeline options keep it read-only:
// automatic resource provider registration (a POST) is off, and the
// request guard is installed.
func TestNewClient_NoNetworkAndReadOnlyOptions(t *testing.T) {
	c, err := NewClient()
	if err != nil || c == nil {
		t.Fatalf("NewClient = %v, %v", c, err)
	}
	if !c.armOpts.DisableRPRegistration {
		t.Errorf("resource provider auto-registration must be disabled")
	}
	assertEqual(t, "retries", c.armOpts.Retry.MaxRetries, int32(maxRetries))
	assertEqual(t, "per-call policies", c.armOpts.PerCallPolicies,
		[]policy.Policy{requestGuard{host: armHost}})
	if _, ok := c.cred.(credentialGuard); !ok {
		t.Errorf("credential is not guarded: %T", c.cred)
	}
}

func TestNewClient_InvalidTokenCredentialsSelection(t *testing.T) {
	t.Setenv("AZURE_TOKEN_CREDENTIALS", markSecret)
	c, err := NewClient()
	if c != nil || !errors.Is(err, ErrCredentials) || err.Error() != ErrCredentials.Error() {
		t.Fatalf("NewClient = %v, %v", c, err)
	}
	assertNoMarkers(t, "error", err.Error())
}

func TestEndpointHost(t *testing.T) {
	h, err := endpointHost(cloudConf("https://" + armHost))
	assertEqual(t, "host", h, armHost)
	assertEqual(t, "err", err, error(nil))
	for _, ep := range []string{"http://" + armHost, "://bad", ""} {
		if _, err := endpointHost(cloudConf(ep)); err == nil {
			t.Errorf("%q accepted", ep)
		}
	}
}

func cloudConf(endpoint string) cloud.Configuration {
	return cloud.Configuration{Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
		cloud.ResourceManager: {Endpoint: endpoint, Audience: "https://" + armHost},
	}}
}
