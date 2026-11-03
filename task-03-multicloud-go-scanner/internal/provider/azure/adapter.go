package azure

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	azlog "github.com/Azure/azure-sdk-for-go/sdk/azcore/log"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions/v2"
)

// maxRetries is the azcore retry policy limit (DESIGN.md 5.7). Retries
// stop early when the request's context ends.
const maxRetries = 4

// maxPages bounds one listing. ARM pages hold hundreds of items, so this is
// far above any real subscription; reaching it means the API keeps
// returning new nextLinks.
const maxPages = 1000

// ErrCredentials is returned by NewClient when DefaultAzureCredential cannot
// be constructed. Its text is fixed: the SDK's own error is dropped because
// it can quote environment or configuration values.
var ErrCredentials = errors.New(
	"could not create the Azure DefaultAzureCredential: check the AZURE_* environment variables, " +
		"workload identity / managed identity configuration, or 'az login'")

// Client is the SDK adapter. It is safe for concurrent use.
//
// Every request goes through an azcore pipeline that:
//
//   - uses the guarded credential (errors replaced by credentialsError);
//   - refuses non-GET requests and requests to any host other than the
//     Azure Resource Manager endpoint (requestGuard). This runs before the
//     bearer token policy, so a nextLink pointing elsewhere never receives
//     the token;
//   - has automatic resource provider registration disabled
//     (DisableRPRegistration): that policy would send a POST to register
//     Microsoft.Network on a 409 MissingSubscriptionRegistration.
//
// Each page request is sent with the caller's context, so a deadline or
// cancellation stops the request in flight (including retry back-off) and
// no further page is requested. The SDK starts no background goroutines:
// tokens are acquired inside the request that needs them, and when a List
// method returns the client is idle.
type Client struct {
	cred    azcore.TokenCredential // guarded
	armOpts *arm.ClientOptions
	subs    *armsubscriptions.Client
}

// NewClient builds a client on azidentity.DefaultAzureCredential
// (environment service principal, workload identity, managed identity,
// Azure CLI, Azure Developer CLI). The credential is created here but no
// token is requested until the first API call.
//
// It never reads, stores or logs credential values. SDK logging is
// switched off process-wide (disableSDKLogging), because with
// AZURE_SDK_GO_LOGGING=all the SDK writes full error response bodies and
// credential diagnostics to stderr.
func NewClient() (*Client, error) {
	disableSDKLogging()
	cred, err := newDefaultCredential(nil)
	if err != nil {
		return nil, err
	}
	return newClient(cred, nil, policy.RetryOptions{MaxRetries: maxRetries})
}

// newDefaultCredential creates DefaultAzureCredential. transport is for
// tests (a fake token endpoint); nil uses the SDK default.
func newDefaultCredential(transport policy.Transporter) (azcore.TokenCredential, error) {
	opts := &azidentity.DefaultAzureCredentialOptions{}
	if transport != nil {
		opts.ClientOptions.Transport = transport
	}
	cred, err := azidentity.NewDefaultAzureCredential(opts)
	if err != nil {
		return nil, ErrCredentials
	}
	return cred, nil
}

// newClient builds the adapter on an explicit credential. transport and
// retry are for tests (a fake ARM endpoint, short retry delays).
func newClient(cred azcore.TokenCredential, transport policy.Transporter, retry policy.RetryOptions) (*Client, error) {
	disableSDKLogging()
	conf := cloud.AzurePublic
	host, err := endpointHost(conf)
	if err != nil {
		return nil, errClientInit
	}
	opts := &arm.ClientOptions{
		ClientOptions: policy.ClientOptions{
			Cloud:           conf,
			Retry:           retry,
			Transport:       transport,
			PerCallPolicies: []policy.Policy{requestGuard{host: host}},
		},
		DisableRPRegistration: true,
	}
	guarded := guardCredential(cred)
	subs, err := armsubscriptions.NewClient(guarded, opts)
	if err != nil {
		return nil, errClientInit
	}
	return &Client{cred: guarded, armOpts: opts, subs: subs}, nil
}

// endpointHost returns the Resource Manager host of a cloud configuration.
func endpointHost(conf cloud.Configuration) (string, error) {
	svc, ok := conf.Services[cloud.ResourceManager]
	if !ok {
		return "", errClientInit
	}
	u, err := url.Parse(svc.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", errClientInit
	}
	return u.Host, nil
}

// disableSDKLogging removes the azcore log listener. It is process-wide;
// this tool has no other use for SDK logs.
func disableSDKLogging() { azlog.SetListener(nil) }

// ListSubscriptions returns every subscription the identity can see, with
// its raw state, following nextLink to the last page. An error on any page
// returns no subscriptions (DESIGN.md 5.6).
//
// The subscription ID comes from subscriptionId, or, if that is missing,
// from an id of the form "/subscriptions/<guid>". A record with neither is
// returned with an empty ID, and the scanner reports it as a failed scope.
// A missing state gives State "" with HasState true (unknown, scanned).
func (c *Client) ListSubscriptions(ctx context.Context) ([]Subscription, error) {
	pager := c.subs.NewListPager(nil)
	raw, err := collectPages(ctx, maxPages, pager,
		func(r armsubscriptions.ClientListResponse) ([]*armsubscriptions.Subscription, *string) {
			return r.Value, r.NextLink
		})
	if err != nil {
		return nil, err
	}
	out := make([]Subscription, 0, len(raw))
	for _, s := range raw {
		out = append(out, toSubscription(s))
	}
	return out, nil
}

func toSubscription(s *armsubscriptions.Subscription) Subscription {
	sub := Subscription{HasState: true}
	if s == nil {
		return sub
	}
	sub.ID = strings.TrimSpace(deref(s.SubscriptionID))
	if sub.ID == "" {
		if rest, ok := strings.CutPrefix(deref(s.ID), "/subscriptions/"); ok && ValidSubscriptionID(rest) {
			sub.ID = rest
		}
	}
	if s.State != nil {
		sub.State = SubscriptionState(*s.State)
	}
	return sub
}

// ListNSGs returns every NSG of a subscription (all resource groups),
// following nextLink to the last page. The subscription ID is validated
// before any request is built. An error on any page returns no NSGs.
func (c *Client) ListNSGs(ctx context.Context, subscriptionID string) ([]*armnetwork.SecurityGroup, error) {
	if !ValidSubscriptionID(subscriptionID) {
		return nil, errInvalidSubscriptionID
	}
	client, err := armnetwork.NewSecurityGroupsClient(subscriptionID, c.cred, c.armOpts)
	if err != nil {
		return nil, errClientInit
	}
	pager := client.NewListAllPager(nil)
	return collectPages(ctx, maxPages, pager,
		func(r armnetwork.SecurityGroupsClientListAllResponse) ([]*armnetwork.SecurityGroup, *string) {
			return r.Value, r.NextLink
		})
}

// collectPages drives an SDK pager to the end and returns the items of all
// pages. Every page is inspected, including pages with no items, and page
// numbers count requests: the Nth request is page N.
//
// It fails, returning no items, when:
//   - ctx has ended before a request (no further request is made);
//   - a request fails (if ctx has ended by then, the context error is
//     reported, so a cancelled listing is never a successful empty one);
//   - a nextLink was already seen (a repeat or a cycle);
//   - more than limit pages would be needed.
func collectPages[P, E any](ctx context.Context, limit int, pager *runtime.Pager[P],
	page func(P) ([]E, *string)) ([]E, error) {
	var all []E
	seen := map[string]bool{}
	for n := 1; pager.More(); n++ {
		if n > limit {
			return nil, &pageError{page: n, err: errTooManyPages}
		}
		if err := ctx.Err(); err != nil {
			return nil, &pageError{page: n, err: err}
		}
		resp, err := pager.NextPage(ctx)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				err = ctxErr
			}
			return nil, &pageError{page: n, err: err}
		}
		items, next := page(resp)
		all = append(all, items...)
		if link := deref(next); link != "" {
			if seen[link] {
				return nil, &pageError{page: n, err: errRepeatedNextLink}
			}
			seen[link] = true
		}
	}
	return all, nil
}

// requestGuard is the first per-call policy of every ARM request. It
// refuses anything but an HTTPS GET to the Resource Manager host, before
// the request is retried or a token is attached.
type requestGuard struct {
	host string
}

func (g requestGuard) Do(req *policy.Request) (*http.Response, error) {
	r := req.Raw()
	if r.Method != http.MethodGet {
		return nil, errNonReadRequest
	}
	if r.URL == nil || r.URL.Scheme != "https" || !strings.EqualFold(r.URL.Host, g.host) {
		return nil, errUnexpectedHost
	}
	return req.Next()
}

// guardCredential returns a credential that delegates to c unchanged, so
// the standard DefaultAzureCredential behaviour is preserved, but replaces
// every error with credentialsError. This gives a typed signal for
// "credentials could not be resolved" and guarantees that token endpoint
// responses and CLI output cannot reach the report or a log.
func guardCredential(c azcore.TokenCredential) azcore.TokenCredential {
	return credentialGuard{inner: c}
}

type credentialGuard struct {
	inner azcore.TokenCredential
}

func (g credentialGuard) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if g.inner == nil {
		return azcore.AccessToken{}, &credentialsError{}
	}
	tok, err := g.inner.GetToken(ctx, opts)
	if err != nil {
		return azcore.AccessToken{}, newCredentialsError(err)
	}
	return tok, nil
}

func deref[T any](p *T) T {
	if p == nil {
		var zero T
		return zero
	}
	return *p
}
