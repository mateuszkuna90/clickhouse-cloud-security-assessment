package gcp

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"cloud.google.com/go/auth"
	"cloud.google.com/go/auth/credentials"
	"cloud.google.com/go/auth/httptransport"
	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
)

// ScopeComputeReadOnly is the only OAuth scope requested. Tokens minted for
// service accounts and workload identity are limited to read-only Compute
// Engine calls even if the identity's IAM roles allow more. (Credentials
// from "gcloud auth application-default login" carry the scopes chosen at
// login; for them IAM is the effective limit.)
const ScopeComputeReadOnly = "https://www.googleapis.com/auth/compute.readonly"

// pageSize is the firewalls.list maxResults value (the API maximum is 500).
const pageSize = 500

// maxPages bounds one project's listing. At pageSize rules per page this is
// far above any real project, so reaching it means the API keeps returning
// new page tokens (for example empty pages that never end).
const maxPages = 1000

// Errors returned by NewClient. Their text is fixed here: the SDK's own
// error is dropped because it can quote credential file contents or token
// endpoint responses.
var (
	// ErrCredentials means Application Default Credentials could not be
	// found or loaded.
	ErrCredentials = errors.New(
		"Google Application Default Credentials could not be loaded: " +
			"check GOOGLE_APPLICATION_CREDENTIALS, run 'gcloud auth application-default login', " +
			"or use an attached service account / workload identity")
	// ErrClientInit means the Compute API client could not be created.
	ErrClientInit = errors.New("Compute Engine API client could not be created")
)

// Client is the SDK adapter. It is safe for concurrent use.
//
// It uses the Compute Engine REST client google.golang.org/api/compute/v1
// and requests one page at a time. Each page request is sent with the
// caller's context (FirewallsListCall.Context, which the generated client
// passes to http.Request.WithContext), so a deadline or cancellation stops
// the request in flight and no further page is requested. Nothing runs in
// the background: tokens are refreshed synchronously (NewClient), and when
// ListFirewalls returns the client is idle.
type Client struct {
	hc  *http.Client
	svc *compute.Service
}

// NewClient builds a Compute REST client on Application Default Credentials
// (GOOGLE_APPLICATION_CREDENTIALS, the gcloud ADC file, or the metadata
// server of an attached service account; workload identity federation
// configurations are supported through the same file).
//
// It never reads, stores or logs credential values. The credentials are
// wrapped (guardCredentials) so their errors cannot reach the report, and
// the SDK's debug loggers are replaced with discarding ones, because the
// SDK logs full request and response bodies when
// GOOGLE_SDK_GO_LOGGING_LEVEL is set.
func NewClient(ctx context.Context) (*Client, error) {
	creds, err := credentials.DetectDefault(&credentials.DetectOptions{
		Scopes: []string{ScopeComputeReadOnly},
		Logger: discardLogger(),
		// Refresh tokens synchronously, inside the request that needs them
		// and under its context. The default refreshes in a background
		// goroutine, which could outlive ListFirewalls.
		DisableAsyncRefresh: true,
	})
	if err != nil {
		return nil, ErrCredentials
	}
	return newClient(ctx, creds)
}

// newClient builds the client on explicit credentials. extra options are
// for tests (a local endpoint).
//
// The HTTP client is built here with the auth library's standard transport,
// so that the guarded credentials and the discard logger are the only ones
// in use.
func newClient(ctx context.Context, creds *auth.Credentials, extra ...option.ClientOption) (*Client, error) {
	hc, err := httptransport.NewClient(&httptransport.Options{
		Credentials: guardCredentials(creds),
		Logger:      discardLogger(),
	})
	if err != nil {
		return nil, ErrClientInit
	}
	opts := []option.ClientOption{
		option.WithHTTPClient(hc),
		option.WithLogger(discardLogger()),
	}
	opts = append(opts, extra...)
	svc, err := compute.NewService(ctx, opts...)
	if err != nil {
		return nil, ErrClientInit
	}
	return &Client{hc: hc, svc: svc}, nil
}

// Close releases idle connections. The client starts no background work,
// so it is safe to call once the ListFirewalls calls using it have returned.
func (c *Client) Close() error {
	if c == nil || c.hc == nil {
		return nil
	}
	c.hc.CloseIdleConnections()
	return nil
}

// ListFirewalls returns every VPC firewall rule of a project, following
// nextPageToken to the last page. The project ID is validated before any
// request is built.
//
// An error on any page returns no rules at all: a partial listing would
// look like coverage that did not happen (DESIGN.md 5.6).
func (c *Client) ListFirewalls(ctx context.Context, project string) ([]*compute.Firewall, error) {
	if !ValidProject(project) {
		return nil, errInvalidProject
	}
	return listPages(ctx, maxPages, func(ctx context.Context, token string) (*compute.FirewallList, error) {
		call := c.svc.Firewalls.List(project).MaxResults(pageSize).Context(ctx)
		if token != "" {
			call = call.PageToken(token)
		}
		return call.Do()
	})
}

// fetchPage requests one page of firewalls.list; token is "" for the first.
type fetchPage func(ctx context.Context, token string) (*compute.FirewallList, error)

// listPages requests pages one after another until a page has no
// nextPageToken, and returns the items of all of them. Every page is
// inspected, including pages with no items, and page numbers count
// requests: the Nth request is page N.
//
// It fails, returning no items, when:
//   - ctx has ended before a request (no further request is made);
//   - a request fails (if ctx has ended by then, the context error is
//     reported, so a cancelled listing is never a successful empty one);
//   - a nextPageToken was already seen (a repeat or a cycle);
//   - more than limit pages would be needed.
func listPages(ctx context.Context, limit int, fetch fetchPage) ([]*compute.Firewall, error) {
	var all []*compute.Firewall
	seen := map[string]bool{}
	token := ""
	for page := 1; ; page++ {
		if page > limit {
			return nil, &pageError{page: page, err: errTooManyPages}
		}
		if err := ctx.Err(); err != nil {
			return nil, &pageError{page: page, err: err}
		}
		list, err := fetch(ctx, token)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				err = ctxErr
			}
			return nil, &pageError{page: page, err: err}
		}
		if list == nil {
			return nil, &pageError{page: page, err: errNoResponse}
		}
		all = append(all, list.Items...)
		token = list.NextPageToken
		if token == "" {
			return all, nil
		}
		if seen[token] {
			return nil, &pageError{page: page, err: errRepeatedToken}
		}
		seen[token] = true
	}
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// guardCredentials returns credentials that delegate to c unchanged, so the
// standard ADC behaviour is preserved, but replace every error with
// credentialsError. This gives a typed signal for "credentials could not be
// resolved" (the transport otherwise returns untyped or url.Error-wrapped
// errors) and guarantees that token endpoint responses, credential file
// contents and executable output cannot reach the report or a log.
//
// The raw credentials JSON is deliberately not copied into the wrapper.
func guardCredentials(c *auth.Credentials) *auth.Credentials {
	return auth.NewCredentials(&auth.CredentialsOptions{
		TokenProvider:          tokenGuard{inner: c},
		ProjectIDProvider:      guardProperty(c, (*auth.Credentials).ProjectID),
		QuotaProjectIDProvider: guardProperty(c, (*auth.Credentials).QuotaProjectID),
		UniverseDomainProvider: guardProperty(c, (*auth.Credentials).UniverseDomain),
	})
}

// tokenGuard delegates Token to the wrapped credentials.
type tokenGuard struct {
	inner *auth.Credentials
}

func (g tokenGuard) Token(ctx context.Context) (*auth.Token, error) {
	if g.inner == nil || g.inner.TokenProvider == nil {
		return nil, &credentialsError{}
	}
	tok, err := g.inner.Token(ctx)
	if err != nil {
		return nil, newCredentialsError(err)
	}
	return tok, nil
}

// guardProperty wraps one credentials property getter.
func guardProperty(c *auth.Credentials,
	get func(*auth.Credentials, context.Context) (string, error)) auth.CredentialsPropertyProvider {
	return auth.CredentialsPropertyFunc(func(ctx context.Context) (string, error) {
		if c == nil {
			return "", &credentialsError{}
		}
		v, err := get(c, ctx)
		if err != nil {
			return "", newCredentialsError(err)
		}
		return v, nil
	})
}
