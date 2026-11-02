package gcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"cloud.google.com/go/auth"
	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
)

func TestValidProject(t *testing.T) {
	valid := []string{
		"example-project-a", "abcdef", "a23456789012345678901234567890",
		"example.com:my-project", "google.com:example-proj", "123456789012",
	}
	invalid := []string{
		"", "abcde", "a234567890123456789012345678901", "Example-Project", "1project",
		"project-", "-project", "my_project", "proj ect", "p/../x", "p?x=1", "p#x",
		"..", ".", "example.com:", ":my-project", "example-project-a/", "%2e%2e",
		"example-project-a\n",
	}
	for _, p := range valid {
		if !ValidProject(p) {
			t.Errorf("ValidProject(%q) = false, want true", p)
		}
	}
	for _, p := range invalid {
		if ValidProject(p) {
			t.Errorf("ValidProject(%q) = true, want false", p)
		}
	}
}

func TestResolveProjects(t *testing.T) {
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == EnvProject {
				return v
			}
			return ""
		}
	}
	assertEqual(t, "explicit wins", ResolveProjects([]string{projB, projA}, env(projC)), []string{projB, projA})
	assertEqual(t, "env fallback", ResolveProjects(nil, env(" "+projC+" ")), []string{projC})
	assertEqual(t, "nothing", ResolveProjects(nil, env("  ")), []string(nil))
	assertEqual(t, "nil getenv", ResolveProjects(nil, nil), []string(nil))
	in := []string{projA}
	out := ResolveProjects(in, nil)
	out[0] = "changed"
	assertEqual(t, "input not aliased", in[0], projA)
}

type fakeNetTimeout struct{}

func (fakeNetTimeout) Error() string   { return "i/o timeout" }
func (fakeNetTimeout) Timeout() bool   { return true }
func (fakeNetTimeout) Temporary() bool { return true }

var _ net.Error = fakeNetTimeout{}

func TestClassify(t *testing.T) {
	gerr := func(code int, reasons ...string) error {
		e := &googleapi.Error{Code: code, Message: "m", Body: "b"}
		for _, r := range reasons {
			e.Errors = append(e.Errors, googleapi.ErrorItem{Reason: r, Message: "x"})
		}
		return &pageError{page: 1, err: e}
	}
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"deadline", fmt.Errorf("x: %w", context.DeadlineExceeded), model.ErrorKindTimeout},
		{"canceled in url.Error", &url.Error{Op: "Get", URL: "u", Err: context.Canceled}, model.ErrorKindTimeout},
		{"net timeout", &url.Error{Op: "Get", URL: "u", Err: fakeNetTimeout{}}, model.ErrorKindTimeout},
		{"credentials", &url.Error{Op: "Get", URL: "u", Err: &credentialsError{}}, model.ErrorKindAuth},
		{"credentials timeout", &credentialsError{ctxErr: context.DeadlineExceeded}, model.ErrorKindTimeout},
		{"401", gerr(401), model.ErrorKindAuth},
		{"403", gerr(403, "forbidden"), model.ErrorKindPermissionDenied},
		{"403 not enabled", gerr(403, "accessNotConfigured"), model.ErrorKindPermissionDenied},
		{"403 rate", gerr(403, "rateLimitExceeded"), model.ErrorKindThrottled},
		{"403 user rate", gerr(403, "userRateLimitExceeded"), model.ErrorKindThrottled},
		{"403 quota", gerr(403, "quotaExceeded"), model.ErrorKindThrottled},
		{"404", gerr(404, "notFound"), model.ErrorKindNotFound},
		{"429", gerr(429), model.ErrorKindThrottled},
		{"400", gerr(400, "invalid"), model.ErrorKindOther},
		{"500", gerr(500), model.ErrorKindOther},
		{"plain error", errors.New("x"), model.ErrorKindOther},
		{"safe error", errInvalidProject, model.ErrorKindOther},
	}
	for _, tc := range tests {
		if got := classify(tc.err); got != tc.want {
			t.Errorf("%s: classify = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestSafeMessageUsesOnlyAllowlistedParts(t *testing.T) {
	e := &googleapi.Error{
		Code: 403, Message: "SECRET-MESSAGE", Body: "SECRET-BODY",
		Errors: []googleapi.ErrorItem{
			{Reason: "forbidden", Message: "SECRET-ITEM"},
			{Reason: "SECRET-REASON"},
			{Reason: "forbidden"},
			{Reason: "accessNotConfigured"},
		},
	}
	got := scanError(projA, OpListFirewalls, &pageError{page: 3, err: e})
	assertEqual(t, "error", got, model.ScanError{
		Provider: model.ProviderGCP, Scope: projA, Operation: OpListFirewalls,
		Kind: model.ErrorKindPermissionDenied,
		Message: "compute.firewalls.list failed: permission denied, or the Compute Engine API is not enabled " +
			"for the project (page 3) [HTTP 403] [reason: accessNotConfigured,forbidden]",
	})
	// Every kind has fixed text.
	for _, k := range []string{model.ErrorKindAuth, model.ErrorKindPermissionDenied, model.ErrorKindThrottled,
		model.ErrorKindTimeout, model.ErrorKindNotFound, model.ErrorKindOther} {
		if kindText[k] == "" {
			t.Errorf("no text for kind %q", k)
		}
	}
}

// scriptedFetch serves scripted pages to listPages and records each call
// (the page token it was asked for).
type scriptedFetch struct {
	pages []fakePage
	calls []string
	// during, if set, runs inside call number duringAt (1-based).
	during   func()
	duringAt int
}

type fakePage struct {
	items []*compute.Firewall
	next  string
	err   error
	nilOK bool // return (nil, nil)
}

func (s *scriptedFetch) fetch(_ context.Context, token string) (*compute.FirewallList, error) {
	s.calls = append(s.calls, token)
	n := len(s.calls)
	if s.during != nil && n == s.duringAt {
		s.during()
	}
	if n > len(s.pages) {
		return nil, errors.New("scripted fetch: no more pages")
	}
	p := s.pages[n-1]
	if p.err != nil {
		return nil, p.err
	}
	if p.nilOK {
		return nil, nil
	}
	return &compute.FirewallList{Items: p.items, NextPageToken: p.next}, nil
}

func named(n string) *compute.Firewall { return &compute.Firewall{Name: n} }

// listErr checks that listPages failed on the given page with an error
// matching target, and returned no items.
func listErr(t *testing.T, got []*compute.Firewall, err error, page int, target error) {
	t.Helper()
	var pe *pageError
	if got != nil || !errors.As(err, &pe) || pe.page != page || !errors.Is(err, target) {
		t.Fatalf("listPages = %d items, %v; want no items and page %d error %v", len(got), err, page, target)
	}
}

func TestListPages(t *testing.T) {
	ctx := context.Background()
	t.Run("every page is read, including empty ones", func(t *testing.T) {
		s := &scriptedFetch{pages: []fakePage{
			{next: "t1"},
			{items: []*compute.Firewall{named("a")}, next: "t2"},
			{next: "t3"},
			{items: []*compute.Firewall{named("b"), named("c")}},
		}}
		got, err := listPages(ctx, maxPages, s.fetch)
		if err != nil || len(got) != 3 {
			t.Fatalf("listPages = %d items, %v", len(got), err)
		}
		assertEqual(t, "tokens requested", s.calls, []string{"", "t1", "t2", "t3"})
	})
	t.Run("empty page 1 then an error: the error is page 2", func(t *testing.T) {
		boom := errors.New("boom")
		s := &scriptedFetch{pages: []fakePage{{next: "t1"}, {err: boom}}}
		got, err := listPages(ctx, maxPages, s.fetch)
		listErr(t, got, err, 2, boom)
	})
	t.Run("an error discards earlier pages", func(t *testing.T) {
		boom := errors.New("boom")
		s := &scriptedFetch{pages: []fakePage{
			{items: []*compute.Firewall{named("a"), named("b")}, next: "t1"},
			{items: []*compute.Firewall{named("c")}, next: "t2"},
			{err: boom},
		}}
		got, err := listPages(ctx, maxPages, s.fetch)
		listErr(t, got, err, 3, boom)
	})
	t.Run("a page returning its own token", func(t *testing.T) {
		s := &scriptedFetch{pages: []fakePage{{next: "t1"}, {next: "t1"}}}
		got, err := listPages(ctx, maxPages, s.fetch)
		listErr(t, got, err, 2, errRepeatedToken)
		assertEqual(t, "calls", len(s.calls), 2)
	})
	t.Run("a token cycle", func(t *testing.T) {
		s := &scriptedFetch{pages: []fakePage{
			{items: []*compute.Firewall{named("a")}, next: "t1"},
			{next: "t2"},
			{next: "t3"},
			{next: "t1"},
		}}
		got, err := listPages(ctx, maxPages, s.fetch)
		listErr(t, got, err, 4, errRepeatedToken)
		assertEqual(t, "calls", len(s.calls), 4)
	})
	t.Run("endless empty pages with new tokens stop at the limit", func(t *testing.T) {
		var pages []fakePage
		for i := range 10 {
			pages = append(pages, fakePage{next: "t" + strconv.Itoa(i+1)})
		}
		s := &scriptedFetch{pages: pages}
		got, err := listPages(ctx, 5, s.fetch)
		listErr(t, got, err, 6, errTooManyPages)
		assertEqual(t, "calls", len(s.calls), 5)
	})
	t.Run("a listing that ends exactly at the limit succeeds", func(t *testing.T) {
		s := &scriptedFetch{pages: []fakePage{{next: "t1"}, {items: []*compute.Firewall{named("a")}}}}
		got, err := listPages(ctx, 2, s.fetch)
		if err != nil || len(got) != 1 {
			t.Fatalf("listPages = %d items, %v", len(got), err)
		}
	})
	t.Run("cancelled before the first request: no request", func(t *testing.T) {
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		s := &scriptedFetch{pages: []fakePage{{}}}
		got, err := listPages(cctx, maxPages, s.fetch)
		listErr(t, got, err, 1, context.Canceled)
		assertEqual(t, "calls", len(s.calls), 0)
	})
	t.Run("cancelled between pages: no further request", func(t *testing.T) {
		cctx, cancel := context.WithCancel(ctx)
		defer cancel()
		s := &scriptedFetch{
			pages:  []fakePage{{items: []*compute.Firewall{named("a")}, next: "t1"}, {}},
			during: cancel, duringAt: 1,
		}
		got, err := listPages(cctx, maxPages, s.fetch)
		listErr(t, got, err, 2, context.Canceled)
		assertEqual(t, "calls", len(s.calls), 1)
	})
	t.Run("a request failing after cancellation reports the cancellation", func(t *testing.T) {
		cctx, cancel := context.WithCancel(ctx)
		defer cancel()
		s := &scriptedFetch{pages: []fakePage{{err: errors.New("read: connection reset")}}, during: cancel, duringAt: 1}
		got, err := listPages(cctx, maxPages, s.fetch)
		listErr(t, got, err, 1, context.Canceled)
		assertEqual(t, "kind", classify(err), model.ErrorKindTimeout)
	})
	t.Run("no response and no error", func(t *testing.T) {
		s := &scriptedFetch{pages: []fakePage{{nilOK: true}}}
		got, err := listPages(ctx, maxPages, s.fetch)
		listErr(t, got, err, 1, errNoResponse)
	})
}

// fakeProps returns scripted values and errors for credentials properties.
type fakeProps struct {
	val string
	err error
}

func (p fakeProps) GetProperty(context.Context) (string, error) { return p.val, p.err }

func TestGuardCredentials(t *testing.T) {
	secretErr := errors.New(markerPayload)
	ok := auth.NewCredentials(&auth.CredentialsOptions{
		TokenProvider:          staticToken{},
		JSON:                   []byte(`{"private_key":"` + markKey + `"}`),
		ProjectIDProvider:      fakeProps{val: "example-project-a"},
		QuotaProjectIDProvider: fakeProps{val: "example-quota"},
		UniverseDomainProvider: fakeProps{val: "googleapis.com"},
	})
	g := guardCredentials(ok)
	ctx := context.Background()
	tok, err := g.Token(ctx)
	if err != nil || tok.Value != fakeToken {
		t.Fatalf("Token = %v, %v", tok, err)
	}
	for name, get := range map[string]func(context.Context) (string, error){
		"project": g.ProjectID, "quota": g.QuotaProjectID, "universe": g.UniverseDomain,
	} {
		if v, err := get(ctx); err != nil || v == "" {
			t.Errorf("%s = %q, %v; want delegated value", name, v, err)
		}
	}
	if len(g.JSON()) != 0 {
		t.Errorf("guarded credentials expose the raw JSON")
	}

	bad := guardCredentials(auth.NewCredentials(&auth.CredentialsOptions{
		TokenProvider:          failingToken{err: secretErr},
		ProjectIDProvider:      fakeProps{err: secretErr},
		QuotaProjectIDProvider: fakeProps{err: secretErr},
		UniverseDomainProvider: fakeProps{err: fmt.Errorf("%s: %w", markSecret, context.Canceled)},
	}))
	checks := map[string]func() error{
		"token":    func() error { _, err := bad.Token(ctx); return err },
		"project":  func() error { _, err := bad.ProjectID(ctx); return err },
		"quota":    func() error { _, err := bad.QuotaProjectID(ctx); return err },
		"universe": func() error { _, err := bad.UniverseDomain(ctx); return err },
	}
	for name, call := range checks {
		err := call()
		var ce *credentialsError
		if !errors.As(err, &ce) {
			t.Errorf("%s: error %T is not credentialsError", name, err)
			continue
		}
		assertNoMarkers(t, name, err.Error())
		if errors.Is(err, secretErr) {
			t.Errorf("%s: original error is still reachable through Unwrap", name)
		}
	}
	if err := checks["universe"](); !errors.Is(err, context.Canceled) {
		t.Errorf("context state lost: %v", err)
	}

	empty := guardCredentials(auth.NewCredentials(&auth.CredentialsOptions{}))
	if _, err := empty.Token(ctx); err == nil {
		t.Errorf("credentials without a token provider must fail")
	}
}

func TestClientCloseNil(t *testing.T) {
	var c *Client
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestNewClient_LoadsADCWithoutNetwork: a well-formed (fake) authorized_user
// ADC file is accepted. No token is fetched and no request is made until
// ListFirewalls is called, so this needs no network.
func TestNewClient_LoadsADCWithoutNetwork(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fake-authorized-user.json")
	fake := `{"type":"authorized_user","client_id":"fake-client-id.apps.googleusercontent.com",` +
		`"client_secret":"fake-client-secret","refresh_token":"fake-refresh-token"}`
	if err := os.WriteFile(path, []byte(fake), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", path)
	c, err := NewClient(context.Background())
	if err != nil || c == nil {
		t.Fatalf("NewClient = %v, %v", c, err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestListFirewallsChecksInputBeforeAnyRequest(t *testing.T) {
	f, srv := newFakeCompute(t, map[string][]page{projA: onePage(t)})
	c := realClient(t, srv, staticToken{})
	if _, err := c.ListFirewalls(context.Background(), "p/../x"); !errors.Is(err, errInvalidProject) {
		t.Errorf("invalid project: err = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.ListFirewalls(ctx, projA); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled context: err = %v", err)
	}
	assertEqual(t, "requests", len(f.requestLog()), 0)
}

func TestProviderAndPageError(t *testing.T) {
	assertEqual(t, "provider", NewScanner(Config{}, nil).Provider(), model.ProviderGCP)
	pe := &pageError{page: 2, err: errRepeatedToken}
	assertEqual(t, "text", pe.Error(), "page 2: "+string(errRepeatedToken))
}
