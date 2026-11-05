package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/auth"
	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/option"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
)

// TestMain makes sure no test can reach a real Google account: ADC points
// at a file that does not exist (so detection stops there, before the
// gcloud file or the metadata server), the gcloud config directory is
// empty, and the metadata host is unreachable. Every API call goes to a
// local httptest server.
//
// GOOGLE_SDK_GO_LOGGING_LEVEL=debug is set on purpose: the SDK then logs
// full requests and responses unless its logger is replaced. The leak
// tests capture stderr to prove the adapter's discard logger holds.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "gcp-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, k := range []string{
		"GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CLOUD_PROJECT", "GCLOUD_PROJECT",
		"CLOUDSDK_CORE_PROJECT", "GOOGLE_CLOUD_UNIVERSE_DOMAIN",
		"GOOGLE_API_USE_CLIENT_CERTIFICATE", "GOOGLE_API_USE_MTLS_ENDPOINT",
		"GOOGLE_API_GO_EXPERIMENTAL_ENABLE_NEW_AUTH_LIB",
	} {
		os.Unsetenv(k)
	}
	os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(dir, "does-not-exist.json"))
	os.Setenv("CLOUDSDK_CONFIG", dir)
	os.Setenv("GCE_METADATA_HOST", "127.0.0.1:1")
	os.Setenv("NO_GCE_CHECK", "True")
	os.Setenv("GOOGLE_SDK_GO_LOGGING_LEVEL", "debug")
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// Fake identifiers. None of these exist.
const (
	projA     = "example-project-a"
	projB     = "example-project-b"
	projC     = "example-project-c"
	worldStr  = "0.0.0.0/0"
	fakeToken = "fake-access-token-not-a-secret"
	netURL    = "https://www.googleapis.com/compute/v1/projects/example-project-a/global/networks/default"
)

// ---- firewall JSON, as the REST API returns it --------------------------

// entry is one allowed[] or denied[] element.
type entry struct {
	IPProtocol string   `json:"IPProtocol"`
	Ports      []string `json:"ports,omitempty"`
}

// fw mirrors the REST representation of a Firewall resource (field names,
// string-encoded uint64 id, RFC3339 creationTimestamp, logConfig).
type fw struct {
	Kind                  string   `json:"kind,omitempty"`
	ID                    string   `json:"id,omitempty"`
	CreationTimestamp     string   `json:"creationTimestamp,omitempty"`
	Name                  string   `json:"name,omitempty"`
	Description           string   `json:"description,omitempty"`
	Network               string   `json:"network,omitempty"`
	Priority              *int     `json:"priority,omitempty"`
	SourceRanges          []string `json:"sourceRanges,omitempty"`
	SourceTags            []string `json:"sourceTags,omitempty"`
	SourceServiceAccounts []string `json:"sourceServiceAccounts,omitempty"`
	TargetTags            []string `json:"targetTags,omitempty"`
	TargetServiceAccounts []string `json:"targetServiceAccounts,omitempty"`
	Allowed               []entry  `json:"allowed,omitempty"`
	Denied                []entry  `json:"denied,omitempty"`
	Direction             string   `json:"direction,omitempty"`
	LogConfig             *struct {
		Enable bool `json:"enable"`
	} `json:"logConfig,omitempty"`
	Disabled *bool  `json:"disabled,omitempty"`
	SelfLink string `json:"selfLink,omitempty"`
}

var nextID = struct {
	sync.Mutex
	n uint64
}{n: 1000000000000000000}

// ingress returns a realistic enabled INGRESS rule with priority 1000.
func ingress(name string, ranges []string, allowed ...entry) fw {
	nextID.Lock()
	nextID.n++
	id := nextID.n
	nextID.Unlock()
	f := false
	p := 1000
	return fw{
		Kind:              "compute#firewall",
		ID:                strconv.FormatUint(id, 10),
		CreationTimestamp: "2026-01-01T00:00:00.000-08:00",
		Name:              name,
		Network:           netURL,
		Priority:          &p,
		SourceRanges:      ranges,
		Allowed:           allowed,
		Direction:         "INGRESS",
		LogConfig: &struct {
			Enable bool `json:"enable"`
		}{},
		Disabled: &f,
		SelfLink: "https://www.googleapis.com/compute/v1/projects/" + projA + "/global/firewalls/" + name,
	}
}

func tcp(ports ...string) entry { return entry{IPProtocol: "tcp", Ports: ports} }
func udp(ports ...string) entry { return entry{IPProtocol: "udp", Ports: ports} }
func allow(p string, ports ...string) entry {
	return entry{IPProtocol: p, Ports: ports}
}
func world() []string { return []string{worldStr} }

func (f fw) json(t testing.TB) string {
	t.Helper()
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// ---- fake Compute REST server -------------------------------------------

// page is one firewalls.list response. With status 0 and body "", the
// server builds a realistic FirewallList from items with nextPageToken
// "p<i+1>" (or next, if set) unless this is the last page.
type page struct {
	items  []string // Firewall JSON objects
	next   *string
	status int
	body   string
}

// fakeCompute serves projects/{p}/global/firewalls. No token is page 0,
// token "p<i>" is page i. Unknown projects get a realistic 404.
type fakeCompute struct {
	t        *testing.T
	mu       sync.Mutex
	projects map[string][]page
	// block makes every request wait until the client gives up or the
	// test ends.
	block   bool
	release chan struct{}
	// requests records "project pageToken" for each request.
	requests []string
	auth     []string // Authorization headers seen
	// inflight counts handlers still running; cancelled counts blocked
	// requests whose context the server saw end (the client went away).
	inflight  int
	cancelled int
	// onRequest, if set, runs at the start of each request, outside mu.
	onRequest func(n int)
}

// blockLimit is how long a blocked request waits for the client to cancel
// it before the test fails.
const blockLimit = 10 * time.Second

func newFakeCompute(t *testing.T, projects map[string][]page) (*fakeCompute, *httptest.Server) {
	f := &fakeCompute{t: t, projects: projects, release: make(chan struct{})}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	// Cleanups run last-in first-out: blocked handlers are released before
	// srv.Close waits for them.
	t.Cleanup(func() { close(f.release) })
	return f, srv
}

func (f *fakeCompute) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Read-only guarantee at the wire level: only GET of the list path.
	rest, ok := strings.CutPrefix(r.URL.Path, "/compute/v1/projects/")
	project, tail, _ := strings.Cut(rest, "/")
	if r.Method != http.MethodGet || !ok || tail != "global/firewalls" {
		f.t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		http.Error(w, "unexpected", http.StatusMethodNotAllowed)
		return
	}
	token := r.URL.Query().Get("pageToken")
	f.mu.Lock()
	f.requests = append(f.requests, project+" "+token)
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	pages, known := f.projects[project]
	block := f.block
	n := len(f.requests)
	f.inflight++
	hook := f.onRequest
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.inflight--
		f.mu.Unlock()
	}()
	if hook != nil {
		hook(n)
	}

	if got := r.URL.Query().Get("maxResults"); got != strconv.Itoa(pageSize) {
		f.t.Errorf("maxResults = %q, want %d", got, pageSize)
	}
	if block {
		select {
		case <-r.Context().Done():
			f.mu.Lock()
			f.cancelled++
			f.mu.Unlock()
		case <-f.release:
		case <-time.After(blockLimit):
			// Every blocking test cancels its request; reaching this means
			// the client did not, so fail instead of hanging.
			f.t.Errorf("blocked request to %s was never cancelled by the client", r.URL.Path)
		}
		return
	}
	if !known {
		writeGoogleError(w, http.StatusNotFound, "notFound",
			"The resource 'projects/"+project+"' was not found")
		return
	}
	idx := 0
	if token != "" {
		n, err := strconv.Atoi(strings.TrimPrefix(token, "p"))
		if err != nil || n < 0 || n >= len(pages) {
			writeGoogleError(w, http.StatusBadRequest, "invalid", "Invalid value for field 'pageToken'")
			return
		}
		idx = n
	}
	p := pages[idx]
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	if p.status != 0 || p.body != "" {
		status := p.status
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		fmt.Fprint(w, p.body)
		return
	}
	next := ""
	if idx+1 < len(pages) {
		next = "p" + strconv.Itoa(idx+1)
	}
	if p.next != nil {
		next = *p.next
	}
	var b strings.Builder
	b.WriteString(`{"kind":"compute#firewallList","id":"projects/` + project + `/global/firewalls",`)
	b.WriteString(`"items":[` + strings.Join(p.items, ",") + `]`)
	if next != "" {
		b.WriteString(`,"nextPageToken":"` + next + `"`)
	}
	b.WriteString(`,"selfLink":"https://www.googleapis.com/compute/v1/projects/` + project + `/global/firewalls"}`)
	fmt.Fprint(w, b.String())
}

func (f *fakeCompute) requestLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.requests)
}

// waitIdle waits until no handler is running and the server has seen at
// least wantCancelled blocked requests cancelled by the client. The server
// learns of a cancellation when the client closes the connection, which can
// lag the client's return by a moment.
func (f *fakeCompute) waitIdle(t *testing.T, wantCancelled int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		f.mu.Lock()
		inflight, cancelled := f.inflight, f.cancelled
		f.mu.Unlock()
		if inflight == 0 && cancelled >= wantCancelled {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("server: %d requests still running, %d cancelled (want %d)", inflight, cancelled, wantCancelled)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// googleErrorBody is the JSON error format of the Compute API.
func googleErrorBody(code int, reason, msg string) string {
	b, _ := json.Marshal(map[string]any{"error": map[string]any{
		"code": code, "message": msg,
		"errors": []map[string]string{{"message": msg, "domain": "global", "reason": reason}},
	}})
	return string(b)
}

func writeGoogleError(w http.ResponseWriter, code int, reason, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(code)
	fmt.Fprint(w, googleErrorBody(code, reason, msg))
}

func errorPage(code int, reason, msg string) page {
	return page{status: code, body: googleErrorBody(code, reason, msg)}
}

// onePage serves the given firewalls as a single page.
func onePage(t testing.TB, fws ...fw) []page {
	var items []string
	for _, f := range fws {
		items = append(items, f.json(t))
	}
	return []page{{items: items}}
}

// ---- credentials --------------------------------------------------------

// staticToken is a fake token provider. It is not a credential.
type staticToken struct{}

func (staticToken) Token(context.Context) (*auth.Token, error) {
	return &auth.Token{Value: fakeToken, Type: "Bearer", Expiry: time.Now().Add(time.Hour)}, nil
}

// failingToken fails the way a real token endpoint failure does.
type failingToken struct{ err error }

func (f failingToken) Token(context.Context) (*auth.Token, error) { return nil, f.err }

func fakeCreds(tp auth.TokenProvider) *auth.Credentials {
	return auth.NewCredentials(&auth.CredentialsOptions{TokenProvider: tp})
}

// realClient builds the real SDK adapter against the local server.
func realClient(t testing.TB, srv *httptest.Server, tp auth.TokenProvider) *Client {
	t.Helper()
	c, err := newClient(context.Background(), fakeCreds(tp), option.WithEndpoint(srv.URL+"/compute/v1/"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// scanServer scans projects through the real adapter and a fake server.
func scanServer(t *testing.T, projects map[string][]page, cfg Config) (model.ProviderResult, *fakeCompute) {
	t.Helper()
	f, srv := newFakeCompute(t, projects)
	if cfg.Projects == nil {
		for p := range projects {
			cfg.Projects = append(cfg.Projects, p)
		}
	}
	res := NewScanner(cfg, realClient(t, srv, staticToken{})).Scan(context.Background())
	return res, f
}

// scanOne scans one project (projA) served as a single page.
func scanOne(t *testing.T, fws ...fw) model.ProviderResult {
	t.Helper()
	res, _ := scanServer(t, map[string][]page{projA: onePage(t, fws...)}, Config{})
	return res
}

// ---- fake lister (for cases the REST layer cannot produce) --------------

type fakeLister struct {
	mu     sync.Mutex
	result map[string][]*compute.Firewall
	errs   map[string]error
	calls  []string
}

func (f *fakeLister) ListFirewalls(_ context.Context, project string) ([]*compute.Firewall, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, project)
	if err := f.errs[project]; err != nil {
		return nil, err
	}
	return f.result[project], nil
}

// ---- assertions -----------------------------------------------------------

func ptr(v *int) string {
	if v == nil {
		return "-"
	}
	return strconv.Itoa(*v)
}

// line renders the decision-relevant fields of a finding.
func line(f model.InsecureRule) string {
	return fmt.Sprintf("%s %s from=%s to=%s type=%s code=%s src=%s raw=%s/%s/%s reason=%s",
		f.Protocol, f.Port, ptr(f.FromPort), ptr(f.ToPort), ptr(f.ICMPType), ptr(f.ICMPCode),
		f.Source, f.ProviderProtocol, f.ProviderPort, f.ProviderSource, f.MatchReason)
}

func lines(rules []model.GCPFirewallRule) []string {
	var out []string
	for _, r := range rules {
		for _, f := range r.InsecureRules {
			out = append(out, r.Project+" "+r.Name+" "+line(f))
		}
	}
	slices.Sort(out)
	return out
}

func diagCodes(diags []model.Diagnostic) []string {
	var out []string
	for _, d := range diags {
		out = append(out, d.RuleRef+" "+d.Code+"/"+d.Field+"/"+d.Value+"/"+d.Effect)
	}
	slices.Sort(out)
	return out
}

func errorKinds(errs []model.ScanError) []string {
	var out []string
	for _, e := range errs {
		out = append(out, e.Scope+" "+e.Operation+" "+e.Kind)
	}
	slices.Sort(out)
	return out
}

func assertEqual[T any](t *testing.T, what string, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s:\n got  %v\n want %v", what, got, want)
	}
}
