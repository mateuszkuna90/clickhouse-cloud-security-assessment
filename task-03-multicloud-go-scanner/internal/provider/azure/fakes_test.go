package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
)

// TestMain makes sure no test can reach a real Azure account: every Azure
// credential environment variable is cleared, the Azure CLI and Developer
// CLI configuration directories point at an empty temporary directory, and
// managed identity endpoints are unset. No test calls GetToken on a
// DefaultAzureCredential without a fake transport, and every ARM request
// goes to the in-process fake transport (fakeARM).
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "azure-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, k := range []string{
		"AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_CLIENT_SECRET",
		"AZURE_CLIENT_CERTIFICATE_PATH", "AZURE_CLIENT_CERTIFICATE_PASSWORD",
		"AZURE_CLIENT_SEND_CERTIFICATE_CHAIN", "AZURE_USERNAME", "AZURE_PASSWORD",
		"AZURE_FEDERATED_TOKEN_FILE", "AZURE_AUTHORITY_HOST", "AZURE_TOKEN_CREDENTIALS",
		"AZURE_ADDITIONALLY_ALLOWED_TENANTS", "AZURE_REGIONAL_AUTHORITY_NAME",
		"IDENTITY_ENDPOINT", "IDENTITY_HEADER", "IDENTITY_SERVER_THUMBPRINT",
		"IMDS_ENDPOINT", "MSI_ENDPOINT", "MSI_SECRET",
	} {
		os.Unsetenv(k)
	}
	os.Setenv("AZURE_CONFIG_DIR", dir)
	os.Setenv("AZD_CONFIG_DIR", filepath.Join(dir, "azd"))
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// Fake identifiers. None of these exist.
const (
	subA      = "00000000-0000-0000-0000-00000000000a"
	subB      = "00000000-0000-0000-0000-00000000000b"
	subC      = "00000000-0000-0000-0000-00000000000c"
	subD      = "00000000-0000-0000-0000-00000000000d"
	subE      = "00000000-0000-0000-0000-00000000000e"
	subF      = "00000000-0000-0000-0000-00000000000f"
	subG      = "00000000-0000-0000-0000-000000000010"
	subH      = "00000000-0000-0000-0000-000000000011"
	fakeToken = "fake-access-token-not-a-secret"
	armHost   = "management.azure.com"
	worldStr  = "0.0.0.0/0"
)

func nsgID(sub, name string) string {
	return "/subscriptions/" + sub + "/resourceGroups/example-rg/providers/Microsoft.Network/networkSecurityGroups/" + name
}

// ---- SDK fixtures --------------------------------------------------------

// ruleSpec describes a security rule; zero values mean "absent".
type ruleSpec struct {
	name       string
	direction  string // "" = absent
	access     string // "" = absent
	protocol   string // "" = absent
	priority   int32  // 0 = absent
	srcPrefix  *string
	srcList    []string
	srcASGs    []string
	srcPort    *string
	dstPort    *string
	dstPorts   []string
	descr      string
	noProps    bool
	nilSrcItem bool // add a nil entry to SourceAddressPrefixes
}

func (r ruleSpec) build(nsg string, field string) *armnetwork.SecurityRule {
	sr := &armnetwork.SecurityRule{
		Name: to.Ptr(r.name),
		ID:   to.Ptr(nsg + "/" + field + "/" + r.name),
		Type: to.Ptr("Microsoft.Network/networkSecurityGroups/" + field),
	}
	if r.name == "" {
		sr.Name = nil
	}
	if r.noProps {
		return sr
	}
	p := &armnetwork.SecurityRulePropertiesFormat{
		SourceAddressPrefix:  r.srcPrefix,
		SourcePortRange:      r.srcPort,
		DestinationPortRange: r.dstPort,
		ProvisioningState:    to.Ptr(armnetwork.ProvisioningStateSucceeded),
	}
	if r.direction != "" {
		p.Direction = to.Ptr(armnetwork.SecurityRuleDirection(r.direction))
	}
	if r.access != "" {
		p.Access = to.Ptr(armnetwork.SecurityRuleAccess(r.access))
	}
	if r.protocol != "" {
		p.Protocol = to.Ptr(armnetwork.SecurityRuleProtocol(r.protocol))
	}
	if r.priority != 0 {
		p.Priority = to.Ptr(r.priority)
	}
	if r.descr != "" {
		p.Description = to.Ptr(r.descr)
	}
	for _, s := range r.srcList {
		p.SourceAddressPrefixes = append(p.SourceAddressPrefixes, to.Ptr(s))
	}
	if r.nilSrcItem {
		p.SourceAddressPrefixes = append(p.SourceAddressPrefixes, nil)
	}
	for _, d := range r.dstPorts {
		p.DestinationPortRanges = append(p.DestinationPortRanges, to.Ptr(d))
	}
	for _, a := range r.srcASGs {
		p.SourceApplicationSecurityGroups = append(p.SourceApplicationSecurityGroups,
			&armnetwork.ApplicationSecurityGroup{ID: to.Ptr(a)})
	}
	sr.Properties = p
	return sr
}

// inAllow is a typical inbound allow rule from a single source prefix to a
// single destination port.
func inAllow(name, proto, src, port string, priority int32) ruleSpec {
	return ruleSpec{
		name: name, direction: "Inbound", access: "Allow", protocol: proto, priority: priority,
		srcPrefix: to.Ptr(src), srcPort: to.Ptr("*"), dstPort: to.Ptr(port),
	}
}

// defaultRules are the six default rules Azure adds to every NSG, exactly
// as ARM returns them.
func defaultRules() []ruleSpec {
	r := func(name, dir, access, src, dst string, prio int32) ruleSpec {
		return ruleSpec{
			name: name, direction: dir, access: access, protocol: "*", priority: prio,
			srcPrefix: to.Ptr(src), srcPort: to.Ptr("*"), dstPort: to.Ptr("*"),
			descr: "default rule",
		}
	}
	return []ruleSpec{
		r("AllowVnetInBound", "Inbound", "Allow", "VirtualNetwork", "VirtualNetwork", 65000),
		r("AllowAzureLoadBalancerInBound", "Inbound", "Allow", "AzureLoadBalancer", "*", 65001),
		r("DenyAllInBound", "Inbound", "Deny", "*", "*", 65500),
		r("AllowVnetOutBound", "Outbound", "Allow", "VirtualNetwork", "VirtualNetwork", 65000),
		r("AllowInternetOutBound", "Outbound", "Allow", "*", "Internet", 65001),
		r("DenyAllOutBound", "Outbound", "Deny", "*", "*", 65500),
	}
}

// nsgSpec describes an NSG.
type nsgSpec struct {
	name     string
	rules    []ruleSpec
	defaults []ruleSpec // nil = the standard defaults
	attached bool
	noID     bool
	noProps  bool
}

func (n nsgSpec) build(sub string) *armnetwork.SecurityGroup {
	id := nsgID(sub, n.name)
	sg := &armnetwork.SecurityGroup{
		ID:       to.Ptr(id),
		Name:     to.Ptr(n.name),
		Location: to.Ptr("westeurope"),
		Type:     to.Ptr("Microsoft.Network/networkSecurityGroups"),
		Etag:     to.Ptr(`W/"00000000-0000-0000-0000-000000000000"`),
	}
	if n.noID {
		sg.ID = nil
	}
	if n.noProps {
		return sg
	}
	p := &armnetwork.SecurityGroupPropertiesFormat{
		ProvisioningState: to.Ptr(armnetwork.ProvisioningStateSucceeded),
		ResourceGUID:      to.Ptr("00000000-0000-0000-0000-0000000000ff"),
	}
	for _, r := range n.rules {
		p.SecurityRules = append(p.SecurityRules, r.build(id, fieldSecurityRules))
	}
	defs := n.defaults
	if defs == nil {
		defs = defaultRules()
	}
	for _, r := range defs {
		p.DefaultSecurityRules = append(p.DefaultSecurityRules, r.build(id, fieldDefaultSecurityRules))
	}
	if n.attached {
		p.Subnets = []*armnetwork.Subnet{{ID: to.Ptr("/subscriptions/" + sub +
			"/resourceGroups/example-rg/providers/Microsoft.Network/virtualNetworks/example-vnet/subnets/default")}}
	}
	sg.Properties = p
	return sg
}

func nsgJSON(t testing.TB, sub string, n nsgSpec) string {
	t.Helper()
	b, err := json.Marshal(n.build(sub))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// subJSON is a subscription as GET /subscriptions returns it. state "" is
// omitted from the JSON.
func subJSON(id, state string) string {
	m := map[string]any{
		"id":                   "/subscriptions/" + id,
		"subscriptionId":       id,
		"displayName":          "example-subscription",
		"tenantId":             "00000000-0000-0000-0000-0000000000aa",
		"authorizationSource":  "RoleBased",
		"subscriptionPolicies": map[string]any{"locationPlacementId": "Public_2014-09-01", "quotaId": "Example", "spendingLimit": "Off"},
	}
	if state != "" {
		m["state"] = state
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// ---- fake ARM transport --------------------------------------------------

// armPage is one list response. With status 0 and body "", the transport
// builds {"value": items, "nextLink": ...}: nextLink points at the next
// page unless this is the last page, or is next if set.
type armPage struct {
	items  []string
	next   *string
	status int
	body   string
	header map[string]string
	err    error
}

type recordedRequest struct {
	method string
	url    string
	auth   string
}

// fakeARM implements policy.Transporter. It serves pages by path; the page
// index is the $skiptoken query value ("" = first page, "pN" = page N+1).
type fakeARM struct {
	mu       sync.Mutex
	routes   map[string][]armPage
	requests []recordedRequest
	// hold, if set, blocks every request until it is closed or the
	// request's context ends.
	hold chan struct{}
	// started receives one value per request when non-nil.
	started chan string
}

func newFakeARM(routes map[string][]armPage) *fakeARM {
	return &fakeARM{routes: routes}
}

func subsPath() string { return "/subscriptions" }
func nsgPath(sub string) string {
	return "/subscriptions/" + sub + "/providers/Microsoft.Network/networkSecurityGroups"
}
func pageURL(path, tok string) string {
	return "https://" + armHost + path + "?api-version=x&%24skiptoken=" + tok
}

func (f *fakeARM) requestLog() []recordedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.requests)
}

func (f *fakeARM) Do(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.requests = append(f.requests, recordedRequest{
		method: req.Method, url: req.URL.String(), auth: req.Header.Get("Authorization"),
	})
	pages := f.routes[req.URL.Path]
	hold, started := f.hold, f.started
	f.mu.Unlock()

	if started != nil {
		started <- req.URL.Path
	}
	if hold != nil {
		select {
		case <-hold:
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	if pages == nil {
		return jsonResponse(req, http.StatusNotFound, nil,
			`{"error":{"code":"ResourceNotFound","message":"fake: no such path"}}`), nil
	}
	idx := 0
	if tok := req.URL.Query().Get("$skiptoken"); tok != "" {
		n, err := strconv.Atoi(strings.TrimPrefix(tok, "p"))
		if err != nil || n < 1 || n >= len(pages) {
			return jsonResponse(req, http.StatusBadRequest, nil,
				`{"error":{"code":"BadRequest","message":"fake: bad skiptoken"}}`), nil
		}
		idx = n
	}
	p := pages[idx]
	if p.err != nil {
		return nil, p.err
	}
	if p.status != 0 || p.body != "" {
		status := p.status
		if status == 0 {
			status = http.StatusOK
		}
		return jsonResponse(req, status, p.header, p.body), nil
	}
	body := `{"value":[` + strings.Join(p.items, ",") + `]`
	switch {
	case p.next != nil:
		body += `,"nextLink":` + strconv.Quote(*p.next)
	case idx+1 < len(pages):
		body += `,"nextLink":` + strconv.Quote(pageURL(req.URL.Path, "p"+strconv.Itoa(idx+1)))
	}
	body += "}"
	return jsonResponse(req, http.StatusOK, p.header, body), nil
}

func jsonResponse(req *http.Request, status int, header map[string]string, body string) *http.Response {
	h := http.Header{"Content-Type": {"application/json; charset=utf-8"}}
	for k, v := range header {
		h.Set(k, v)
	}
	return &http.Response{
		StatusCode: status,
		Status:     strconv.Itoa(status) + " " + http.StatusText(status),
		Header:     h,
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}

// armError is an ARM error body.
func armError(status int, code, message string) armPage {
	return armPage{status: status, body: `{"error":{"code":` + strconv.Quote(code) +
		`,"message":` + strconv.Quote(message) + `}}`}
}

// ---- fake credentials ----------------------------------------------------

type staticCred struct{}

func (staticCred) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: fakeToken, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

type failingCred struct{ err error }

func (c failingCred) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{}, c.err
}

// fastRetry keeps retries short in tests.
var fastRetry = policy.RetryOptions{MaxRetries: 2, RetryDelay: time.Millisecond, MaxRetryDelay: 2 * time.Millisecond}

// realClient is the real SDK adapter on the fake transport.
func realClient(t testing.TB, f *fakeARM, cred azcore.TokenCredential) *Client {
	t.Helper()
	c, err := newClient(cred, f, fastRetry)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// ---- fake listers for scanner tests --------------------------------------

type fakeSubs struct {
	subs  []Subscription
	err   error
	calls int
	mu    sync.Mutex
}

func (f *fakeSubs) ListSubscriptions(ctx context.Context) ([]Subscription, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.subs, nil
}

type fakeNSGs struct {
	mu    sync.Mutex
	bySub map[string][]*armnetwork.SecurityGroup
	errs  map[string]error
	calls []string
	block map[string]bool // wait for ctx.Done
}

func (f *fakeNSGs) ListNSGs(ctx context.Context, sub string) ([]*armnetwork.SecurityGroup, error) {
	f.mu.Lock()
	f.calls = append(f.calls, sub)
	block := f.block[sub]
	err := f.errs[sub]
	groups := f.bySub[sub]
	f.mu.Unlock()
	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	return groups, nil
}

func (f *fakeNSGs) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := slices.Clone(f.calls)
	slices.Sort(out)
	return out
}

// ---- assertions ----------------------------------------------------------

func assertEqual[T any](t *testing.T, what string, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s:\n got  %#v\n want %#v", what, got, want)
	}
}

// errorKinds renders errors as "scope operation kind", sorted.
func errorKinds(errs []model.ScanError) []string {
	out := []string{}
	for _, e := range errs {
		out = append(out, e.Scope+" "+e.Operation+" "+e.Kind)
	}
	slices.Sort(out)
	return out
}

// scopeStatuses renders scopes as "scope status state".
func scopeStatuses(scopes []model.ScopeResult) []string {
	out := []string{}
	for _, s := range scopes {
		st := "<null>"
		if s.SubscriptionState != nil {
			st = *s.SubscriptionState
		}
		out = append(out, s.Scope+" "+string(s.Status)+" "+st)
	}
	slices.Sort(out)
	return out
}

// diagCodes renders diagnostics as "ruleRef code field effect", sorted.
func diagCodes(diags []model.Diagnostic) []string {
	out := []string{}
	for _, d := range diags {
		out = append(out, d.RuleRef+" "+d.Code+" "+d.Field+" "+d.Effect)
	}
	slices.Sort(out)
	return out
}
