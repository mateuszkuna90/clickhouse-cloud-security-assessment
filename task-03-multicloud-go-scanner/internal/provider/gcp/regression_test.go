package gcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
)

// Regression tests for the M3 review findings: cancellation, page
// inspection and counting, and deterministic error messages. All of them go
// through the real REST client (google.golang.org/api/compute/v1) and a
// local httptest server.

// A. A server returning empty pages with a new token each time is stopped
// by the page limit, not by a timeout.
func TestRegression_EndlessEmptyPages(t *testing.T) {
	var mu sync.Mutex
	requests := 0
	srv := newRawServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		n := requests
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"kind":"compute#firewallList","items":[],"nextPageToken":"t%d"}`, n)
	})
	start := time.Now()
	res := NewScanner(Config{Projects: []string{projA}, ScopeTimeout: time.Minute},
		realClient(t, srv, staticToken{})).Scan(context.Background())
	if d := time.Since(start); d > 30*time.Second {
		t.Errorf("listing took %v", d)
	}
	mu.Lock()
	assertEqual(t, "requests", requests, maxPages)
	mu.Unlock()
	assertEqual(t, "scope", res.Scopes[0].Status, model.ScopeFailed)
	assertEqual(t, "message", res.Errors[0].Message,
		"compute.firewalls.list failed: unexpected error; "+string(errTooManyPages)+" (page "+strconv.Itoa(maxPages+1)+")")
}

// B. Repeated and cyclic page tokens fail the scope after the request that
// returned the repeat, and discard what was read.
func TestRegression_RepeatedAndCyclicTokens(t *testing.T) {
	tok := func(s string) *string { return &s }
	tests := map[string]struct {
		pages    []page
		requests []string
		page     int
	}{
		"page repeats its own token": {
			pages: []page{
				{items: []string{ingress("r1", world(), tcp("22")).json(t)}},
				{next: tok("p1")},
			},
			requests: []string{projA + " ", projA + " p1"},
			page:     2,
		},
		"cycle p1 -> p2 -> p1": {
			pages: []page{
				{items: []string{ingress("r1", world(), tcp("22")).json(t)}},
				{},
				{next: tok("p1")},
			},
			requests: []string{projA + " ", projA + " p1", projA + " p2"},
			page:     3,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			res, f := scanServer(t, map[string][]page{projA: tc.pages}, Config{})
			assertEqual(t, "requests", f.requestLog(), tc.requests)
			assertEqual(t, "scope", res.Scopes[0].Status, model.ScopeFailed)
			assertEqual(t, "rules", res.GCPFirewallRules, []model.GCPFirewallRule{})
			assertEqual(t, "message", res.Errors[0].Message, "compute.firewalls.list failed: unexpected error; "+
				string(errRepeatedToken)+" (page "+strconv.Itoa(tc.page)+")")
		})
	}
}

// C and E. Cancelling while a request is outstanding aborts that request:
// ListFirewalls returns at once, the server sees the request cancelled, and
// after Close nothing else reaches the server.
func TestRegression_CancelDuringRequest(t *testing.T) {
	f, srv := newFakeCompute(t, map[string][]page{projA: onePage(t)})
	f.block = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.onRequest = func(int) { cancel() }

	c := realClient(t, srv, staticToken{})
	start := time.Now()
	got, err := c.ListFirewalls(ctx, projA)
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("ListFirewalls took %v after cancellation", d)
	}
	listErr(t, got, err, 1, context.Canceled)

	// The request is aborted on the wire, not abandoned.
	f.waitIdle(t, 1)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	assertEqual(t, "requests after close", len(f.requestLog()), 1)
	f.mu.Lock()
	assertEqual(t, "running handlers", f.inflight, 0)
	f.mu.Unlock()
}

// D. Cancelling after page 1 was sent stops the listing: no request for
// page 2, and the project fails rather than reporting page 1 alone.
func TestRegression_CancelBetweenPages(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var tokens []string
	srv := newRawServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		tokens = append(tokens, r.URL.Query().Get("pageToken"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"items":[`+ingress("r1", world(), tcp("22")).json(t)+`],"nextPageToken":"p1"}`)
		w.(http.Flusher).Flush()
		cancel()
	})
	res := NewScanner(Config{Projects: []string{projA}}, realClient(t, srv, staticToken{})).Scan(ctx)
	mu.Lock()
	assertEqual(t, "requests", tokens, []string{""})
	mu.Unlock()
	assertEqual(t, "scope", res.Scopes[0].Status, model.ScopeFailed)
	assertEqual(t, "rules", res.GCPFirewallRules, []model.GCPFirewallRule{})
	assertEqual(t, "errors", errorKinds(res.Errors), []string{projA + " compute.firewalls.list timeout"})
}

// F. Page numbers count requests: an empty first page still counts.
func TestRegression_EmptyPageThenForbidden(t *testing.T) {
	res, f := scanServer(t, map[string][]page{projA: {
		{},
		errorPage(403, "forbidden", "Required 'compute.firewalls.list' permission"),
	}}, Config{})
	assertEqual(t, "requests", f.requestLog(), []string{projA + " ", projA + " p1"})
	assertEqual(t, "errors", errorKinds(res.Errors), []string{projA + " compute.firewalls.list permission_denied"})
	assertEqual(t, "message", res.Errors[0].Message, "compute.firewalls.list failed: permission denied, "+
		"or the Compute Engine API is not enabled for the project (page 2) [HTTP 403] [reason: forbidden]")
}

// G. The same error with its reasons listed in a different order gives a
// byte-identical report.
func TestRegression_ReasonOrderDoesNotChangeJSON(t *testing.T) {
	body := func(reasons ...string) string {
		var items []map[string]string
		for _, r := range reasons {
			items = append(items, map[string]string{"message": "m", "domain": "global", "reason": r})
		}
		b, err := json.Marshal(map[string]any{"error": map[string]any{"code": 403, "message": "m", "errors": items}})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	scan := func(reasons ...string) ([]byte, string) {
		res, _ := scanServer(t, map[string][]page{projA: {{status: 403, body: body(reasons...)}}}, Config{})
		return encode(t, res), res.Errors[0].Message
	}
	a, msg := scan("forbidden", "accessNotConfigured", "SERVICE_DISABLED", "forbidden", "unlistedReason")
	b, _ := scan("unlistedReason", "SERVICE_DISABLED", "accessNotConfigured", "forbidden")
	if !bytes.Equal(a, b) {
		t.Errorf("reports differ:\n%s\n---\n%s", a, b)
	}
	if !strings.HasSuffix(msg, "[reason: SERVICE_DISABLED,accessNotConfigured,forbidden]") {
		t.Errorf("message = %q", msg)
	}
}

// H. A project failing on a later page is discarded; the other projects
// are scanned normally.
func TestRegression_PartialProjectFailure(t *testing.T) {
	res, f := scanServer(t, map[string][]page{
		projA: onePage(t, ingress("a-ssh", world(), tcp("22"))),
		projB: {
			onePage(t, ingress("b-ssh", world(), tcp("22")))[0],
			errorPage(503, "backendError", "Service unavailable"),
		},
		projC: {{}, onePage(t, ingress("c-rdp", world(), tcp("3389")))[0]},
	}, Config{Projects: []string{projA, projB, projC}})
	assertEqual(t, "status", res.Status, model.ProviderPartial)
	assertEqual(t, "scopes", res.Scopes, []model.ScopeResult{
		completeScope(projA, 1, 1, 0)[0],
		{Provider: model.ProviderGCP, Scope: projB, Status: model.ScopeFailed},
		completeScope(projC, 1, 1, 0)[0],
	})
	assertEqual(t, "findings", lines(res.GCPFirewallRules), []string{
		projA + " a-ssh tcp 22 from=22 to=22 type=- code=- src=0.0.0.0/0 raw=tcp/22/0.0.0.0/0 reason=ipv4_world_cidr",
		projC + " c-rdp tcp 3389 from=3389 to=3389 type=- code=- src=0.0.0.0/0 raw=tcp/3389/0.0.0.0/0 reason=ipv4_world_cidr",
	})
	assertEqual(t, "message", res.Errors[0].Message,
		"compute.firewalls.list failed: unexpected error (page 2) [HTTP 503] [reason: backendError]")
	// No retry: each page was requested once.
	assertEqual(t, "requests", len(f.requestLog()), 5)
}

// A cancelled scan never looks like an empty inventory.
func TestRegression_CancelledIsNotEmpty(t *testing.T) {
	f, srv := newFakeCompute(t, map[string][]page{projA: onePage(t)})
	f.block = true
	ctx, cancel := context.WithCancel(context.Background())
	f.onRequest = func(int) { cancel() }
	res := NewScanner(Config{Projects: []string{projA}}, realClient(t, srv, staticToken{})).Scan(ctx)
	if res.Scopes[0].Status == model.ScopeComplete || res.Status == model.ProviderComplete {
		t.Fatalf("cancelled scan reported complete: %+v", res)
	}
	if !errors.Is(context.Cause(ctx), context.Canceled) {
		t.Fatal("context was not cancelled")
	}
}
