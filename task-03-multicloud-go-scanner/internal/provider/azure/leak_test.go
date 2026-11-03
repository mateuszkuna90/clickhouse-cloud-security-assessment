package azure

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	azlog "github.com/Azure/azure-sdk-for-go/sdk/azcore/log"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/report"
)

// Regression tests for credential and payload leakage through error
// reports and logs (the M2/M3 principles applied to Azure).
//
// Each test drives a failure through the real SDK (credential chain,
// bearer token policy, ARM pipeline, pager, error decoding) with dummy
// marker strings placed where a real failure could carry secrets, then
// checks that no marker reaches the result, the encoded JSON report, or
// anything written to stdout, stderr, the standard logger, slog or the
// Azure SDK log listener.

// Dummy markers. They are not credentials.
const (
	markRefresh = "DUMMY_REFRESH_TOKEN_MARKER_4A7C"
	markSecret  = "DUMMY_CLIENT_SECRET_MARKER_8B2E"
	markKey     = "DUMMY_PRIVATE_KEY_MARKER_1D9F"
	markBody    = "DUMMY_RESPONSE_BODY_MARKER_6C3A"
)

var allMarkers = []string{markRefresh, markSecret, markKey, markBody}

const markerPayload = markRefresh + " " + markSecret + " " + markKey + " " + markBody

func assertNoMarkers(t *testing.T, where, data string) {
	t.Helper()
	upper := strings.ToUpper(data)
	for _, m := range allMarkers {
		if strings.Contains(upper, m) {
			t.Errorf("%s contains marker %s:\n%s", where, m, data)
		}
	}
}

// captureOutput runs fn while stdout, stderr, the standard logger and the
// default slog logger write to a buffer, and returns what was written.
func captureOutput(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	var mu sync.Mutex
	done := make(chan struct{})
	go func() {
		defer close(done)
		var b bytes.Buffer
		_, _ = io.Copy(&b, r)
		mu.Lock()
		buf.Write(b.Bytes())
		mu.Unlock()
	}()

	var logBuf bytes.Buffer
	oldOut, oldErr := os.Stdout, os.Stderr
	oldLog := log.Writer()
	oldSlog := slog.Default()
	os.Stdout, os.Stderr = w, w
	log.SetOutput(&logBuf)
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer func() {
		os.Stdout, os.Stderr = oldOut, oldErr
		log.SetOutput(oldLog)
		slog.SetDefault(oldSlog)
	}()

	fn()

	w.Close()
	<-done
	r.Close()
	mu.Lock()
	defer mu.Unlock()
	return buf.String() + logBuf.String()
}

// sdkLogCapture installs an Azure SDK log listener that writes to stderr,
// exactly what AZURE_SDK_GO_LOGGING=all does at process start (that
// variable is read in the SDK's init, before TestMain, so it is simulated
// here). The adapter must remove it.
func sdkLogCapture(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	var mu sync.Mutex
	azlog.SetListener(func(ev azlog.Event, msg string) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(&buf, "[%s] %s\n", ev, msg)
		fmt.Fprintf(os.Stderr, "[%s] %s\n", ev, msg)
	})
	t.Cleanup(func() { azlog.SetListener(nil) })
	return &buf
}

// scanAndCheck builds a lister with newLister and scans subA with it, both
// under output capture, then checks the result, the JSON report and the
// captured output for markers.
func scanAndCheck(t *testing.T, newLister func() NSGLister) model.ProviderResult {
	t.Helper()
	sdkLog := sdkLogCapture(t)
	var res model.ProviderResult
	out := captureOutput(t, func() {
		res = NewScanner(Config{Subscriptions: []string{subA}}, nil, newLister()).Scan(context.Background())
	})
	assertNoMarkers(t, "stdout/stderr/logs", out)
	assertNoMarkers(t, "Azure SDK log", sdkLog.String())
	assertNoMarkers(t, "result", fmt.Sprintf("%+v", res))
	js, err := report.Encode(report.Build([]model.ProviderResult{res}, report.Options{ToolVersion: "test"}))
	if err != nil {
		t.Fatal(err)
	}
	assertNoMarkers(t, "JSON report", string(js))
	return res
}

// TestLeak_CredentialErrors: azidentity errors carry token endpoint
// response bodies and CLI output. They must become a fixed auth error, and
// no ARM request may be sent without a token.
func TestLeak_CredentialErrors(t *testing.T) {
	tokenResp := &http.Response{
		StatusCode: 400, Status: "400 Bad Request",
		Header: http.Header{"X-Echo": {markRefresh}},
		Body: io.NopCloser(strings.NewReader(`{"error":"invalid_client","error_description":"` +
			markerPayload + `"}`)),
		Request: &http.Request{Method: "POST", URL: mustURL("https://login.microsoftonline.com/x/oauth2/v2.0/token")},
	}
	cases := map[string]error{
		"AuthenticationFailedError with body": &azidentity.AuthenticationFailedError{RawResponse: tokenResp},
		"credential unavailable (CLI output)": azidentity.NewCredentialUnavailableError("az: " + markerPayload),
		"wrapped plain error":                 fmt.Errorf("chain: %w", errors.New(markerPayload)),
		"timeout during token fetch":          fmt.Errorf("%s: %w", markSecret, context.DeadlineExceeded),
	}
	for name, cerr := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFakeARM(map[string][]armPage{nsgPath(subA): {{}}})
			res := scanAndCheck(t, func() NSGLister { return realClient(t, f, failingCred{err: cerr}) })
			assertEqual(t, "no ARM request without a token", len(f.requestLog()), 0)
			want := model.ErrorKindAuth
			if errors.Is(cerr, context.DeadlineExceeded) {
				want = model.ErrorKindTimeout
			}
			assertEqual(t, "errors", errorKinds(res.Errors), []string{subA + " " + OpListNSGs + " " + want})
			if want == model.ErrorKindAuth {
				assertEqual(t, "message", res.Errors[0].Message,
					OpListNSGs+" failed: Azure credentials could not be resolved or were rejected (page 1)")
			}
		})
	}
}

// fakeLogin is a Microsoft Entra token endpoint that rejects the client
// secret with a response body full of markers.
type fakeLogin struct {
	mu         sync.Mutex
	paths      []string
	tokenCalls int
}

func (f *fakeLogin) Do(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.paths = append(f.paths, req.URL.Host+req.URL.Path)
	f.mu.Unlock()
	tenant := "00000000-0000-0000-0000-0000000000aa"
	base := "https://login.microsoftonline.com/" + tenant
	switch p := req.URL.Path; {
	case strings.HasSuffix(p, "/discovery/instance"):
		return jsonResponse(req, 200, nil, `{"tenant_discovery_endpoint":"`+base+
			`/v2.0/.well-known/openid-configuration","api-version":"1.1","metadata":[{"preferred_network":`+
			`"login.microsoftonline.com","preferred_cache":"login.windows.net","aliases":["login.microsoftonline.com"]}]}`), nil
	case strings.HasSuffix(p, "/.well-known/openid-configuration"):
		return jsonResponse(req, 200, nil, `{"token_endpoint":"`+base+`/oauth2/v2.0/token",`+
			`"authorization_endpoint":"`+base+`/oauth2/v2.0/authorize","issuer":"`+base+`/v2.0"}`), nil
	case strings.HasSuffix(p, "/oauth2/v2.0/token"):
		f.mu.Lock()
		f.tokenCalls++
		f.mu.Unlock()
		return jsonResponse(req, 401, map[string]string{"X-Echo": markKey},
			`{"error":"invalid_client","error_description":"AADSTS7000215: `+markerPayload+
				`","error_codes":[7000215],"trace_id":"`+markBody+`"}`), nil
	}
	return jsonResponse(req, 404, nil, `{}`), nil
}

// TestLeak_DefaultAzureCredentialEndToEnd drives the real
// DefaultAzureCredential (restricted to EnvironmentCredential, with a dummy
// client secret marker) against a fake token endpoint that rejects it with
// a marker-laden body. Nothing reaches the report or any log.
func TestLeak_DefaultAzureCredentialEndToEnd(t *testing.T) {
	t.Setenv("AZURE_TOKEN_CREDENTIALS", "EnvironmentCredential")
	t.Setenv("AZURE_TENANT_ID", "00000000-0000-0000-0000-0000000000aa")
	t.Setenv("AZURE_CLIENT_ID", "00000000-0000-0000-0000-0000000000bb")
	t.Setenv("AZURE_CLIENT_SECRET", markSecret)
	login := &fakeLogin{}
	f := newFakeARM(map[string][]armPage{nsgPath(subA): {{}}})
	res := scanAndCheck(t, func() NSGLister {
		cred, err := newDefaultCredential(login)
		if err != nil {
			t.Fatal(err)
		}
		return realClient(t, f, cred)
	})
	if login.tokenCalls == 0 {
		t.Fatalf("token endpoint never called; requests: %v", login.paths)
	}
	assertEqual(t, "no ARM request", len(f.requestLog()), 0)
	assertEqual(t, "errors", errorKinds(res.Errors), []string{subA + " " + OpListNSGs + " auth"})
}

// TestLeak_ARMErrorPayloads: azcore.ResponseError.Error() contains the full
// response body and the request URL. None of it may reach the report.
func TestLeak_ARMErrorPayloads(t *testing.T) {
	cases := map[string]armPage{
		"message with markers": armError(403, "AuthorizationFailed",
			"The client '"+markSecret+"' with object id '"+markKey+"' does not have authorization"),
		"unlisted code":      armError(400, markRefresh, "x"),
		"details and target": {status: 409, body: `{"error":{"code":"Conflict","message":"x","target":"` + markBody + `","details":[{"code":"` + markSecret + `","message":"` + markerPayload + `"}]}}`},
		"non-JSON body":      {status: 500, body: "<html>" + markerPayload + "</html>"},
		"code in header":     {status: 403, header: map[string]string{"x-ms-error-code": markSecret, "X-Echo": markKey}, body: markerPayload},
		"malformed 200 body": {body: `{"value":[` + markerPayload},
		"bad field type":     {body: `{"value":[{"id":"x","properties":{"securityRules":"` + markBody + `"}}]}`},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFakeARM(map[string][]armPage{nsgPath(subA): {p}})
			res := scanAndCheck(t, func() NSGLister { return realClient(t, f, staticCred{}) })
			assertEqual(t, "scope", res.Scopes[0].Status, model.ScopeFailed)
		})
	}
}

// TestLeak_SuccessfulScanDoesNotLog: with SDK logging switched on, a
// successful scan writes nothing to stdout, stderr or any logger, and the
// token never appears.
func TestLeak_SuccessfulScanDoesNotLog(t *testing.T) {
	f := newFakeARM(map[string][]armPage{nsgPath(subA): {
		{items: []string{nsgJSON(t, subA, nsgSpec{name: "logged", rules: []ruleSpec{inAllow("ssh", "Tcp", "*", "22", 100)}})}},
	}})
	sdkLog := sdkLogCapture(t)
	out := captureOutput(t, func() {
		c := realClient(t, f, staticCred{})
		NewScanner(Config{Subscriptions: []string{subA}}, nil, c).Scan(context.Background())
	})
	if out != "" || sdkLog.Len() != 0 {
		t.Errorf("unexpected output: %q / SDK log %q", out, sdkLog.String())
	}
}

// TestNewClient_DisablesSDKLogging: NewClient itself removes a listener
// installed by AZURE_SDK_GO_LOGGING.
func TestNewClient_DisablesSDKLogging(t *testing.T) {
	sdkLog := sdkLogCapture(t)
	if _, err := NewClient(); err != nil {
		t.Fatal(err)
	}
	// A bare SDK pipeline (not built by newClient) that gets an error
	// response: the SDK logs every ResponseError if a listener is set.
	f := newFakeARM(map[string][]armPage{subsPath(): {armError(403, "AuthorizationFailed", markerPayload)}})
	pl := runtime.NewPipeline("test", "v0", runtime.PipelineOptions{}, &policy.ClientOptions{Transport: f})
	req, err := runtime.NewRequest(context.Background(), http.MethodGet, "https://"+armHost+subsPath())
	if err != nil {
		t.Fatal(err)
	}
	resp, err := pl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = runtime.NewResponseError(resp)
	if sdkLog.Len() != 0 {
		t.Errorf("SDK logged: %s", sdkLog.String())
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
