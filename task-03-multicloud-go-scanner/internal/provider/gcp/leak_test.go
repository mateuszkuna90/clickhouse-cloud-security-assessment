package gcp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"cloud.google.com/go/auth"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/report"
)

// Regression tests for credential and payload leakage through error
// reports and logs (the M2 principles applied to GCP).
//
// Each test drives a failure through the real SDK (auth transport, REST
// client, page loop, error decoding) with dummy marker strings placed where
// a real failure could carry secrets, then checks that no marker reaches
// the result, the encoded JSON report, or anything written to stdout,
// stderr, the standard logger or slog. TestMain sets
// GOOGLE_SDK_GO_LOGGING_LEVEL=debug, so SDK debug logging would be on if
// the adapter did not replace the logger.

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

// scanAndCheck builds a lister with newLister and scans projA with it, both
// under output capture (the SDK binds its logger to os.Stderr when the
// client is created), then checks the result, the JSON report and the
// captured output for markers.
func scanAndCheck(t *testing.T, newLister func() FirewallLister) model.ProviderResult {
	t.Helper()
	var res model.ProviderResult
	out := captureOutput(t, func() {
		res = NewScanner(Config{Projects: []string{projA}}, newLister()).Scan(context.Background())
	})
	assertNoMarkers(t, "stdout/stderr/logs", out)
	assertNoMarkers(t, "result", fmt.Sprintf("%+v", res))
	js, err := report.Encode(report.Build([]model.ProviderResult{res}, report.Options{ToolVersion: "test"}))
	if err != nil {
		t.Fatal(err)
	}
	assertNoMarkers(t, "JSON report", string(js))
	return res
}

// TestLeak_TokenProviderErrors: token endpoint and credential-source
// failures carry raw response bodies and executable output. They must
// become a fixed auth error.
func TestLeak_TokenProviderErrors(t *testing.T) {
	tokenEndpoint := &auth.Error{
		Response: &http.Response{StatusCode: 400},
		Body:     []byte(`{"error":"invalid_grant","error_description":"` + markerPayload + `"}`),
		Err:      errors.New(markRefresh),
	}
	cases := map[string]error{
		"token endpoint 400 (auth.Error)": tokenEndpoint,
		"wrapped auth.Error":              fmt.Errorf("credentials: %w", tokenEndpoint),
		"executable credential output":    errors.New("executable returned: " + markerPayload),
		"timeout during token fetch":      fmt.Errorf("%s: %w", markSecret, context.DeadlineExceeded),
	}
	for name, err := range cases {
		t.Run(name, func(t *testing.T) {
			f, srv := newFakeCompute(t, map[string][]page{projA: onePage(t)})
			res := scanAndCheck(t, func() FirewallLister { return realClient(t, srv, failingToken{err: err}) })
			assertEqual(t, "no API request without a token", len(f.requestLog()), 0)
			want := model.ErrorKindAuth
			if errors.Is(err, context.DeadlineExceeded) {
				want = model.ErrorKindTimeout
			}
			assertEqual(t, "errors", errorKinds(res.Errors), []string{projA + " compute.firewalls.list " + want})
			if want == model.ErrorKindAuth {
				assertEqual(t, "message", res.Errors[0].Message,
					"compute.firewalls.list failed: Google credentials could not be resolved or were rejected (page 1)")
			}
		})
	}
}

// TestLeak_APIErrorPayloads: googleapi.Error carries the raw body, the
// message, details and headers. None of them may reach the report.
func TestLeak_APIErrorPayloads(t *testing.T) {
	detailBody := `{"error":{"code":403,"message":"` + markerPayload + `","errors":[{"message":"` + markSecret +
		`","domain":"global","reason":"forbidden"},{"message":"x","reason":"` + markKey + `"}],` +
		`"details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"` + markRefresh + `"}]}}`
	cases := map[string]page{
		"message, item message, unlisted reason, details": {status: 403, body: detailBody},
		"401 with marker message":                         errorPage(401, "authError", markerPayload),
		"non-JSON body":                                   {status: 500, body: "<html>" + markerPayload + "</html>"},
		"malformed 200 body":                              {body: `{"items":[` + markerPayload},
		"bad field value":                                 {body: `{"items":[{"name":"r","id":"` + markBody + `"}]}`},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			_, srv := newFakeCompute(t, map[string][]page{projA: {p}})
			res := scanAndCheck(t, func() FirewallLister { return realClient(t, srv, staticToken{}) })
			assertEqual(t, "scope", res.Scopes[0].Status, model.ScopeFailed)
		})
	}
}

// TestLeak_HeadersAndLogging: response headers with marker values and SDK
// debug logging (enabled by TestMain) must not surface anywhere.
func TestLeak_HeadersAndLogging(t *testing.T) {
	srv := newRawServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Debug-Echo", markerPayload)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, googleErrorBody(403, "forbidden", markBody))
	})
	res := scanAndCheck(t, func() FirewallLister { return realClient(t, srv, staticToken{}) })
	assertEqual(t, "kind", res.Errors[0].Kind, model.ErrorKindPermissionDenied)
}

// TestLeak_SuccessfulScanDoesNotLogPayloads: with debug logging requested
// through the environment, a successful scan writes nothing to stdout,
// stderr or the loggers.
func TestLeak_SuccessfulScanDoesNotLogPayloads(t *testing.T) {
	f := ingress("logged", world(), tcp("22"))
	f.Description = "desc"
	_, srv := newFakeCompute(t, map[string][]page{projA: onePage(t, f)})
	// The client is created inside the capture: the SDK binds its logger to
	// os.Stderr at that moment.
	out := captureOutput(t, func() {
		c := realClient(t, srv, staticToken{})
		NewScanner(Config{Projects: []string{projA}}, c).Scan(context.Background())
	})
	if strings.Contains(out, fakeToken) || strings.Contains(out, "logged") {
		t.Errorf("SDK logged request or response data:\n%s", out)
	}
	if out != "" {
		t.Errorf("unexpected output: %q", out)
	}
}

// TestNewClient_ADCErrorsHaveFixedText: a credentials file that cannot be
// parsed (here containing marker text) or does not exist gives ErrCredentials,
// never the SDK's error, which can quote the file.
func TestNewClient_ADCErrorsHaveFixedText(t *testing.T) {
	dir := t.TempDir()
	garbage := filepath.Join(dir, "fake-adc.json")
	if err := os.WriteFile(garbage, []byte(`{"type":"service_account","private_key":"`+markKey+`",`+markerPayload), 0o600); err != nil {
		t.Fatal(err)
	}
	unknownType := filepath.Join(dir, "fake-unknown-type.json")
	if err := os.WriteFile(unknownType, []byte(`{"type":"`+markSecret+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(dir, "missing.json"), garbage, unknownType} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", path)
			var c *Client
			var err error
			out := captureOutput(t, func() { c, err = NewClient(context.Background()) })
			if c != nil || !errors.Is(err, ErrCredentials) || err.Error() != ErrCredentials.Error() {
				t.Fatalf("NewClient = %v, %v; want ErrCredentials", c, err)
			}
			assertNoMarkers(t, "error", err.Error())
			assertNoMarkers(t, "output", out)
		})
	}
}

// newRawServer serves every request with h.
func newRawServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}
