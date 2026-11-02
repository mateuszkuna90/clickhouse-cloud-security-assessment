package aws

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
	"path/filepath"
	"strings"
	"sync"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/smithy-go"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/report"
)

// Regression tests for credential leakage through error reports.
//
// Each test drives a failure through the real SDK (credential providers,
// STS and EC2 clients, middleware, deserializers) with dummy marker strings
// placed where a real failure could carry secrets, then checks that no
// marker reaches the result, the encoded JSON report, or anything written
// to stdout, stderr, the standard logger or slog.

// Dummy markers. They are not credentials.
const (
	markAccessKey = "DUMMY_ACCESS_KEY_MARKER_7F3A"
	markSecret    = "DUMMY_SECRET_ACCESS_KEY_MARKER_9C1E"
	markToken     = "DUMMY_SESSION_TOKEN_MARKER_2B4D"
	// markStaticKey is the access key ID of the static dummy credentials.
	markStaticKey = "DUMMY_STATIC_AKID_MARKER_5E6F"
)

var allMarkers = []string{markAccessKey, markSecret, markToken, markStaticKey}

// markerPayload looks like leaked credential material.
const markerPayload = markAccessKey + " " + markSecret + " " + markToken

const fakeRequestID = "11111111-2222-3333-4444-555555555555"

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

// scanAndCheck runs the scan with output captured, then checks the result,
// the encoded report and the captured output for markers.
func scanAndCheck(t *testing.T, s *Scanner) model.ProviderResult {
	t.Helper()
	var res model.ProviderResult
	out := captureOutput(t, func() { res = s.Scan(context.Background()) })
	assertNoMarkers(t, "stdout/stderr/logs", out)
	assertNoMarkers(t, "result", fmt.Sprintf("%+v", res))
	js, err := report.Encode(report.Build([]model.ProviderResult{res}, report.Options{ToolVersion: "test"}))
	if err != nil {
		t.Fatal(err)
	}
	assertNoMarkers(t, "JSON report", string(js))
	return res
}

// ---- fake AWS HTTP endpoint -------------------------------------------

// awsResponse is one canned HTTP response.
type awsResponse struct {
	status int
	body   string
	err    error // transport error instead of a response
}

// fakeAWSHTTP serves STS and EC2 query-protocol requests by Action. EC2
// DescribeSecurityGroups is also keyed by NextToken ("" or "p1").
type fakeAWSHTTP struct {
	t         *testing.T
	mu        sync.Mutex
	responses map[string]awsResponse // "Action" or "Action/NextToken"
	calls     []string
}

func (f *fakeAWSHTTP) Do(req *http.Request) (*http.Response, error) {
	var form url.Values
	if req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		form, _ = url.ParseQuery(string(b))
	}
	key := form.Get("Action")
	if tok := form.Get("NextToken"); tok != "" {
		key += "/" + tok
	}
	f.mu.Lock()
	f.calls = append(f.calls, key)
	r, ok := f.responses[key]
	f.mu.Unlock()
	if !ok {
		f.t.Errorf("unexpected request %q to %s", key, req.URL.Host)
		r = awsResponse{status: 500, body: ec2ErrorXML("InternalError", "unexpected", fakeRequestID)}
	}
	if r.err != nil {
		return nil, r.err
	}
	return &http.Response{
		StatusCode: r.status,
		Status:     http.StatusText(r.status),
		Header:     http.Header{"Content-Type": []string{"text/xml"}},
		Body:       io.NopCloser(strings.NewReader(r.body)),
		Request:    req,
	}, nil
}

func (f *fakeAWSHTTP) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// noHTTP fails the test if any request is sent.
type noHTTP struct{ t *testing.T }

func (n noHTTP) Do(req *http.Request) (*http.Response, error) {
	n.t.Errorf("unexpected HTTP request to %s", req.URL.Host)
	return nil, errors.New("no network in tests")
}

func stsIdentityXML() string {
	return `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
<GetCallerIdentityResult><Arn>arn:aws:iam::111111111111:user/example-user</Arn>
<UserId>EXAMPLEUSERID</UserId><Account>111111111111</Account></GetCallerIdentityResult>
<ResponseMetadata><RequestId>` + fakeRequestID + `</RequestId></ResponseMetadata>
</GetCallerIdentityResponse>`
}

func stsErrorXML(code, msg, reqID string) string {
	return `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
<Error><Type>Sender</Type><Code>` + code + `</Code><Message>` + msg + `</Message></Error>
<RequestId>` + reqID + `</RequestId></ErrorResponse>`
}

func ec2ErrorXML(code, msg, reqID string) string {
	return `<Response><Errors><Error><Code>` + code + `</Code><Message>` + msg +
		`</Message></Error></Errors><RequestID>` + reqID + `</RequestID></Response>`
}

func ec2RegionsXML(regions ...string) string {
	var items strings.Builder
	for _, r := range regions {
		items.WriteString(`<item><regionName>` + r + `</regionName><regionEndpoint>ec2.` + r +
			`.amazonaws.com</regionEndpoint><optInStatus>opt-in-not-required</optInStatus></item>`)
	}
	return `<DescribeRegionsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
<requestId>` + fakeRequestID + `</requestId><regionInfo>` + items.String() + `</regionInfo>
</DescribeRegionsResponse>`
}

func ec2GroupsXML(next string) string {
	nt := ""
	if next != "" {
		nt = `<nextToken>` + next + `</nextToken>`
	}
	return `<DescribeSecurityGroupsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
<requestId>` + fakeRequestID + `</requestId><securityGroupInfo><item>
<ownerId>111111111111</ownerId><groupId>sg-0fake0000000000001</groupId><groupName>open-ssh</groupName>
<groupDescription>example</groupDescription><vpcId>vpc-0fake000000000001</vpcId>
<ipPermissions><item><ipProtocol>tcp</ipProtocol><fromPort>22</fromPort><toPort>22</toPort>
<groups/><ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges><ipv6Ranges/><prefixListIds/>
</item></ipPermissions><ipPermissionsEgress/></item></securityGroupInfo>` + nt + `
</DescribeSecurityGroupsResponse>`
}

// sdkConfig builds an SDK config for tests: no retries (failures are
// immediate), the given credentials and HTTP client.
func sdkConfig(creds awssdk.CredentialsProvider, httpc awssdk.HTTPClient) awssdk.Config {
	return awssdk.Config{
		Region:      "eu-west-1",
		Credentials: creds,
		HTTPClient:  httpc,
		Retryer:     func() awssdk.Retryer { return awssdk.NopRetryer{} },
	}
}

// staticCreds are dummy credentials; the fake endpoint ignores signatures.
func staticCreds() awssdk.CredentialsProvider {
	return awssdk.NewCredentialsCache(awssdk.CredentialsProviderFunc(
		func(context.Context) (awssdk.Credentials, error) {
			return awssdk.Credentials{AccessKeyID: markStaticKey, SecretAccessKey: "dummy-secret"}, nil
		}))
}

// failingCreds is a credential provider whose error carries the markers,
// cached the way LoadDefaultConfig caches the default chain.
func failingCreds() awssdk.CredentialsProvider {
	return awssdk.NewCredentialsCache(awssdk.CredentialsProviderFunc(
		func(context.Context) (awssdk.Credentials, error) {
			return awssdk.Credentials{}, errors.New("credential provider output: " + markerPayload)
		}))
}

// ---- tests -------------------------------------------------------------

// TestLeak_CredentialProcess uses the real SDK default chain: a shared
// config profile with credential_process. The process prints the markers
// instead of JSON, and the SDK's processcreds provider puts that stdout
// into its error text.
func TestLeak_CredentialProcess(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "dummy-aws-config")
	content := "[default]\ncredential_process = echo " + markerPayload + "\n"
	if err := os.WriteFile(cfgFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", cfgFile)

	cfg, err := LoadConfig(context.Background(), "eu-west-1")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	// Precondition: the unprotected SDK error really carries the markers,
	// so this test exercises a live leak path.
	_, rawErr := cfg.Credentials.Retrieve(context.Background())
	if rawErr == nil || !strings.Contains(rawErr.Error(), markSecret) {
		t.Fatalf("precondition: SDK credential error should contain the markers, got %v", rawErr)
	}

	cfg.HTTPClient = noHTTP{t}
	cfg.Retryer = func() awssdk.Retryer { return awssdk.NopRetryer{} }
	res := scanAndCheck(t, NewScannerFromConfig(cfg, Config{}))

	assertEqual(t, "status", res.Status, model.ProviderFailed)
	assertEqual(t, "errors", errorKinds(res.Errors), []string{" sts:GetCallerIdentity auth"})
	assertEqual(t, "message", res.Errors[0].Message,
		"sts:GetCallerIdentity failed: AWS credentials could not be resolved or were rejected")
}

// TestLeak_CredentialProviderOnEveryOperation fails credential resolution
// on STS, DescribeRegions and DescribeSecurityGroups through real clients.
func TestLeak_CredentialProviderOnEveryOperation(t *testing.T) {
	t.Run("GetCallerIdentity", func(t *testing.T) {
		s := NewScannerFromConfig(sdkConfig(failingCreds(), noHTTP{t}), Config{})
		res := scanAndCheck(t, s)
		assertEqual(t, "status", res.Status, model.ProviderFailed)
		assertEqual(t, "errors", errorKinds(res.Errors), []string{" sts:GetCallerIdentity auth"})
	})
	t.Run("DescribeRegions", func(t *testing.T) {
		s := NewScannerFromConfig(sdkConfig(failingCreds(), noHTTP{t}), Config{})
		s.sts = okSTS() // identity succeeds; EC2 credentials fail
		res := scanAndCheck(t, s)
		assertEqual(t, "status", res.Status, model.ProviderFailed)
		assertEqual(t, "errors", errorKinds(res.Errors), []string{fakeAccount + " ec2:DescribeRegions auth"})
	})
	t.Run("DescribeSecurityGroups", func(t *testing.T) {
		s := NewScannerFromConfig(sdkConfig(failingCreds(), noHTTP{t}), Config{Regions: []string{euWest1, usEast1}})
		s.sts = okSTS()
		res := scanAndCheck(t, s)
		assertEqual(t, "status", res.Status, model.ProviderFailed)
		assertEqual(t, "errors", errorKinds(res.Errors), []string{
			scopeEU + " ec2:DescribeSecurityGroups auth",
			scopeUS + " ec2:DescribeSecurityGroups auth",
		})
	})
}

// TestLeak_APIErrors returns AWS error responses whose messages carry the
// markers, through the real STS/EC2 deserializers.
func TestLeak_APIErrors(t *testing.T) {
	bogusID := "not a request id " + markToken
	tests := []struct {
		name       string
		cfg        Config
		responses  map[string]awsResponse
		wantStatus model.ProviderStatus
		wantErrs   []string
		wantMsg    string
	}{
		{
			name: "STS GetCallerIdentity rejected",
			responses: map[string]awsResponse{
				"GetCallerIdentity": {status: 403, body: stsErrorXML("InvalidClientTokenId", markerPayload, fakeRequestID)},
			},
			wantStatus: model.ProviderFailed,
			wantErrs:   []string{" sts:GetCallerIdentity auth"},
			wantMsg: "sts:GetCallerIdentity failed: AWS credentials could not be resolved or were rejected" +
				" [AWS error code: InvalidClientTokenId] [request ID: " + fakeRequestID + "]",
		},
		{
			name: "EC2 DescribeRegions denied",
			responses: map[string]awsResponse{
				"GetCallerIdentity": {status: 200, body: stsIdentityXML()},
				"DescribeRegions": {status: 403, body: ec2ErrorXML("UnauthorizedOperation",
					"You are not authorized. Encoded authorization failure message: "+markerPayload, fakeRequestID)},
			},
			wantStatus: model.ProviderFailed,
			wantErrs:   []string{fakeAccount + " ec2:DescribeRegions permission_denied"},
			wantMsg: "ec2:DescribeRegions failed: access denied, or the region is not enabled for the account" +
				" [AWS error code: UnauthorizedOperation] [request ID: " + fakeRequestID + "]",
		},
		{
			name: "EC2 DescribeSecurityGroups denied",
			cfg:  Config{Regions: []string{euWest1}},
			responses: map[string]awsResponse{
				"GetCallerIdentity":      {status: 200, body: stsIdentityXML()},
				"DescribeSecurityGroups": {status: 403, body: ec2ErrorXML("UnauthorizedOperation", markerPayload, fakeRequestID)},
			},
			wantStatus: model.ProviderFailed,
			wantErrs:   []string{scopeEU + " ec2:DescribeSecurityGroups permission_denied"},
			wantMsg: "ec2:DescribeSecurityGroups failed: access denied, or the region is not enabled for the account" +
				" (page 1) [AWS error code: UnauthorizedOperation] [request ID: " + fakeRequestID + "]",
		},
		{
			name: "pagination failure with unknown code and malformed request ID",
			cfg:  Config{Regions: []string{euWest1}},
			responses: map[string]awsResponse{
				"GetCallerIdentity":         {status: 200, body: stsIdentityXML()},
				"DescribeSecurityGroups":    {status: 200, body: ec2GroupsXML("p1")},
				"DescribeSecurityGroups/p1": {status: 400, body: ec2ErrorXML("Dummy."+markAccessKey, markerPayload, bogusID)},
			},
			wantStatus: model.ProviderFailed,
			wantErrs:   []string{scopeEU + " ec2:DescribeSecurityGroups other"},
			wantMsg:    "ec2:DescribeSecurityGroups failed: unexpected error (page 2)",
		},
		{
			name: "transport error",
			cfg:  Config{Regions: []string{euWest1}},
			responses: map[string]awsResponse{
				"GetCallerIdentity":      {status: 200, body: stsIdentityXML()},
				"DescribeSecurityGroups": {err: errors.New("proxy said: " + markerPayload)},
			},
			wantStatus: model.ProviderFailed,
			wantErrs:   []string{scopeEU + " ec2:DescribeSecurityGroups other"},
			wantMsg:    "ec2:DescribeSecurityGroups failed: unexpected error (page 1)",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			httpc := &fakeAWSHTTP{t: t, responses: tc.responses}
			res := scanAndCheck(t, NewScannerFromConfig(sdkConfig(staticCreds(), httpc), tc.cfg))
			assertEqual(t, "status", res.Status, tc.wantStatus)
			assertEqual(t, "errors", errorKinds(res.Errors), tc.wantErrs)
			if len(res.Errors) == 1 {
				assertEqual(t, "message", res.Errors[0].Message, tc.wantMsg)
			}
			assertEqual(t, "no findings kept", len(res.AWSSecurityGroups), 0)
		})
	}
}

// TestRealClientsEndToEnd checks the fake endpoint and the real clients
// produce a finding when nothing fails, so the failure tests above are
// exercising the real request/response path.
func TestRealClientsEndToEnd(t *testing.T) {
	httpc := &fakeAWSHTTP{t: t, responses: map[string]awsResponse{
		"GetCallerIdentity":         {status: 200, body: stsIdentityXML()},
		"DescribeRegions":           {status: 200, body: ec2RegionsXML(euWest1)},
		"DescribeSecurityGroups":    {status: 200, body: ec2GroupsXML("p1")},
		"DescribeSecurityGroups/p1": {status: 200, body: ec2GroupsXML("")},
	}}
	res := scanAndCheck(t, NewScannerFromConfig(sdkConfig(staticCreds(), httpc), Config{}))
	assertEqual(t, "status", res.Status, model.ProviderComplete)
	assertEqual(t, "calls", httpc.called(), []string{
		"GetCallerIdentity", "DescribeRegions", "DescribeSecurityGroups", "DescribeSecurityGroups/p1",
	})
	assertEqual(t, "findings", lines(res.AWSSecurityGroups), []string{
		"sg-0fake0000000000001 tcp 22 from=22 to=22 type=- code=- src=0.0.0.0/0 raw=0.0.0.0/0 ref=tcp:22:22:0.0.0.0/0",
		"sg-0fake0000000000001 tcp 22 from=22 to=22 type=- code=- src=0.0.0.0/0 raw=0.0.0.0/0 ref=tcp:22:22:0.0.0.0/0",
	})
}

// TestLeak_UnknownWrappedErrors covers errors no classifier knows: the
// message must be the generic template.
func TestLeak_UnknownWrappedErrors(t *testing.T) {
	errs := []error{
		errors.New(markerPayload),
		fmt.Errorf("wrapped: %w", errors.New(markerPayload)),
		opError("DescribeSecurityGroups", errors.New(markerPayload)),
		opError("DescribeSecurityGroups", &smithy.GenericAPIError{Code: markAccessKey, Message: markerPayload}),
		fmt.Errorf("x: %w", &smithy.GenericAPIError{Code: "AccessDenied", Message: markerPayload}),
	}
	for i, e := range errs {
		fake := &fakeEC2{pages: []page{{err: e}}}
		res := scanAndCheck(t, newTestScanner(Config{Regions: []string{euWest1}}, okSTS(),
			newFactory(map[string]*fakeEC2{euWest1: fake})))
		assertEqual(t, fmt.Sprintf("case %d status", i), res.Status, model.ProviderFailed)
		if len(res.Errors) != 1 {
			t.Fatalf("case %d: errors = %+v", i, res.Errors)
		}
		want := "ec2:DescribeSecurityGroups failed: unexpected error (page 1)"
		if i == len(errs)-1 {
			// A listed code is kept; its message is not.
			want = "ec2:DescribeSecurityGroups failed: access denied, or the region is not enabled for the account" +
				" (page 1) [AWS error code: AccessDenied]"
		}
		assertEqual(t, fmt.Sprintf("case %d message", i), res.Errors[0].Message, want)
	}
}

func TestCredentialsGuard(t *testing.T) {
	ctx := context.Background()
	g := wrapCredentials(failingCreds())
	if wrapCredentials(g) != g {
		t.Error("wrapping is not idempotent")
	}
	if wrapCredentials(nil) != nil {
		t.Error("nil provider should stay nil")
	}
	_, err := g.Retrieve(ctx)
	var ce *credentialsError
	if !errors.As(err, &ce) {
		t.Fatalf("err = %T, want *credentialsError", err)
	}
	assertNoMarkers(t, "guard error", err.Error())
	if errors.Unwrap(err) != nil {
		t.Error("guard must not keep the provider error")
	}

	// Context errors survive, so a timeout is still a timeout.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	_, err = wrapCredentials(awssdk.CredentialsProviderFunc(func(c context.Context) (awssdk.Credentials, error) {
		return awssdk.Credentials{}, fmt.Errorf("%s: %w", markerPayload, c.Err())
	})).Retrieve(cctx)
	assertEqual(t, "kind", classify(err), model.ErrorKindTimeout)
	assertNoMarkers(t, "guard ctx error", err.Error())

	// Successful retrieval passes through unchanged.
	creds, err := wrapCredentials(staticCreds()).Retrieve(ctx)
	if err != nil || creds.AccessKeyID != markStaticKey {
		t.Errorf("pass-through failed: %v", err)
	}
	// The SDK checks for anonymous credentials with IsCredentialsProvider;
	// the check must still see through the wrapper.
	anon := wrapCredentials(awssdk.AnonymousCredentials{})
	if !awssdk.IsCredentialsProvider(anon, (*awssdk.AnonymousCredentials)(nil)) {
		t.Error("IsCredentialsProvider not forwarded for anonymous credentials")
	}
	if awssdk.IsCredentialsProvider(g, (*awssdk.AnonymousCredentials)(nil)) {
		t.Error("non-anonymous provider reported as anonymous")
	}
}

func TestLoadConfigErrorsHaveFixedText(t *testing.T) {
	// A shared config file that the SDK cannot parse; its error would
	// quote the file.
	cfgFile := filepath.Join(t.TempDir(), "dummy-aws-config")
	content := "[profile broken\naws_secret_access_key = " + markSecret + "\n"
	if err := os.WriteFile(cfgFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", cfgFile)
	t.Setenv("AWS_PROFILE", "broken")
	_, err := LoadConfig(context.Background(), "eu-west-1")
	if err == nil {
		t.Skip("SDK accepted the malformed file; nothing to check")
	}
	if !errors.Is(err, ErrConfigLoad) {
		t.Errorf("err = %v, want ErrConfigLoad", err)
	}
	assertNoMarkers(t, "LoadConfig error", err.Error())
}
