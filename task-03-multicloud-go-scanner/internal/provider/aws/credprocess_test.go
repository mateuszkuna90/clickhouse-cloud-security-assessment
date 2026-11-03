package aws

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/processcreds"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
)

// Regression tests for the final review: credential_process stderr leaking
// to the application's stderr (High), and a cancelled scan leaving the
// credential helper running (Medium).
//
// The helper is a real executable: this test binary, started by the SDK's
// processcreds provider through the real shell (cmd.exe /C or sh -c), with
// helperModeEnv selecting what it does (TestMain in fakes_test.go). Every
// start is appended to a log file, so the tests can see that the real
// subprocess path ran, which PIDs to check, and that no further helper was
// started after a cancellation.

const (
	helperModeEnv = "CLOUDFW_TEST_CREDENTIAL_HELPER"
	helperLogEnv  = "CLOUDFW_TEST_CREDENTIAL_HELPER_LOG"
	// helperAKID is the access key the "ok" helper returns. It is not a
	// marker: it is expected in the signed request, never in output.
	helperAKID = "DUMMYHELPERAKID0001"
)

// runCredentialHelper is the fake credential_process. It writes the dummy
// markers to stderr in every mode.
func runCredentialHelper(mode string) int {
	if path := os.Getenv(helperLogEnv); path != "" {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err == nil {
			fmt.Fprintf(f, "%s %d\n", mode, os.Getpid())
			f.Close()
		}
	}
	fmt.Fprintf(os.Stderr, "helper diagnostics: AccessKeyId=%s SecretAccessKey=%s SessionToken=%s\n",
		markAccessKey, markSecret, markToken)
	switch mode {
	case "ok":
		fmt.Printf(`{"Version":1,"AccessKeyId":%q,"SecretAccessKey":"dummy-helper-secret"}`, helperAKID)
		return 0
	case "fail":
		return 3
	case "garbage":
		fmt.Print("not json: " + markerPayload)
		return 0
	case "block":
		blockForever()
	case "spawn":
		// A child of the helper that inherits its stdout pipe and also
		// blocks: the tree a wrapper script would create.
		child := exec.Command(os.Args[0])
		child.Env = append(os.Environ(), helperModeEnv+"=block")
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			return 4
		}
		blockForever()
	}
	return 2
}

func blockForever() {
	for {
		time.Sleep(time.Hour)
	}
}

// helperSetup writes a shared config whose default profile runs this test
// binary as credential_process in the given mode, and returns the log path.
func helperSetup(t *testing.T, mode string) (logPath string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(exe, " \t\"") {
		t.Fatalf("test binary path %q contains spaces or quotes; the credential_process line would need quoting", exe)
	}
	dir := t.TempDir()
	logPath = filepath.Join(dir, "dummy-helper.log")
	cfgFile := filepath.Join(dir, "dummy-aws-config")
	if err := os.WriteFile(cfgFile, []byte("[default]\ncredential_process = "+exe+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", cfgFile)
	t.Setenv(helperModeEnv, mode)
	t.Setenv(helperLogEnv, logPath)
	return logPath
}

// helperStarts reads the helper log: one "mode pid" entry per start.
func helperStarts(t *testing.T, logPath string) []int {
	t.Helper()
	f, err := os.Open(logPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var pids []int
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 2 {
			if pid, err := strconv.Atoi(fields[1]); err == nil {
				pids = append(pids, pid)
			}
		}
	}
	return pids
}

// waitFor polls cond until it is true or the deadline passes.
func waitFor(t *testing.T, what string, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", d, what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// stsDenied answers every request with an STS AccessDenied error and
// records the access key the request was signed with.
type stsDenied struct {
	mu    sync.Mutex
	akids []string
}

func (s *stsDenied) Do(req *http.Request) (*http.Response, error) {
	auth := req.Header.Get("Authorization")
	akid := ""
	if _, rest, ok := strings.Cut(auth, "Credential="); ok {
		akid, _, _ = strings.Cut(rest, "/")
	}
	s.mu.Lock()
	s.akids = append(s.akids, akid)
	s.mu.Unlock()
	body := `<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>denied</Message></Error>` +
		`<RequestId>` + fakeRequestID + `</RequestId></ErrorResponse>`
	return &http.Response{
		StatusCode: 403, Status: "403 Forbidden",
		Header:  http.Header{"Content-Type": {"text/xml"}},
		Body:    io.NopCloser(strings.NewReader(body)),
		Request: req,
	}, nil
}

// loadContained runs LoadConfig on the helper profile and checks that the
// credential_process provider was replaced by the contained one.
func loadContained(t *testing.T) awssdk.Config {
	t.Helper()
	cfg, err := LoadConfig(context.Background(), euWest1)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if _, ok := cfg.Credentials.(*cancellableCache); !ok {
		t.Fatalf("credential_process provider not contained: %T", cfg.Credentials)
	}
	cfg.Retryer = func() awssdk.Retryer { return awssdk.NopRetryer{} }
	return cfg
}

// ---- A. helper stderr never reaches the application ----------------------

// Precondition: with the SDK's default builder, the helper's stderr really
// reaches the application's stderr. This is the defect, shown on the real
// SDK path with the same capture the regression tests use.
func TestCredentialProcess_SDKDefaultLeaksStderr(t *testing.T) {
	logPath := helperSetup(t, "fail")
	exe, _ := os.Executable()
	out := captureOutput(t, func() {
		_, _ = processcreds.NewProvider(exe).Retrieve(context.Background())
	})
	if len(helperStarts(t, logPath)) != 1 {
		t.Fatalf("helper did not run")
	}
	if !strings.Contains(out, markSecret) {
		t.Fatalf("precondition: the SDK default builder should leak helper stderr; captured %q", out)
	}
}

func TestCredentialProcess_StderrContained(t *testing.T) {
	cases := []struct {
		mode string
		// wantKind of the GetCallerIdentity error.
		wantKind string
		signed   bool
	}{
		// Credentials come back on stdout; the request is signed with
		// them and denied by the fake STS.
		{"ok", model.ErrorKindPermissionDenied, true},
		// The helper exits non-zero.
		{"fail", model.ErrorKindAuth, false},
		// stdout is not JSON: the SDK error quotes stdout (the markers).
		{"garbage", model.ErrorKindAuth, false},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			logPath := helperSetup(t, tc.mode)
			cfg := loadContained(t)
			sts := &stsDenied{}
			cfg.HTTPClient = sts
			res := scanAndCheck(t, NewScannerFromConfig(cfg, Config{Regions: []string{euWest1}}))

			if got := len(helperStarts(t, logPath)); got != 1 {
				t.Fatalf("helper started %d times, want 1 (the real subprocess path must run)", got)
			}
			assertEqual(t, "errors", errorKinds(res.Errors), []string{" sts:GetCallerIdentity " + tc.wantKind})
			sts.mu.Lock()
			defer sts.mu.Unlock()
			if tc.signed {
				assertEqual(t, "signed with helper credentials", sts.akids, []string{helperAKID})
			} else {
				assertEqual(t, "no request without credentials", len(sts.akids), 0)
			}
		})
	}
}

// The structured diagnostics/errors and the CLI-visible message carry no
// helper output for the stdout path either.
func TestCredentialProcess_ErrorTextIsFixed(t *testing.T) {
	helperSetup(t, "garbage")
	cfg := loadContained(t)
	cfg.HTTPClient = noHTTP{t}
	res := scanAndCheck(t, NewScannerFromConfig(cfg, Config{}))
	assertEqual(t, "message", res.Errors[0].Message,
		"sts:GetCallerIdentity failed: AWS credentials could not be resolved or were rejected")
}

// ---- B. cancellation: no helper outlives the scan ------------------------

func TestCredentialProcess_CancellationKillsHelperTree(t *testing.T) {
	for _, tc := range []struct {
		mode    string
		helpers int // processes expected per start
	}{
		{"block", 1},
		{"spawn", 2},
	} {
		for _, how := range []string{"cancel", "timeout"} {
			t.Run(tc.mode+"/"+how, func(t *testing.T) {
				logPath := helperSetup(t, tc.mode)
				cfg := loadContained(t)
				cfg.HTTPClient = noHTTP{t}
				s := NewScannerFromConfig(cfg, Config{Regions: []string{euWest1}})

				// Two scans on the same scanner: repeated cancellation.
				for round := 1; round <= 2; round++ {
					var res model.ProviderResult
					out := captureOutput(t, func() {
						ctx, cancel := context.WithCancel(context.Background())
						if how == "timeout" {
							ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
						}
						defer cancel()
						done := make(chan model.ProviderResult, 1)
						go func() { done <- s.Scan(ctx) }()
						want := round * tc.helpers
						waitFor(t, "helper start", 20*time.Second, func() bool {
							return len(helperStarts(t, logPath)) >= want
						})
						if how == "cancel" {
							cancel()
						}
						select {
						case res = <-done:
						case <-time.After(30 * time.Second):
							t.Fatal("Scan did not return after cancellation")
						}
					})
					assertNoMarkers(t, "output", out)
					assertNoMarkers(t, "result", fmt.Sprintf("%+v", res))
					assertEqual(t, "errors", errorKinds(res.Errors), []string{" sts:GetCallerIdentity timeout"})

					pids := helperStarts(t, logPath)
					assertEqual(t, "helpers started", len(pids), round*tc.helpers)
					// Every helper process, including children, is gone
					// by the time Scan has returned (allowing the OS a
					// moment to finish tearing them down).
					waitFor(t, "helper processes to exit", 5*time.Second, func() bool {
						for _, pid := range pids {
							if processAlive(pid) {
								return false
							}
						}
						return true
					})
					// No further credential retrieval after the scan.
					time.Sleep(300 * time.Millisecond)
					assertEqual(t, "no new helper after return", len(helperStarts(t, logPath)), round*tc.helpers)
				}
			})
		}
	}
}

// ---- fail closed for credential_process inside a chain -------------------

func TestCredentialProcess_ChainFailsClosed(t *testing.T) {
	logPath := helperSetup(t, "ok")
	exe, _ := os.Executable()
	cfgFile := filepath.Join(t.TempDir(), "dummy-aws-config-chain")
	content := "[default]\nrole_arn = arn:aws:iam::111111111111:role/example-role\nsource_profile = helper\n\n" +
		"[profile helper]\ncredential_process = " + exe + "\n"
	if err := os.WriteFile(cfgFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", cfgFile)
	cfg, err := LoadConfig(context.Background(), euWest1)
	if !errors.Is(err, ErrCredentialProcessChain) || cfg.Credentials != nil {
		t.Fatalf("LoadConfig = %T, %v; want ErrCredentialProcessChain", cfg.Credentials, err)
	}
	assertNoMarkers(t, "error", err.Error())
	assertEqual(t, "helper never started", len(helperStarts(t, logPath)), 0)

	// credential_process and role_arn on the same profile is a chain too.
	if err := os.WriteFile(cfgFile, []byte("[default]\nrole_arn = arn:aws:iam::111111111111:role/example-role\n"+
		"credential_process = "+exe+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(context.Background(), euWest1); !errors.Is(err, ErrCredentialProcessChain) {
		t.Fatalf("same-profile chain: err = %v", err)
	}
}

// Other credential sources are left unchanged.
func TestCredentialProcess_OtherSourcesUntouched(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "DUMMYENVAKID0001")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "dummy-env-secret")
	helperSetup(t, "ok") // the profile has credential_process, but env keys win
	cfg, err := LoadConfig(context.Background(), euWest1)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Credentials.(*awssdk.CredentialsCache); !ok {
		t.Fatalf("env credentials should keep the SDK cache, got %T", cfg.Credentials)
	}
	creds, err := cfg.Credentials.Retrieve(context.Background())
	if err != nil || creds.AccessKeyID != "DUMMYENVAKID0001" {
		t.Fatalf("Retrieve = %v, %v", creds.AccessKeyID, err)
	}
}

func TestContainedCommand(t *testing.T) {
	if _, err := (containedCommand{command: "  "}).NewCommand(context.Background()); !errors.Is(err, errEmptyCredentialProcess) {
		t.Errorf("empty command: %v", err)
	}
	cmd, err := containedCommand{command: "example-helper --flag"}.NewCommand(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Stderr != nil || cmd.Stdin != nil || cmd.WaitDelay != helperWaitDelay || cmd.Cancel == nil {
		t.Errorf("stderr=%v stdin=%v waitDelay=%v cancel=%v", cmd.Stderr, cmd.Stdin, cmd.WaitDelay, cmd.Cancel != nil)
	}
	if last := cmd.Args[len(cmd.Args)-1]; last != "example-helper --flag" {
		t.Errorf("command line %q", last)
	}
}

// ---- cancellableCache ----------------------------------------------------

type countingProvider struct {
	calls   atomic.Int32
	block   chan struct{} // if set, Retrieve waits for it or ctx
	expires time.Time
}

func (p *countingProvider) Retrieve(ctx context.Context) (awssdk.Credentials, error) {
	p.calls.Add(1)
	if p.block != nil {
		select {
		case <-p.block:
		case <-ctx.Done():
			return awssdk.Credentials{}, errors.New("provider stopped: " + markSecret)
		}
	}
	c := awssdk.Credentials{AccessKeyID: "AKID", SecretAccessKey: "s"}
	if !p.expires.IsZero() {
		c.CanExpire, c.Expires = true, p.expires
	}
	return c, nil
}

func TestCancellableCache(t *testing.T) {
	ctx := context.Background()
	t.Run("caches until near expiry", func(t *testing.T) {
		now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		p := &countingProvider{expires: now.Add(10 * time.Minute)}
		c := newCancellableCache(p)
		c.now = func() time.Time { return now }
		for range 3 {
			if _, err := c.Retrieve(ctx); err != nil {
				t.Fatal(err)
			}
		}
		assertEqual(t, "calls", p.calls.Load(), int32(1))
		now = now.Add(9*time.Minute + 30*time.Second) // inside the refresh margin
		_, _ = c.Retrieve(ctx)
		assertEqual(t, "refreshed", p.calls.Load(), int32(2))
	})
	t.Run("the caller's cancellation stops the provider and reports the context error", func(t *testing.T) {
		p := &countingProvider{block: make(chan struct{})}
		c := newCancellableCache(p)
		cctx, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { _, err := c.Retrieve(cctx); done <- err }()
		waitFor(t, "provider call", 5*time.Second, func() bool { return p.calls.Load() == 1 })
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), markSecret) {
				t.Fatalf("err = %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Retrieve did not return")
		}
	})
	t.Run("a waiting caller gives up on its own context", func(t *testing.T) {
		p := &countingProvider{block: make(chan struct{})}
		c := newCancellableCache(p)
		go func() { _, _ = c.Retrieve(ctx) }() // holds the slot
		waitFor(t, "first call", 5*time.Second, func() bool { return p.calls.Load() == 1 })
		wctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel()
		if _, err := c.Retrieve(wctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v", err)
		}
		assertEqual(t, "waiter did not start a second retrieval", p.calls.Load(), int32(1))
		close(p.block)
	})
	t.Run("already cancelled: no retrieval", func(t *testing.T) {
		p := &countingProvider{}
		c := newCancellableCache(p)
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := c.Retrieve(cctx); err == nil {
			t.Fatal("want error")
		}
		assertEqual(t, "calls", p.calls.Load(), int32(0))
	})
}

// captureDrainTimeout bounds how long output capture waits for its pipe to
// close after the code under test returned.
const captureDrainTimeout = 10 * time.Second
