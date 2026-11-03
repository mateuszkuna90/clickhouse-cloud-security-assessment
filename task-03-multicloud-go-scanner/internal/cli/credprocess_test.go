package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/report"
)

// End-to-end regression for the final review (credential_process stderr
// leak and helper lifetime) through cli.Run with the real AWS factory
// (config.LoadDefaultConfig and the real processcreds provider). The helper
// is this test binary, selected by cliHelperEnv in TestMain.

const cliHelperEnv = "CLOUDFW_CLI_TEST_CREDENTIAL_HELPER"

func TestMain(m *testing.M) {
	switch os.Getenv(cliHelperEnv) {
	case "":
		os.Exit(m.Run())
	case "fail":
		fmt.Fprintln(os.Stderr, "helper: "+markerPayload)
		fmt.Println("not json: " + markerPayload)
		os.Exit(3)
	case "block":
		fmt.Fprintln(os.Stderr, "helper: "+markerPayload)
		for {
			time.Sleep(time.Hour)
		}
	}
	os.Exit(2)
}

// awsHelperEnv points the AWS SDK at a profile whose credential_process is
// this test binary, with no other credentials and no network.
func awsHelperEnv(t *testing.T, mode string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(exe, " \t\"") {
		t.Fatalf("test binary path %q needs quoting", exe)
	}
	dir := t.TempDir()
	cfg := filepath.Join(dir, "dummy-aws-config")
	if err := os.WriteFile(cfg, []byte("[default]\ncredential_process = "+exe+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE",
		"AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
		"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_REGION", "AWS_DEFAULT_REGION"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	t.Setenv("AWS_CONFIG_FILE", cfg)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "dummy-missing-credentials"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv(cliHelperEnv, mode)
}

// captureProcessStderr replaces os.Stderr while fn runs. The SDK's default
// credential_process builder reads os.Stderr when it builds the command, so
// a leaking helper would write here.
func captureProcessStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	done := make(chan struct{})
	go func() { _, _ = io.Copy(&buf, r); close(done) }()
	old := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = old }()
	fn()
	w.Close()
	// Bounded: a helper that outlived the run and still holds the pipe
	// fails the test instead of hanging it.
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Errorf("process stderr still open 10s after the run: a credential helper outlived it")
		return ""
	}
	r.Close()
	return buf.String()
}

func runRealAWS(t *testing.T, args ...string) (int, string, string, string) {
	t.Helper()
	env, stdout, stderr := testEnv(cleanCloud(), nil)
	env.Factories = SDKFactories()
	var code int
	procErr := captureProcessStderr(t, func() { code = Run(context.Background(), args, env) })
	return code, stdout.String(), stderr.String(), procErr
}

func TestE2E_CredentialProcessHelperOutputNeverShown(t *testing.T) {
	awsHelperEnv(t, "fail")
	code, stdout, stderr, procErr := runRealAWS(t, "--providers", "aws",
		"--aws-bootstrap-region", regionEU, "--aws-regions", regionEU)
	assertEqual(t, "exit", code, report.ExitIncomplete)
	rep := decode(t, stdout)
	assertEqual(t, "error", fmt.Sprint(errorSummary(rep)), "[aws  sts:GetCallerIdentity auth]")
	assertNoMarkers(t, "report", stdout)
	assertNoMarkers(t, "command stderr", stderr)
	assertNoMarkers(t, "process stderr", procErr)
}

func TestE2E_CredentialProcessHelperStoppedOnTimeout(t *testing.T) {
	awsHelperEnv(t, "block")
	start := time.Now()
	code, stdout, stderr, procErr := runRealAWS(t, "--providers", "aws",
		"--aws-bootstrap-region", regionEU, "--aws-regions", regionEU, "--timeout", "2s")
	if d := time.Since(start); d > 20*time.Second {
		t.Fatalf("run took %v", d)
	}
	assertEqual(t, "exit", code, report.ExitIncomplete)
	rep := decode(t, stdout)
	assertEqual(t, "error", fmt.Sprint(errorSummary(rep)), "[aws  sts:GetCallerIdentity timeout]")
	assertNoMarkers(t, "report", stdout)
	assertNoMarkers(t, "command stderr", stderr)
	assertNoMarkers(t, "process stderr", procErr)
}
