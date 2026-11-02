package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
)

// These tests run the real cloudfw-scan entry point (main) in a child
// process: the test binary re-executes itself with runMainEnv set, and
// TestMain then calls main() with the given arguments.
//
// No real cloud account is reached. The child gets a minimal environment:
// no cloud credentials, cloud config files that do not exist, the AWS
// instance metadata service disabled, Azure restricted to
// EnvironmentCredential (which has nothing to use), and every HTTP(S)
// request sent to a proxy on 127.0.0.1:1 that refuses connections, so even
// an unexpected request cannot leave the machine.

const runMainEnv = "CLOUDFW_SCAN_TEST_RUN_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(runMainEnv) == "1" {
		args := strings.Split(os.Getenv("CLOUDFW_SCAN_TEST_ARGS"), "\x1f")
		if len(args) == 1 && args[0] == "" {
			args = nil
		}
		os.Args = append([]string{"cloudfw-scan"}, args...)
		main()
		return
	}
	os.Exit(m.Run())
}

type proc struct {
	code   int
	stdout string
	stderr string
}

// offlineEnv is the child's whole environment.
func offlineEnv(t *testing.T, extra ...string) []string {
	dir := t.TempDir()
	env := []string{
		runMainEnv + "=1",
		"HOME=" + dir, "USERPROFILE=" + dir, "APPDATA=" + dir, "LOCALAPPDATA=" + dir,
		"TEMP=" + dir, "TMP=" + dir,
		"HTTP_PROXY=http://127.0.0.1:1", "HTTPS_PROXY=http://127.0.0.1:1", "NO_PROXY=",
		// AWS: no credentials, no config, no instance metadata.
		"AWS_CONFIG_FILE=" + filepath.Join(dir, "fake-aws-config"),
		"AWS_SHARED_CREDENTIALS_FILE=" + filepath.Join(dir, "fake-aws-credentials"),
		"AWS_EC2_METADATA_DISABLED=true",
		// GCP: ADC points at a file that does not exist; no metadata server.
		"GOOGLE_APPLICATION_CREDENTIALS=" + filepath.Join(dir, "fake-adc-missing.json"),
		"CLOUDSDK_CONFIG=" + dir, "GCE_METADATA_HOST=127.0.0.1:1", "NO_GCE_CHECK=True",
		// Azure: only EnvironmentCredential, with no AZURE_* values.
		"AZURE_TOKEN_CREDENTIALS=EnvironmentCredential", "AZURE_CONFIG_DIR=" + dir,
	}
	if runtime.GOOS == "windows" {
		env = append(env, "SystemRoot="+os.Getenv("SystemRoot"))
	}
	return append(env, extra...)
}

func runMain(t *testing.T, env []string, args ...string) proc {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(env, "CLOUDFW_SCAN_TEST_ARGS="+strings.Join(args, "\x1f"))
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return proc{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

func decodeReport(t *testing.T, s string) model.Report {
	t.Helper()
	var rep model.Report
	dec := json.NewDecoder(strings.NewReader(s))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rep); err != nil || dec.More() {
		t.Fatalf("stdout is not one valid report (%v):\n%s", err, s)
	}
	return rep
}

func TestMain_UsageErrorsExit3(t *testing.T) {
	env := offlineEnv(t)
	for name, args := range map[string][]string{
		"no arguments":          nil,
		"unknown provider":      {"--providers", "oracle"},
		"unknown flag":          {"--providers", "aws", "--nope"},
		"invalid region":        {"--providers", "aws", "--aws-regions", "not a region"},
		"invalid project":       {"--providers", "gcp", "--gcp-projects", "BAD"},
		"invalid subscription":  {"--providers", "azure", "--azure-subscriptions", "x"},
		"gcp without a project": {"--providers", "gcp"},
		// AWS with no region in flags, environment or (empty) config.
		"aws without a bootstrap region": {"--providers", "aws"},
	} {
		t.Run(name, func(t *testing.T) {
			p := runMain(t, env, args...)
			if p.code != 3 || p.stdout != "" || !strings.Contains(p.stderr, "cloudfw-scan:") {
				t.Errorf("code=%d stdout=%q stderr=%q", p.code, p.stdout, p.stderr)
			}
		})
	}
}

func TestMain_HelpExit0(t *testing.T) {
	p := runMain(t, offlineEnv(t), "--help")
	if p.code != 0 || p.stdout != "" || !strings.Contains(p.stderr, "Exit codes:") {
		t.Errorf("code=%d stdout=%q stderr=%q", p.code, p.stdout, p.stderr)
	}
}

// With no usable credentials, every provider fails as a provider (auth),
// the report is still written to stdout as valid JSON, and the exit code
// is 2.
func TestMain_NoCredentialsExit2WithReport(t *testing.T) {
	env := offlineEnv(t)
	cases := map[string]struct {
		args []string
		want map[model.Provider]bool // providers expected failed
	}{
		"gcp": {[]string{"--providers", "gcp", "--gcp-projects", "example-project-a"},
			map[model.Provider]bool{model.ProviderGCP: true}},
		"azure": {[]string{"--providers", "azure", "--azure-subscriptions", "00000000-0000-0000-0000-00000000000a"},
			map[model.Provider]bool{model.ProviderAzure: true}},
		"aws": {[]string{"--providers", "aws", "--aws-bootstrap-region", "eu-west-1", "--aws-regions", "eu-west-1"},
			map[model.Provider]bool{model.ProviderAWS: true}},
		"all three": {[]string{"--providers", "aws,gcp,azure", "--aws-bootstrap-region", "eu-west-1",
			"--gcp-projects", "example-project-a", "--azure-subscriptions", "00000000-0000-0000-0000-00000000000a",
			"--timeout", "60s"},
			map[model.Provider]bool{model.ProviderAWS: true, model.ProviderGCP: true, model.ProviderAzure: true}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := runMain(t, env, tc.args...)
			if p.code != 2 {
				t.Fatalf("code=%d stderr=%q", p.code, p.stderr)
			}
			rep := decodeReport(t, p.stdout)
			got := map[model.Provider]model.ProviderStatus{
				model.ProviderAWS: rep.Scan.Providers.AWS, model.ProviderGCP: rep.Scan.Providers.GCP,
				model.ProviderAzure: rep.Scan.Providers.Azure,
			}
			for prov, st := range got {
				want := model.ProviderNotSelected
				if tc.want[prov] {
					want = model.ProviderFailed
				}
				if st != want {
					t.Errorf("%s: status %s, want %s", prov, st, want)
				}
			}
			for _, e := range rep.Errors {
				if e.Kind != model.ErrorKindAuth {
					t.Errorf("error kind %q, want auth: %+v", e.Kind, e)
				}
			}
			if !strings.Contains(p.stderr, "exit=2") {
				t.Errorf("summary missing: %q", p.stderr)
			}
		})
	}
}

func TestMain_OutputFile(t *testing.T) {
	env := offlineEnv(t)
	path := filepath.Join(t.TempDir(), "example-report.json")
	args := []string{"--providers", "gcp", "--gcp-projects", "example-project-a", "--output", path}
	p := runMain(t, env, args...)
	if p.code != 2 || p.stdout != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q", p.code, p.stdout, p.stderr)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decodeReport(t, string(data))
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
			t.Errorf("mode %v, want 0600", info.Mode().Perm())
		}
	}
	// A second run never overwrites it.
	p = runMain(t, env, args...)
	if p.code != 3 || p.stdout != "" || !strings.Contains(p.stderr, "already exists") {
		t.Errorf("second run: code=%d stderr=%q", p.code, p.stderr)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, data) {
		t.Errorf("existing report was modified")
	}
}
