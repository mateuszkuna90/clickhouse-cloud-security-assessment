package aws

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/smithy-go"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
)

type fakeNetTimeout struct{}

func (fakeNetTimeout) Error() string   { return "i/o timeout" }
func (fakeNetTimeout) Timeout() bool   { return true }
func (fakeNetTimeout) Temporary() bool { return true }

var _ net.Error = fakeNetTimeout{}

func TestClassify(t *testing.T) {
	api := func(code string) error {
		return opError("DescribeSecurityGroups", &smithy.GenericAPIError{Code: code})
	}
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"deadline", fmt.Errorf("wrapped: %w", context.DeadlineExceeded), model.ErrorKindTimeout},
		{"canceled", opError("x", context.Canceled), model.ErrorKindTimeout},
		{"sdk request canceled", &awssdk.RequestCanceledError{Err: errors.New("x")}, model.ErrorKindTimeout},
		{"net timeout", opError("x", fakeNetTimeout{}), model.ErrorKindTimeout},
		{"no credentials", opError("x", &v4.SigningError{Err: errors.New("failed to retrieve credentials")}), model.ErrorKindAuth},
		{"credential provider (get identity)", fmt.Errorf("get identity: %w", &credentialsError{}), model.ErrorKindAuth},
		{"credential provider timeout", fmt.Errorf("get identity: %w", &credentialsError{ctxErr: context.DeadlineExceeded}), model.ErrorKindTimeout},
		{"AuthFailure", api("AuthFailure"), model.ErrorKindAuth},
		{"ExpiredToken", api("ExpiredToken"), model.ErrorKindAuth},
		{"InvalidClientTokenId", api("InvalidClientTokenId"), model.ErrorKindAuth},
		{"UnauthorizedOperation", api("UnauthorizedOperation"), model.ErrorKindPermissionDenied},
		{"AccessDenied", api("AccessDenied"), model.ErrorKindPermissionDenied},
		{"OptInRequired", api("OptInRequired"), model.ErrorKindPermissionDenied},
		{"RequestLimitExceeded", api("RequestLimitExceeded"), model.ErrorKindThrottled},
		{"Throttling", api("Throttling"), model.ErrorKindThrottled},
		{"InternalError", api("InternalError"), model.ErrorKindOther},
		{"plain", errors.New("boom"), model.ErrorKindOther},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classify(tc.err); got != tc.want {
				t.Errorf("classify = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestValidRegion(t *testing.T) {
	valid := []string{"eu-west-1", "us-east-1", "ap-southeast-5", "us-gov-west-1", "cn-north-1",
		"cn-northwest-1", "il-central-1", "us-isob-east-1", "eu-isoe-west-1"}
	invalid := []string{"", " ", "eu-west", "EU-WEST-1", "eu_west_1", "eu-west-1 ", "eu-west-1.evil.com",
		"evil.example.com#", "127.0.0.1", "eu-west-1/", "-west-1", "aws-global"}
	for _, r := range valid {
		if !ValidRegion(r) {
			t.Errorf("ValidRegion(%q) = false", r)
		}
	}
	for _, r := range invalid {
		if ValidRegion(r) {
			t.Errorf("ValidRegion(%q) = true", r)
		}
	}
}

// TestLoadConfig checks bootstrap region resolution. LoadDefaultConfig
// only reads the environment and (empty, per TestMain) config files; it
// makes no network call and resolves no credentials.
func TestLoadConfig(t *testing.T) {
	ctx := context.Background()

	t.Run("explicit bootstrap region wins", func(t *testing.T) {
		t.Setenv("AWS_REGION", "us-east-1")
		cfg, err := LoadConfig(ctx, "eu-west-1")
		if err != nil || cfg.Region != "eu-west-1" {
			t.Fatalf("region = %q, err = %v", cfg.Region, err)
		}
		if cfg.RetryMaxAttempts != retryMaxAttempts {
			t.Errorf("RetryMaxAttempts = %d, want %d", cfg.RetryMaxAttempts, retryMaxAttempts)
		}
	})
	t.Run("region from environment", func(t *testing.T) {
		t.Setenv("AWS_REGION", "ap-southeast-2")
		cfg, err := LoadConfig(ctx, "")
		if err != nil || cfg.Region != "ap-southeast-2" {
			t.Fatalf("region = %q, err = %v", cfg.Region, err)
		}
	})
	t.Run("no region anywhere", func(t *testing.T) {
		_, err := LoadConfig(ctx, "")
		if !errors.Is(err, ErrNoBootstrapRegion) {
			t.Fatalf("err = %v, want ErrNoBootstrapRegion", err)
		}
	})
	t.Run("invalid region", func(t *testing.T) {
		if _, err := LoadConfig(ctx, "evil.example.com#"); !errors.Is(err, ErrInvalidBootstrapRegion) {
			t.Fatal("want error for invalid region")
		}
	})
}

func TestNewScannerFromConfig(t *testing.T) {
	cfg := awssdk.Config{Region: "eu-west-1"}
	s := NewScannerFromConfig(cfg, Config{Regions: []string{"us-east-1"}})
	if s.cfg.BootstrapRegion != "eu-west-1" {
		t.Errorf("bootstrap = %q", s.cfg.BootstrapRegion)
	}
	if s.cfg.Concurrency != DefaultConcurrency || s.cfg.ScopeTimeout != DefaultScopeTimeout {
		t.Errorf("defaults not applied: %+v", s.cfg)
	}
	if s.clients("us-east-1") == nil || s.sts == nil {
		t.Error("clients not built")
	}
}
