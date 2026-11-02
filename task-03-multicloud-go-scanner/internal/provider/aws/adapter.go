package aws

import (
	"context"
	"errors"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// retryMaxAttempts is the SDK standard retryer limit (DESIGN.md 5.7).
const retryMaxAttempts = 5

// Errors returned by LoadConfig. Their text is fixed here: the SDK's own
// error is dropped because it can quote shared config file contents.
var (
	// ErrNoBootstrapRegion means neither the caller nor the SDK
	// configuration (AWS_REGION, AWS_DEFAULT_REGION, profile) gave a
	// region. The tool does not guess one: a guessed region would silently
	// choose the partition. The CLI turns this into a usage error.
	ErrNoBootstrapRegion = errors.New(
		"no AWS bootstrap region: set --aws-bootstrap-region, or AWS_REGION / a profile region")
	// ErrInvalidBootstrapRegion means the bootstrap region is not a
	// syntactically valid AWS region name.
	ErrInvalidBootstrapRegion = errors.New("invalid AWS bootstrap region")
	// ErrConfigLoad means the SDK configuration could not be loaded.
	ErrConfigLoad = errors.New(
		"AWS configuration could not be loaded: check AWS_PROFILE, AWS_CONFIG_FILE and AWS_SHARED_CREDENTIALS_FILE")
)

// LoadConfig loads the SDK configuration with the standard credential
// chain (environment, shared config and SSO, credential_process, web
// identity, container and instance roles). It never reads, stores or logs
// credential values; credentials are resolved lazily by the SDK when a
// request is signed.
//
// bootstrapRegion overrides the configured region when non-empty. The
// returned config's Region is the bootstrap region.
func LoadConfig(ctx context.Context, bootstrapRegion string) (awssdk.Config, error) {
	opts := []func(*config.LoadOptions) error{
		config.WithRetryMaxAttempts(retryMaxAttempts),
	}
	if bootstrapRegion != "" {
		opts = append(opts, config.WithRegion(bootstrapRegion))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return awssdk.Config{}, ErrConfigLoad
	}
	if cfg.Region == "" {
		return awssdk.Config{}, ErrNoBootstrapRegion
	}
	if !ValidRegion(cfg.Region) {
		return awssdk.Config{}, ErrInvalidBootstrapRegion
	}
	return cfg, nil
}

// NewScannerFromConfig builds a scanner on real SDK clients. The STS client
// uses the bootstrap region (cfg.Region); EC2 clients are created per
// region from the same configuration and credentials.
//
// The configured credential provider is wrapped (wrapCredentials): it is
// still used unchanged, but its errors are replaced by a typed error with
// fixed text, so credential provider output can never reach the report.
func NewScannerFromConfig(cfg awssdk.Config, sc Config) *Scanner {
	cfg.Credentials = wrapCredentials(cfg.Credentials)
	sc.BootstrapRegion = cfg.Region
	stsClient := sts.NewFromConfig(cfg)
	clients := func(region string) EC2API {
		return ec2.NewFromConfig(cfg, func(o *ec2.Options) { o.Region = region })
	}
	return NewScanner(sc, stsClient, clients)
}
