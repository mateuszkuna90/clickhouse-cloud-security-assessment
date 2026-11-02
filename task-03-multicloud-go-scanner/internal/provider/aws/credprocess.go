package aws

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/processcreds"
)

// credential_process containment
//
// The SDK's default chain runs a profile's credential_process with
// processcreds.NewProvider, whose DefaultNewCommandBuilder connects the
// helper's stderr to os.Stderr and its stdin to os.Stdin (pinned
// credentials v1.20.13, processcreds/provider.go). Whatever the helper
// writes to stderr (error text, debug output, even credentials) would reach
// the terminal or CI log, outside the scanner's error sanitising. The
// config package only exposes processcreds.Options (a timeout), not the
// command builder.
//
// The SDK default cache (aws.CredentialsCache) also runs the provider with
// a context whose cancellation is suppressed and returns to the caller as
// soon as the caller's context ends, so a cancelled scan could return while
// the helper keeps running (up to processcreds.DefaultTimeout). With
// cmd.exe /C (Windows) or a helper that starts children, killing only the
// direct child leaves the real helper running and, because the SDK sets no
// WaitDelay, can keep cmd.Wait blocked on the stdout pipe.
//
// So after LoadDefaultConfig, a profile whose credentials come directly from
// credential_process is rebuilt with the SDK's supported extension point,
// processcreds.NewProviderCommand, and a command builder of ours:
//
//   - stderr and stdin are the null device: helper stderr is discarded by
//     the operating system and never passes through this process;
//   - the command line is run exactly as the SDK runs it (cmd.exe /C or
//     sh -c, the current environment);
//   - on cancellation or the helper timeout the whole process tree is
//     killed (process group on Unix, descendant walk on Windows), and
//     WaitDelay bounds the wait for the stdout pipe;
//   - the provider is cached by cancellableCache, which runs the helper
//     with the caller's own context and waits for it, so no helper outlives
//     the Retrieve call that started it.
//
// credential_process inside an assume-role or source_profile chain cannot be
// rebuilt without re-implementing the SDK's chain, so it fails closed with
// ErrCredentialProcessChain. Every other credential source is unchanged.

// ErrCredentialProcessChain is returned by LoadConfig when credential_process
// is used as the source of another credential provider (role_arn,
// source_profile). Its text is fixed.
var ErrCredentialProcessChain = errors.New(
	"credential_process is only supported directly on the selected AWS profile, not inside a " +
		"role_arn / source_profile chain: its stderr and lifetime could not be contained")

// helperWaitDelay bounds how long cmd.Wait waits for the helper's stdout
// pipe after the helper was killed or exited (exec.Cmd.WaitDelay).
const helperWaitDelay = 2 * time.Second

// credsRefreshMargin refreshes expiring credentials this long before they
// expire, so a request is not signed with credentials about to expire.
const credsRefreshMargin = time.Minute

// containCredentialProcess replaces a direct credential_process provider in
// cfg with a contained one, rejects credential_process inside a chain, and
// leaves every other provider untouched.
func containCredentialProcess(cfg *awssdk.Config) error {
	if cfg.Credentials == nil {
		return nil
	}
	direct := awssdk.IsCredentialsProvider(cfg.Credentials, &processcreds.Provider{})
	var sources []awssdk.CredentialSource
	if s, ok := cfg.Credentials.(awssdk.CredentialProviderSource); ok {
		sources = s.ProviderSources()
	}
	if !direct && !slices.Contains(sources, awssdk.CredentialSourceProcess) {
		return nil
	}
	if !direct {
		return ErrCredentialProcessChain
	}
	sc := sharedConfigOf(cfg.ConfigSources)
	if sc == nil || strings.TrimSpace(sc.CredentialProcess) == "" || sc.Source != nil || sc.RoleARN != "" {
		return ErrCredentialProcessChain
	}
	cfg.Credentials = newContainedProcessProvider(sc.CredentialProcess)
	return nil
}

// sharedConfigOf returns the profile the SDK resolved credentials from: the
// first SharedConfig in the config sources, as the SDK's own
// getAWSConfigSources picks it.
func sharedConfigOf(sources []any) *config.SharedConfig {
	for _, s := range sources {
		switch c := s.(type) {
		case config.SharedConfig:
			return &c
		case *config.SharedConfig:
			return c
		}
	}
	return nil
}

// newContainedProcessProvider runs command as credential_process with the
// contained builder, behind a cache that honours cancellation.
func newContainedProcessProvider(command string) awssdk.CredentialsProvider {
	p := processcreds.NewProviderCommand(containedCommand{command: command},
		func(o *processcreds.Options) {
			o.CredentialSources = []awssdk.CredentialSource{
				awssdk.CredentialSourceProfileProcess, awssdk.CredentialSourceProcess,
			}
		})
	return newCancellableCache(p)
}

// containedCommand builds the credential_process command. It implements
// processcreds.NewCommandBuilder.
type containedCommand struct {
	command string
}

func (b containedCommand) NewCommand(ctx context.Context) (*exec.Cmd, error) {
	if strings.TrimSpace(b.command) == "" {
		return nil, errEmptyCredentialProcess
	}
	// The same shell invocation as processcreds.DefaultNewCommandBuilder.
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd.exe", "/C", b.command)
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", b.command)
	}
	cmd.Env = os.Environ()
	// nil stdin and stderr are connected to the null device (os/exec):
	// helper stderr is discarded; an interactive prompt reads end-of-file.
	cmd.Stdin = nil
	cmd.Stderr = nil
	cmd.WaitDelay = helperWaitDelay
	containProcessTree(cmd)
	return cmd, nil
}

// cancellableCache caches credentials like aws.CredentialsCache, but runs
// the provider with the caller's context and waits for it: when the caller
// is cancelled, the provider (and its helper process) is cancelled too, and
// Retrieve returns only after it has stopped. One retrieval runs at a time;
// callers waiting for it give up when their own context ends.
type cancellableCache struct {
	inner awssdk.CredentialsProvider
	sem   chan struct{} // one slot: held during a retrieval
	creds awssdk.Credentials
	have  bool // creds is valid; guarded by sem
	now   func() time.Time
}

func newCancellableCache(inner awssdk.CredentialsProvider) *cancellableCache {
	return &cancellableCache{inner: inner, sem: make(chan struct{}, 1), now: time.Now}
}

func (c *cancellableCache) Retrieve(ctx context.Context) (awssdk.Credentials, error) {
	select {
	case c.sem <- struct{}{}:
	case <-ctx.Done():
		return awssdk.Credentials{}, ctx.Err()
	}
	defer func() { <-c.sem }()
	if c.have && c.fresh(c.creds) {
		return c.creds, nil
	}
	if err := ctx.Err(); err != nil {
		return awssdk.Credentials{}, err
	}
	creds, err := c.inner.Retrieve(ctx)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return awssdk.Credentials{}, ctxErr
		}
		return awssdk.Credentials{}, err
	}
	c.creds, c.have = creds, true
	return creds, nil
}

func (c *cancellableCache) fresh(cr awssdk.Credentials) bool {
	if !cr.HasKeys() {
		return false
	}
	return !cr.CanExpire || c.now().Add(credsRefreshMargin).Before(cr.Expires)
}

// ProviderSources forwards the inner provider's sources (SDK user agent).
func (c *cancellableCache) ProviderSources() []awssdk.CredentialSource {
	if s, ok := c.inner.(awssdk.CredentialProviderSource); ok {
		return s.ProviderSources()
	}
	return nil
}

// IsCredentialsProvider keeps aws.IsCredentialsProvider checks working.
func (c *cancellableCache) IsCredentialsProvider(target awssdk.CredentialsProvider) bool {
	return awssdk.IsCredentialsProvider(c.inner, target)
}
