package aws

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/smithy-go"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
)

// Error reporting policy
//
// The text of an SDK error is never copied into the report. SDK errors can
// carry sensitive data: the credential_process provider includes the
// process's raw stdout in its parse error, and API error messages can carry
// encoded authorization details. So ScanError.Message is built only from:
//
//   - the operation name (a constant of this package),
//   - a fixed sentence per error kind,
//   - a fixed sentence for errors raised by this package (safeError),
//   - a page number (an int),
//   - the AWS error code, only if it is in the allowlist below,
//   - the AWS request ID, only if it matches a strict pattern.
//
// err.Error(), smithy.APIError.ErrorMessage() and unlisted error codes are
// never used.

// Operation names written into model.ScanError.Operation.
const (
	OpGetCallerIdentity      = "sts:GetCallerIdentity"
	OpDescribeRegions        = "ec2:DescribeRegions"
	OpDescribeSecurityGroups = "ec2:DescribeSecurityGroups"
	// OpConfig covers local validation that happens before any API call.
	OpConfig = "config"
)

// AWS error codes, grouped by report kind. Codes are compared exactly with
// smithy.APIError.ErrorCode. Only codes listed here (including otherCodes)
// are ever written into a report.
var (
	authCodes = map[string]bool{
		"AuthFailure":                 true,
		"InvalidClientTokenId":        true,
		"UnrecognizedClientException": true,
		"ExpiredToken":                true,
		"ExpiredTokenException":       true,
		"RequestExpired":              true,
		"SignatureDoesNotMatch":       true,
		"IncompleteSignature":         true,
		"MissingAuthenticationToken":  true,
	}
	permissionCodes = map[string]bool{
		"UnauthorizedOperation": true,
		"AccessDenied":          true,
		"AccessDeniedException": true,
		// OptInRequired: the region is not enabled for the account.
		"OptInRequired": true,
	}
	throttleCodes = map[string]bool{
		"Throttling":               true,
		"ThrottlingException":      true,
		"RequestLimitExceeded":     true,
		"TooManyRequestsException": true,
	}
	// otherCodes are known, non-sensitive codes that map to kind "other".
	otherCodes = map[string]bool{
		"InternalError":         true,
		"InternalFailure":       true,
		"ServiceUnavailable":    true,
		"Unavailable":           true,
		"InvalidParameterValue": true,
		"InvalidNextToken":      true,
		"UnknownError":          true,
	}
)

// kindText is the fixed description of each error kind.
var kindText = map[string]string{
	model.ErrorKindAuth:             "AWS credentials could not be resolved or were rejected",
	model.ErrorKindPermissionDenied: "access denied, or the region is not enabled for the account",
	model.ErrorKindThrottled:        "request throttled by AWS",
	model.ErrorKindTimeout:          "timed out or cancelled",
	model.ErrorKindOther:            "unexpected error",
}

// requestIDPattern matches AWS request IDs (UUIDs and similar tokens).
// Anything else is dropped.
var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9-]{8,64}$`)

// safeError is an error raised by this package. Its text is a constant
// written here, so it may appear in the report.
type safeError string

func (e safeError) Error() string { return string(e) }

// Errors raised by this package. Region names and other values are not
// part of the text; the scope already names the region.
const (
	errInvalidBootstrapRegion safeError = "invalid or missing bootstrap region"
	errInvalidRegion          safeError = "invalid region name"
	errNoClient               safeError = "no EC2 client for the region"
	errNoSTSClient            safeError = "no STS client"
	errNoAccount              safeError = "GetCallerIdentity returned no account ID"
	errNoRegionName           safeError = "DescribeRegions returned a region with no name"
	errNoOutput               safeError = "the API returned no output"
	errRepeatedToken          safeError = "NextToken repeated; the listing would not end"
	errNotStarted             safeError = "region not scanned before the run ended"
)

// pageError records which DescribeSecurityGroups page failed.
type pageError struct {
	page int
	err  error
}

func (e *pageError) Error() string { return "page " + strconv.Itoa(e.page) + ": " + e.err.Error() }
func (e *pageError) Unwrap() error { return e.err }

// credentialsError replaces any error from the configured credential
// provider (see wrapCredentials). It keeps no part of the provider's error:
// only whether the context ended, so that timeouts stay timeouts.
type credentialsError struct {
	ctxErr error // context.Canceled, context.DeadlineExceeded or nil
}

func (e *credentialsError) Error() string { return "AWS credentials could not be resolved" }
func (e *credentialsError) Unwrap() error { return e.ctxErr }

// classify maps an error to a report kind using typed errors only; it
// never inspects error text. Errors it cannot place are "other".
func classify(err error) string {
	var canceled *awssdk.RequestCanceledError
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) ||
		errors.As(err, &canceled) {
		// In this tool a context ends only when a scope or run deadline
		// expires or the run is interrupted.
		return model.ErrorKindTimeout
	}
	// Credential resolution failures: our wrapper around the configured
	// provider (the reliable signal), and the signer's own error.
	var credErr *credentialsError
	var signErr *v4.SigningError
	if errors.As(err, &credErr) || errors.As(err, &signErr) {
		return model.ErrorKindAuth
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()
		switch {
		case authCodes[code]:
			return model.ErrorKindAuth
		case permissionCodes[code]:
			return model.ErrorKindPermissionDenied
		case throttleCodes[code]:
			return model.ErrorKindThrottled
		}
		return model.ErrorKindOther
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return model.ErrorKindTimeout
	}
	return model.ErrorKindOther
}

// scanError builds a report error under the policy above.
func scanError(scope, op string, err error) model.ScanError {
	kind := classify(err)
	return model.ScanError{
		Provider:  model.ProviderAWS,
		Scope:     scope,
		Operation: op,
		Kind:      kind,
		Message:   safeMessage(op, kind, err),
	}
}

// safeMessage renders the report message from allowlisted parts only.
func safeMessage(op, kind string, err error) string {
	var b strings.Builder
	b.WriteString(op)
	b.WriteString(" failed: ")
	b.WriteString(kindText[kind])
	var se safeError
	if errors.As(err, &se) {
		b.WriteString("; ")
		b.WriteString(string(se))
	}
	var pe *pageError
	if errors.As(err, &pe) {
		b.WriteString(" (page ")
		b.WriteString(strconv.Itoa(pe.page))
		b.WriteString(")")
	}
	if code := allowlistedCode(err); code != "" {
		b.WriteString(" [AWS error code: ")
		b.WriteString(code)
		b.WriteString("]")
	}
	if id := requestID(err); id != "" {
		b.WriteString(" [request ID: ")
		b.WriteString(id)
		b.WriteString("]")
	}
	return b.String()
}

// allowlistedCode returns the AWS error code if it is a known code, else "".
func allowlistedCode(err error) string {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return ""
	}
	code := apiErr.ErrorCode()
	if authCodes[code] || permissionCodes[code] || throttleCodes[code] || otherCodes[code] {
		return code
	}
	return ""
}

// requestID returns the AWS request ID if present and well-formed, else "".
func requestID(err error) string {
	var re *awshttp.ResponseError
	if !errors.As(err, &re) {
		return ""
	}
	id := re.ServiceRequestID()
	if !requestIDPattern.MatchString(id) {
		return ""
	}
	return id
}

// credentialsGuard wraps the configured credential provider. It delegates
// to it unchanged, so the standard SDK chain is preserved, but replaces any
// error with credentialsError. This gives a typed signal for "credentials
// could not be resolved" (the SDK wraps such failures in untyped errors,
// e.g. "get identity: ..."), and guarantees the provider's error text,
// which can include credential_process output, cannot reach the report or
// a log.
type credentialsGuard struct {
	inner awssdk.CredentialsProvider
}

func (g credentialsGuard) Retrieve(ctx context.Context) (awssdk.Credentials, error) {
	creds, err := g.inner.Retrieve(ctx)
	if err == nil {
		return creds, nil
	}
	ce := &credentialsError{}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		ce.ctxErr = context.DeadlineExceeded
	case errors.Is(err, context.Canceled):
		ce.ctxErr = context.Canceled
	}
	return awssdk.Credentials{}, ce
}

// IsCredentialsProvider keeps aws.IsCredentialsProvider checks (for
// example for anonymous credentials) working through the wrapper.
func (g credentialsGuard) IsCredentialsProvider(target awssdk.CredentialsProvider) bool {
	return awssdk.IsCredentialsProvider(g.inner, target)
}

// ProviderSources forwards the credential source, which the SDK reports in
// its user agent.
func (g credentialsGuard) ProviderSources() []awssdk.CredentialSource {
	if s, ok := g.inner.(awssdk.CredentialProviderSource); ok {
		return s.ProviderSources()
	}
	return nil
}

// wrapCredentials guards p. nil stays nil (no credentials configured; the
// SDK then fails with its own error, which is classified and never
// printed). Wrapping is idempotent.
func wrapCredentials(p awssdk.CredentialsProvider) awssdk.CredentialsProvider {
	if p == nil {
		return nil
	}
	if _, ok := p.(credentialsGuard); ok {
		return p
	}
	return credentialsGuard{inner: p}
}
