package azure

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
)

// Error reporting policy (same principles as the AWS and GCP collectors)
//
// The text of an SDK error is never copied into the report. Azure errors
// can carry sensitive data: azcore.ResponseError.Error() includes the
// request URL and the full response body; azidentity errors include token
// endpoint responses, and Azure CLI / developer CLI credential errors can
// include the tool's output. So ScanError.Message is built only from:
//
//   - the operation name (a constant of this package),
//   - a fixed sentence per error kind,
//   - a fixed sentence for errors raised by this package (safeError),
//   - a page number (an int),
//   - the HTTP status code of an azcore.ResponseError (an int),
//   - the ARM error code, only if it is in the allowlist below.
//
// err.Error(), ResponseError.RawResponse (body, headers, URL) and unlisted
// error codes are never used.

// Operation names written into model.ScanError.Operation. They match the
// Azure RBAC action each call needs.
const (
	OpListSubscriptions = "Microsoft.Resources/subscriptions/read"
	OpListNSGs          = "Microsoft.Network/networkSecurityGroups/read"
	// OpConfig covers local validation that happens before any API call.
	OpConfig = "config"
)

// ARM error codes (azcore.ResponseError.ErrorCode), grouped by the report
// kind they select. Only codes listed here are ever written into a report.
var (
	authCodes = map[string]bool{
		"AuthenticationFailed":             true,
		"InvalidAuthenticationToken":       true,
		"InvalidAuthenticationTokenTenant": true,
		"ExpiredAuthenticationToken":       true,
	}
	permissionCodes = map[string]bool{
		"AuthorizationFailed":       true,
		"LinkedAuthorizationFailed": true,
		// The subscription is disabled or expired and only accepts
		// some reads, or none.
		"ReadOnlyDisabledSubscription": true,
		"SubscriptionNotRegistered":    true,
		"DisallowedOperation":          true,
	}
	throttleCodes = map[string]bool{
		"TooManyRequests":               true,
		"SubscriptionRequestsThrottled": true,
		"TenantRequestsThrottled":       true,
	}
	notFoundCodes = map[string]bool{
		"SubscriptionNotFound":  true,
		"InvalidSubscriptionId": true,
	}
	// otherCodes are known, non-sensitive codes that do not change the
	// kind decided by the HTTP status.
	otherCodes = map[string]bool{
		"MissingSubscriptionRegistration": true,
		"InternalServerError":             true,
		"ServiceUnavailable":              true,
		"GatewayTimeout":                  true,
		"BadRequest":                      true,
		"InvalidApiVersionParameter":      true,
	}
)

// kindText is the fixed description of each error kind.
var kindText = map[string]string{
	model.ErrorKindAuth:             "Azure credentials could not be resolved or were rejected",
	model.ErrorKindPermissionDenied: "permission denied, or the subscription does not allow this read in its current state",
	model.ErrorKindThrottled:        "request throttled by Azure Resource Manager",
	model.ErrorKindTimeout:          "timed out or cancelled",
	model.ErrorKindNotFound:         "subscription not found or not visible to the identity",
	model.ErrorKindOther:            "unexpected error",
}

// safeError is an error raised by this package. Its text is a constant
// written here, so it may appear in the report.
type safeError string

func (e safeError) Error() string { return string(e) }

// Errors raised by this package. Subscription IDs and other values are not
// part of the text; the scope already names the subscription.
const (
	errInvalidSubscriptionID safeError = "invalid subscription ID"
	errNoSubscriptionID      safeError = "the API returned a subscription with no ID"
	errNoNSGLister           safeError = "no Network API client"
	errNoSubscriptionLister  safeError = "no Subscriptions API client"
	errRepeatedNextLink      safeError = "nextLink repeated; the listing would not end"
	errTooManyPages          safeError = "page limit reached; the listing would not end"
	errNotStarted            safeError = "subscription not scanned before the run ended"
	errClientInit            safeError = "Azure SDK client could not be created"
	errNonReadRequest        safeError = "refused a non-GET request (the scanner is read-only)"
	errUnexpectedHost        safeError = "refused a request to a host other than Azure Resource Manager"
)

// pageError records which list page failed.
type pageError struct {
	page int
	err  error
}

func (e *pageError) Error() string { return "page " + strconv.Itoa(e.page) + ": " + e.err.Error() }
func (e *pageError) Unwrap() error { return e.err }

// credentialsError replaces any error from the configured credential (see
// guardCredential). It keeps no part of the original error: only whether
// the context ended, so that timeouts stay timeouts.
type credentialsError struct {
	ctxErr error // context.Canceled, context.DeadlineExceeded or nil
}

func (e *credentialsError) Error() string { return "Azure credentials could not be resolved" }
func (e *credentialsError) Unwrap() error { return e.ctxErr }

// newCredentialsError builds a credentialsError from err, keeping only the
// context state.
func newCredentialsError(err error) *credentialsError {
	ce := &credentialsError{}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		ce.ctxErr = context.DeadlineExceeded
	case errors.Is(err, context.Canceled):
		ce.ctxErr = context.Canceled
	}
	return ce
}

// classify maps an error to a report kind using typed errors only; it never
// inspects error text. Errors it cannot place are "other".
func classify(err error) string {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		// In this tool a context ends only when a scope or run deadline
		// expires or the run is interrupted.
		return model.ErrorKindTimeout
	}
	var credErr *credentialsError
	if errors.As(err, &credErr) {
		return model.ErrorKindAuth
	}
	var rerr *azcore.ResponseError
	if errors.As(err, &rerr) {
		switch code := rerr.ErrorCode; {
		case authCodes[code]:
			return model.ErrorKindAuth
		case throttleCodes[code]:
			return model.ErrorKindThrottled
		case permissionCodes[code]:
			return model.ErrorKindPermissionDenied
		case notFoundCodes[code]:
			return model.ErrorKindNotFound
		}
		switch rerr.StatusCode {
		case http.StatusUnauthorized:
			return model.ErrorKindAuth
		case http.StatusForbidden:
			return model.ErrorKindPermissionDenied
		case http.StatusNotFound:
			return model.ErrorKindNotFound
		case http.StatusTooManyRequests:
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

// knownCode reports whether an ARM error code may appear in a report.
func knownCode(code string) bool {
	return authCodes[code] || permissionCodes[code] || throttleCodes[code] ||
		notFoundCodes[code] || otherCodes[code]
}

// scanError builds a report error under the policy above.
func scanError(scope, op string, err error) model.ScanError {
	kind := classify(err)
	return model.ScanError{
		Provider:  model.ProviderAzure,
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
	var rerr *azcore.ResponseError
	if errors.As(err, &rerr) {
		b.WriteString(" [HTTP ")
		b.WriteString(strconv.Itoa(rerr.StatusCode))
		b.WriteString("]")
		if knownCode(rerr.ErrorCode) {
			b.WriteString(" [code: ")
			b.WriteString(rerr.ErrorCode)
			b.WriteString("]")
		}
	}
	return b.String()
}
