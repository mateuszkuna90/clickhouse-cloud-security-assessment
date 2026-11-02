package gcp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/api/googleapi"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
)

// Error reporting policy (same principles as the AWS collector, M2)
//
// The text of an SDK error is never copied into the report. Google errors
// can carry sensitive data: googleapi.Error.Error() includes the raw HTTP
// response body, auth.Error carries the raw token endpoint response, and
// external-account (workload identity federation) credential errors can
// include executable or file output. So ScanError.Message is built only
// from:
//
//   - the operation name (a constant of this package),
//   - a fixed sentence per error kind,
//   - a fixed sentence for errors raised by this package (safeError),
//   - a page number (an int),
//   - the HTTP status code of a googleapi.Error (an int),
//   - the googleapi error reason, only if it is in the allowlist below.
//
// err.Error(), googleapi.Error.Message, .Body, .Header, .Details and
// unlisted reasons are never used.

// Operation names written into model.ScanError.Operation. They match the
// IAM permission each call needs.
const (
	OpListFirewalls = "compute.firewalls.list"
	// OpConfig covers local validation that happens before any API call.
	OpConfig = "config"
)

// Reasons are googleapi.ErrorItem.Reason values. Only reasons listed here
// are written into a report; they are also used to refine a 403.
var (
	throttleReasons = map[string]bool{
		"rateLimitExceeded":     true,
		"userRateLimitExceeded": true,
		"quotaExceeded":         true,
		"RATE_LIMIT_EXCEEDED":   true,
	}
	// otherReasons are known, non-sensitive reasons that do not change
	// the kind decided by the HTTP status.
	otherReasons = map[string]bool{
		"forbidden":           true,
		"accessNotConfigured": true,
		"SERVICE_DISABLED":    true,
		"notFound":            true,
		"authError":           true,
		"required":            true,
		"invalid":             true,
		"badRequest":          true,
		"backendError":        true,
		"internalError":       true,
	}
)

// kindText is the fixed description of each error kind.
var kindText = map[string]string{
	model.ErrorKindAuth:             "Google credentials could not be resolved or were rejected",
	model.ErrorKindPermissionDenied: "permission denied, or the Compute Engine API is not enabled for the project",
	model.ErrorKindThrottled:        "request rate-limited or quota exceeded",
	model.ErrorKindTimeout:          "timed out or cancelled",
	model.ErrorKindNotFound:         "project not found or not visible to the identity",
	model.ErrorKindOther:            "unexpected error",
}

// safeError is an error raised by this package. Its text is a constant
// written here, so it may appear in the report.
type safeError string

func (e safeError) Error() string { return string(e) }

// Errors raised by this package. Project IDs and other values are not part
// of the text; the scope already names the project.
const (
	errInvalidProject safeError = "invalid project ID"
	errNoProjects     safeError = "no GCP project selected"
	errNoLister       safeError = "no Compute API client"
	errRepeatedToken  safeError = "nextPageToken repeated; the listing would not end"
	errTooManyPages   safeError = "page limit reached; the listing would not end"
	errNoResponse     safeError = "empty API response"
	errNotStarted     safeError = "project not scanned before the run ended"
)

// pageError records which list page failed.
type pageError struct {
	page int
	err  error
}

func (e *pageError) Error() string { return "page " + strconv.Itoa(e.page) + ": " + e.err.Error() }
func (e *pageError) Unwrap() error { return e.err }

// credentialsError replaces any error from the configured credentials (see
// guardCredentials). It keeps no part of the original error: only whether
// the context ended, so that timeouts stay timeouts.
type credentialsError struct {
	ctxErr error // context.Canceled, context.DeadlineExceeded or nil
}

func (e *credentialsError) Error() string { return "Google credentials could not be resolved" }
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
	var gerr *googleapi.Error
	if errors.As(err, &gerr) {
		switch gerr.Code {
		case http.StatusUnauthorized:
			return model.ErrorKindAuth
		case http.StatusForbidden:
			if hasReason(gerr, throttleReasons) {
				return model.ErrorKindThrottled
			}
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

func hasReason(gerr *googleapi.Error, set map[string]bool) bool {
	for _, item := range gerr.Errors {
		if set[item.Reason] {
			return true
		}
	}
	return false
}

// scanError builds a report error under the policy above.
func scanError(scope, op string, err error) model.ScanError {
	kind := classify(err)
	return model.ScanError{
		Provider:  model.ProviderGCP,
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
	var gerr *googleapi.Error
	if errors.As(err, &gerr) {
		b.WriteString(" [HTTP ")
		b.WriteString(strconv.Itoa(gerr.Code))
		b.WriteString("]")
		if reasons := allowlistedReasons(gerr); reasons != "" {
			b.WriteString(" [reason: ")
			b.WriteString(reasons)
			b.WriteString("]")
		}
	}
	return b.String()
}

// allowlistedReasons returns the known reasons of gerr, sorted and without
// duplicates, comma-separated. Sorting keeps the message (and the JSON
// report) identical whatever order the API lists the reasons in.
func allowlistedReasons(gerr *googleapi.Error) string {
	var out []string
	for _, item := range gerr.Errors {
		r := item.Reason
		if (throttleReasons[r] || otherReasons[r]) && !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	slices.Sort(out)
	return strings.Join(out, ",")
}
