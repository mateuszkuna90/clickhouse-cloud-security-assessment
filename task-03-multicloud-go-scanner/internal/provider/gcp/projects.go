package gcp

import (
	"regexp"
	"slices"
	"strings"
)

// EnvProject is the environment variable used when no project list is given
// (DESIGN.md 5.2).
const EnvProject = "GOOGLE_CLOUD_PROJECT"

// projectPattern accepts:
//
//   - project IDs: 6-30 characters, lower-case letters, digits and hyphens,
//     starting with a letter and not ending with a hyphen;
//   - legacy domain-scoped project IDs, e.g. "example.com:my-project";
//   - project numbers (digits only), which the Compute API also accepts.
//
// The project is placed into the request URL path by the SDK without
// escaping (the SDK itself only rejects "." and ".."), so every value is
// checked here before a request is built. A value such as "p/../x" or
// "p?x=1" never reaches the SDK.
var projectPattern = regexp.MustCompile(
	`^(?:(?:[a-z0-9][a-z0-9.-]{0,61}[a-z0-9]:)?[a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]{1,20})$`)

// ValidProject reports whether s is a syntactically valid project ID or
// project number. Whether the project exists, and whether the identity can
// read it, is found out when it is scanned.
func ValidProject(s string) bool { return projectPattern.MatchString(s) }

// ResolveProjects returns the projects to scan: the explicit list if it is
// non-empty, otherwise the single project in GOOGLE_CLOUD_PROJECT (read with
// getenv), otherwise nil. Explicit entries are not filtered here; invalid
// ones fail as scopes when scanned. getenv is a parameter so that callers
// and tests do not depend on the process environment.
func ResolveProjects(explicit []string, getenv func(string) string) []string {
	if len(explicit) > 0 {
		return slices.Clone(explicit)
	}
	if getenv == nil {
		return nil
	}
	if p := strings.TrimSpace(getenv(EnvProject)); p != "" {
		return []string{p}
	}
	return nil
}

// normalizeProjects trims, de-duplicates and sorts a project list. Empty
// entries are kept as "" so that the scanner reports them as failed scopes
// rather than dropping them.
func normalizeProjects(in []string) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		out = append(out, strings.TrimSpace(p))
	}
	slices.Sort(out)
	return slices.Compact(out)
}
