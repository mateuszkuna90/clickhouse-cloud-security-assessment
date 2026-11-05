package model

// ScopeStatusFor returns the status of a scope whose API reads all
// succeeded. It is incomplete if any diagnostic says a rule could not be
// evaluated; diagnostics that only affect finding details do not count.
func ScopeStatusFor(diags []Diagnostic) ScopeStatus {
	for _, d := range diags {
		if d.Effect == EffectScopeIncomplete {
			return ScopeIncomplete
		}
	}
	return ScopeComplete
}

// ProviderStatusFor summarises the scopes of a provider whose setup
// (credentials, discovery) succeeded. If setup failed, the caller sets
// ProviderFailed directly.
//
//   - no scopes at all: failed (nothing was covered)
//   - every scope complete or skipped: complete
//   - every non-skipped scope failed: failed
//   - otherwise: partial
func ProviderStatusFor(scopes []ScopeResult) ProviderStatus {
	if len(scopes) == 0 {
		return ProviderFailed
	}
	var scanned, failed, notComplete int
	for _, s := range scopes {
		if s.Status == ScopeSkipped {
			continue
		}
		scanned++
		switch s.Status {
		case ScopeComplete:
		case ScopeFailed:
			failed++
			notComplete++
		default: // ScopeIncomplete or an unexpected value: never "complete"
			notComplete++
		}
	}
	switch {
	case notComplete == 0:
		return ProviderComplete
	case failed == scanned:
		return ProviderFailed
	default:
		return ProviderPartial
	}
}
