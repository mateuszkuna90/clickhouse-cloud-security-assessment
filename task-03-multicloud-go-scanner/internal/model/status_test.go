package model

import "testing"

func TestScopeStatusFor(t *testing.T) {
	tests := []struct {
		name  string
		diags []Diagnostic
		want  ScopeStatus
	}{
		{"no diagnostics", nil, ScopeComplete},
		{"detail only", []Diagnostic{{Effect: EffectFindingDetailUnknown}}, ScopeComplete},
		{"one blocking", []Diagnostic{{Effect: EffectFindingDetailUnknown}, {Effect: EffectScopeIncomplete}}, ScopeIncomplete},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ScopeStatusFor(tt.diags); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestProviderStatusFor(t *testing.T) {
	s := func(statuses ...ScopeStatus) []ScopeResult {
		var out []ScopeResult
		for _, st := range statuses {
			out = append(out, ScopeResult{Status: st})
		}
		return out
	}
	tests := []struct {
		name   string
		scopes []ScopeResult
		want   ProviderStatus
	}{
		{"zero scopes", nil, ProviderFailed},
		{"all complete", s(ScopeComplete, ScopeComplete), ProviderComplete},
		{"complete plus skipped", s(ScopeComplete, ScopeSkipped), ProviderComplete},
		{"all skipped", s(ScopeSkipped), ProviderComplete},
		{"one failed", s(ScopeComplete, ScopeFailed), ProviderPartial},
		{"one incomplete", s(ScopeComplete, ScopeIncomplete), ProviderPartial},
		{"only scope incomplete", s(ScopeIncomplete), ProviderPartial},
		{"all failed", s(ScopeFailed, ScopeFailed), ProviderFailed},
		{"failed plus skipped", s(ScopeFailed, ScopeSkipped), ProviderFailed},
		{"failed plus incomplete", s(ScopeFailed, ScopeIncomplete), ProviderPartial},
		{"unexpected status is never complete", s(ScopeStatus("bogus")), ProviderPartial},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ProviderStatusFor(tt.scopes); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
