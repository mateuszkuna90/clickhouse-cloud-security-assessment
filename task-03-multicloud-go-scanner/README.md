# Task 03 — Multi-cloud Security Scanner in Go

> **Status: placeholder.** No code has been written yet. The exact checks,
> cloud providers and output format will be copied in from the assessment
> brief.

## Topic

A command-line tool written in Go that inspects cloud resources across more
than one provider (for example GCP, AWS and Azure) and reports security
misconfigurations.

## Expected focus areas

- Read-only access: the scanner needs only list/get permissions, and the
  minimum required roles will be documented for each provider
- Credentials from the standard provider credential chains (environment,
  workload identity, ADC); never hardcoded or logged
- A provider-agnostic design, using interfaces per provider so new checks
  and clouds can be added
- Testability: provider clients behind interfaces, unit tests with fakes, and
  no real cloud calls in tests
- Machine-readable output (for example JSON) and meaningful exit codes

## Planned contents

- Go module (`go.mod`, `go.sum`), CLI entry point, provider packages
- Unit tests and test fixtures (fake data only, in `testdata/`)
- Documentation of the required permissions for each provider

## Validation (planned)

Planned checks, none run yet: `go build ./...`, `go vet ./...`,
`go test ./...`, `staticcheck` and `govulncheck`.
