# Task 03 — Multi-cloud Security Scanner in Go

> **Status: in progress.** M1 (model, detection engine, report), M2 (AWS
> Security Group collector) and M3 (GCP firewall collector) are implemented
> with offline tests. The Azure collector and the CLI are not written yet.
> The design is in [DESIGN.md](DESIGN.md); the full README is milestone M6.

## M2 — AWS Security Group collector

Package [internal/provider/aws](internal/provider/aws/). Not wired to a CLI
yet, and never run against a real AWS account.

**What it does**

1. Loads the SDK config with the standard credential chain
   (`config.LoadDefaultConfig`: environment, shared config/SSO, web
   identity, container and instance roles). Credentials are never read,
   stored or logged by this code. SDK retries: standard retryer, 5 attempts.
2. Resolves the **bootstrap region**: the explicit value, else the SDK
   config region (`AWS_REGION`, `AWS_DEFAULT_REGION`, profile). With no
   region it returns `ErrNoBootstrapRegion` instead of guessing.
3. Calls `sts:GetCallerIdentity` in the bootstrap region to get the account.
4. Regions: an explicit list if given (discovery skipped), otherwise
   `ec2:DescribeRegions` with `AllRegions=false`, which returns only the
   regions enabled for the account. Region names are syntax-checked before
   a client is built for them.
5. For each region (bounded worker pool, default 8, per-region timeout
   default 2m): `DescribeSecurityGroups` through the SDK paginator with
   `MaxResults=1000`, following `NextToken` to the last page.
6. Converts each ingress permission (`IpPermissions`) into an
   `exposure.Rule` and evaluates it with the M1 engine. Every world-open
   IPv4 source (`0.0.0.0/0` or any IPv4 `/0`) produces a finding, on any
   protocol or port. Egress rules are not read.

**Failure handling**

| Situation | Result |
|---|---|
| No / invalid bootstrap region, `GetCallerIdentity` fails, `DescribeRegions` fails | provider `failed`, error recorded, no region scanned |
| Discovery returns zero regions | provider `failed`, diagnostic `no_scopes_discovered` |
| Discovery returns a region with no name | error recorded, provider at most `partial` |
| A region fails (AccessDenied, `OptInRequired`, unknown endpoint, timeout) | that scope `failed`, error recorded with a kind (`auth`, `permission_denied`, `throttled`, `timeout`, `other`); other regions continue |
| An error on any page | the whole region fails; pages already read are discarded |
| `NextToken` repeats, or the API returns no output | the region fails (no silent early stop) |
| Run cancelled or deadline reached | started regions fail with `timeout`; regions not yet started fail with `timeout` without an API call |
| A rule cannot be decided (missing/unparseable `CidrIp` with no world source, no source at all) | diagnostic, scope `incomplete` |
| Rule decided but a detail is missing (protocol, ports, ICMP values, `GroupId`) | finding still reported with `unknown` values plus a diagnostic; scope stays `complete` |

**Coverage boundaries**

- **One account:** the caller's. If the API returns a group owned by another
  account (shared VPC), it is reported under that owner's account ID, but
  other accounts are not covered.
- **One partition:** the bootstrap region's. `DescribeRegions` returns only
  regions of that partition, and credentials are partition-specific.
  `aws-cn` and `aws-us-gov` need a separate run with their own credentials
  and bootstrap region. An explicit region from another partition fails as
  a scope.
- **Enabled regions only** when discovering. Regions not opted in are not
  listed by `DescribeRegions` and are not scanned. A region blocked by an
  SCP is listed, fails, and is reported as a failed scope.
- **IPv6 is out of scope in v1.** `Ipv6Ranges` (including `::/0`) never
  produce a finding. A rule open only to `::/0` is not reported.
- **Prefix lists are not expanded.** A managed prefix list may contain
  `0.0.0.0/0`; references are counted in `prefix_list_refs_unexpanded`.
- **Configuration findings only.** Whether a group is attached to anything
  is not checked (`reachability: not_evaluated`).

**Least-privilege permissions:** `ec2:DescribeSecurityGroups`, plus
`ec2:DescribeRegions` when regions are discovered. `sts:GetCallerIdentity`
needs no grant. The code depends only on interfaces with `Describe*`/`Get*`
methods (a test checks this), so it cannot call a mutating API.

**Error messages never contain SDK error text.** SDK errors can carry
secrets: the `credential_process` provider puts the process's raw stdout
into its error, and API error messages can carry encoded authorization
details. So `errors[].message` is built only from fixed parts: the
operation name, a fixed sentence per error kind, a fixed sentence for
errors raised by the scanner itself, the failing page number, the AWS error
code if it is on a known-code allowlist, and the request ID if it matches
`^[A-Za-z0-9-]{8,64}$`. Example:

```
ec2:DescribeSecurityGroups failed: access denied, or the region is not enabled for the account (page 1) [AWS error code: UnauthorizedOperation] [request ID: 11111111-2222-3333-4444-555555555555]
```

The configured credential provider is wrapped. The SDK still uses it
unchanged, but if it fails, its error is replaced by a typed error with
fixed text (only context timeout/cancellation is kept). This removes the
provider's output and lets the scanner classify the failure as `auth`
reliably, without matching error strings. `LoadConfig` errors also have
fixed text. The cost: the report does not say *why* credentials failed; run
`aws sts get-caller-identity` with the same environment to see the SDK's
own message.

**Validation (run 2026-11-02, Windows, Go 1.27.3)**

```
gofmt -l .                     # no output
go vet ./...                   # no output, exit 0
go build ./...                 # no output, exit 0
go mod verify                  # "all modules verified", exit 0
go test -count=1 ./...         # all 4 packages ok, exit 0
go test -count=1 -cover ./...  # all 4 packages ok, exit 0
```

Coverage: `exposure` 96.2%, `model` 100.0%, `provider/aws` 97.1%,
`report` 87.5%. Each compiled test binary was also run directly: exit 0 for
all four packages, 0 failures, 0 skips.

On earlier runs on this workstation, `go test` sometimes exited 1 *after*
every package reported `ok`, because it could not delete a temporary
`*.test.exe` ("being used by another process"). It named a different
package each time, including unchanged M1 packages, so it looks like a
local file lock (probably antivirus), not a test failure. It did not occur
on the final run. `-race` was not run: it needs cgo, and this machine has
no C compiler.

## M3 — GCP VPC firewall collector

Package [internal/provider/gcp](internal/provider/gcp/). Not wired to a CLI
yet, and never run against a real GCP project.

**SDK** (official Google Cloud client libraries, pinned in `go.mod`):
`google.golang.org/api` v0.310.0 (`compute/v1` REST client, `option`,
`googleapi`) and `cloud.google.com/go/auth` v0.24.2 (ADC, HTTP transport).
api v0.310.0 requires an untagged pre-release of `auth`
(`v0.24.1-0.20261001053825-dbc26066f70a`); `auth` is pinned to the tagged
release v0.24.2 instead, which also raised the indirect `otelhttp` from
v0.69.0 to v0.72.0.

The first M3 version used `cloud.google.com/go/compute/apiv1`
(v1.74.1). Its `FirewallsClient.List` builds the HTTP request without the
caller's context (`http.NewRequest`, no `WithContext`), so a deadline could
not stop a list request in flight, and the workaround left an abandoned
goroutine running after a cancelled scan. The independent review rejected
that, and the collector now uses `google.golang.org/api/compute/v1`, whose
`FirewallsListCall.Context(ctx).Do()` sends each request with
`req.WithContext(ctx)` (checked in the v0.310.0 source). The
`cloud.google.com/go/compute` module is no longer a dependency.

**What it does**

1. Credentials: Application Default Credentials only
   (`credentials.DetectDefault`: `GOOGLE_APPLICATION_CREDENTIALS`, the
   gcloud ADC file, or an attached service account via the metadata
   server; workload identity federation through the same file). The only
   OAuth scope requested is `compute.readonly`. Credentials are never read,
   stored or logged by this code.
2. Projects: an explicit list; `ResolveProjects` falls back to
   `GOOGLE_CLOUD_PROJECT`. There is no project discovery. Each project ID is
   checked against a strict pattern before a request is built. (The REST
   client escapes the path segment itself; the check is defence in depth
   and gives a clear `config` error.)
3. For each project (bounded worker pool, default 8, per-project timeout
   default 2m): one `firewalls.list` call per page
   (`Firewalls.List(project).MaxResults(500).PageToken(t).Context(ctx).Do()`),
   following `nextPageToken` until it is empty. Every page is inspected,
   including pages with no items, and page numbers in error messages count
   requests (the second request is page 2 even if page 1 was empty).
4. Each firewall rule is evaluated with the M1 engine:

| Rule | Handling |
|---|---|
| `disabled: true` | skipped, counted in `disabled_rules_skipped` |
| direction `INGRESS`, or empty (GCP default) | evaluated |
| direction `EGRESS` | ignored, no diagnostic, scope stays `complete` |
| any other direction (case-sensitive, e.g. `ingress`) | `direction_unrecognised`, scope `incomplete` |
| only `denied[]` | no finding |
| neither `allowed[]` nor `denied[]` | `action_missing`, scope `incomplete` |
| each `allowed[]` entry | evaluated separately: protocol (name or number) and each port or range in `ports` |

   Sources: `sourceRanges` are OR-ed with `sourceTags` and
   `sourceServiceAccounts`. A world range (`0.0.0.0/0` or any IPv4 `/0`) is
   a finding even when tags are also listed. Tags and service accounts alone
   are valid selectors: no finding, no diagnostic. Only a rule with no
   source of any kind gets the API default source, reported with
   `match_reason: gcp_default_source` and an empty `provider_source`.
   IPv6 ranges (including `::/0`) are out of scope, as for AWS.

**Rule metadata in the report:** project, rule name and numeric ID, network
URL, raw `direction` (new field on `gcp.firewall_rules[]`; empty when the
API omitted it), and per finding: description, raw protocol and port,
`context.priority`, and `context.targets` (`tag:<name>`,
`serviceAccount:<email>`, or `all_instances` when the rule has no targets).
`reachability` is always `not_evaluated`.

**Failure handling**

| Situation | Result |
|---|---|
| No projects, or no client | provider `failed` |
| Invalid project ID | that scope `failed` (`config`), no request sent |
| 403 / API not enabled | scope `failed`, kind `permission_denied` |
| 401, or credentials cannot produce a token | kind `auth` |
| 404 (project missing or not visible) | kind `not_found` |
| 429, or 403 with a rate/quota reason | kind `throttled` |
| Malformed response (bad JSON, wrong field types) | kind `other` |
| Error on any page | the whole project fails; pages already read are discarded |
| `nextPageToken` repeats, or tokens cycle | the project fails (no endless loop) |
| More than 1000 pages (e.g. endless empty pages with new tokens) | the project fails |
| Scope timeout or run cancelled | started projects fail with `timeout`; projects not yet started fail without a request; a cancelled listing is never reported as an empty one |
| One project fails | the others are still scanned; provider `partial` |

No retries: the REST client does not retry `firewalls.list`, so a 5xx on
any page fails the project.

**Cancellation.** `ListFirewalls` is a plain loop in the calling goroutine:
check the context, send one page request with that context, repeat. A
deadline or cancellation aborts the request in flight (the tests check
that the server sees the request cancelled), no further page is requested,
and the error is reported as `timeout`. Nothing is started in the
background: ADC is loaded with `DisableAsyncRefresh`, so token refreshes
also run inside the request. When `ListFirewalls` returns, the client is
idle, and `Close` only drops idle connections.

**Error messages never contain SDK error text.** `googleapi.Error.Error()`
includes the raw response body, and `auth.Error` carries the raw token
endpoint response. `errors[].message` is built only from the operation
name, a fixed sentence per kind, fixed sentences for the scanner's own
errors, the page number, the HTTP status code, and the error reasons that
are on an allowlist (de-duplicated and sorted, so the same error gives the
same bytes whatever order the API lists its reasons in). Example:

```
compute.firewalls.list failed: permission denied, or the Compute Engine API is not enabled for the project (page 1) [HTTP 403] [reason: forbidden]
```

The credentials are wrapped as in M2: token and property errors are
replaced by a typed error with fixed text (only timeout/cancellation is
kept), and the raw credentials JSON is not carried into the wrapper.
`NewClient` errors have fixed text. The SDK's debug loggers are replaced by
discarding ones, because with `GOOGLE_SDK_GO_LOGGING_LEVEL=debug` the SDK
writes full request and response bodies to stderr. The tests run with that
variable set to `debug`; a temporary mutation that removed the discard
logger made the leak tests fail, and so did one that put `err.Error()` into
the message (both mutations were reverted).

**Least-privilege permissions:** `compute.firewalls.list` on each project
(for Shared VPC, the host project). The scanner depends only on a
`FirewallLister` interface with one `List*` method (a test checks this), and
the fake server in the tests fails any request that is not a `GET` of the
list path.

**Deviations from DESIGN.md, for review**

- `gcp.firewall_rules[]` has a new `direction` field. The M1 golden file
  was regenerated; its only change is that one line.
- `context.targets` entries are prefixed (`tag:`, `serviceAccount:`) so tags
  and service accounts cannot be confused.
- `rules_evaluated` counts firewall rules that were evaluated (EGRESS and
  deny rules included, disabled rules not); `resources_scanned` counts all
  rules returned.
- Findings from two world forms of the same rule (e.g. `0.0.0.0/0` and
  `10.0.0.0/0`) have the same de-duplication key and are merged by the
  report (DESIGN.md 6.6); the first `provider_source` in sort order is kept.

**Coverage boundaries:** listed projects only; VPC firewall rules only
(hierarchical and network firewall policies are not read); IPv6 out of
scope; configuration findings only. A `warning` on a list response is not
read. The REST `Firewall` type cannot tell a missing `priority` from
priority 0; the API always returns the field, so it is always reported.

**Regression tests for the M3 review** ([regression_test.go](internal/provider/gcp/regression_test.go),
`TestListPages` in [helpers_test.go](internal/provider/gcp/helpers_test.go)),
all through local `httptest` servers and fake credentials: endless empty
pages with changing tokens (stopped at 1000 requests); a repeated token and
a token cycle; cancellation during an outstanding request (the server
observes the cancellation; after `Close` no further request arrives);
cancellation between pages (no second request, project failed); empty page
1 then 403 on page 2 (reported as page 2); reasons in reversed order
(byte-identical JSON); a project failing on page 2 while two others
complete. The fake server fails a test if a blocked request is not
cancelled by the client within 10s.

Mutation checks (temporary, reverted, `cmp` confirmed the files restored):
removing `.Context(ctx)` from the page request made the four cancellation
tests fail ("blocked request ... was never cancelled by the client");
removing the reason sort made `TestRegression_ReasonOrderDoesNotChangeJSON`
and `TestSafeMessageUsesOnlyAllowlistedParts` fail.

**Validation (re-run 2026-11-02 after the review fixes, Windows, Go 1.27.3)**

```
gofmt -l .                     # no output, exit 0
go vet ./...                   # no output, exit 0
go build ./...                 # no output, exit 0
go mod verify                  # "all modules verified", exit 0
go test -count=1 ./...         # all 5 packages ok, exit 0
go test -count=1 -cover ./...  # all 5 packages ok, exit 0
go test -cover ./...           # all 5 packages ok, exit 0
```

Coverage: `exposure` 96.2%, `model` 100.0%, `provider/aws` 97.1%,
`provider/gcp` 98.9%, `report` 87.5%. Passing tests and subtests
(`go test -v`): exposure 183, model 16, aws 80, gcp 123, report 18; 0
failures, 0 skips. `-race` was not run (no C compiler).

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
