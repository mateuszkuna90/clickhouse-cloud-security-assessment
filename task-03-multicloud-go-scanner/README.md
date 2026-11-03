# Task 03 — Multi-cloud Firewall Scanner (`cloudfw-scan`)

A Go command-line tool that reads AWS EC2 Security Groups, GCP VPC firewall
rules and Azure Network Security Groups, finds **inbound rules that allow
traffic from `0.0.0.0/0`** on any protocol or port, and writes the findings
as JSON.

> **Status:** milestones M1–M5 implemented (detection engine, AWS, GCP and
> Azure collectors, CLI). **All testing was done offline**, with fake cloud
> adapters and local fake endpoints. The tool has **never been run against
> a real AWS account, GCP project or Azure subscription**, and no result in
> this README comes from a real cloud. The design is in
> [DESIGN.md](DESIGN.md); section 16 there lists where the code differs
> from it.

## Contents

1. [Requirements from the brief](#1-requirements-from-the-brief)
2. [Architecture](#2-architecture)
3. [Install and build](#3-install-and-build)
4. [Usage](#4-usage)
5. [Authentication](#5-authentication)
6. [Read-only permissions](#6-read-only-permissions)
7. [Detection rules](#7-detection-rules)
8. [JSON output](#8-json-output)
9. [Exit codes and failure handling](#9-exit-codes-and-failure-handling)
10. [Security considerations](#10-security-considerations)
11. [Scope and limitations](#11-scope-and-limitations)
12. [Testing and validation](#12-testing-and-validation)

## 1. Requirements from the brief

Section 3 of the assessment ("Automate Security Checks with Go"): a Go CLI
that authenticates with AWS, GCP and Azure, fetches all firewall / security
group rules, identifies rules where `0.0.0.0/0` is allowed for any
protocol/port, and outputs the insecure rules as JSON (top-level
`aws.security_groups[]`, `gcp.firewall_rules[]`, `azure.nsgs[]`, each with
`insecure_rules[]` of `protocol`, `port`, `source`).

The brief's example lists `tcp/8080` and `udp/123`, so "any protocol and
any port" is read as: **every** world-open inbound allow rule is reported,
whatever protocol or port it allows (DESIGN.md 1.3).

## 2. Architecture

```
cmd/cloudfw-scan/main.go      signals (Ctrl-C/SIGTERM) -> cli.Run -> os.Exit
internal/cli                  flags, validation, scanner factories, report writing, exit code
internal/runner               providers in parallel under one deadline; waits for all
internal/provider/aws         STS + DescribeRegions + DescribeSecurityGroups (SDK for Go v2)
internal/provider/gcp         firewalls.list (google.golang.org/api/compute/v1)
internal/provider/azure       subscriptions list + NSG ListAll (azidentity, armsubscriptions/v2, armnetwork/v12)
internal/exposure             pure detection engine: source, protocol, port classification
internal/report               merge, sort, de-duplicate, encode JSON, exit code 0/1/2
internal/model                report types and statuses
```

- **Read-only by construction.** Each collector depends on a narrow
  interface with list/describe methods only (`aws.EC2API`/`STSAPI`,
  `gcp.FirewallLister`, `azure.SubscriptionLister`/`NSGLister`). The SDK
  adapters behind them call nothing else.
- **Pure core.** SDK types are converted to `exposure.Rule`; one tested
  engine decides every cloud's findings.
- **Errors are data.** API failures become `errors[]`, rules that cannot be
  evaluated become `diagnostics[]`, and both lower the scope and provider
  status. Nothing is skipped silently.
- **Deterministic.** All results are gathered, then sorted with a total
  order before encoding. The same inventory gives byte-identical JSON.

Pinned SDKs (see `go.mod`): `aws-sdk-go-v2` (ec2 v1.343.0, sts v1.51.6,
config v1.33.13), `google.golang.org/api` v0.310.0 with
`cloud.google.com/go/auth` v0.24.2, `azidentity` v1.15.0, `azcore` v1.23.3,
`armnetwork/v12` v12.1.0, `armsubscriptions/v2` v2.0.0.

## 3. Install and build

Requirements: Go 1.27.3 or later (the `go` directive in `go.mod`). No cloud
CLI is needed, though the standard credential chains can use one (section 5).

```sh
cd task-03-multicloud-go-scanner
go build -o cloudfw-scan ./cmd/cloudfw-scan        # Windows: -o cloudfw-scan.exe
./cloudfw-scan -h
```

## 4. Usage

```
cloudfw-scan --providers LIST [options]
```

| Flag | Default | Meaning |
|---|---|---|
| `--providers` | *(required)* | Comma-separated: `aws`, `gcp`, `azure`. Only these clouds are touched. |
| `--aws-regions` | every region enabled for the account | Comma-separated regions. Skips `ec2:DescribeRegions`. |
| `--aws-bootstrap-region` | `AWS_REGION` / `AWS_DEFAULT_REGION` / profile region | Region for STS and region discovery; decides the partition. Never guessed. |
| `--gcp-projects` | `GOOGLE_CLOUD_PROJECT` | Comma-separated project IDs (or numbers). There is no project discovery. |
| `--azure-subscriptions` | every subscription the identity can list, except `Deleted` | Comma-separated subscription IDs (GUIDs). |
| `--output` | stdout | Write the report to this **new** file. An existing path is never overwritten. |
| `--timeout` | `10m` | Deadline for the whole run. |
| `--scope-timeout` | `2m` | Deadline for one region, project or subscription (and for Azure discovery). |
| `--concurrency` | `8` | Scopes scanned in parallel per provider (1–64). |
| `--include-timestamps` | off | Add `started_at` / `finished_at` (otherwise output is byte-stable). |

Arguments are validated before anything is scanned (exit 3 on error): the
provider list, list syntax (no empty entries), region / project ID /
subscription GUID syntax, positive timeouts, concurrency range, and the
output path. A provider flag without its provider (for example
`--gcp-projects` with `--providers aws`) is an error, so a typo cannot
silently drop a scope.

Examples (each was run offline with the real binary and no credentials:
all parse and reach the scan stage, exit 2; no real cloud was scanned):

```sh
# One cloud, explicit scopes. AWS always needs a bootstrap region:
# --aws-bootstrap-region, or AWS_REGION / AWS_DEFAULT_REGION / a profile region.
cloudfw-scan --providers aws --aws-bootstrap-region eu-west-1 --aws-regions eu-west-1,us-east-1
AWS_REGION=eu-west-1 cloudfw-scan --providers aws --aws-regions eu-west-1
cloudfw-scan --providers gcp --gcp-projects example-project-a,example-project-b
cloudfw-scan --providers azure --azure-subscriptions 00000000-0000-0000-0000-000000000000

# Discovery: every enabled AWS region; every visible Azure subscription
cloudfw-scan --providers aws --aws-bootstrap-region eu-west-1
cloudfw-scan --providers azure

# GCP project from the environment
GOOGLE_CLOUD_PROJECT=example-project-a cloudfw-scan --providers gcp

# All three clouds, report to a new file, tighter deadlines
cloudfw-scan --providers aws,gcp,azure \
  --aws-bootstrap-region eu-west-1 \
  --gcp-projects example-project-a \
  --output ./example-report.json --timeout 5m --scope-timeout 1m --concurrency 4

# CI gate
cloudfw-scan --providers aws --aws-bootstrap-region eu-west-1 --aws-regions eu-west-1 > report.json
case $? in 0) echo clean;; 1) echo findings;; 2) echo incomplete;; *) echo error;; esac
```

Stdout carries **only** the JSON report. Usage errors and a one-line
summary go to stderr, for example (actual output of an offline run with no
credentials):

```
cloudfw-scan: aws=failed gcp=failed azure=failed findings=0 diagnostics=0 errors=3 exit=2
```

**Windows PowerShell 5.1:** `>` writes UTF-16. Use `--output`, or
`| Out-File -Encoding utf8`.

## 5. Authentication

Only each SDK's standard credential chain is used. The tool has no
credential flags, and never reads, stores, prints or logs credential
values.

| Cloud | Chain | Recommended for CI |
|---|---|---|
| AWS | `config.LoadDefaultConfig`: environment, shared config / SSO, `credential_process`, web identity, container and instance roles | OIDC → `AssumeRoleWithWebIdentity` |
| GCP | Application Default Credentials: `GOOGLE_APPLICATION_CREDENTIALS`, the gcloud ADC file, or the metadata server. Only the `compute.readonly` OAuth scope is requested | Workload Identity Federation (no key files) |
| Azure | `azidentity.DefaultAzureCredential`: environment service principal, workload identity, managed identity, Azure CLI, Azure Developer CLI (`AZURE_TOKEN_CREDENTIALS` can restrict it) | Workload identity federation or managed identity |

If a chain cannot even be set up (no ADC file, unknown `AWS_PROFILE`,
invalid `AZURE_TOKEN_CREDENTIALS`), that provider is reported as `failed`
(`operation: init`, `kind: auth`) and the other providers still run. Error
messages do not say *why* credentials failed, because the SDKs' own
messages can contain secrets. Use `aws sts get-caller-identity`,
`gcloud auth application-default print-access-token` or
`az account get-access-token` with the same environment to see the SDK's
message.

**AWS `credential_process`.** The SDK's own `credential_process` provider
connects the helper's stderr and stdin to the scanner's, so whatever a
helper prints on stderr would reach the terminal or CI log. When the
selected profile itself has `credential_process`, the scanner rebuilds that
provider with the SDK's supported custom command builder
(`processcreds.NewProviderCommand`): the same command line and shell
(`cmd.exe /C` / `sh -c`) and environment, but stderr and stdin are the null
device (helper stderr is discarded by the OS and never read), and the
helper's whole process tree is killed when the scan is cancelled or the
helper times out (default 1 minute). Consequences:

- A helper that prompts interactively (for example for an MFA code) gets
  end-of-file on stdin and fails; use a non-interactive helper.
- `credential_process` used *inside a chain* (a profile with `role_arn`
  and `credential_process`, or a `source_profile` that uses
  `credential_process`) is **refused**: AWS is reported `failed`
  (`operation: init`, `kind: auth`) and no helper is started, because the
  SDK builds that inner provider itself and it cannot be contained. Use a
  profile with `credential_process` directly, or another credential source.
- All other credential sources are used exactly as the SDK provides them.

## 6. Read-only permissions

| Cloud | Minimum | Broader built-in alternative |
|---|---|---|
| AWS | `ec2:DescribeSecurityGroups`; `ec2:DescribeRegions` only without `--aws-regions`. `sts:GetCallerIdentity` needs no grant | `SecurityAudit` or `ViewOnlyAccess` |
| GCP | `compute.firewalls.list` on each project (for Shared VPC, on the host project) | `roles/compute.networkViewer` *(not verified against a live project)* |
| Azure | `Microsoft.Network/networkSecurityGroups/read`; `Microsoft.Resources/subscriptions/read` for discovery | `Reader` |

Use one dedicated, keyless scanner identity per cloud, bound at the
narrowest scope that covers the inventory. Example IAM definitions
(`iam/*.example.*`) are planned for M6 and not written yet.

## 7. Detection rules

Detection depends only on **direction, action and source**. Protocol and
port describe a finding but never decide whether it is reported; an
unknown protocol or malformed port still gives a finding, with `unknown`
values and a diagnostic.

| | AWS | GCP | Azure |
|---|---|---|---|
| Rules read | `IpPermissions` (ingress); egress not read | `INGRESS` (or empty) rules with `allowed[]`; `EGRESS`, deny-only and disabled rules give no finding | custom **and default** rules with direction `Inbound` and access `Allow`; `Outbound` and `Deny` give no finding |
| World sources | any IPv4 `/0` in `IpRanges` (`0.0.0.0/0`, `10.0.0.0/0`) | any IPv4 `/0` in `sourceRanges` (tags and service accounts never narrow it); no source at all → API default `0.0.0.0/0` (`gcp_default_source`) | `*`, `Any`, IPv4 `/0` (→ `0.0.0.0/0`); the `Internet` service tag is reported **separately** as source `Internet`, `match_reason: azure_service_tag_internet` |
| Not world | other CIDRs, IPv6 (incl. `::/0`), SG references, prefix lists (counted, not expanded) | other CIDRs, IPv6, tags, service accounts | other CIDRs, IPv6, other service tags (`VirtualNetwork`, `AzureLoadBalancer`, `Storage.WestEurope`, …), application security groups |
| Ports | `FromPort`–`ToPort`; ICMP type/code in `icmp_type` / `icmp_code`, never in port fields | each entry of `allowed[].ports` | `DestinationPortRange` + `DestinationPortRanges`; **source ports are ignored**; port restrictions are kept when protocol is `*` |

One finding per (rule, port spec, world source). A rule that cannot be
decided (unknown direction or access, no source, only malformed sources,
missing properties) gives a diagnostic and makes the scope `incomplete`.

Findings are **configuration findings**: `reachability` is always
`not_evaluated`. A higher-priority Deny, an unattached group or the absence
of a public IP can make a finding unreachable today. `context` carries
triage hints from the same API response: `priority` (GCP, Azure),
`targets` (GCP), `attached` (Azure: NSG associated with a subnet or NIC).

## 8. JSON output

Top-level shape follows the brief; fields are added, none removed.
`port` is always a string (`"22"`, `"8000-8090"`, `"all"`, `"unknown"`),
with integers in `from_port` / `to_port`. Empty lists are `[]`, never
`null`.

Excerpt of [testdata/golden/example-cli-combined.json](testdata/golden/example-cli-combined.json),
which is the real output of `cli.Run` in an end-to-end test **over fake
inventories** (fake IDs; not a cloud scan):

```json
{
  "schema_version": "1.0",
  "tool": { "name": "cloudfw-scan", "version": "0.1.0" },
  "scan": {
    "providers": { "aws": "complete", "gcp": "complete", "azure": "complete" },
    "scopes": [
      { "provider": "aws", "scope": "111111111111/eu-west-1", "status": "complete",
        "resources_scanned": 2, "rules_evaluated": 5, "disabled_rules_skipped": 0,
        "prefix_list_refs_unexpanded": 0, "subscription_state": null }
    ],
    "findings": 10
  },
  "aws": {
    "security_groups": [
      { "id": "sg-0fake0000000000002", "name": "open-web", "vpc_id": "vpc-0fake000000000001",
        "account_id": "111111111111", "region": "eu-west-1",
        "insecure_rules": [
          { "protocol": "tcp", "port": "8000-8090", "from_port": 8000, "to_port": 8090,
            "icmp_type": null, "icmp_code": null, "source": "0.0.0.0/0",
            "provider_protocol": "tcp", "provider_port": "8000-8090", "provider_source": "0.0.0.0/0",
            "rule_ref": "tcp:8000:8090:0.0.0.0/0", "match_reason": "ipv4_world_cidr",
            "description": "", "context": { "priority": null, "targets": null, "attached": null },
            "reachability": "not_evaluated" }
        ] }
    ]
  },
  "gcp": { "firewall_rules": [ { "name": "allow-ssh-world", "project": "example-project-a", "direction": "INGRESS", "...": "..." } ] },
  "azure": {
    "nsgs": [
      { "id": "/subscriptions/00000000-0000-0000-0000-00000000000a/resourceGroups/example-rg/providers/Microsoft.Network/networkSecurityGroups/web",
        "name": "web", "subscription_id": "00000000-0000-0000-0000-00000000000a",
        "insecure_rules": [
          { "protocol": "all", "port": "80", "from_port": 80, "to_port": 80,
            "source": "Internet", "provider_protocol": "*", "provider_source": "Internet",
            "rule_ref": "securityRules/http-alt", "match_reason": "azure_service_tag_internet",
            "context": { "priority": 110, "targets": null, "attached": false }, "...": "..." }
        ] }
    ]
  },
  "diagnostics": [],
  "errors": []
}
```

(`"...": "..."` marks fields omitted from this excerpt; the golden file has
them all.)

Key fields:

| Field | Meaning |
|---|---|
| `scan.providers.<cloud>` | `complete`, `partial`, `failed`, or `not_selected` |
| `scan.scopes[]` | one entry per AWS `account/region`, GCP project or Azure subscription: `status` (`complete`, `incomplete`, `failed`, `skipped`), counts, Azure `subscription_state` (raw API value; `null` for explicit `--azure-subscriptions`) |
| `rule_ref` | AWS `proto:from:to:cidr` (SG rules have no ID), GCP rule name, Azure `securityRules/<name>` or `defaultSecurityRules/<name>` |
| `provider_*` | raw protocol, port and source exactly as the API returned them |
| `match_reason` | `ipv4_world_cidr`, `azure_any_wildcard`, `azure_service_tag_internet`, `gcp_default_source` |
| `diagnostics[]` | rules that could not be fully evaluated: `effect` `scope_incomplete` or `finding_detail_unknown` |
| `errors[]` | API and setup failures: `operation` (the permission it needs, or `config` / `init`), `kind` (`auth`, `permission_denied`, `throttled`, `timeout`, `not_found`, `other`), fixed-text `message` |

Example error message (format; built only from allowlisted parts):

```
ec2:DescribeSecurityGroups failed: access denied, or the region is not enabled for the account (page 1) [AWS error code: UnauthorizedOperation]
compute.firewalls.list failed: permission denied, or the Compute Engine API is not enabled for the project (page 1) [HTTP 403] [reason: forbidden]
Microsoft.Network/networkSecurityGroups/read failed: permission denied, or the subscription does not allow this read in its current state (page 1) [HTTP 403] [code: AuthorizationFailed]
```

## 9. Exit codes and failure handling

| Exit | Meaning | Report written? |
|---|---|---|
| 0 | Every selected provider `complete`, no findings | yes |
| 1 | Every selected provider `complete`, at least one finding | yes |
| 2 | A selected provider is `partial` or `failed` (API error, timeout, auth failure, a rule that could not be evaluated, interrupt) | **yes**, with all findings that were read |
| 3 | Invalid arguments or configuration (including no AWS bootstrap region, no GCP project, existing `--output` file) | no; nothing is scanned |
| 4 | The report could not be written (stdout error, file error) | no (a partial file is removed) |

Precedence: **4 > 3 > 2 > 1 > 0**. An incomplete scan never returns 0 or
1, even when it found something. A `skipped` Azure subscription (reported
`Deleted` by the API) does not by itself cause exit 2. `-h` exits 0.

| Situation | Result |
|---|---|
| One region / project / subscription fails (403, 404, throttling, timeout) | that scope `failed`, provider `partial`, others continue; exit 2 |
| Error on any page of a listing | the whole scope fails; pages already read are discarded (no partial coverage presented as complete) |
| Repeated page token (GCP `nextPageToken`, Azure `nextLink`, AWS `NextToken`) | scope fails (no endless loop, no silent stop) |
| GCP or Azure listing needs more than 1000 pages | scope fails. AWS has **no page cap**: a listing that keeps returning new `NextToken`s is stopped by `--scope-timeout` (scope fails, kind `timeout`) |
| AWS `GetCallerIdentity` or `DescribeRegions` fails; Azure discovery fails | provider `failed` |
| Discovery returns zero regions / subscriptions | provider `failed`, diagnostic `no_scopes_discovered` |
| Azure subscription in state `Warned`, `PastDue`, `Disabled`, `Expired`, empty or unknown | scanned; a failed read fails that scope |
| Azure discovery record with a missing or malformed ID (even if `Deleted`) | scope `failed` |
| `--scope-timeout` expires | that scope `failed`, kind `timeout` |
| `--timeout` expires or Ctrl-C / SIGTERM | running scopes fail with `timeout`, unstarted scopes fail without a request; report written; exit 2 |
| One provider fails entirely | the other providers' results are unaffected |

## 10. Security considerations

- **No secrets in output.** SDK error text is never copied into the report
  or logs. AWS `credential_process` errors include the process's stdout;
  Google `googleapi.Error` and Azure `ResponseError` include raw response
  bodies; token endpoint errors include their responses. Each provider's
  credentials are wrapped so their errors become a typed error with fixed
  text, and messages are built only from fixed sentences, operation names,
  page numbers, HTTP status codes and allowlisted codes/reasons. Tests put
  dummy marker strings into every such payload and check the JSON, stdout,
  stderr, the Go loggers and the SDK loggers.
- **Credential helper output contained.** AWS `credential_process`
  helpers run with stderr and stdin on the null device; their stdout (the
  credentials JSON) is read only by the SDK, and the SDK's parse errors
  that quote it are replaced by fixed text (section 5).
- **SDK debug logging off.** `GOOGLE_SDK_GO_LOGGING_LEVEL=debug` and
  `AZURE_SDK_GO_LOGGING=all` would make the SDKs log request/response
  bodies; the GCP adapter installs discard loggers and the Azure adapter
  removes the SDK log listener (process-wide).
- **Read-only, also at runtime.** Azure: a pipeline policy rejects any
  request that is not an HTTPS GET to `management.azure.com`, so a forged
  `nextLink` to another host never receives the bearer token, and the SDK's
  automatic resource-provider registration (a POST) is disabled. GCP: only
  the `compute.readonly` OAuth scope is requested.
- **Input validation.** Region names, project IDs and subscription GUIDs are
  checked before any client or URL is built.
- **Untrusted cloud text** (names, descriptions, malformed values) is
  emitted only through `encoding/json`; diagnostic values are truncated to
  256 bytes.
- **Report file.** `--output` opens with `O_CREATE|O_EXCL|O_WRONLY` (never
  follows or replaces an existing file or symlink); on a write, sync or
  close error the partial file is removed and the exit code is 4. On
  Unix-like systems the mode is `0600`. **On Windows the mode only sets the
  read-only attribute; the file inherits its directory's ACL**, so write it
  into a directory whose ACL already restricts access (for example under
  your user profile). Shell redirection (`> file`) uses the shell's rules
  and overwrites existing files.
- **Resource use.** Bounded concurrency per provider, per-scope and global
  deadlines, SDK retry limits (AWS 5 attempts, Azure 4 retries, GCP none),
  page caps for GCP and Azure (1000 pages; AWS relies on the scope
  deadline). The runner waits for every provider, and every API request
  runs under the caller's context.
- **Credential lifetime.** An AWS `credential_process` helper runs under
  the context of the request that needs it, behind a cache that waits for
  it: cancelling the scan kills the helper's process tree (process group on
  Unix; descendant walk on Windows) and the scan returns only after the
  helper has exited. `WaitDelay` bounds the wait for its output pipe.
  Limitation: the SDK's credential cache, used for the **other** AWS
  sources (SSO, assume-role, web identity, container and instance
  metadata), runs a refresh with cancellation suppressed; after a
  cancellation such an in-flight HTTP token request can finish in the
  background. It starts no process, and the CLI exits right after writing
  the report.
- **Supply chain.** Official SDKs only, pinned in `go.sum`; `go mod verify`
  and `govulncheck` were run (section 12).

## 11. Scope and limitations

- **Configuration findings only;** no effective-reachability analysis
  (NACLs, route tables, public IPs, deny priorities, firewall policies).
- **IPv4 only.** `::/0` is not reported. Azure `*` covers both and is
  reported.
- **AWS:** one account (the caller's) and one partition (the bootstrap
  region's) per run; regions not enabled are not discovered; managed prefix
  lists are counted, not expanded. `credential_process` must be
  non-interactive and directly on the selected profile (section 5). Killing
  the helper's process tree does not reach a descendant that deliberately
  leaves it (Unix `setsid`, or a Windows process started after the last
  snapshot); the helper tree kill was tested on Windows only, and the Unix
  code was compiled and vetted but not run.
- **GCP:** only listed projects (no folder/org discovery); VPC firewall
  rules only (hierarchical and network firewall policies are not read);
  for Shared VPC, list the host project.
- **Azure:** one tenant; public cloud only (sovereign clouds fail the host
  check); Azure Firewall and firewall policies are not read.
- Split-range evasion (`0.0.0.0/1` + `128.0.0.0/1`) is not detected.
- **Never run against a real cloud.** SDK behaviour was checked in the
  pinned SDK sources and through fake HTTP endpoints, not live APIs.
- `-race` has not been run (it needs cgo; this workstation has no C
  compiler).

## 12. Testing and validation

All tests are offline. They use fake implementations of each collector's
SDK interface, a local `httptest` Compute API server (GCP), and an
in-process fake ARM and Entra token endpoint behind the real Azure SDK
pipeline. No test needs or uses cloud credentials; test setup clears
credential environment variables and points credential files at paths that
do not exist.

| Package | What is tested |
|---|---|
| `internal/exposure`, `internal/model`, `internal/report` | classification, protocols, ports/ICMP, statuses, sorting, de-duplication, golden JSON |
| `internal/provider/aws`, `gcp`, `azure` | rule conversion, pagination (multi-page, empty pages, errors on later pages, repeated tokens; GCP/Azure page caps), discovery and subscription states, partial failures, cancellation in flight, credential/payload leak tests with dummy markers |
| `internal/provider/aws` (`credential_process`) | a **real helper executable** (the test binary) started by the SDK through `cmd.exe /C` / `sh -c`, writing dummy access-key / secret / session-token markers to stderr: valid credentials on stdout (request signed with them), non-zero exit, non-JSON stdout. Markers are absent from stdout, stderr, the Go loggers, the result and the JSON report. A precondition test shows the SDK's default builder **does** leak them. A blocking helper, and one that starts a blocking child, are cancelled and timed out twice in a row on one scanner: the scan returns, every helper process has exited, and no new helper starts. `credential_process` inside a role chain fails closed without starting a helper |
| `internal/runner` | concurrency, waiting for all providers, panic → failed provider |
| `internal/cli` | **end-to-end** `cli.Run` over the real collectors with fake SDK adapters: clean scan (0), one finding per cloud (1), combined golden report, ports and ranges, determinism with shuffled inputs, partial AWS/GCP/Azure failures (2, findings kept), auth and credential-setup failures, global/scope timeouts and cancellation, 24 invalid-argument cases (3), missing AWS bootstrap region through the real AWS config loader, output file exists / appears mid-run / partial write / sync failure / stdout failure (3, 4), exit precedence, no secrets in report or stderr; `credential_process` through the **real AWS factory** (`config.LoadDefaultConfig`): helper stderr/stdout markers never reach the report, command stderr or process stderr, and a blocking helper is stopped by `--timeout` (exit 2) |
| `cmd/cloudfw-scan` | the **real `main()`** in a child process with an offline environment (no credentials, refused HTTP proxy): usage errors (3), `--help` (0), every provider failing on missing credentials with a valid JSON report (2), `--output` written then never overwritten |

Commands:

```sh
gofmt -l .
go vet ./...
go build ./...
go mod verify
go test -count=1 ./...
go test -cover ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
go test ./internal/cli -run TestE2E_CombinedFindingsGolden -update   # only after reviewing a diff
```

**Results (run 2026-11-02, Windows 11, Go 1.27.3, after the final review
fixes):**

| Command | Exit | Result |
|---|---|---|
| `gofmt -l .` | 0 | no output |
| `go vet ./...` | 0 | no output; also `GOOS=linux` and `GOOS=darwin` |
| `go build ./...` | 0 | no output |
| `go mod verify` | 0 | `all modules verified`; `go mod tidy -diff` clean |
| `go test -count=1 ./...` | 0 | 9 packages ok |
| `go test -cover ./...` | 0 | 9 packages ok |
| `staticcheck` v0.8.2 `./...` | 0 | no findings, for the native (Windows), `GOOS=linux` and `GOOS=darwin` targets |
| `govulncheck@v1.9.0 ./...` | 0 | no vulnerabilities in called code; 3 advisories in required modules not reached by this code: GO-2026-6866 and GO-2026-6860 (`golang.org/x/net` v0.61.0, fixed in v0.62.0), GO-2026-5932 (`golang.org/x/crypto` v0.58.0, no fix) |

Coverage: `internal/cli` 90.5%, `exposure` 96.2%, `model` 100.0%,
`provider/aws` 94.4%, `provider/azure` 98.3%, `provider/gcp` 98.9%,
`report` 87.5%, `runner` 100.0%. `cmd/cloudfw-scan` shows 0.0% because its
tests run `main()` in a child process, which `-cover` does not measure.

Passing tests and subtests (`go test -v`): cmd 16, cli 62, exposure 183,
model 16, aws 99, azure 127, gcp 123, report 18, runner 4 — 648 in total,
0 failures, 0 skips.

The `credential_process` tests start real helper processes. After a run of
the fixed code no helper process was left on the machine (checked with
`Get-CimInstance Win32_Process`).

Mutation checks (temporary edits, reverted, files compared with `cmp`):

- CLI (M5): removing partial-file removal, dropping `O_EXCL`, skipping the
  startup output check, making `--providers` optional, ignoring a write
  failure, and removing the provider-flag cross-check each made the CLI
  tests fail. Reordering the Azure ID check after the `Deleted` check made
  the M4 regression tests fail.
- `credential_process` (final review): forwarding helper stderr to
  `os.Stderr` in the contained builder, using the SDK's default builder,
  removing the process-tree kill, and using the SDK's `CredentialsCache`
  instead of the cancellable cache each made the new tests fail (the last
  two with "timed out ... waiting for helper processes to exit"). Turning
  containment off made both CLI-level tests fail (markers in process stderr;
  a helper still holding stderr 10s after the run). These mutation runs left
  orphaned helper processes, which were stopped afterwards. Output capture
  in the tests is bounded, so such a regression fails instead of hanging.

On this workstation `go test` sometimes prints
`unlinkat ... *.test.exe: being used by another process` after every
package reports `ok`, and then exits 1. It names a different package each
time, including unchanged ones; it looks like a local file lock (probably
antivirus), not a test failure. The final runs above did not hit it.
