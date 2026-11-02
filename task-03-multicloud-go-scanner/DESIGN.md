# Task 03: Multi-Cloud Firewall Scanner — Design

> **Status: design, revision 4, for review. No Go code exists yet.**
> Nothing in this document has been built, tested or run against a cloud
> account. Statements about tests describe **planned tests and acceptance
> criteria**, not results. Details marked *(verify)* must be confirmed
> against the SDK or provider documentation during implementation.
> Section 15 maps each review finding to the change made.

## 1. Requirements

### 1.1 From the assessment brief

Section 3, "Automate Security Checks with Go". Write a Go CLI tool that:

- Scans AWS, GCP and Azure firewall / security group rules.
- Detects any rule that allows inbound traffic from `0.0.0.0/0` for any
  protocol and any port.
- Outputs the list of insecure rules in JSON format.

The program should: (1) authenticate with AWS, GCP and Azure; (2) fetch all
firewall / security group rules from each provider; (3) identify rules where
`0.0.0.0/0` is allowed for any protocol/port; (4) output findings as JSON.

| Cloud | Brief says |
|---|---|
| AWS | Use the AWS SDK for Go to list EC2 Security Groups; identify rules allowing inbound from `0.0.0.0/0` |
| GCP | Use the Google Cloud SDK for Go to list Firewall rules; look for `sourceRanges: ["0.0.0.0/0"]` |
| Azure | Use the Azure SDK for Go to list NSGs; look for rules allowing "Any" source (`0.0.0.0/0`) |

The brief's example JSON has top-level `aws.security_groups[]`,
`gcp.firewall_rules[]`, `azure.nsgs[]`, each with `insecure_rules[]` of
`{protocol, port, source}`.

### 1.2 Additional requirements (from the task owner)

1. AWS: EC2 Security Group **ingress** rules via **AWS SDK for Go v2**.
2. GCP: **ingress Allow** firewall rules via the official Compute API client.
3. Azure: NSG **inbound Allow** rules via the official Azure SDK for Go.
4. Detect IPv4 `0.0.0.0/0` exposure for any protocol, port or port range.
5. Deterministic JSON output.
6. Handle pagination, inventory scope, timeouts and partial API failures.
7. Read-only cloud identities.
8. Offline unit tests with mocks; no real cloud calls in tests.
9. Distinguish **configuration findings** from **effective network
   reachability**.
10. Keep v1 simple and aligned with the brief: no severity scoring, no
    suppression framework, no reachability analysis.

### 1.3 Interpretation of "any protocol and any port"

The brief's example output lists `tcp/8080` and `udp/123`, so the check
means *a rule open to `0.0.0.0/0` on whatever protocol or port it allows*,
not only rules that allow all protocols and all ports. Every world-open
inbound allow rule is reported.

**Detection depends only on direction, action and source.** Protocol and
port values describe a finding; they never decide whether it is reported.
An unknown or malformed protocol or port still produces a finding.

## 2. Scope

### 2.1 In scope (v1)

- AWS: Security Groups owned by the caller's account in the selected or
  discovered regions of one partition. Ingress rules with an IPv4 source of
  prefix length 0.
- GCP: VPC firewall rules in the listed projects. Ingress rules with an
  `allowed[]` list and a world IPv4 source.
- Azure: NSGs in the selected or discovered subscriptions. Inbound Allow
  rules with a world source.
- JSON report on stdout (default) or to a new file; exit code for CI.

### 2.2 Coverage boundaries

What one run does and does not see. These are repeated in the README so a
clean result is not over-read.

| Cloud | Covered | Not covered |
|---|---|---|
| AWS | One account (the caller's, from `sts:GetCallerIdentity`); one partition (the bootstrap region's, section 5.3); every region in `--aws-regions`, or every **enabled** region returned by `DescribeRegions`; all SGs the account owns in those regions, in every VPC including the default VPC | Other accounts (including other owners' SGs in a shared VPC); other partitions (`aws-cn`, `aws-us-gov`); regions not opted in; regions blocked by SCPs (reported as failed scopes) |
| GCP | Every project in `--gcp-projects`; all VPC firewall rules in each project | Projects not listed; folders/org discovery; hierarchical and network firewall policies |
| GCP Shared VPC | Firewall rules live in the **host project** that owns the network. List the host project to cover workloads in its service projects. | Scanning only a service project returns that project's own networks' rules (often none), not the host's. v1 does **not** auto-discover the host project (it would need `compute.projects.get`). |
| Azure | Every subscription in `--azure-subscriptions`, or every non-`Deleted` subscription the identity can list in its tenant, including `Disabled`, `Expired`, `Warned` and `PastDue` (section 5.5); all NSGs in all resource groups; custom and default rules | Other tenants; subscriptions the identity cannot see; `Deleted` subscriptions; Azure Firewall / firewall policies |

### 2.3 Out of scope (v1)

| Item | Note |
|---|---|
| IPv6 `::/0` | The brief and task owner specify IPv4. Azure `*` covers both and is reported. |
| Effective reachability | v1 reports configuration findings only (section 7). |
| Contents of AWS managed prefix lists | A prefix list may contain `0.0.0.0/0`; v1 does not expand it. The count of unexpanded prefix-list references is reported per scope. |
| GCP firewall policies, AWS NACLs / Network Firewall, Azure Firewall | Not the rule types the brief names. |
| Severity scoring, suppressions, baselines | Not required by the brief. |
| Multi-account / org discovery | One identity, explicit scopes. |
| Split-range evasion (`0.0.0.0/1` + `128.0.0.0/1`) | Brief asks for `0.0.0.0/0`. |

## 3. Architecture

```
                 ┌───────────────────────────────────────────────┐
  flags/env ───► │ cmd/cloudfw-scan  (parse, validate, wire,     │
                 │                    write report, exit code)   │
                 └───────────────┬───────────────────────────────┘
                                 ▼
                 ┌───────────────────────────────────────────────┐
                 │ internal/runner                               │
                 │  global deadline; providers run concurrently; │
                 │  one provider's failure never stops another   │
                 └──────┬──────────────────┬──────────────────┬──┘
                        ▼                  ▼                  ▼
            provider/aws.Scanner  provider/gcp.Scanner  provider/azure.Scanner
              scope: region         scope: project        scope: subscription
              bounded workers       bounded workers       bounded workers
                        │                  │                  │
          EC2API / STSAPI (iface)  FirewallLister (iface)  NSGLister (iface)
                        │                  │                  │
                  SDK adapter         SDK adapter         SDK adapter
                        └──────► convert to model.Rule ◄──────┘
                                          ▼
                 ┌───────────────────────────────────────────────┐
                 │ internal/exposure (pure)                      │
                 │  source classification, protocol and port     │
                 │  normalisation, diagnostics                   │
                 └───────────────────────┬───────────────────────┘
                                         ▼
                 ┌───────────────────────────────────────────────┐
                 │ internal/report: sort, de-dup, encode JSON    │
                 └───────────────────────────────────────────────┘
```

Principles:

1. **Pure core, thin edges.** Detection is pure functions over plain structs.
   SDK adapters only fetch and translate.
2. **Narrow, read-only interfaces.** Scanners depend on interfaces with only
   `List*`/`Describe*`/`Get*` methods, so scanner code holds no value that
   can mutate cloud resources.
3. **Errors and anomalies are data.** API failures become `errors[]`;
   rules the tool cannot evaluate become `diagnostics[]`. Neither is
   dropped silently, and both lower the scope's status.
4. **Deterministic by construction.** Gather everything, sort with a total
   order, then encode.

### 3.1 Package layout

```
task-03-multicloud-go-scanner/
├── DESIGN.md, README.md
├── go.mod / go.sum                 # pinned; go + toolchain directives
├── cmd/cloudfw-scan/main.go
├── internal/
│   ├── model/      # report types, statuses, diagnostics
│   ├── exposure/   # pure classification + normalisation
│   ├── report/     # sort, de-dup, encode, write
│   ├── runner/     # orchestration, deadlines, concurrency
│   └── provider/{aws,gcp,azure}/   # api.go, adapter.go, convert.go, scanner.go
├── iam/            # *.example.* read-only role/policy definitions
└── testdata/       # golden/ and fixtures/ (fake IDs, example-* names)
```

The CLI uses only the standard library plus the official SDKs (`flag`,
`log/slog`, `encoding/json`, `net/netip`).

### 3.2 Dependencies (pinned at implementation time)

| Purpose | Module |
|---|---|
| AWS | `github.com/aws/aws-sdk-go-v2/config`, `.../service/ec2`, `.../service/sts` |
| GCP | `google.golang.org/api/compute/v1` (REST client), `google.golang.org/api/option`, `google.golang.org/api/googleapi`, `cloud.google.com/go/auth` (ADC, HTTP transport) |
| Azure | `github.com/Azure/azure-sdk-for-go/sdk/azidentity`, `.../sdk/azcore`, `.../sdk/resourcemanager/network/armnetwork/vN` (*verify* latest major), `.../sdk/resourcemanager/resources/armsubscriptions` |

Versions are fixed in `go.mod`/`go.sum`. Go is **not installed** on the
current workstation; installing a current stable toolchain is step one of M1.

## 4. Interfaces

```go
package model

type Scanner interface {
    Provider() Provider            // "aws" | "gcp" | "azure"
    Scan(ctx context.Context) ProviderResult
}
```

`Scan` never returns an error; failures are recorded in the result.

**AWS.** `EC2API` satisfies `ec2.DescribeSecurityGroupsAPIClient`, so the
real SDK paginator runs against fakes in tests.

```go
type EC2API interface {
    DescribeSecurityGroups(ctx context.Context, in *ec2.DescribeSecurityGroupsInput,
        opts ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
    DescribeRegions(ctx context.Context, in *ec2.DescribeRegionsInput,
        opts ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error)
}
type STSAPI interface {
    GetCallerIdentity(ctx context.Context, in *sts.GetCallerIdentityInput,
        opts ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}
type ClientFactory func(region string) EC2API
```

**GCP.** The adapter requests every page itself (5.6) and returns the complete list:

```go
type FirewallLister interface {
    ListFirewalls(ctx context.Context, project string) ([]*compute.Firewall, error) // compute = google.golang.org/api/compute/v1
}
```

**Azure.**

```go
type NSGLister interface {
    ListNSGs(ctx context.Context, subscriptionID string) ([]*armnetwork.SecurityGroup, error)
}
// SubscriptionState holds the raw state string from the API, unchanged.
// The scanner compares it case-insensitively with the known values below.
// Any other value, including an empty one, means "unknown" and the
// subscription is scanned.
type SubscriptionState string

const (
    StateEnabled  SubscriptionState = "Enabled"
    StateWarned   SubscriptionState = "Warned"
    StatePastDue  SubscriptionState = "PastDue"
    StateDisabled SubscriptionState = "Disabled"
    StateExpired  SubscriptionState = "Expired"
    StateDeleted  SubscriptionState = "Deleted"
)

type Subscription struct {
    ID       string
    State    SubscriptionState // "" = no state metadata (unknown)
    HasState bool              // false for --azure-subscriptions entries
}

type SubscriptionLister interface {
    // ListSubscriptions returns every subscription the identity can see,
    // with its state, following the armsubscriptions pager to the end.
    ListSubscriptions(ctx context.Context) ([]Subscription, error)
}
```

The adapter maps `armsubscriptions.Subscription.SubscriptionID` and
`.State` into `Subscription`. A nil state becomes `State: ""` with
`HasState: true` (the API answered but gave no state, so it is unknown).
*(verify which state values the pinned `armsubscriptions` enum defines;
`Expired` may be absent from the SDK enum, which is why the raw string is
kept rather than mapped to an SDK constant.)*

## 5. Operational behaviour

### 5.1 Authentication

Standard SDK credential chains only. The tool never accepts, stores, prints
or logs secrets.

| Cloud | Chain | Preferred in CI |
|---|---|---|
| AWS | `config.LoadDefaultConfig` (env, shared config/SSO, web identity, container/instance role) | OIDC → `AssumeRoleWithWebIdentity` |
| GCP | Application Default Credentials | Workload Identity Federation (no SA keys) |
| Azure | `azidentity.NewDefaultAzureCredential` | Workload identity federation / managed identity |

### 5.2 Startup validation (before any API call)

Exit **3** (no scan) if:

- a flag is invalid or a list flag is given but empty;
- `gcp` is selected and no project comes from `--gcp-projects` or
  `GOOGLE_CLOUD_PROJECT`;
- `aws` is selected and no bootstrap region can be resolved (5.3);
- `--output` names a file that already exists (5.9).

### 5.3 AWS regions, bootstrap region and partition

- **Bootstrap region** = `--aws-bootstrap-region`, else the region from the
  SDK config (`AWS_REGION`, `AWS_DEFAULT_REGION`, profile). If none, exit 3
  with a message naming both options. The SDK has no safe default region,
  and guessing `us-east-1` would silently pick a partition.
- The bootstrap region is used for `sts:GetCallerIdentity` and, when
  `--aws-regions` is not set, for `ec2:DescribeRegions`.
- **Discovery** calls `DescribeRegions` with `AllRegions=false`, so only
  regions enabled for the account are returned.
- **Partition.** `DescribeRegions` returns regions of the bootstrap region's
  partition only, and credentials are partition-specific. v1 scans exactly
  one partition. Covering `aws-cn` or `aws-us-gov` needs a separate run with
  credentials and a bootstrap region in that partition.
- **Explicit list.** With `--aws-regions`, discovery is skipped. Each listed
  region is a scope; a region that is invalid, disabled or blocked by an SCP
  fails as a scope (exit 2), not at startup.
- **Failures.** If `GetCallerIdentity` or `DescribeRegions` fails, the AWS
  provider is `failed` and the error says to check credentials or use
  `--aws-regions`. If discovery returns **zero** regions, the provider is
  `failed` with diagnostic `no_scopes_discovered`.

### 5.4 GCP projects

Scopes are exactly the listed projects. A listed project that does not
exist or is not visible fails as a scope. A project with zero firewall rules
is `complete` with `resources_scanned: 0`; this is legitimate (for example
a Shared VPC service project, section 2.2).

### 5.5 Azure subscriptions

Both paths produce `[]Subscription` records (section 4), and one policy
function decides per record:

```go
func shouldScan(s Subscription) bool {
    return !(s.HasState && strings.EqualFold(string(s.State), string(StateDeleted)))
}
```

**Explicit list.** With `--azure-subscriptions`, each ID becomes
`Subscription{ID: id, HasState: false}`. No state lookup is made, and the
NSG read is always attempted; the tool never assumes a listed subscription
is empty or deleted. An inaccessible subscription fails as a scope.

**Discovery.** Without the flag, `SubscriptionLister.ListSubscriptions`
returns every subscription the identity can see, with its state. A
subscription that is not `Enabled` can still hold resources and answer read
(GET/list) calls, so state never implies "empty" except for `Deleted`:

| State (case-insensitive) | Action | Why |
|---|---|---|
| `Enabled` | scan | normal |
| `Warned`, `PastDue` | scan | fully readable; resources still exist |
| `Disabled`, `Expired` | scan | resources are kept for a retention period and reads are allowed |
| `Deleted` (reported by the API) | skip: listed in `scan.scopes` as `skipped` with its state; no NSG call | reliably identified as gone |
| empty, missing or any other value | scan | an unknown state is never treated as empty or deleted |

`Deleted` is skipped only when the API itself reports it. There is no other
reason to skip a subscription.

Each scope in the report carries `subscription_state`: the raw API value
for discovered subscriptions, `null` for explicit-list entries.

**Failures and completeness.**

- A failed NSG read in any state that is scanned: error recorded, scope
  `failed`, provider `partial` (or `failed` if no scope completed), exit 2.
- A `skipped` (Deleted) subscription does not cause exit 2 by itself.
- Discovery API failure: provider `failed`, exit 2.
- A discovered record with an empty subscription ID: it cannot be scanned,
  so an error is recorded and the provider is `partial`, exit 2.
- Zero discovered subscriptions: provider `failed` with
  `no_scopes_discovered`, exit 2, because it usually means missing RBAC,
  not an empty estate.

**Actual coverage** is therefore: every subscription in the identity's
tenant that the identity has read access to and that is not `Deleted`.
Subscriptions in other tenants, and subscriptions the identity has no role
on, do not appear in discovery and are not covered.

### 5.6 Pagination

| Cloud | Mechanism |
|---|---|
| AWS | `ec2.NewDescribeSecurityGroupsPaginator`, `MaxResults: 1000`, follows `NextToken` |
| GCP | `Firewalls.List(project).MaxResults(500).PageToken(t).Context(ctx).Do()`, one call per page, until `nextPageToken` is empty; a repeated token or more than 1000 pages fails the scope |
| Azure | `NewListAllPager` / subscriptions pager while `More()` (`nextLink`) |

An error on any page **fails the whole scope**; results already read from
that scope are discarded. Keeping a subset would look like coverage that
did not happen. Filtering is client-side so every rule goes through the
same tested code and counts are accurate.

### 5.7 Timeouts, retries, concurrency

| Control | Flag | Default |
|---|---|---|
| Whole run | `--timeout` | `10m` |
| One scope | `--scope-timeout` | `2m` |
| Parallel scopes per provider | `--concurrency` | `8` |
| SDK retries | built in | AWS standard retryer (5 attempts), GCP none (the `compute/v1` REST client does not retry `firewalls.list`; a failed page fails the scope), Azure `policy.RetryOptions` (4 retries) |

Providers run concurrently; scopes run in a bounded worker pool. A failure
does not cancel siblings. When a deadline expires, unfinished scopes are
`failed` with kind `timeout`, and the report is still written.

### 5.8 Statuses and exit codes

| Level | Values |
|---|---|
| Scope | `complete`; `incomplete` (listed, but at least one rule could not be evaluated, section 6.5); `failed` (API error or timeout); `skipped` (only a `Deleted` Azure subscription, section 5.5) |
| Provider | `complete`; `partial` (some scopes not `complete`); `failed` (setup failed, all scopes failed, or zero scopes); `not_selected` |

| Exit | Meaning | Precedence |
|---|---|---|
| 4 | Report could not be written (5.9) | highest |
| 3 | Usage / configuration error at startup; no scan | |
| 2 | Scan not fully evaluated: any selected provider not `complete` | |
| 1 | Fully evaluated, at least one finding | |
| 0 | Fully evaluated, no findings | lowest |

Exit 2 outranks 1 because incomplete coverage is the less safe state for a
CI gate. With exit 2 the report is still written and may contain findings.
A `skipped` (Deleted) Azure subscription does not by itself cause exit 2.
Both `incomplete` and `failed` scopes make the provider `partial` (or
`failed` if no scope completed) and the run exit 2.

### 5.9 Writing the report

- The whole report is encoded to memory first. The tool never streams a
  half-built report.
- **Default: stdout.** Logs and the one-line summary go to stderr.
- `--output PATH`: opened with `O_CREATE|O_EXCL|O_WRONLY`. An existing file
  is never overwritten or truncated (also checked at startup, exit 3; the
  `O_EXCL` open is the authoritative check). On a write, sync or close error
  the partial file is removed and the tool exits 4.
- A write error on stdout (closed pipe, full disk) is logged to stderr and
  the tool exits 4.

**File permissions.** On Unix-like systems the file is created with mode
`0600` (subject to umask, which can only remove bits). **On Windows this
does not apply:** Go maps the mode only to the read-only attribute, and the
file inherits the ACL of its directory. Windows users should write into a
directory whose ACL already restricts access (for example under their user
profile). The README will say so and will not claim equivalent protection.

**Shell redirection.** `cloudfw-scan > report.json` uses the shell's rules:
it overwrites existing files, and on Unix it uses the shell's umask. Windows
PowerShell 5.1 writes UTF-16 with `>`; use `--output` or
`| Out-File -Encoding utf8` instead. `--output` is the recommended way to
create a file.

## 6. Detection logic

### 6.1 Source classification

Every source value is classified into exactly one class:

| Class | Examples | Effect |
|---|---|---|
| `world_ipv4` | `0.0.0.0/0`; any IPv4 prefix with length 0 (`10.0.0.0/0`); Azure `*`, `Any`, `Internet` | finding |
| `not_world` | other IPv4/IPv6 CIDRs or plain addresses, including `::/0` | ignored |
| `selector` | valid provider-specific non-address selector: AWS SG reference, prefix-list ID; GCP source tag, source service account; Azure ASG, Azure service tag other than `Internet` (e.g. `VirtualNetwork`, `AzureLoadBalancer`, `Storage.WestEurope`) | ignored; AWS prefix lists are counted (2.3) |
| `malformed` | empty string, unparseable address, value that is neither an address nor a valid selector for that provider | diagnostic (6.5) |

Addresses are parsed with `net/netip` after trimming whitespace. World match
is `prefix.Addr().Is4() && prefix.Bits() == 0`. A plain address without a
prefix length is a host, so it is `not_world`. Keyword matching for Azure is
case-insensitive. `Internet` is matched with `match_reason:
azure_service_tag_internet` so it can be told apart from a literal
`0.0.0.0/0` (open question, section 14). An Azure service tag is accepted as
`selector` if it matches the documented tag syntax (letters and digits,
optional `.Region` suffix) *(verify against the service tag list)*.

### 6.2 Per-provider rule selection

**AWS** — `SecurityGroup.IpPermissions` (ingress by definition; egress is a
separate list and is not read):

- Sources: each `IpRanges[].CidrIp` (classified as above),
  `PrefixListIds` and `UserIdGroupPairs` (`selector`), `Ipv6Ranges`
  (`not_world`).
- One finding per (permission, world CIDR).

**GCP** — `compute.Firewall` (`google.golang.org/api/compute/v1`):

- `direction` (compared case-sensitively against the API enum values):

  | Value | Handling |
  |---|---|
  | `INGRESS` | evaluated |
  | empty | evaluated as `INGRESS` (the GCP default) |
  | `EGRESS` | valid, out of scope: ignored, no diagnostic, no effect on scope status; counted in `rules_evaluated` |
  | anything else | diagnostic `direction_unrecognised`, scope `incomplete` |
- `allowed[]` non-empty. Rules with only `denied[]` are not allow rules.
  A rule with both empty → diagnostic `action_missing`.
- `disabled: true` → not reported; counted in `disabled_rules_skipped`.
  A disabled rule allows nothing.
- Sources: `sourceRanges` are OR-ed with `sourceTags` and
  `sourceServiceAccounts`, so tags never narrow a world range.
- No source of any kind → treated as world with `match_reason:
  gcp_default_source` (API default for ingress) *(verify whether the API
  returns `0.0.0.0/0` explicitly)*.
- One finding per (allowed entry, port spec, world source).

**Azure** — `Properties.SecurityRules` and `Properties.DefaultSecurityRules`:

- `direction` `Inbound` and `access` `Allow` are evaluated. Valid
  `Outbound` or `Deny` rules are ignored with no diagnostic. Missing or
  unrecognised values → diagnostic, scope `incomplete`.
- Sources: `SourceAddressPrefix`, `SourceAddressPrefixes[]`,
  `SourceApplicationSecurityGroups` (`selector`). No source at all →
  diagnostic `source_missing`.
- Ports: `DestinationPortRange` and `DestinationPortRanges[]`.
- One finding per (rule, port range, world source); duplicates from the
  single and plural fields are merged.

### 6.3 Protocol normalisation

`protocol` is canonical; `provider_protocol` keeps the raw value unchanged.

| Input (any provider, case-insensitive) | `protocol` |
|---|---|
| AWS `-1`, GCP `all`, Azure `*` | `all` |
| `tcp`, `6` | `tcp` |
| `udp`, `17` | `udp` |
| `icmp`, `1` | `icmp` |
| `icmpv6`, `58` | `icmpv6` |
| `esp`, `50` | `esp` |
| `ah`, `51` | `ah` |
| `sctp`, `132` | `sctp` |
| other number 0–255 | the number as a decimal string, e.g. `"47"` |
| other non-empty name (e.g. GCP `ipip`) | lower-cased name |
| empty, or number outside 0–255 | `unknown` + diagnostic (6.5) |

Every case still produces a finding when the source is world.

### 6.4 Ports and ICMP

Port fields and ICMP fields are separate. Fields that do not apply are
`null`.

| `protocol` | `port` | `from_port` / `to_port` | `icmp_type` / `icmp_code` |
|---|---|---|---|
| `tcp`, `udp`, `sctp` | `"22"`, `"8000-8090"`, or `"all"` for 0–65535 / no restriction | ints | `null` |
| `icmp`, `icmpv6` | `"all"` (no port concept; matches the brief's example) | `null` | see below |
| `all` with a port restriction (Azure protocol `*` with destination port `443` or `80-443`) | `"443"`, `"80-443"` | ints | `null` |
| `all` without a port restriction (AWS `-1` always; Azure `*`/`*`; GCP `all`) | `"all"` | `null` | `null` |
| any other protocol | `"all"` | `null` | `null` |
| port value malformed | `"unknown"` + diagnostic | `null` | `null` |

ICMP type and code:

- **AWS** stores ICMP type in `FromPort` and code in `ToPort`; `-1` is a
  wildcard. Type `-1` → `icmp_type: null, icmp_code: null` (all ICMP).
  Type 8, code `-1` → `icmp_type: 8, icmp_code: null` (all codes of echo
  request). Type 3, code 4 → `3` / `4`. These values are never copied into
  `from_port`/`to_port`. For `icmpv6` the range is optional: if both values
  are omitted, all types and codes are allowed (EC2 API reference,
  `IpPermission`). For `icmp` the range is required.
- **AWS protocol `-1` or a number other than tcp/udp/icmp/icmpv6:** AWS
  ignores port fields and allows all ports; `port: "all"`.
- **GCP and Azure** cannot restrict ICMP type/code in these rule types;
  both fields are `null`. Azure port values on non-port protocols are kept
  only in `provider_port`.

`provider_port` keeps the raw port text (`"22"`, `"*"`, `"8000-8090"`,
AWS `"8080-8080"`).

### 6.5 Diagnostics and completeness

A rule the tool cannot evaluate is never skipped silently. It produces a
diagnostic:

```go
type Diagnostic struct {
    Provider, Scope, ResourceID, RuleRef string
    Code   string // see table
    Field  string // e.g. "SourceAddressPrefix"
    Value  string // raw value, truncated to 256 bytes
    Effect string // "scope_incomplete" | "finding_detail_unknown"
}
```

| Code | When | Effect |
|---|---|---|
| `source_malformed` | a source is `malformed` **and** no other source of the rule is world | `scope_incomplete` |
| `source_malformed` | a source is `malformed` but another source of the rule is world (finding already emitted) | `finding_detail_unknown` |
| `source_missing` | Azure rule with no source fields | `scope_incomplete` |
| `direction_unrecognised`, `access_unrecognised`, `action_missing` | cannot tell if the rule is inbound allow | `scope_incomplete` |
| `rule_nil` | nil entry in a rule list | `scope_incomplete` |
| `protocol_unknown` | empty or out-of-range protocol on a world rule | `finding_detail_unknown` |
| `port_malformed` | unparseable port / ICMP values on a world rule | `finding_detail_unknown` |
| `no_scopes_discovered` | discovery returned zero regions / subscriptions | provider `failed` |

Rule: if the tool **cannot decide whether a rule is world-open inbound
allow**, the scope is `incomplete` and the run exits 2. If it **can decide**
(the finding is emitted) but some descriptive field is unknown, the finding
carries `unknown` values, the diagnostic is recorded, and the scope stays
`complete`. Valid selectors (6.1) are never diagnostics.

### 6.6 Finding model and de-duplication

```go
type InsecureRule struct {
    Protocol         string  // canonical, 6.3
    Port             string  // "all" | "22" | "8000-8090" | "unknown"
    FromPort, ToPort *int    // tcp/udp/sctp only
    ICMPType         *int    // icmp/icmpv6 only; nil = any
    ICMPCode         *int    // icmp/icmpv6 only; nil = any
    Source           string  // "0.0.0.0/0" for world CIDRs and Azure */Any; "Internet" for the Azure tag
    ProviderProtocol string  // raw
    ProviderPort     string  // raw
    ProviderSource   string  // raw, e.g. "*", "10.0.0.0/0"
    RuleRef          string  // GCP rule name; Azure rule name; AWS "<proto>:<from>:<to>:<cidr>" (SG rules have no ID in DescribeSecurityGroups)
    MatchReason      string  // ipv4_world_cidr | azure_any_wildcard | azure_service_tag_internet | gcp_default_source
    Description      string  // cloud-side description; untrusted text
    Context          RuleContext
    Reachability     string  // always "not_evaluated" in v1
}
```

Identical findings (same resource, rule ref, protocol, port, ICMP fields and
source) are merged.

## 7. Configuration findings vs effective reachability

Every v1 finding is a **configuration finding**: a rule permits inbound
traffic from `0.0.0.0/0`. That is necessary for internet exposure but not
sufficient, and each finding says so with `"reachability":
"not_evaluated"`. An insecure rule is still worth fixing even when nothing
reaches it today, because the next attachment or public IP makes it live.

Effective reachability would also need:

| Factor | AWS | GCP | Azure |
|---|---|---|---|
| Rule applies to something | SG attached to an ENI | target tags/SAs match a running instance (empty target = all instances in the network) | NSG associated with a subnet or NIC |
| Public path | public/Elastic IP + IGW route, or public load balancer | external IP or external load balancer (Cloud NAT is egress-only) | public IP or public load balancer |
| Not overridden | NACLs | higher-priority deny rule; hierarchical/network firewall policies | higher-priority Deny in the NSG; subnet **and** NIC NSGs must both allow |
| Other controls | AWS Network Firewall, routes | Cloud Armor, routes | Azure Firewall, UDRs |
| A listener | process on the port, host firewall | same | same |

v1 does no reachability analysis. It only copies facts already in the API
response, without extra calls or permissions, into `context`:

| Field | AWS | GCP | Azure |
|---|---|---|---|
| `priority` | `null` | rule priority | rule priority |
| `targets` | `null` | `"all_instances"` or the listed tags/SAs | `null` |
| `attached` | `null` (unknown) | `null` | `true`/`false` from the NSG's `subnets` / `networkInterfaces` |

These are hints for triage, not reachability verdicts.

## 8. Output format

Top-level shape follows the brief (`aws.security_groups`,
`gcp.firewall_rules`, `azure.nsgs`, each with `insecure_rules[]` containing
`protocol`, `port`, `source`). Fields are added; none are removed.

Deliberate deviation: the brief shows AWS `port` as a number (`8080`) and
other ports as strings. Here `port` is **always a string**; integers are in
`from_port`/`to_port`.

Illustrative example, hand-written, not tool output (fake IDs):

```json
{
  "schema_version": "1.0",
  "tool": { "name": "cloudfw-scan", "version": "0.1.0" },
  "scan": {
    "providers": { "aws": "complete", "gcp": "partial", "azure": "not_selected" },
    "scopes": [
      { "provider": "aws", "scope": "111111111111/eu-west-1", "status": "complete",
        "resources_scanned": 2, "rules_evaluated": 5,
        "disabled_rules_skipped": 0, "prefix_list_refs_unexpanded": 0,
        "subscription_state": null },
      { "provider": "gcp", "scope": "example-project-a", "status": "incomplete",
        "resources_scanned": 3, "rules_evaluated": 3,
        "disabled_rules_skipped": 1, "prefix_list_refs_unexpanded": 0,
        "subscription_state": null },
      { "provider": "gcp", "scope": "example-project-b", "status": "failed",
        "resources_scanned": 0, "rules_evaluated": 0,
        "disabled_rules_skipped": 0, "prefix_list_refs_unexpanded": 0,
        "subscription_state": null }
    ],
    "findings": 2
  },
  "aws": {
    "security_groups": [
      {
        "id": "sg-0fake0000000000001", "name": "open-sg",
        "vpc_id": "vpc-0fake000000000001", "account_id": "111111111111",
        "region": "eu-west-1",
        "insecure_rules": [
          {
            "protocol": "tcp", "port": "8080", "from_port": 8080, "to_port": 8080,
            "icmp_type": null, "icmp_code": null,
            "source": "0.0.0.0/0",
            "provider_protocol": "tcp", "provider_port": "8080-8080",
            "provider_source": "0.0.0.0/0",
            "rule_ref": "tcp:8080:8080:0.0.0.0/0",
            "match_reason": "ipv4_world_cidr",
            "description": "",
            "context": { "priority": null, "targets": null, "attached": null },
            "reachability": "not_evaluated"
          },
          {
            "protocol": "icmp", "port": "all", "from_port": null, "to_port": null,
            "icmp_type": 8, "icmp_code": null,
            "source": "0.0.0.0/0",
            "provider_protocol": "icmp", "provider_port": "8:-1",
            "provider_source": "0.0.0.0/0",
            "rule_ref": "icmp:8:-1:0.0.0.0/0",
            "match_reason": "ipv4_world_cidr",
            "description": "ping",
            "context": { "priority": null, "targets": null, "attached": null },
            "reachability": "not_evaluated"
          }
        ]
      }
    ]
  },
  "gcp": { "firewall_rules": [] },
  "azure": { "nsgs": [] },
  "diagnostics": [
    { "provider": "gcp", "scope": "example-project-a",
      "resource_id": "projects/example-project-a/global/firewalls/fake-rule",
      "rule_ref": "fake-rule", "code": "source_malformed",
      "field": "sourceRanges", "value": "not-a-cidr", "effect": "scope_incomplete" }
  ],
  "errors": [
    { "provider": "gcp", "scope": "example-project-b",
      "operation": "compute.firewalls.list", "kind": "permission_denied",
      "message": "googleapi: Error 403: ..." }
  ]
}
```

### 8.1 Determinism rules

- Structs, not maps, so field order is fixed.
- Total-order sorting: scopes by `(provider, scope)`; resources by
  `(account/project/subscription, region, id)`; findings by `(protocol,
  port, from_port, to_port, icmp_type, icmp_code, source, rule_ref)`;
  diagnostics and errors by all their fields in declaration order.
- Empty collections encode as `[]`, never `null`.
- `json.Encoder` with two-space indent, `SetEscapeHTML(false)`, trailing
  newline.
- No timestamps unless `--include-timestamps`.

**Acceptance criterion (not yet tested):** the same fake inventory, fed in
shuffled order with `--concurrency 8`, must produce byte-identical output
across repeated runs.

## 9. Read-only identities

Example definitions ship as `iam/*.example.*` (no credentials).

| Cloud | Minimum permissions | Broader built-in alternative |
|---|---|---|
| AWS | `ec2:DescribeSecurityGroups`, `ec2:DescribeRegions` (not needed with `--aws-regions`); `sts:GetCallerIdentity` needs no grant | `SecurityAudit` / `ViewOnlyAccess` |
| GCP | custom role with `compute.firewalls.list` on each project (host project for Shared VPC) | `roles/compute.networkViewer` *(verify it includes the permission)* |
| Azure | custom role: `Microsoft.Network/networkSecurityGroups/read`, `Microsoft.Resources/subscriptions/read` | `Reader` |

- One dedicated scanner identity per cloud; keyless where possible (AWS OIDC
  role, GCP Workload Identity Federation, Azure federated credential or
  managed identity).
- Bind at the narrowest scope that covers the inventory.
- The read-only interfaces (section 4) are a second, code-level guarantee.

## 10. Security of the scanner itself

| Concern | Control |
|---|---|
| Credential leakage | No secret flags; SDK chains only; nothing credential-related logged; error messages sanitised |
| Untrusted cloud text (names, descriptions, malformed values) | Emitted only through `encoding/json`; diagnostic values truncated to 256 bytes |
| Report confidentiality | stdout by default; `--output` never overwrites; Unix `0600`; Windows relies on directory ACLs (5.9) |
| Supply chain | Official SDKs only; pinned `go.sum`; `go mod verify` and `govulncheck` in validation |
| Resource use | Bounded concurrency, deadlines, SDK retry caps |

## 11. Testing strategy (planned)

All tests are offline. No test builds a default credential chain; `TestMain`
sets `AWS_EC2_METADATA_DISABLED=true` and clears cloud credential
environment variables as a guard.

| Layer | How |
|---|---|
| Classification and normalisation | Table-driven tests; fuzz targets for source parsing and port parsing |
| Provider conversion | Table-driven tests from fake SDK structs to findings and diagnostics |
| Scanners | Hand-written fakes of `EC2API`, `STSAPI`, `FirewallLister`, `NSGLister`, `SubscriptionLister` |
| Pagination | AWS: fake `DescribeSecurityGroups` with `NextToken`, driven by the real SDK paginator. GCP: `httptest.Server` serving fake REST pages via `option.WithEndpoint`/`WithoutAuthentication`/`WithHTTPClient`. Azure: `armnetwork/fake` server or a custom `policy.Transporter` *(verify)* |
| Report | Golden files in `testdata/golden/`, regenerated only with `-update` |
| CLI | `run(args, stdout, stderr, scanners) int` with injected scanners and writers |

Required test cases:

| Area | Cases |
|---|---|
| Numeric protocols | AWS `6`/`17`/`1`/`58`/`50`; GCP `6`, `47`; Azure `Tcp` vs `6`-style input; `300` and empty → `unknown` + diagnostic, finding still emitted; raw value preserved |
| ICMP | AWS type `-1`; type 8 code `-1`; type 3 code 4; icmpv6; GCP and Azure icmp → null type/code; ICMP values never in `from_port`/`to_port` |
| Ports | single port, range, `0-65535` → `all`, GCP empty ports, Azure `*`, multiple Azure ranges, malformed port → `unknown` |
| Sources | `0.0.0.0/0`; `10.0.0.0/0`; `0.0.0.0` (host, not world); `::/0`; Azure `*`/`Any`/`Internet`/`VirtualNetwork`/`Storage.WestEurope`/ASG; GCP tags with world range; GCP no source; AWS SG reference and prefix list (counted) |
| Malformed data | unparseable source alone → scope `incomplete`, exit 2; unparseable source next to a world source → finding + `finding_detail_unknown`, scope `complete`; Azure rule with no source; unknown direction/access; nil rule |
| Rule selection | AWS egress ignored; GCP deny and disabled rules; Azure Deny/Outbound; Azure default rules |
| GCP direction | `INGRESS` world rule → finding; empty direction → evaluated as ingress → finding; **valid `EGRESS` world-open rule → no finding, no diagnostic, scope stays `complete`, exit 0 when nothing else is found**; a project mixing `EGRESS` rules with one `INGRESS` finding → exit 1, not 2; unknown value (e.g. `SIDEWAYS`, lower-case `ingress`) → `direction_unrecognised`, scope `incomplete`, exit 2 |
| Region discovery | bootstrap from flag; from config; neither → exit 3; `DescribeRegions` fails → AWS `failed`, exit 2; returns zero regions → `no_scopes_discovered`; explicit `--aws-regions` skips discovery; one listed region fails, others succeed → `partial` |
| Empty discovery | Azure zero subscriptions → provider `failed`, `no_scopes_discovered`, exit 2 |
| Azure subscription states (discovery, fake `SubscriptionLister` returning `[]Subscription`) | One record per state: `Enabled`, `Warned`, `PastDue`, `Disabled`, `Expired` → fake `NSGLister` asserts `ListNSGs` was called for each and findings are reported; `Deleted` and `deleted` → no `ListNSGs` call, scope `skipped` with `subscription_state` set, exit not raised to 2 by itself; empty state and an unrecognised value (e.g. `Suspended`) → scanned; `Disabled` / `Expired` whose `ListNSGs` returns 403 or 409 → error recorded, scope `failed`, provider `partial`, exit 2; record with empty ID → error, provider `partial`, exit 2; `ListSubscriptions` error → provider `failed`, exit 2 |
| Azure explicit list | `--azure-subscriptions` → `SubscriptionLister` never called; every listed ID scanned with `subscription_state: null`; inaccessible ID → scope `failed`, exit 2 |
| Azure adapter | `armsubscriptions` pager across two pages maps ID and raw state; nil state → `State: ""`, `HasState: true` |
| Pagination failures | error on page 2 discards page 1 and fails the scope (each provider); multi-page success; empty page with token |
| Timeouts | slow scope hits `--scope-timeout`; global deadline still writes the report |
| Partial failures | 403 / throttling / timeout errors classified correctly; one provider fails, others complete |
| Output | stdout write error → exit 4; `--output` to an existing file → exit 3, file unchanged; write failure mid-file → partial file removed, exit 4; exit precedence 4 > 3 > 2 > 1 > 0 |
| Determinism | shuffled input + concurrency → identical bytes; empty lists are `[]` |

Optional live smoke test: `//go:build integration`, only with
`-tags integration` and an explicit env var. Not run in CI and not part of
the assessment results.

### 11.1 Validation commands (planned; none run yet)

```
go mod verify
gofmt -l .                 # must print nothing
go vet ./...
go build ./...
go test -race -count=1 ./...
go test -run=^$ -fuzz=FuzzClassifySource -fuzztime=30s ./internal/exposure
staticcheck ./...
govulncheck ./...
```

### 11.2 Validation results

**None yet.** No code exists. The README will record the real output of
each command above once it has been run, and will say which were not run.

## 12. Assumptions

1. "Any protocol and any port" means world-open on whatever the rule allows
   (section 1.3).
2. "Firewall rules" means AWS Security Groups, GCP VPC firewall rules and
   Azure NSG rules.
3. One identity per cloud, one AWS partition per run, one Azure tenant per
   run.
4. IPv4 world sources only, as in the brief; Azure `*` is reported because
   it includes IPv4.
5. GCP projects are supplied by the user; for Shared VPC that includes the
   host project.
6. The brief's JSON is an example; adding fields and typing `port` as a
   string is acceptable (open question).
7. No real cloud resources are created and no live scan results are claimed.

## 13. Milestones

Each milestone ends with `gofmt`, `go vet` and `go test` passing and an
independent review (AGENTS.md) before the next starts.

| # | Deliverable | Acceptance criteria |
|---|---|---|
| M0 | This design | Review findings resolved; open questions answered |
| M1 | Toolchain; module; `model`, `exposure`, `report` | Classification, protocol, port/ICMP and diagnostic tables of section 11 pass with no SDK imports; golden and determinism tests pass |
| M2 | AWS provider | Bootstrap/region-discovery, pagination and partial-failure cases pass |
| M3 | GCP provider | Direction cases (incl. valid `EGRESS` leaving the scope `complete`), `httptest` pagination and project-failure cases pass |
| M4 | Azure provider | Subscription discovery, subscription-state matrix, pagination and failure cases pass |
| M5 | Runner + CLI | Statuses, exit codes 0–4, timeouts and output-failure cases pass under `-race` |
| M6 | README, `iam/*.example.*`, validation run | Every command in 11.1 run; real output recorded |

## 14. Open questions

1. Is `port` always a string acceptable, given the brief's mixed example?
2. Should the Azure `Internet` service tag be reported as world (current
   design: yes, labelled `azure_service_tag_internet`)?
3. Should `finding_detail_unknown` diagnostics (finding emitted, but
   protocol or port unknown) keep the scope `complete` (current design), or
   should any diagnostic force exit 2?
4. For ICMP, `port` is `"all"` to match the brief's GCP example, with ICMP
   restrictions in `icmp_type`/`icmp_code`. Is that clear enough, or should
   `port` be `null` for non-port protocols?

## 15. Review response (revision 2)

Changes made for the independent architecture review (Codex, decision:
changes required).

| # | Finding | Change | Sections |
|---|---|---|---|
| M1 | Protocol normalisation; detection must not depend on severity | Canonical protocol table incl. numeric 1/6/17/58/50/51/132; raw value kept in `provider_protocol`; unknown/empty protocols still reported; detection depends only on direction, action and source. **Severity removed.** | 1.3, 6.3 |
| M2 | AWS ICMP type/code | Nullable `icmp_type`/`icmp_code`; AWS `-1` wildcard handled; ICMP values never in port fields; `provider_port` keeps raw values | 6.4, 8 |
| M3 | Scan completeness | Source classification separates malformed data from valid selectors; diagnostics model; scope status `incomplete`; exit 2 when any rule cannot be evaluated | 6.1, 6.5, 5.8 |
| M4 | AWS region discovery | Bootstrap region resolution and failure (exit 3); single-partition limit; enabled-regions-only; discovery failure and zero-region handling; tests listed | 5.2, 5.3, 2.2, 11 |
| L1 | Windows output file security | stdout default; `O_EXCL`, never overwrite; partial file removed on error; Windows ACL caveat stated, no `0600` equivalence claimed; shell redirection notes | 5.9, 10 |
| L2 | Test status wording | Determinism "tested" claim rewritten as an acceptance criterion; planned vs actual results split (11.1, 11.2); status banner states nothing has run | header, 8.1, 11 |
| — | Zero discovered scopes | `no_scopes_discovered` → provider `failed`, exit 2; empty scope is `complete` | 5.3–5.5 |
| — | Report-writing errors | Encode in memory, exit 4 on write failure, precedence defined | 5.8, 5.9 |
| — | Coverage boundaries, Shared VPC | Coverage table per cloud; Shared VPC host-project rule | 2.2, 5.4, 9 |
| — | Simplicity | Removed severity, `finding_id` hashes (only needed for suppressions), and the optional reachability milestone | 6.6, 13 |

### Revision 3 (second review: two Medium findings)

| # | Finding | Change | Sections |
|---|---|---|---|
| M5 | GCP `EGRESS` rules were treated as malformed | Direction table: `INGRESS` evaluated; empty → `INGRESS`; `EGRESS` ignored with no diagnostic and no effect on scope status; only unknown values produce `direction_unrecognised` and scope `incomplete`. Azure `Outbound`/`Deny` stated the same way. Tests added confirming valid `EGRESS` rules leave the scope `complete`. | 6.2, 11 |
| M6 | Azure scanned only `Enabled` subscriptions | Discovery scans every non-`Deleted` subscription (`Enabled`, `Warned`, `PastDue`, `Disabled`, `Expired`, unknown); `Deleted` is `skipped` and reported; read failures are recorded and fail the scope (exit 2); `subscription_state` per scope; coverage statement updated; state test matrix added. Open question on subscription states removed. | 2.2, 5.5, 5.8, 8, 11, 14 |

### Revision 4 (third review: one Medium finding)

| # | Finding | Change | Sections |
|---|---|---|---|
| M7 | `SubscriptionLister` returned only `[]string` IDs, so the scanner could not apply the state policy | `ListSubscriptionIDs` replaced by `ListSubscriptions(ctx) ([]Subscription, error)`; `Subscription{ID, State, HasState}` keeps the raw API state; explicit-list entries carry `HasState: false` and are always scanned; one `shouldScan` policy skips only an API-reported `Deleted`; unknown and empty states are scanned; failure and exit-code rules listed; discovery, explicit-list and adapter tests updated | 4, 5.5, 11 |
