# Task 02: Cloud Security Check (CloudFormation + Dockerfile)

Security review and remediation of the CloudFormation template and Dockerfile
given in the assessment brief, plus a prevention strategy for both.

> **Scope of evidence.** Nothing in this task was deployed to AWS or built
> with Docker. The template was validated with **cfn-lint** and **checkov**,
> and the Dockerfile with **checkov** and offline tests. Exact commands and
> results are in [Validation](#validation), which also lists what was not run.

## Contents

| Path | Purpose |
|---|---|
| [fixtures/](fixtures/README.md) | **Intentionally insecure** verbatim copies of the brief's inputs: `example-insecure-cloudformation.yaml` and `example-insecure.Dockerfile`. Never deploy, build or copy them. Used as the "before" state and as negative test inputs. |
| [ci/checkov-secrets.baseline.json](ci/checkov-secrets.baseline.json) | The only secret-scanning exception: the SHA-1 of one exact fake value from the brief |
| [cloudformation/secure-bucket.yaml](cloudformation/secure-bucket.yaml) | Remediated CloudFormation template |
| [docker/Dockerfile](docker/Dockerfile) | Hardened Dockerfile |
| [docker/Dockerfile.dockerignore](docker/Dockerfile.dockerignore) | Build-context exclusions for the hardened Dockerfile |
| [.gitignore](.gitignore) | Task-local rule that keeps runtime secret files (`*.env`) out of Git |
| [ci/security-checks.example.yml](ci/security-checks.example.yml) | Example CI gate (GitHub Actions). **Not active.** |
| [guardrails/scp-baseline.example.json](guardrails/scp-baseline.example.json) | Example Service Control Policy |
| [tests/](tests/) | Offline structural tests (Terraform `yamldecode` assertions, shell assertions) |

Answers to the brief's questions:

| Brief question | Section |
|---|---|
| Identify at least three security issues with the CloudFormation template | [A.1](#a1-findings) |
| Write an improved template following AWS best practices | [A.2](#a2-remediated-template) |
| How to find and fix this misconfiguration if the user already exists | [A.3](#a3-finding-and-fixing-this-in-an-existing-aws-environment) |
| What are the issues with the Dockerfile? | [B.1](#b1-findings) |
| How to address them with security best practices | [B.2](#b2-hardened-dockerfile), [B.3](#b3-runtime-configuration-and-secrets) |
| How to prevent these misconfigurations for both files | [C](#c-prevention-for-both-files) |

### How findings are classified

Each finding is either:

- a **Vulnerability**: the file as written is exploitable, or exposes data or credentials; or
- **Hardening**: as written it is not directly exploitable (often because an AWS or Docker default already covers it), but making the control explicit or stronger reduces risk.

Severity assumes a production AWS account:

| Severity | Meaning |
|---|---|
| Critical | Directly leads to account or system compromise, or exposes credentials. |
| High | Likely compromise when combined with one other common failure. |
| Medium | Realistic impact, but needs specific conditions to exploit. |
| Low | Hygiene or defence in depth; limited direct impact. |
| Info | Not a security issue on its own. |

---

## Part A: CloudFormation template

### A.1 Findings

| ID | Type | Severity | Issue | Impact |
|---|---|---|---|---|
| CF-1 | Vulnerability | **Critical** | `MyIAMUser` has an inline policy with `Action: "*"` on `Resource: "*"`, which is full administrator access. | Whoever holds this identity can do anything: read or delete all data, create users and keys for persistence, disable CloudTrail and GuardDuty, delete backups. The access is not limited to `MyBucket` in any way. |
| CF-2 | Vulnerability | **High** | An **IAM user** is used as the identity. IAM users authenticate with long-term access keys or passwords, and no MFA requirement is defined. | Long-term keys do not expire and leak through code, CI logs, laptops and backups. Combined with CF-1, one leaked key means a full account takeover. |
| CF-7 | Vulnerability | Medium | No bucket policy requires TLS. | Plain-HTTP requests are accepted, so data and request metadata can be exposed in transit to anyone who can see the network path. |
| CF-5 | Hardening | Medium | No explicit S3 Block Public Access. | AWS enables it by default for new buckets (since April 2023), so the bucket is not public as written. But anyone with `s3:PutBucketPublicAccessBlock`, including CF-1's user, can turn it off, and the template gives no signal when that happens. |
| CF-8 | Hardening | Medium | No versioning. | Overwrites and deletions, accidental or malicious (ransomware), cannot be recovered. |
| CF-3 | Hardening | Low | Permissions are an inline policy attached directly to a user. | Harder to review and reuse. The real risk is the policy's content (CF-1). |
| CF-4 | Hardening | Low | Hardcoded `UserName`. | Requires `CAPABILITY_NAMED_IAM` and blocks a second deployment in the same account. The name advertises a high-value target. |
| CF-6 | Hardening | Low | No explicit encryption configuration. | New objects already get SSE-S3 by default (since January 2023). A customer managed KMS key adds a second permission check (`kms:Decrypt`) on reads. |
| CF-9 | Hardening | Low | No access logging. | No object-level access record for investigations. |
| CF-10 | Hardening | Low | No `DeletionPolicy` / `UpdateReplacePolicy` and no lifecycle rules. | A stack deletion can remove an empty bucket and free its name for others to claim. Storage grows without limit. |
| CF-11 | Hardening | Low | `PolicyDocument` has no `Version`. | It defaults to the legacy `2008-10-17` policy language, which lacks newer features such as policy variables. |
| CF-12 | Hardening | Low | ACLs are not explicitly disabled. | `BucketOwnerEnforced` is the default for new buckets; making it explicit prevents ACL grants that bypass bucket policy review. |

The brief asks for at least three. The vulnerabilities are **CF-1, CF-2 and CF-7**.

### A.2 Remediated template

[cloudformation/secure-bucket.yaml](cloudformation/secure-bucket.yaml): cfn-lint clean; checkov 31 passed, 0 failed, 1 justified skip (see [Validation](#validation)).

**Assumption.** The original template does not say what the IAM user is for.
Because it sits next to a bucket, I assume it is **a workload that reads and
writes that bucket**. The AWS service that runs it (ECS, Lambda or EC2) is a
parameter. If the identity is a human, use IAM Identity Center with MFA
instead. If it is a system outside AWS, use OIDC federation or IAM Roles
Anywhere instead of access keys.

| Change | Kind | Addresses |
|---|---|---|
| IAM user replaced by an **IAM role** with short-lived credentials. An instance profile is created only for EC2. | Fix | CF-2 |
| `*:*` replaced by a customer managed policy: `s3:ListBucket` on the bucket, `s3:GetObject` and `s3:PutObject` on its objects, `kms:Decrypt` and `kms:GenerateDataKey` on its key only through S3 (`kms:ViaService`). No `s3:DeleteObject`. | Fix | CF-1, CF-3 |
| Bucket policy denies requests without TLS (`aws:SecureTransport = false`). | Fix | CF-7 |
| **ECS trust policy** limited to ECS resources in this account and region (`aws:SourceAccount`, `aws:SourceArn`), so ECS cannot be made to assume the role on behalf of another account (confused deputy). Not applied for Lambda and EC2; for those, restrict who can attach the role with `iam:PassRole`. | Hardening | CF-2 |
| Explicit public access block (all four settings) and `BucketOwnerEnforced` (ACLs disabled). | Hardening | CF-5, CF-12 |
| Versioning, expiry of noncurrent versions (default 90 days) and clean-up of incomplete multipart uploads. | Hardening | CF-8, CF-10 |
| SSE-KMS with a customer managed key (rotation on) and S3 Bucket Keys. | Hardening | CF-6 |
| Bucket policy also denies TLS older than 1.2, and uploads that explicitly ask for a non-KMS algorithm. | Hardening (optional) | CF-6, CF-7 |
| Server access logs go to a separate log bucket. That bucket is private, versioned and TLS-only, and accepts log delivery only from this bucket in this account. | Hardening | CF-9 |
| `Retain` on both buckets, **both bucket policies** and the key. A retained bucket keeps its TLS-only and log-delivery restrictions after stack deletion. | Hardening | CF-10 |
| No hardcoded names; `Version: "2012-10-17"` on every policy. | Hardening | CF-4, CF-11 |

**S3 Bucket Keys and auditing.** With Bucket Keys, S3 asks KMS for a
bucket-level key and derives per-object keys itself. This greatly reduces KMS
requests and cost, but it changes what KMS CloudTrail events show:

- They are generated per bucket key, not per object request, and their
  encryption context is the bucket ARN, not the object ARN.
- So **KMS events cannot be used as an object-level access log.** Object-level
  auditing comes from **CloudTrail S3 data events** (authoritative, paid) or
  **S3 server access logs** (best effort, included here).
- Any policy condition on `kms:EncryptionContext` must use the bucket ARN.
- If a compliance requirement demands one KMS event per object access, set
  `BucketKeyEnabled: false` and accept the higher KMS cost.

### A.3 Finding and fixing this in an existing AWS environment

The brief assumes this user already exists. An administrator identity with
long-term credentials should be handled as a **potential incident**, not just
a configuration issue: confirm it has not been misused before cleaning it up.

> The commands below are illustrative. They were **not** run against an AWS
> account as part of this assessment.

**1. Find it (detection)**

| Source | What it shows | Limitation |
|---|---|---|
| IAM credential report (`aws iam generate-credential-report`, then `get-credential-report`) | All users, key and password age, last use, MFA status | Shows credentials, not permissions |
| `aws iam get-account-authorization-details` | All users, roles, groups and policies, **including inline policy content** | A point-in-time snapshot; needs parsing (example below) |
| IAM Access Analyzer | Unused roles, keys and permissions; external access; policy generation from CloudTrail activity | Unused-access analysis is a paid feature |
| Prowler (open source) | Many IAM and S3 checks, including inline policy content, across accounts | Periodic scans, not real time |
| AWS Config / Security Hub | Continuous compliance status across accounts | **See the limitations below** |
| CloudFormation `describe-stack-resources` and drift detection | Which stack owns the user; changes made outside IaC | Only for stack-managed resources |

**Limitations of AWS Config managed rules (and Security Hub).** Managed rules
are useful, but none of them alone detects exactly this misconfiguration. According to
the AWS documentation (verify against the current version of each rule):

- `iam-policy-no-statements-with-admin-access` and Security Hub **IAM.1**
  evaluate **customer managed policies only**. They do **not** evaluate inline
  policies, such as CF-1's `FullAccess`, or the AWS managed
  `AdministratorAccess` policy.
- `iam-no-inline-policy-check` and `iam-user-no-policies-check` flag that a
  policy is *attached* (inline or directly to a user). They report that it
  exists, not what it allows. That is useful as a hygiene control, but it
  produces findings for harmless policies too.
- Config evaluates only resource types that are being **recorded**. IAM is a
  global service: if no region records global IAM resources, IAM rules never
  produce results.
- Config is **detective and delayed** (change-triggered or periodic). It
  reports after the fact and does not block anything.
- Rules are per account and region unless deployed organization-wide
  (conformance packs plus an aggregator).

For that reason, detection of `*:*` in **inline** policies relies on policy
content analysis: Access Analyzer, Prowler, or the query below.

Example: list users that have an inline `*:*` policy or `AdministratorAccess` attached.

```bash
aws iam get-account-authorization-details --filter User --output json > auth.json
jq -r '
  .UserDetailList[]
  | select(
      ([.UserPolicyList[]?.PolicyDocument.Statement
        | if type == "array" then .[] else . end
        | select(.Effect == "Allow"
                 and ([.Action] | flatten | index("*"))
                 and ([.Resource] | flatten | index("*")))] | length > 0)
      or ([.AttachedManagedPolicies[]?.PolicyArn
           | select(endswith(":policy/AdministratorAccess"))] | length > 0)
    )
  | .UserName' auth.json
```

**2. Investigate before changing anything**

- Identify the owner and every consumer of the user (tags, CMDB, code search for the access key ID).
- `aws iam list-access-keys` and `aws iam get-access-key-last-used`.
- CloudTrail: all activity by the user, e.g.
  `aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=UnrestrictedUser`
  (90 days; use CloudTrail Lake or Athena over the org trail for longer). Check GuardDuty findings.
- IAM "last accessed" data or Access Analyzer policy generation: which actions are actually used. This becomes the least-privilege replacement policy.
- **If there is any sign of misuse:** switch to incident response. Deactivate the keys, attach `AWSDenyAll`, remove the console password, and look for persistence (new users, keys, roles, changed trust policies, Lambda functions, instances).

**3. Remediate (corrective)**

1. Create a least-privilege role based on observed usage, as in [A.2](#a2-remediated-template).
2. Move each consumer to the role.
3. **Deactivate** the access keys (`aws iam update-access-key --status Inactive`). This step is reversible.
4. After an agreed observation period, delete the keys, inline policy, login profile and MFA devices, then the user.
5. If a CloudFormation stack manages the user, make the change **in the template, through the pipeline**. A console fix would be reverted by the next stack update.

---

## Part B: Dockerfile

### B.1 Findings

| ID | Type | Severity | Issue | Impact |
|---|---|---|---|---|
| D-1 | Vulnerability | **Critical** | Secrets hardcoded in `ENV` (`DB_PASSWORD`, `API_KEY="prod-key-..."`). | Stored in the image configuration. Anyone who can pull the image can read them with `docker inspect` or `docker history`, as can every registry and cache. They are also in source control and visible to every process in the container. **Treat any secret that was ever built this way as compromised and rotate it.** |
| D-2 | Vulnerability | **High** | Runs as **root**. | Without user namespaces, container root is UID 0 on the host. A container escape, or a privileged container, host mount or Docker socket, becomes host root. |
| D-3 | Vulnerability | **High** | **End-of-life base image** `ubuntu:18.04` (standard support ended 31 May 2023), with Python 3.6 (end of life December 2021). Mutable tag. | No security updates without paid extended support; known vulnerabilities accumulate. |
| D-4 | Vulnerability | Medium | `chmod -R 777 /app`. | Code is world-writable, so any process in the container can modify it (code injection, persistence). |
| D-5 | Vulnerability | Medium | `COPY . /app` with **no `.dockerignore`**. | `.git` history, `.env` files, keys and state files from the build context end up in image layers. |
| D-6 | Hardening | Low | Unneeded packages (`curl`, `vim`, `dnsutils`, unused `python3-pip`); no `--no-install-recommends`; apt lists kept. | Larger attack surface and more CVEs; tools for an attacker after compromise. |
| D-7 | Hardening | Low | Unpinned packages and base image. | Builds are not reproducible. |
| D-8 | Hardening | Low | Shell-form `CMD`. | `/bin/sh` is PID 1 and does not forward `SIGTERM`, so there is no graceful shutdown. |
| D-9 | Info | – | No `HEALTHCHECK`. | **Not added**, because the brief defines no health endpoint and adding one would assume an app feature. Recorded as an accepted checkov skip (`CKV_DOCKER_2`). |
| D-10 | Info | – | `EXPOSE 80` (plain HTTP). | TLS should be terminated by a load balancer or ingress in front of the container. |

### B.2 Hardened Dockerfile

[docker/Dockerfile](docker/Dockerfile): checkov 30 passed, 0 failed, 1 justified skip (D-9); no secrets found.

| Change | Kind | Addresses |
|---|---|---|
| `ENV` secrets removed; secrets are injected at runtime ([B.3](#b3-runtime-configuration-and-secrets)). Build-time secrets, if ever needed, use BuildKit `RUN --mount=type=secret`, never `ENV` or `ARG`. | Fix | D-1 |
| Dedicated user `app` (UID/GID 10001, no home, no shell); final `USER 10001:10001`. | Fix | D-2 |
| `python:3.13-slim-trixie` (official image, Debian 13), pinned by index digest (resolved from Docker Hub on 2026-11-02). | Fix | D-3, D-7 |
| `COPY --chown=root:root --chmod=0755`: files are root-owned and read-only for the runtime user. | Fix | D-4 |
| `Dockerfile.dockerignore` (applied automatically by BuildKit) excludes `.git`, `.env*`, `*.env`, keys, credentials and state files. | Fix | D-5 |
| No `apt-get` at all; the base image already provides `python3` and `pip`. | Hardening | D-6 |
| Exec-form `CMD ["python3", "app.py"]`. | Hardening | D-8 |

**Port 80 as non-root.** `EXPOSE 80` is kept because the brief does not say
which port `app.py` uses. Docker Engine 20.10 and later lets non-root
processes bind ports below 1024 inside the container
(`net.ipv4.ip_unprivileged_port_start`). On other runtimes, set that sysctl
or make the app use a high port. Do not run as root or add
`CAP_NET_BIND_SERVICE` for this.

**If the app has dependencies.** None are assumed, because the brief provides
no `requirements.txt`. If one exists, add a builder stage with
`pip install --no-cache-dir --require-hashes -r requirements.txt` into a
virtualenv, and copy only the virtualenv into the final image.

### B.3 Runtime configuration and secrets

**Where secrets live.** In production, inject secrets from a secret store:
ECS task `secrets` from Secrets Manager or SSM Parameter Store, or Kubernetes
Secrets (ideally via an external secrets operator). For local testing only,
keep the env file **outside the repository and outside the build context**,
readable only by you:

```bash
mkdir -p ~/.config/task02 && chmod 700 ~/.config/task02
# create ~/.config/task02/runtime.env with the variables, then:
chmod 600 ~/.config/task02/runtime.env
```

If such a file is accidentally created inside the repository, two safety nets
apply. Task 2's [.gitignore](.gitignore) ignores `*.env`, and
[Dockerfile.dockerignore](docker/Dockerfile.dockerignore) excludes `**/*.env`
from the build context. Both are covered by `tests/dockerfile-assertions.sh`.

**Run hardening** (cannot be set in a Dockerfile):

```bash
docker run --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --pids-limit 100 --memory 256m \
  --env-file ~/.config/task02/runtime.env \
  -p 8080:80 app:local
```

Kubernetes equivalent:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  runAsGroup: 10001
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: ["ALL"]
  seccompProfile:
    type: RuntimeDefault
```

---

## C. Prevention for both files

There are three kinds of control, and no single one is enough:

- **Preventive** controls stop a misconfiguration from being merged or applied.
- **Detective** controls find what got through, or what was changed outside IaC.
- **Corrective** controls fix it.

### C.1 Preventive controls

| Stage | CloudFormation | Dockerfile / image |
|---|---|---|
| **Pull request** (required status check + branch protection + code-owner review); see [ci/security-checks.example.yml](ci/security-checks.example.yml) | `cfn-lint` (schema); `checkov` (security policies); IAM Access Analyzer `validate-policy` and custom policy checks (`check-access-not-granted`) to block `*:*` | `hadolint`; `checkov` (Dockerfile policies); secret scanning of **all** files with `checkov` and `trivy fs`; build and `trivy image`, failing on fixable HIGH/CRITICAL CVEs |
| **Developer workstation** (fast feedback, but bypassable) | `pre-commit` with `cfn-lint`, `checkov` | `pre-commit` with `hadolint`, `gitleaks` |
| **Deployment** | Only the pipeline's deploy role can change infrastructure. CloudFormation Hooks (Guard) block non-compliant resources even if CI was bypassed. | Private registry with immutable tags; image signing and signature verification at admission |
| **Organization** | SCPs (below); account-level S3 Block Public Access; IAM Identity Center for humans | Approved base-image list; secrets only from a secret store |

**Why the scanners are layered.** Running checkov 3.4.2 on the insecure
fixtures (see [Validation](#validation)) showed that it **does not** flag:

- CloudFormation: CF-2 (IAM user), CF-7 (no TLS policy) or CF-11 (no policy version).
- Dockerfile: D-3 (end-of-life base image), D-4 (`chmod 777`) or D-5 (no `.dockerignore`).
- Hardcoded secrets (D-1), unless its separate `secrets` framework is run. Even
  then it reports only `API_KEY`, **not** `DB_PASSWORD="SuperSecret..."`.
  D-1 is fully covered by `tests/dockerfile-assertions.sh`, which rejects any
  secret-like `ENV`/`ARG`.

The missing checks are covered by other layers:

- `trivy image` for end-of-life and vulnerable packages;
- `hadolint` for Dockerfile practices;
- secret scanners;
- IAM Access Analyzer for policies;
- this task's own tests.

**Negative tests in CI.** The example workflow checks that scanners still
detect the insecure fixtures. It never treats a scanner failure as a
detection:

- Scanners run in report-only mode (`--soft-fail` / `--no-fail`), so a
  non-zero exit code means a tool error and fails the step.
- A tool error can also exit 0: checkov reports an unparsable or missing file
  under `parsing_errors` and still exits 0, as verified locally. So
  `parsing_errors == 0` is checked explicitly.
- Detection is proven only by **specific expected findings** in the JSON
  report:
  - `CKV_AWS_62` on `MyIAMUser` and `CKV_AWS_53` on `MyBucket` (IDs confirmed by a checkov run);
  - `CKV_SECRET_6` with the exact hash of the fake `API_KEY` in the Dockerfile fixture (confirmed);
  - hadolint `DL3002` and `DL3025` (not confirmed locally, because hadolint was not run).

**Secret scanning and test fixtures.** Policy scans of the remediated files
skip `fixtures/`, because the policy findings there are intentional and are
checked by the negative tests. **Secret scanning never skips any path**: it
covers every file, including the fixtures. The fake values from the brief are
handled by an exception that is as narrow as the tools allow.

- The **only** exception is [ci/checkov-secrets.baseline.json](ci/checkov-secrets.baseline.json).
  It holds the SHA-1 of the exact fake `API_KEY` value, the one checkov
  reports, for check `CKV_SECRET_6`. No directory, file or rule is excluded.
- Local tests showed that checkov 3.4.2 matches baseline entries **by hash and
  check ID only; the file path is ignored**. So a baseline alone would also
  hide the same fake value if it were copied into another file.
  [tests/known-fake-secrets.sh](tests/known-fake-secrets.sh) closes that gap.
  It fails if:
  - a known fake value appears in any file other than the fixture;
  - the fixture's values differ from the pinned known fakes;
  - the baseline contains any hash other than a pinned fake value.
  The script stores only hashes, so it contains no secret-like text itself.
- **Any other secret fails the gate**: a different value in the fixture, or
  any secret in a remediated file. This was verified by mutation tests (see
  [Validation](#validation)).
- **Trivy secret scanning** in the example CI also covers all files, with no
  allow-rules. Trivy was not run locally, so no exception was added in
  advance. If it reports the fake values, the exception must likewise match
  only those exact values.

**SCP guardrails** ([guardrails/scp-baseline.example.json](guardrails/scp-baseline.example.json)):

| Statement | Purpose |
|---|---|
| `DenyIamUserAndAccessKeyCreation` | No new IAM users, access keys or console passwords (prevents CF-2) |
| `DenyAttachingAdministratorAccess` | No attaching the AWS managed admin policy |
| `DenyDisablingAccountPublicAccessBlock` | Account-level S3 Block Public Access stays on |
| `ProtectOrgProtectedRoles` | No one can create, modify, delete or re-tag roles under `/org-protected/` except `OrgGuardrailProvisioner` |
| `DenyPassingOrgProtectedRoles` | Protected roles cannot be passed to a service (e.g. attached to an instance) |

**Break-glass exception: how it is protected.** The first three statements
exempt a break-glass role. An exception based on a role *name* is only as
strong as the control over who can create or change that role. Without
protection, anyone with `iam:CreateRole` could create a role with the
break-glass name, or change the trust policy of the real one, and inherit the
exemption. Two layers close this gap.

*In the SCP:*

- The exempt role lives under the IAM path `/org-protected/`.
  `ProtectOrgProtectedRoles` denies every create, update, delete, policy or
  tag change for roles under that path, except by the provisioning role.
  Creating a look-alike role under that path is denied too.
- `DenyPassingOrgProtectedRoles` stops anyone from obtaining the role's
  permissions indirectly, by passing it to EC2, Lambda or ECS.
- **Bootstrapping:** create the roles with service-managed CloudFormation
  StackSets from the management account. That runs through a service-linked
  role, which SCPs do not restrict, so the provisioner role can be created
  despite the deny.

*Independent of SCPs* (needed because SCPs do not apply to the management
account, and whoever controls the provisioner can still change the roles):

- **Trust policy:** the break-glass role can be assumed only from a dedicated
  security or identity account, and only with MFA (`aws:MultiFactorAuthPresent`).
- **Dual control:** credentials are held under dual control (hardware MFA and
  a sealed credential owned by two people).
- **Alerting:** every `AssumeRole` of the break-glass role and every IAM change
  under `/org-protected/` raises a high-priority alert. EventBridge rules on
  the organization CloudTrail, with logs stored in a separate log-archive
  account, send it to the security team.
- **Management account:** kept free of workloads, with root protected by
  hardware MFA. Root credentials of member accounts are managed centrally.
- **Regular drill:** break-glass access is tested regularly, and every use is
  reviewed after the fact.

*Remaining limits:*

- SCPs cannot inspect inline policy content, so a `*:*` inline policy is
  blocked by CI, Hooks and Access Analyzer rather than by SCP.
- `BreakGlassAdmin` and `OrgGuardrailProvisioner` are placeholder names.
  Test the SCP in a non-production OU first.

### C.2 Detective controls

| Control | Detects |
|---|---|
| AWS Config rules and Security Hub, organization-wide (limitations in [A.3](#a3-finding-and-fixing-this-in-an-existing-aws-environment)) | Policy attachments, customer managed admin policies, old or unused keys, missing MFA, S3 public access, TLS, versioning, logging |
| IAM Access Analyzer; Prowler | Inline policy content, unused access, external access |
| Organization CloudTrail with EventBridge alerts on `CreateUser`, `CreateAccessKey`, `PutUserPolicy`, `AttachUserPolicy`, `PutBucketPolicy`, `DeletePublicAccessBlock` | High-risk changes as they happen |
| GuardDuty (including runtime monitoring) | Use of leaked credentials; suspicious container behaviour |
| CloudFormation drift detection | Changes made outside IaC |
| ECR enhanced scanning (Amazon Inspector) | New CVEs in images that were clean at build time |

### C.3 Corrective controls

| Control | Action |
|---|---|
| AWS Config auto-remediation (SSM Automation) | Re-enable bucket public access block, re-apply TLS-only policy, enable versioning |
| EventBridge + Lambda for high-confidence cases | Deactivate newly created access keys, quarantine an unexpected admin user, notify the owner |
| Automated base-image updates (Dependabot or Renovate on the digest), with rebuild and redeploy | Removes vulnerable base images |
| Secrets Manager rotation and an incident runbook | Fast rotation when a secret leaks (D-1) |

Start IAM auto-remediation in alert-only mode; automatic IAM changes can break production.

---

## Assumptions and tradeoffs

| Topic | Decision | Tradeoff |
|---|---|---|
| Purpose of the IAM user | A workload that uses the bucket; the service is a parameter | A human or an external system needs Identity Center or federation instead |
| Read/write scope | `GetObject`, `PutObject`, `ListBucket`; no `DeleteObject` | Remove `PutObject` for read-only workloads |
| KMS key policy | Standard default statement (account root, `kms:*`) that delegates key access to IAM | Simple and avoids lock-out; stricter setups name key admins and users explicitly |
| Bucket Keys | Enabled (cost) | No per-object KMS events (see [A.2](#a2-remediated-template)) |
| Log bucket encryption | SSE-S3 | S3 server access log delivery does not support SSE-KMS on the destination bucket |
| `Retain` policies | Buckets, bucket policies and key survive stack deletion | Must be cleaned up manually |
| Base image | `python:3.13-slim` (Debian) | Has a shell and apt (easier to debug, larger surface) compared with distroless |
| Python 3.6 → 3.13 | Supported version | `app.py` was not provided and could not be tested |
| Secrets as runtime environment variables | Same variable names as the original | Visible to `docker inspect` on the host; secrets mounted as files are stronger but need an app change |
| Long-form intrinsic functions | `Fn::Sub` instead of `!Sub` | More verbose, but plain YAML for the offline tests |

---

## Validation

All results are from real runs on 2026-11-02 (Windows 11, Git Bash).
**Nothing was deployed to AWS, no AWS credentials were used, no image was built.**

**Tool setup.** cfn-lint 1.59.0 and checkov 3.4.2 were installed from PyPI
into a temporary virtualenv outside the repository (Python 3.11.2), with the
user's approval. This machine's antivirus (Norton) intercepts TLS, so pip
could not verify PyPI's certificate with its own CA bundle. Verification was
**not disabled**: pip was given the Windows trusted-root store instead
(`--cert`).

### cfn-lint 1.59.0 (AWS resource schema and template validation)

| Command (from `task-02-security-review/`) | Result |
|---|---|
| `cfn-lint cloudformation/secure-bucket.yaml` | **Pass**: no errors or warnings, exit 0 |
| `cfn-lint fixtures/example-insecure-cloudformation.yaml` | Exit 0. Expected: the fixture is schema-valid, and cfn-lint is not a security scanner. |
| Sanity check: a temporary copy with an invalid property, an out-of-range value and a missing `GetAtt` target | Fails as expected with `E3002`, `E3034`, `E1010`, `E6101`, exit 2. This shows cfn-lint really validates the file. |

### checkov 3.4.2 (security policies)

| Command | Result |
|---|---|
| Policies: `checkov --directory . --framework cloudformation dockerfile --skip-path fixtures` | **Pass**, exit 0. CloudFormation: 31 passed, 0 failed, 1 skipped (`CKV_AWS_18` on the log bucket, justified inline). Dockerfile: 30 passed, 0 failed, 1 skipped (`CKV_DOCKER_2`, D-9). |
| Secrets, all files: `checkov --directory . --framework secrets --baseline ci/checkov-secrets.baseline.json` | **Pass**, exit 0, no findings. Without the baseline, the same scan reports exactly one finding: `CKV_SECRET_6`, hash `18c0337a…`, in `fixtures/example-insecure.Dockerfile`. That is the only thing the exception hides. |
| Secrets, whole repository, no baseline, no skips (`checkov --directory <repo root> --framework secrets`) | One finding: the same known fake value in the fixture. Nothing else. |
| Negative: `checkov --file fixtures/example-insecure-cloudformation.yaml --framework cloudformation --output json --soft-fail` | Exit 0, 13 failed checks, 0 parsing errors. Includes `CKV_AWS_62` (full `*-*` admin) and `CKV_AWS_63` on `MyIAMUser`, and `CKV_AWS_53`–`56` (public access block), `CKV_AWS_21` (versioning) and `CKV_AWS_18` (logging) on `MyBucket`. The CI assertions (`CKV_AWS_62` on `MyIAMUser`, `CKV_AWS_53` on `MyBucket`) both hold. |
| Negative: `checkov --file fixtures/example-insecure.Dockerfile --framework dockerfile` | 2 failed: `CKV_DOCKER_8` (last USER root), `CKV_DOCKER_2` |
| Negative: `checkov --file fixtures/example-insecure.Dockerfile --framework secrets` | `CKV_SECRET_6` with the expected hash, so the CI assertion holds. `DB_PASSWORD` is **not** reported (checkov limitation; see C.1). |
| Tool-error path: the same negative command on a non-existent file | **Exit 0**, file listed under `parsing_errors`, no findings. The CI logic correctly fails in this case, and this run is why the explicit `parsing_errors` check was added. |
| Baseline behaviour, tested on temporary copies | Matching is by secret hash and check ID. A wrong hash or a wrong check ID → finding reported. A wrong or nonexistent file path in the baseline → finding **still suppressed**, so the path is ignored. |

The first checkov run also found a mistake in the previous version:
`CKV_AWS_145` was listed as a skip, but checkov 3.4.2 does not apply that check
to CloudFormation. The unused skip was removed.

### Offline tests

| Command | Result |
|---|---|
| `bash tests/dockerfile-assertions.sh` | **Pass.** Hardened Dockerfile checks; negative checks on the fixture; `.dockerignore` patterns; Git ignores `runtime.env`, `docker/runtime.env` and `.env` while `runtime.env.example` stays trackable. |
| `bash tests/known-fake-secrets.sh` | **Pass.** Both fake values are present in the fixture, match the pinned hashes and appear in no other file; the baseline holds only a pinned hash. |
| Repository-wide credential pattern search (AWS `AKIA`/`ASIA` key IDs, private key headers, GCP service-account JSON and API keys, GitHub, Slack, Stripe and Azure storage keys) over tracked and untracked files | No matches. No Git-ignored files exist on disk. |
| `cd tests/template-structure && terraform fmt -check && terraform init && terraform validate && terraform plan` (Terraform 1.8.3) | **Pass**. Asserts no IAM users, no `Allow` on `Action "*"`, no anonymous `Allow`, policy version, bucket controls, a TLS-only policy per bucket, **retained bucket policies for retained buckets**, the **ECS trust conditions**, and negative checks on the fixture. |
| Mutation tests (deliberately broken copies in a temporary directory) | Each mutation was detected with the expected message; the unmodified copy passed. See below. |
| `git diff --check` | Pass |

Mutation tests:

- **Earlier round** (previous review): 14 mutations of the Dockerfile, `.dockerignore` and template.
- **Second round:**
  - removed `DeletionPolicy` from a bucket policy;
  - removed the ECS trust condition;
  - removed `**/*.env` from the `.dockerignore`.
- **Secret-exception round.** Expected outcomes held in every case, and the
  unmodified copy passed both the scan and the guard:
  - A new fake AWS secret key in the hardened Dockerfile: the scan fails (`CKV_SECRET_2`).
  - A different `API_KEY` value in the fixture: the scan fails and the guard fails.
  - The known fake `API_KEY` copied into the hardened Dockerfile: the scan
    passes (baseline limitation); **the guard fails**.
  - The known fake password copied into the README: checkov does not detect
    it; **the guard fails**.
  - An arbitrary extra hash added to the baseline: the guard fails.
  - A fake secret removed from the fixture: the guard fails.

### Not run

| Tool | Reason |
|---|---|
| hadolint | Not installed. The CI rule IDs `DL3002` / `DL3025` are unconfirmed. |
| trivy (config, secrets, image), docker build | Not installed; no image was built |
| `aws cloudformation validate-template`, IAM Access Analyzer `validate-policy` | Need AWS credentials, which this task does not use |
| actionlint for the example workflow | Not installed. The workflow was only parsed as YAML; it has never run in GitHub Actions. |

---

## Limitations

- **Not deployed or built.** cfn-lint validates the template against AWS
  resource schemas, but behaviour that only appears at deploy time has not
  been tested: IAM evaluation, log delivery, KMS access through S3.
- **No application.** It is untested whether `app.py` runs on Python 3.13,
  as non-root, on port 80.
- **The example CI workflow has never run.** Action SHAs and tool versions
  were resolved on 2026-11-02.
- **The SCP is a sketch.** The role names are placeholders, and it must be
  tested in a non-production OU.
- **Secret-scanner exceptions are tool-specific.** The exact-value exception
  is implemented and verified for checkov only. Trivy's secret scan (example
  CI) has no exception, because trivy was not run. Any other scanner (e.g.
  gitleaks) that reports the fake values needs its own exception for the exact
  values only, never a path or rule exclusion. See
  [fixtures/README.md](fixtures/README.md).
- **checkov does not detect `DB_PASSWORD`** in the fixture. That fake value
  is covered by `tests/dockerfile-assertions.sh` (secret-like `ENV`) and
  `tests/known-fake-secrets.sh`.
- **`.gitignore` is a name-based safety net.** The repository-root
  `.gitignore` now also ignores `*.env` and `*.env.*` (for example
  `runtime.env`) everywhere, and Task 2's own `.gitignore` keeps the same rule
  locally. Neither inspects file content; a secret in a differently named file
  is only caught by a content scanner.
