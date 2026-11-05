# ClickHouse Cloud Security Engineer — Technical Assessment

Solutions to the four tasks of the ClickHouse Cloud Security Engineer
technical assessment. Each task lives in its own directory with a README
that quotes the brief's requirements, explains the design and security
decisions, and records exactly what was validated and what was not.

> **Scope of evidence.** Everything was validated **offline**. Nothing was
> deployed to GCP or AWS, no Docker image was built, and the scanner has never
> run against a real cloud account. No cloud credentials were used. The only
> live service contacted was the public npm registry, for the Task 4 audit.

## Tasks

| # | Directory | Brief | Solution |
|---|---|---|---|
| 1 | [task-01-gcp-terraform](task-01-gcp-terraform/README.md) | Terraform for a GCP VPC, a private VM behind a global HTTPS load balancer, and least-privilege firewall rules | Module with public/private subnets, a VM with no external IP, Cloud NAT, HTTPS-only LB, SSH only through IAP or a trusted range, a dedicated VM service account with an allowlist of roles, and a fail-closed bootstrap script. Design: [DESIGN.md](task-01-gcp-terraform/DESIGN.md) |
| 2 | [task-02-security-review](task-02-security-review/README.md) | Review a CloudFormation template (S3 bucket + `*:*` IAM user) and a Dockerfile; fix both; prevent recurrence | Findings, a remediated template ([secure-bucket.yaml](task-02-security-review/cloudformation/secure-bucket.yaml)), a hardened [Dockerfile](task-02-security-review/docker/Dockerfile), steps for an existing AWS account, and preventive, detective and corrective controls (example CI gate and SCP) |
| 3 | [task-03-multicloud-go-scanner](task-03-multicloud-go-scanner/README.md) | Go CLI that finds inbound `0.0.0.0/0` rules in AWS Security Groups, GCP firewall rules and Azure NSGs, with JSON output | `cloudfw-scan`: read-only collectors for the three clouds, a shared detection engine, deterministic JSON report, defined exit codes for partial failure. Design: [DESIGN.md](task-03-multicloud-go-scanner/DESIGN.md) |
| 4 | [task-04-dependency-audit](task-04-dependency-audit/README.md) | Audit the supplied `package.json`, analyse high/critical issues and fixes, count what is fixable; bonus report script | `npm audit` on a lockfile-only tree (no install scripts run), remediation scenarios re-audited with saved evidence, and a fail-closed Python script that produces JSON and CSV reports |

## Prerequisites

| Tool | Needed for | Version used |
|---|---|---|
| Bash (Git Bash on Windows) | shell tests in Tasks 1, 2, 4 | 5.2.37 |
| Terraform | Tasks 1 and 2 (offline validation, mock-provider tests) | 1.17.1 (Task 1 needs ≥ 1.9) |
| Go | Task 3 | 1.27.3 (`go.mod`) |
| Python 3, standard library only | Task 4 report script and tests | 3.11.2 |
| Node.js + npm | Task 4, only to re-run the audit (needs the npm registry) | Node v26.13.0, npm 11.20.0 |

Optional scanners used in the task READMEs: tflint, trivy, checkov,
shellcheck, cfn-lint, staticcheck, govulncheck. None are needed for the
commands below.

## Quick validation

No command needs cloud credentials, calls a cloud API or creates cloud
resources. `terraform init` downloads the pinned providers from the
Terraform Registry; everything else runs locally. Task 1's `terraform test`
uses a mock provider. Run the blocks from the repository root.

```sh
# Task 1: format, validate, mock-provider tests, static and bootstrap tests
cd task-01-gcp-terraform
terraform fmt -recursive -check
terraform init -backend=false -input=false
terraform validate
terraform test
bash tests/static_checks.sh
bash tests/bootstrap/test_startup.sh
cd ..

# Task 2: Dockerfile / secret-exception tests and template structure checks
cd task-02-security-review
bash tests/dockerfile-assertions.sh
bash tests/known-fake-secrets.sh
(cd tests/template-structure && terraform init -input=false && terraform validate && terraform plan -input=false)
cd ..

# Task 3: format, vet, build, tests (fake cloud adapters)
cd task-03-multicloud-go-scanner
gofmt -l .
go vet ./...
go build ./...
go test -count=1 ./...
cd ..

# Task 4: unit tests and evidence hashes (no npm needed)
cd task-04-dependency-audit
python3 -m unittest discover -s tests          # Windows: py -3 -m unittest ...
for d in reports/remediation/rerun-2026-11-03/*/; do (cd "$d" && sha256sum -c sha256.txt); done
cd ..
```

Full command lists, including the optional scanners, are in each task
README's validation section.

## Validation summary

Results recorded in the task READMEs (dates are when they were run):

| Task | Result |
|---|---|
| 1 | `terraform test` 94 passed, static checks 18 passed, bootstrap tests 93 passed; tflint, trivy and checkov clean (2026-11-03) |
| 2 | cfn-lint and checkov pass on the fixed files and report the expected failures on the original inputs; offline tests pass and catch every deliberate mutation (2026-11-02) |
| 3 | 9 packages pass (648 tests and subtests), `gofmt`/`go vet` clean, staticcheck clean, govulncheck: no vulnerabilities in called code (2026-11-02) |
| 4 | 26 vulnerable packages (10 critical, 8 high); all 18 high/critical shown fixable by re-audit, 3 moderate dev-only issues remain; 38 unit tests pass (2026-11-03) |

The commands in [Quick validation](#quick-validation) were re-run on
2026-11-05 (Windows 11, Git Bash) after the repository-wide line-ending fix,
with the same counts. Exceptions: Task 1's `terraform init` was not re-run
(the existing provider cache was used), and `terraform validate`/`test` ran
through the provider-reattach workaround described in the Task 1 README. The
optional scanners (tflint, trivy, checkov, cfn-lint, staticcheck,
govulncheck) were not re-run on that date.

## Limitations

- **No live cloud behaviour has been observed.** Task 1 has not been planned
  or applied against a real project. Its runtime checks (backend health,
  certificate issuance, IAP access) are listed but not run. Task 2's template
  was not deployed and its image was not built. Task 3 has only run against
  fakes and local test endpoints.
- **Task 4 results are dated.** `npm audit` output depends on the advisory
  database on the scan date (2026-11-03). A later scan can differ. The
  committed evidence is historical and must not be overwritten.
- **Local tooling note.** On the author's workstation, antivirus TLS
  interception breaks Terraform's local provider-plugin handshake. Task 1
  documents the workaround that was used. On a normal machine or in CI the
  commands run as written.
- Each task README ends with its own detailed limitations.

## Repository conventions

- **Line endings.** [.gitattributes](.gitattributes) checks out text files
  with LF on every platform. Task 3 golden files and Task 4 evidence hashes
  are byte-exact and depend on this.
- **Secrets.** [.gitignore](.gitignore) excludes state, `*.tfvars`, `.env`
  and `*.env` files, keys and credential files. Test fixtures are synthetic
  and named `example-*`, `fake-*` or `dummy-*`.
- **Review process.** The implementation was reviewed by an independent
  read-only reviewer ([AGENTS.md](AGENTS.md)); implementation rules are in
  [CLAUDE.md](CLAUDE.md).
