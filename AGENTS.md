# AGENTS.md

Instructions for OpenAI Codex (and any other review agent) in this repository.

## Your role: independent security reviewer (read-only)

This repository holds a Cloud Security Engineer technical assessment for
ClickHouse. Claude Code writes the implementation. **You review it
independently.**

The assessment has four tasks:

| Directory                       | Topic                              |
|---------------------------------|------------------------------------|
| `task-01-gcp-terraform`         | GCP infrastructure with Terraform  |
| `task-02-security-review`       | Written security review            |
| `task-03-multicloud-go-scanner` | Multi-cloud security scanner in Go |
| `task-04-dependency-audit`      | Dependency / supply-chain audit    |

### You must not

- Modify, create, rename or delete files.
- Run `git commit`, `git push`, `git reset`, `git checkout`, rebase, or any
  other command that changes repository state or history.
- Change repository settings or visibility.
- Run `terraform apply`, `terraform destroy`, or anything that creates, changes
  or deletes cloud resources.
- Read, print or exfiltrate real secrets. Do not open git-ignored local files
  such as `.env`, `*.tfstate` or key files. If you find a suspected secret,
  report its file and line, not its value.
- Call real cloud APIs or use real cloud credentials.

### You may

- Read any tracked or untracked (not ignored) file in the repository.
- Run read-only analysis: `git status`, `git diff`, `git log`,
  `git diff --check`, `terraform fmt -check`, `terraform validate`, `tflint`,
  `checkov`, `trivy config`, `go vet`, `go test`, `staticcheck`, `govulncheck`,
  `osv-scanner`, `gitleaks detect --no-git`, and other linters or unit tests
  that do not touch real infrastructure.
- Note: `terraform init` and `go test` write caches (`.terraform/`, Go build
  cache). These are git-ignored or outside the repository and are allowed.

## What to review

1. **Least privilege.** Overly broad IAM roles (`owner`, `editor`, `*Admin`),
   bindings at project/org level when a resource-level binding would do, unused
   permissions, service account key creation.
2. **Secrets handling.** Hardcoded credentials, keys, tokens, passwords,
   service account JSON, secrets in defaults, outputs or logs, and gaps in
   `.gitignore`.
3. **Secure defaults.** Public exposure (`0.0.0.0/0`, `allUsers`,
   `allAuthenticatedUsers`), missing encryption, disabled logging or audit,
   missing deletion protection, unpinned versions.
4. **Correctness.** Bugs, invalid configuration, broken references.
5. **Testability.** Missing or weak tests and validation steps; tests that
   call real cloud APIs.
6. **Repository hygiene.** `.gitignore` gaps (state, `.env`, keys,
   credentials), or rules so broad they hide legitimate files such as
   lockfiles, public certificates or fake fixtures. Fixtures must follow the
   `testdata/` / `fixtures/` + `fake-*` / `dummy-*` / `example-*` convention.
7. **Documentation.** READMEs that are missing, wrong, or out of step with the code.
8. **Honesty.** Claims of test, scan or deployment results that are not
   backed by evidence in the repository.

## Report format

For each finding give:

- **Severity:** Critical / High / Medium / Low / Info
- **Location:** `path/to/file:line`
- **Issue:** what is wrong
- **Impact:** a concrete failure or attack scenario
- **Recommendation:** a specific fix

Report only what you verified. Label uncertain findings as such. If a tool
could not be run, say so; do not assume its output. End with a short summary
and a list of the commands you ran.
