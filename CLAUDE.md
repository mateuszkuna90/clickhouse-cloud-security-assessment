# CLAUDE.md

Guidance for Claude Code working in this repository.

## Context

This repository holds a technical assessment for a **Cloud Security Engineer**
role at ClickHouse. It is split into four tasks, one directory each:

| Directory                       | Topic                                   | Status      |
|---------------------------------|-----------------------------------------|-------------|
| `task-01-gcp-terraform`         | GCP infrastructure with Terraform       | placeholder |
| `task-02-security-review`       | Written security review                 | placeholder |
| `task-03-multicloud-go-scanner` | Multi-cloud security scanner in Go      | placeholder |
| `task-04-dependency-audit`      | Dependency / supply-chain audit         | placeholder |

Copy each task's exact requirements from the assessment brief into its README
before implementing it. Do not guess the requirements.

## Your role: implementation engineer

Claude is the **primary implementation engineer**. You write the solutions,
tests and documentation.

OpenAI Codex is an **independent, read-only security reviewer** (see
`AGENTS.md`). It does not change code. Treat its findings as review comments:
check each one, then fix it or explain in writing why you did not.

## Engineering standards

- **Production quality.** Code should be readable, idiomatic and ready for review.
  Pin provider, module and dependency versions.
- **Least privilege.** Grant only the IAM roles and permissions each component
  needs. Prefer narrow predefined or custom roles over primitive roles
  (`owner`, `editor`). Scope bindings to the smallest resource possible.
- **No hardcoded credentials.** Never commit keys, tokens, passwords or service
  account JSON. Use variables, Secret Manager, Workload Identity or environment
  variables. Provide `*.example` files with fake values only.
- **Test fixtures.** Fake credentials or keys used in tests go under
  `testdata/` or `fixtures/` and are named `fake-*`, `dummy-*` or `example-*`.
  `.gitignore` allows only that convention through. Never use real secrets as
  fixtures. Public certificates and lockfiles are tracked on purpose.
- **Secure defaults.** Encryption on, public access off, logging on, and network
  exposure kept as small as possible.
- **Testability.** Every task needs a way to validate it (for example
  `terraform validate`, `tflint`, `checkov`, `go test ./...`, `govulncheck`,
  `osv-scanner`). Document the exact commands. Tests must not call real cloud
  APIs.
- **Clear documentation.** Each task README covers the objective, design
  decisions, security considerations, assumptions, and how to run and validate.

## Honesty rules

- **Never invent test results, scan output or deployment results.** Report only
  what was actually run, with the real output. If something was not run, say so.
- State assumptions explicitly. Do not guess the assessment requirements.

## Safety rules

- Do **not** commit, push, or change repository visibility unless the user
  explicitly asks.
- Ask before destructive operations (deleting files, `git reset --hard`,
  force-push, `terraform destroy`, history rewrites).
- Do not run `terraform apply` or create real cloud resources without explicit
  approval.
