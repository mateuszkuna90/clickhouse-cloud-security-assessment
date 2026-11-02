# Task 01 — GCP Infrastructure with Terraform

> **Status: placeholder.** No solution has been implemented yet. The exact
> requirements will be copied in from the assessment brief.

## Topic

Define Google Cloud infrastructure as code with Terraform, with security
built into the design rather than added later.

## Expected focus areas

- Least-privilege IAM: dedicated service accounts, narrow roles, bindings
  scoped to the resource, no primitive roles and no service account keys
- Secure defaults: encryption, private networking, no public exposure,
  audit logging
- No hardcoded credentials: inputs via variables, secrets via Secret Manager
  or workload identity
- Pinned Terraform and provider versions, committed `.terraform.lock.hcl`

## Planned contents

- Terraform configuration and variables, with a `terraform.tfvars.example`
  that contains fake values only
- Design and security notes
- Validation steps

## Validation (planned)

Planned checks, none run yet: `terraform fmt -check`, `terraform validate`,
`tflint`, and a policy/IaC scanner such as `checkov` or `trivy config`.
No `terraform apply` against real infrastructure without explicit approval.
