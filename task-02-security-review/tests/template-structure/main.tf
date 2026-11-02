# Offline structural checks for the Task 2 templates.
#
# This is NOT a CloudFormation validator; use cfn-lint and checkov for that.
# Terraform is used only because it is available locally and has YAML/JSON
# parsers: no provider, no credentials, no cloud calls, no state written.
#
# Run:  terraform init && terraform plan
# Every output has preconditions; `terraform plan` fails if any assertion fails.
# Negative tests assert that the same checks DO flag the original fixture
# (fixtures/example-insecure-*).

terraform {
  required_version = ">= 1.5.0"
}

locals {
  task_dir = "${path.module}/../.."

  fixed    = yamldecode(file("${local.task_dir}/cloudformation/secure-bucket.yaml"))
  original = yamldecode(file("${local.task_dir}/fixtures/example-insecure-cloudformation.yaml"))
  ci       = yamldecode(file("${local.task_dir}/ci/security-checks.example.yml"))
  scp      = jsondecode(file("${local.task_dir}/guardrails/scp-baseline.example.json"))

  templates = { fixed = local.fixed, original = local.original }

  # Every policy document (IAM, bucket, key, trust) in each template.
  policy_docs = { for name, t in local.templates : name => flatten([
    for rk, r in t.Resources : concat(
      can(r.Properties.PolicyDocument) ? [{ res = rk, doc = r.Properties.PolicyDocument }] : [],
      can(r.Properties.KeyPolicy) ? [{ res = rk, doc = r.Properties.KeyPolicy }] : [],
      can(r.Properties.AssumeRolePolicyDocument) ? [{ res = rk, doc = r.Properties.AssumeRolePolicyDocument }] : [],
      [for p in try(r.Properties.Policies, []) : { res = rk, doc = p.PolicyDocument }]
    )
  ]) }

  # Resources with an Allow statement on Action "*" AND Resource "*".
  allow_star_star = { for name, docs in local.policy_docs : name => [
    for d in docs : d.res if anytrue([
      for s in d.doc.Statement : s.Effect == "Allow"
      && contains(flatten([s.Action]), "*")
      && contains(flatten([try(s.Resource, [])]), "*")
    ])
  ] }

  # Resources with an Allow statement on Action "*" (any resource).
  allow_any_action = { for name, docs in local.policy_docs : name => [
    for d in docs : d.res if anytrue([
      for s in d.doc.Statement : s.Effect == "Allow" && contains(flatten([s.Action]), "*")
    ])
  ] }

  # Resources with an Allow statement for an anonymous principal ("*").
  allow_anonymous = { for name, docs in local.policy_docs : name => [
    for d in docs : d.res if anytrue([
      for s in d.doc.Statement : s.Effect == "Allow" && (
        try(s.Principal == "*", false) || contains(flatten([try(s.Principal.AWS, [])]), "*")
      )
    ])
  ] }

  missing_policy_version = { for name, docs in local.policy_docs : name => [
    for d in docs : d.res if try(d.doc.Version, "") != "2012-10-17"
  ] }

  iam_users = { for name, t in local.templates : name => [
    for rk, r in t.Resources : rk if r.Type == "AWS::IAM::User"
  ] }

  bucket_checks = { for name, t in local.templates : name => {
    for rk, r in t.Resources : rk => {
      public_access_block_all_true = try(alltrue([for v in values(r.Properties.PublicAccessBlockConfiguration) : v == true]), false)
      encryption                   = try(r.Properties.BucketEncryption.ServerSideEncryptionConfiguration[0].ServerSideEncryptionByDefault.SSEAlgorithm, "NOT SET")
      versioning                   = try(r.Properties.VersioningConfiguration.Status, "NOT SET")
      acls_disabled                = try(r.Properties.OwnershipControls.Rules[0].ObjectOwnership == "BucketOwnerEnforced", false)
      access_logging               = can(r.Properties.LoggingConfiguration)
      retained_on_delete           = try(r.DeletionPolicy, "") == "Retain"
    } if r.Type == "AWS::S3::Bucket"
  } }

  # A retained bucket must keep its policy, otherwise deleting the stack leaves
  # the bucket without its TLS-only and log-delivery restrictions.
  bucket_policy_retention = {
    for rk, r in local.fixed.Resources : rk => {
      bucket          = r.Properties.Bucket.Ref
      bucket_retained = try(local.fixed.Resources[r.Properties.Bucket.Ref].DeletionPolicy, "") == "Retain"
      policy_retained = try(r.DeletionPolicy, "") == "Retain" && try(r.UpdateReplacePolicy, "") == "Retain"
    } if r.Type == "AWS::S3::BucketPolicy"
  }

  # The ECS branch of the trust policy condition must pin source account/ARN.
  trust_condition = try(local.fixed.Resources.WorkloadRole.Properties.AssumeRolePolicyDocument.Statement[0].Condition["Fn::If"], [])
  ecs_trust_hardened = (
    length(local.trust_condition) == 3
    && try(local.trust_condition[0], "") == "IsEcsWorkload"
    && can(local.trust_condition[1].StringEquals["aws:SourceAccount"])
    && can(local.trust_condition[1].ArnLike["aws:SourceArn"])
  )

  bucket_policies = [for rk, r in local.fixed.Resources : r.Properties if r.Type == "AWS::S3::BucketPolicy"]
  buckets_with_tls_deny = [for p in local.bucket_policies : p.Bucket.Ref if anytrue([
    for s in p.PolicyDocument.Statement : s.Effect == "Deny" && try(s.Condition.Bool["aws:SecureTransport"], "") == "false"
  ])]
}

output "remediated_resource_types" {
  value = { for k, r in local.fixed.Resources : k => r.Type }
}

output "iam_users" {
  value = local.iam_users
  precondition {
    condition     = length(local.iam_users.fixed) == 0
    error_message = "Remediated template must not create IAM users."
  }
  precondition {
    condition     = length(local.iam_users.original) > 0
    error_message = "Negative test: expected an IAM user in the original fixture."
  }
}

output "allow_star_star_policies" {
  value = local.allow_star_star
  precondition {
    condition     = length(local.allow_star_star.fixed) == 0
    error_message = "Remediated template must not allow Action * on Resource *."
  }
  precondition {
    condition     = length(local.allow_star_star.original) > 0
    error_message = "Negative test: expected Action * / Resource * in the original fixture."
  }
}

output "allow_any_action_policies" {
  value = local.allow_any_action
  precondition {
    condition     = length(local.allow_any_action.fixed) == 0
    error_message = "Remediated template must not allow Action * on any resource."
  }
}

output "allow_anonymous_principal_policies" {
  value = local.allow_anonymous
  precondition {
    condition     = length(local.allow_anonymous.fixed) == 0
    error_message = "Remediated template must not allow an anonymous (*) principal."
  }
}

output "policies_without_version_2012_10_17" {
  value = local.missing_policy_version
  precondition {
    condition     = length(local.missing_policy_version.fixed) == 0
    error_message = "Every policy document must declare Version 2012-10-17."
  }
}

output "bucket_checks" {
  value = local.bucket_checks
  precondition {
    condition = alltrue([for b in values(local.bucket_checks.fixed) :
      b.public_access_block_all_true && b.acls_disabled && b.versioning == "Enabled"
      && b.encryption != "NOT SET" && b.retained_on_delete
    ])
    error_message = "Every remediated bucket needs full public access block, ACLs disabled, versioning, encryption and Retain."
  }
  precondition {
    condition     = local.bucket_checks.fixed.DataBucket.encryption == "aws:kms" && local.bucket_checks.fixed.DataBucket.access_logging
    error_message = "DataBucket must use SSE-KMS and server access logging."
  }
  precondition {
    condition     = !local.bucket_checks.original.MyBucket.public_access_block_all_true
    error_message = "Negative test: expected the original bucket to lack an explicit public access block."
  }
}

output "buckets_with_tls_only_policy" {
  value = local.buckets_with_tls_deny
  precondition {
    condition     = length(setsubtract(keys(local.bucket_checks.fixed), local.buckets_with_tls_deny)) == 0
    error_message = "Every remediated bucket needs a policy that denies aws:SecureTransport = false."
  }
}

output "bucket_policy_retention" {
  value = local.bucket_policy_retention
  precondition {
    condition     = alltrue([for p in values(local.bucket_policy_retention) : p.policy_retained if p.bucket_retained])
    error_message = "A bucket policy must be retained when its bucket is retained."
  }
}

output "ecs_trust_policy_hardened" {
  value = local.ecs_trust_hardened
  precondition {
    condition     = local.ecs_trust_hardened
    error_message = "ECS trust policy must restrict aws:SourceAccount and aws:SourceArn."
  }
}

output "example_ci_jobs" {
  value = keys(local.ci.jobs)
  precondition {
    condition     = try(local.ci.permissions.contents, "") == "read"
    error_message = "Example CI workflow must use read-only token permissions."
  }
}

output "example_scp_statements" {
  value = [for s in local.scp.Statement : s.Sid]
  precondition {
    condition     = alltrue([for s in local.scp.Statement : s.Effect == "Deny"])
    error_message = "Example SCP must contain only Deny statements."
  }
}
