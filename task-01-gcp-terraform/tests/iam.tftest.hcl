# Least-privilege IAM (bonus requirement). Mock provider only.

mock_provider "google" {}

variables {
  project_id                  = "example-project-id"
  region                      = "europe-west1"
  zone                        = "europe-west1-b"
  managed_certificate_domains = ["app.example.com"]
}

override_resource {
  target = google_service_account.vm
  values = {
    email = "secure-web-vm@example-project-id.iam.gserviceaccount.com"
    name  = "projects/example-project-id/serviceAccounts/secure-web-vm@example-project-id.iam.gserviceaccount.com"
  }
}

run "default_no_grants" {
  command = apply

  assert {
    condition     = length(google_project_iam_member.vm) == 0
    error_message = "VM service account must hold no project roles by default."
  }
  assert {
    condition = (
      length(google_iap_tunnel_instance_iam_member.ssh) == 0 &&
      length(google_compute_instance_iam_member.os_login) == 0 &&
      length(google_service_account_iam_member.ssh_admin_sa_user) == 0
    )
    error_message = "No admin grants without ssh_admin_members."
  }
  assert {
    condition     = google_service_account.vm.account_id == "secure-web-vm"
    error_message = "Dedicated service account ID must derive from name_prefix."
  }
}

run "admin_grants_are_resource_scoped" {
  command = apply

  variables {
    ssh_admin_members = ["group:gcp-admins@example.com", "user:alice@example.com"]
  }

  assert {
    condition = alltrue([
      for b in values(google_iap_tunnel_instance_iam_member.ssh) :
      b.role == "roles/iap.tunnelResourceAccessor" && b.instance == google_compute_instance.this.name && b.zone == "europe-west1-b"
    ]) && length(google_iap_tunnel_instance_iam_member.ssh) == 2
    error_message = "IAP tunnel access must be granted on this VM only."
  }
  assert {
    condition = alltrue([
      for b in values(google_compute_instance_iam_member.os_login) :
      b.role == "roles/compute.osLogin" && b.instance_name == google_compute_instance.this.name
    ]) && length(google_compute_instance_iam_member.os_login) == 2
    error_message = "OS Login (no sudo) must be granted on this VM only."
  }
  assert {
    condition = alltrue([
      for b in values(google_service_account_iam_member.ssh_admin_sa_user) :
      b.role == "roles/iam.serviceAccountUser" && b.service_account_id == google_service_account.vm.name
    ]) && length(google_service_account_iam_member.ssh_admin_sa_user) == 2
    error_message = "serviceAccountUser must be granted on the VM service account only."
  }
  assert {
    condition     = length(google_project_iam_member.vm) == 0
    error_message = "Admin grants must not add project-level bindings."
  }
}

run "admin_sudo_opt_in" {
  command = apply

  variables {
    ssh_admin_members = ["group:gcp-admins@example.com"]
    ssh_admin_sudo    = true
  }

  assert {
    condition     = one(values(google_compute_instance_iam_member.os_login)).role == "roles/compute.osAdminLogin"
    error_message = "ssh_admin_sudo must switch to roles/compute.osAdminLogin."
  }
}

run "optional_vm_roles" {
  command = apply

  variables {
    vm_service_account_roles = ["roles/logging.logWriter", "roles/monitoring.metricWriter"]
  }

  assert {
    condition = length(google_project_iam_member.vm) == 2 && alltrue([
      for b in values(google_project_iam_member.vm) :
      b.member == "serviceAccount:secure-web-vm@example-project-id.iam.gserviceaccount.com" && b.project == "example-project-id"
    ])
    error_message = "Optional roles must bind only the VM service account."
  }
}

run "editor_role_rejected" {
  command = plan
  variables {
    vm_service_account_roles = ["roles/editor"]
  }
  expect_failures = [var.vm_service_account_roles]
}

run "owner_role_rejected" {
  command = plan
  variables {
    vm_service_account_roles = ["roles/owner"]
  }
  expect_failures = [var.vm_service_account_roles]
}

run "admin_role_rejected" {
  command = plan
  variables {
    vm_service_account_roles = ["roles/compute.admin"]
  }
  expect_failures = [var.vm_service_account_roles]
}

run "impersonation_role_rejected" {
  command = plan
  variables {
    vm_service_account_roles = ["roles/iam.serviceAccountTokenCreator"]
  }
  expect_failures = [var.vm_service_account_roles]
}

run "all_users_admin_rejected" {
  command = plan
  variables {
    ssh_admin_members = ["allUsers"]
  }
  expect_failures = [var.ssh_admin_members]
}

run "all_authenticated_users_admin_rejected" {
  command = plan
  variables {
    ssh_admin_members = ["allAuthenticatedUsers"]
  }
  expect_failures = [var.ssh_admin_members]
}

run "domain_admin_rejected" {
  command = plan
  variables {
    ssh_admin_members = ["domain:example.com"]
  }
  expect_failures = [var.ssh_admin_members]
}

run "unprefixed_admin_rejected" {
  command = plan
  variables {
    ssh_admin_members = ["alice@example.com"]
  }
  expect_failures = [var.ssh_admin_members]
}

# --- Allowlist regression tests (Codex final review, Medium 2) ---------------
# The old name-pattern check accepted any role not ending in "admin", for
# example roles/compute.instanceAdmin.v1, and granted it at project scope.

run "versioned_admin_role_rejected" {
  command = plan
  variables {
    vm_service_account_roles = ["roles/compute.instanceAdmin.v1"]
  }
  expect_failures = [var.vm_service_account_roles]
}

run "viewer_role_rejected" {
  command = plan
  variables {
    vm_service_account_roles = ["roles/viewer"]
  }
  expect_failures = [var.vm_service_account_roles]
}

run "service_account_user_role_rejected" {
  command = plan
  variables {
    vm_service_account_roles = ["roles/iam.serviceAccountUser"]
  }
  expect_failures = [var.vm_service_account_roles]
}

run "unsupported_read_role_rejected" {
  command = plan
  variables {
    vm_service_account_roles = ["roles/compute.viewer"]
  }
  expect_failures = [var.vm_service_account_roles]
}

run "unsupported_storage_role_rejected" {
  command = plan
  variables {
    vm_service_account_roles = ["roles/storage.objectViewer"]
  }
  expect_failures = [var.vm_service_account_roles]
}

run "custom_role_rejected" {
  command = plan
  variables {
    vm_service_account_roles = ["projects/example-project-id/roles/customWriter"]
  }
  expect_failures = [var.vm_service_account_roles]
}

run "allowed_plus_disallowed_rejected" {
  command = plan
  variables {
    vm_service_account_roles = ["roles/logging.logWriter", "roles/compute.instanceAdmin.v1"]
  }
  expect_failures = [var.vm_service_account_roles]
}

run "logging_role_alone_accepted" {
  command = apply
  variables {
    vm_service_account_roles = ["roles/logging.logWriter"]
  }
  assert {
    condition     = toset(keys(google_project_iam_member.vm)) == toset(["roles/logging.logWriter"]) && google_project_iam_member.vm["roles/logging.logWriter"].role == "roles/logging.logWriter"
    error_message = "roles/logging.logWriter must be accepted and granted to the VM service account."
  }
}

run "monitoring_role_alone_accepted" {
  command = apply
  variables {
    vm_service_account_roles = ["roles/monitoring.metricWriter"]
  }
  assert {
    condition     = toset(keys(google_project_iam_member.vm)) == toset(["roles/monitoring.metricWriter"])
    error_message = "roles/monitoring.metricWriter must be accepted."
  }
}

run "empty_role_list_accepted" {
  command = apply
  variables {
    vm_service_account_roles = []
  }
  assert {
    condition     = length(google_project_iam_member.vm) == 0
    error_message = "An empty role list must be accepted and grant nothing."
  }
}
