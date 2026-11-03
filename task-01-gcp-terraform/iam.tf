# Dedicated workload identity for the backend VM. No keys are ever created:
# the VM gets short-lived tokens from the metadata server.
resource "google_service_account" "vm" {
  project      = var.project_id
  account_id   = local.names.vm_sa
  display_name = "${var.name_prefix} backend VM"
  description  = "Workload identity of the secure web backend VM. No keys; no project roles by default."
}

# Optional project roles for the VM (default: none). Only the explicit
# allowlist in local.allowed_vm_project_roles can be granted; the variable
# validation checks it first and this precondition checks it again at the
# resource, so a future edit of the variable cannot widen the grant.
resource "google_project_iam_member" "vm" {
  for_each = var.vm_service_account_roles

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.vm.email}"

  lifecycle {
    precondition {
      condition     = contains(local.allowed_vm_project_roles, each.value)
      error_message = "Role ${each.value} is not in the VM service account allowlist (roles/logging.logWriter, roles/monitoring.metricWriter)."
    }
  }
}

# ---------------------------------------------------------------------------
# Administrator access (IAP TCP forwarding + OS Login), scoped to this VM and
# its service account. Project-level read access needed by `gcloud compute ssh`
# (compute.projects.get, compute.instances.get/list) is a documented
# prerequisite and is NOT granted here.
# ---------------------------------------------------------------------------

resource "google_iap_tunnel_instance_iam_member" "ssh" {
  for_each = local.ssh_admin_members

  project  = var.project_id
  zone     = var.zone
  instance = google_compute_instance.this.name
  role     = "roles/iap.tunnelResourceAccessor"
  member   = each.value
}

resource "google_compute_instance_iam_member" "os_login" {
  for_each = local.ssh_admin_members

  project       = var.project_id
  zone          = var.zone
  instance_name = google_compute_instance.this.name
  role          = local.os_login_role
  member        = each.value
}

# OS Login requires actAs on the VM's service account when the VM has one.
# Granted on this service account only, which itself holds no roles by default.
resource "google_service_account_iam_member" "ssh_admin_sa_user" {
  for_each = local.ssh_admin_members

  service_account_id = google_service_account.vm.name
  role               = "roles/iam.serviceAccountUser"
  member             = each.value
}
