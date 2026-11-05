# VPC firewall rules. A new custom VPC has only the implied rules (deny all
# ingress, allow all egress). Targets use the VM's service account, not network
# tags: tags can be changed with compute.instances.setTags, while changing the
# service account needs iam.serviceAccounts.actAs and a stopped VM.
#
# PDF rule "Allow only HTTPS (443) from the internet to the Load Balancer" is
# NOT a VPC firewall rule: VPC firewall rules do not apply to Google Front Ends.
# It is enforced by the single 443 forwarding rule in load_balancer.tf.

# PDF: "Allow only HTTP (80) from the Load Balancer to the Compute Engine instance."
resource "google_compute_firewall" "allow_lb_to_backend_http" {
  project     = var.project_id
  name        = local.names.fw_lb_to_backend
  description = "HTTP 80 from Google Front End proxy and health-check ranges to the backend VM only."
  network     = google_compute_network.this.id
  direction   = "INGRESS"
  priority    = 1000

  source_ranges           = local.lb_backend_source_ranges
  target_service_accounts = [google_service_account.vm.email]

  allow {
    protocol = "tcp"
    ports    = [tostring(local.backend_port)]
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# PDF: "Allow only SSH (22) from a trusted IP range (not 0.0.0.0/0) to the Compute Engine instance."
resource "google_compute_firewall" "allow_ssh_trusted" {
  project     = var.project_id
  name        = local.names.fw_ssh
  description = "SSH 22 from trusted ranges only (default: IAP TCP forwarding 35.235.240.0/20)."
  network     = google_compute_network.this.id
  direction   = "INGRESS"
  priority    = 1000

  source_ranges           = var.ssh_source_ranges
  target_service_accounts = [google_service_account.vm.email]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# Explicit low-priority deny so blocked ingress is logged (the implied deny
# rule is not logged). Applies to every VM in this VPC.
resource "google_compute_firewall" "deny_all_ingress" {
  project     = var.project_id
  name        = local.names.fw_deny_all
  description = "Logged default deny for all other ingress."
  network     = google_compute_network.this.id
  direction   = "INGRESS"
  priority    = 65534

  source_ranges = ["0.0.0.0/0"]

  # trivy:ignore:GCP-0074 False positive: the check flags wide port ranges, but this rule DENIES every port; it opens nothing.
  deny {
    protocol = "all"
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}
