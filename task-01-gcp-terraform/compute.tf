# PDF: "A Compute Engine instance in the private subnet."
resource "google_compute_instance" "this" {
  project      = var.project_id
  name         = local.names.instance
  description  = "Private nginx backend for the global external HTTPS load balancer."
  zone         = var.zone
  machine_type = var.machine_type
  labels       = local.labels

  can_ip_forward      = false
  deletion_protection = var.deletion_protection

  boot_disk {
    auto_delete = true
    # Null = Google-managed encryption (always on). Optional CMEK.
    kms_key_self_link = var.boot_disk_kms_key_self_link

    initialize_params {
      image  = var.boot_image
      size   = var.boot_disk_size_gb
      type   = "pd-balanced"
      labels = local.labels
    }
  }

  # Private subnet only. There is deliberately NO access_config block, so the
  # VM gets no external IP address.
  network_interface {
    subnetwork = google_compute_subnetwork.private.self_link
    stack_type = "IPV4_ONLY"
  }

  # Dedicated service account. Google's recommendation: cloud-platform scope,
  # with access limited by IAM roles (none by default).
  service_account {
    email  = google_service_account.vm.email
    scopes = ["cloud-platform"]
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  metadata = {
    enable-oslogin         = "TRUE"  # SSH identities come from IAM (OS Login)
    block-project-ssh-keys = "TRUE"  # ignore project-wide metadata SSH keys
    serial-port-enable     = "FALSE" # no interactive serial console
  }

  # Plain file (no template variables, no secrets). Changing it recreates the
  # VM, which re-runs a clean bootstrap.
  metadata_startup_script = file("${path.module}/files/startup.sh")

  # The startup script installs nginx over Cloud NAT, and nothing in this
  # resource refers to NAT, so the ordering must be explicit. This orders API
  # operations only; the script's bounded retries cover NAT data-plane lag.
  depends_on = [google_compute_router_nat.this]
}

# Unmanaged instance group: the smallest supported backend for one named VM.
resource "google_compute_instance_group" "this" {
  project     = var.project_id
  name        = local.names.instance_group
  description = "Unmanaged instance group holding the backend VM."
  zone        = var.zone
  network     = google_compute_network.this.self_link
  instances   = [google_compute_instance.this.self_link]

  named_port {
    name = local.backend_port_name
    port = local.backend_port
  }
}
