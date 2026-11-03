# Cloud NAT coverage, default-route preservation and startup-script wiring.
# Mock provider only. The VM -> NAT `depends_on` edge is not visible to
# assertions; tests/static_checks.sh proves it with `terraform graph`.

mock_provider "google" {}

variables {
  project_id                  = "example-project-id"
  region                      = "europe-west1"
  zone                        = "europe-west1-b"
  managed_certificate_domains = ["app.example.com"]
}

override_resource {
  target = google_compute_subnetwork.private
  values = {
    self_link = "https://www.googleapis.com/compute/v1/projects/example-project-id/regions/europe-west1/subnetworks/secure-web-private"
  }
}

override_resource {
  target = google_compute_subnetwork.public
  values = {
    self_link = "https://www.googleapis.com/compute/v1/projects/example-project-id/regions/europe-west1/subnetworks/secure-web-public"
  }
}

run "nat_covers_private_subnet_only" {
  command = apply

  assert {
    condition     = google_compute_network.this.delete_default_routes_on_create == false
    error_message = "B-TF-1: default internet route must be kept for Cloud NAT."
  }
  assert {
    condition     = length(google_compute_router.nat) == 1 && length(google_compute_router_nat.this) == 1
    error_message = "B-TF-2: exactly one Cloud Router and one NAT by default."
  }
  assert {
    condition = (
      google_compute_router.nat[0].region == "europe-west1" &&
      google_compute_router_nat.this[0].region == "europe-west1" &&
      google_compute_router.nat[0].network == google_compute_network.this.id &&
      google_compute_router_nat.this[0].router == google_compute_router.nat[0].name
    )
    error_message = "B-TF-2: router and NAT must be in var.region and the custom VPC."
  }
  assert {
    condition = (
      google_compute_router_nat.this[0].source_subnetwork_ip_ranges_to_nat == "LIST_OF_SUBNETWORKS" &&
      google_compute_router_nat.this[0].nat_ip_allocate_option == "AUTO_ONLY" &&
      google_compute_router_nat.this[0].log_config[0].enable == true &&
      google_compute_router_nat.this[0].log_config[0].filter == "ERRORS_ONLY"
    )
    error_message = "B-TF-3: NAT must use LIST_OF_SUBNETWORKS, AUTO_ONLY and error logging."
  }
  assert {
    condition     = length(google_compute_router_nat.this[0].subnetwork) == 1
    error_message = "B-TF-4: NAT must list exactly one subnet."
  }
  assert {
    condition     = one(google_compute_router_nat.this[0].subnetwork).name == google_compute_subnetwork.private.self_link
    error_message = "B-TF-4: NAT must cover the private subnet."
  }
  assert {
    condition     = one(google_compute_router_nat.this[0].subnetwork).name != google_compute_subnetwork.public.self_link
    error_message = "B-TF-4: NAT must NOT cover the public subnet."
  }
  assert {
    condition     = one(google_compute_router_nat.this[0].subnetwork).source_ip_ranges_to_nat == toset(["PRIMARY_IP_RANGE"])
    error_message = "B-TF-4: NAT must cover only the private subnet's primary range."
  }
}

run "startup_script_wiring" {
  command = apply

  assert {
    condition     = google_compute_instance.this.metadata_startup_script == file("files/startup.sh")
    error_message = "B-TF-5: VM must run files/startup.sh unchanged."
  }
  assert {
    condition     = !contains(keys(google_compute_instance.this.metadata), "startup-script")
    error_message = "B-TF-5: startup-script metadata key must not be used alongside metadata_startup_script."
  }
  assert {
    condition     = !strcontains(google_compute_instance.this.metadata_startup_script, "\r")
    error_message = "B-TF-5: startup.sh must use LF line endings (CRLF breaks bash on the VM)."
  }
  assert {
    condition = alltrue([
      for s in [
        "set -Eeuo pipefail",
        "flock -w",
        "DPkg::Lock::Timeout=120",
        "ATTEMPT_TIMEOUT_SECONDS=120",
        "BOOTSTRAP_MAX_ATTEMPTS:-5",
        "HARD_MAX_ATTEMPTS=10",
        "SECURE_WEB_BOOTSTRAP=OK",
        "SECURE_WEB_BOOTSTRAP=FAILED",
        "bootstrap.failed",
        "bootstrap.ok",
        "systemctl enable --now nginx",
        "http://127.0.0.1/",
      ] : strcontains(google_compute_instance.this.metadata_startup_script, s)
    ])
    error_message = "B-TF-6: startup.sh is missing a required control (strict mode, lock, bounded retries, markers, self-check)."
  }
  assert {
    condition     = length(regexall("(?i)(BEGIN [A-Z ]*PRIVATE KEY|password\\s*=|token\\s*=|api[_-]?key|gserviceaccount\\.com)", google_compute_instance.this.metadata_startup_script)) == 0
    error_message = "B-TF-7: startup.sh must not contain credential-like content."
  }
}

run "nat_disabled_with_prebaked_image" {
  command = apply

  variables {
    enable_cloud_nat          = false
    boot_image                = "projects/example-project-id/global/images/family/example-nginx"
    boot_image_includes_nginx = true
  }

  assert {
    condition     = length(google_compute_router.nat) == 0 && length(google_compute_router_nat.this) == 0
    error_message = "B-TF-8: no router/NAT when disabled."
  }
}

run "nat_disabled_without_nginx_image_is_rejected" {
  command = plan

  variables {
    enable_cloud_nat = false
  }

  expect_failures = [var.enable_cloud_nat]
}
