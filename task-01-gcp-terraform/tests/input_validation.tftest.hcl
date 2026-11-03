# Input validation: SSH source ranges, subnet CIDRs, placement, certificates.
# Negative cases use expect_failures; positive cases assert the planned value.

mock_provider "google" {}

variables {
  project_id                  = "example-project-id"
  region                      = "europe-west1"
  zone                        = "europe-west1-b"
  managed_certificate_domains = ["app.example.com"]
}

# --- SSH source ranges -------------------------------------------------------

run "ssh_world_ipv4_rejected" {
  command = plan
  variables {
    ssh_source_ranges = ["0.0.0.0/0"]
  }
  expect_failures = [var.ssh_source_ranges]
}

run "ssh_world_ipv6_rejected" {
  command = plan
  variables {
    ssh_source_ranges = ["::/0"]
  }
  expect_failures = [var.ssh_source_ranges]
}

run "ssh_world_mixed_rejected" {
  command = plan
  variables {
    ssh_source_ranges = ["10.0.0.0/8", "0.0.0.0/0"]
  }
  expect_failures = [var.ssh_source_ranges]
}

run "ssh_half_internet_rejected" {
  command = plan
  variables {
    ssh_source_ranges = ["0.0.0.0/1"]
  }
  expect_failures = [var.ssh_source_ranges]
}

run "ssh_not_cidr_rejected" {
  command = plan
  variables {
    ssh_source_ranges = ["not-a-cidr"]
  }
  expect_failures = [var.ssh_source_ranges]
}

run "ssh_non_canonical_rejected" {
  command = plan
  variables {
    ssh_source_ranges = ["10.20.0.1/16"]
  }
  expect_failures = [var.ssh_source_ranges]
}

run "ssh_empty_rejected" {
  command = plan
  variables {
    ssh_source_ranges = []
  }
  expect_failures = [var.ssh_source_ranges]
}

run "ssh_iap_plus_vpn_accepted" {
  command = plan
  variables {
    ssh_source_ranges = ["35.235.240.0/20", "10.20.0.0/16"]
  }
  assert {
    condition     = toset(google_compute_firewall.allow_ssh_trusted.source_ranges) == toset(["35.235.240.0/20", "10.20.0.0/16"])
    error_message = "IAP + private VPN range must be accepted."
  }
}

# --- Subnet CIDRs --------------------------------------------------------------

run "subnets_overlap_rejected" {
  command = plan
  variables {
    public_subnet_cidr  = "10.10.0.0/16"
    private_subnet_cidr = "10.10.1.0/24"
  }
  expect_failures = [var.private_subnet_cidr]
}

run "subnets_identical_rejected" {
  command = plan
  variables {
    public_subnet_cidr  = "10.10.0.0/24"
    private_subnet_cidr = "10.10.0.0/24"
  }
  expect_failures = [var.private_subnet_cidr]
}

run "public_subnet_not_rfc1918_rejected" {
  command = plan
  variables {
    public_subnet_cidr = "8.8.8.0/24"
  }
  expect_failures = [var.public_subnet_cidr]
}

run "private_subnet_too_small_rejected" {
  command = plan
  variables {
    private_subnet_cidr = "10.10.1.0/30"
  }
  expect_failures = [var.private_subnet_cidr]
}

run "private_subnet_not_canonical_rejected" {
  command = plan
  variables {
    private_subnet_cidr = "10.10.1.5/24"
  }
  expect_failures = [var.private_subnet_cidr]
}

run "custom_non_overlapping_subnets_accepted" {
  command = plan
  variables {
    public_subnet_cidr  = "172.16.0.0/24"
    private_subnet_cidr = "192.168.10.0/24"
  }
  assert {
    condition     = google_compute_subnetwork.private.ip_cidr_range == "192.168.10.0/24"
    error_message = "Valid custom CIDRs must be accepted."
  }
}

# --- Placement and naming ------------------------------------------------------

run "zone_outside_region_rejected" {
  command = plan
  variables {
    zone = "us-central1-a"
  }
  expect_failures = [var.zone]
}

run "bad_name_prefix_rejected" {
  command = plan
  variables {
    name_prefix = "Bad_Prefix"
  }
  expect_failures = [var.name_prefix]
}

run "bad_health_check_path_rejected" {
  command = plan
  variables {
    health_check_path = "healthz"
  }
  expect_failures = [var.health_check_path]
}

# --- Certificates --------------------------------------------------------------

run "no_certificate_rejected" {
  command = plan
  variables {
    managed_certificate_domains = []
  }
  expect_failures = [var.managed_certificate_domains]
}

run "both_certificate_sources_rejected" {
  command = plan
  variables {
    ssl_certificate_self_links = ["projects/example-project-id/global/sslCertificates/example-cert"]
  }
  expect_failures = [var.managed_certificate_domains]
}

run "wildcard_domain_rejected" {
  command = plan
  variables {
    managed_certificate_domains = ["*.example.com"]
  }
  expect_failures = [var.managed_certificate_domains]
}

run "bad_certificate_reference_rejected" {
  command = plan
  variables {
    managed_certificate_domains = []
    ssl_certificate_self_links  = ["not-a-certificate"]
  }
  expect_failures = [var.ssl_certificate_self_links]
}

# --- RFC 1918 containment regression tests (Codex final review, Medium 3) ---
# The old check matched a text prefix, so ranges that START inside an RFC 1918
# block but extend beyond it (e.g. 192.168.0.0/15) were accepted. Each input is
# tested on its own; the other subnet keeps a valid non-overlapping value.

run "rfc1918_public_192_168_0_0_15_rejected" {
  command = plan
  variables {
    public_subnet_cidr  = "192.168.0.0/15"
    private_subnet_cidr = "10.200.0.0/24"
  }
  expect_failures = [var.public_subnet_cidr]
}

run "rfc1918_public_192_168_0_0_14_rejected" {
  command = plan
  variables {
    public_subnet_cidr  = "192.168.0.0/14"
    private_subnet_cidr = "10.200.0.0/24"
  }
  expect_failures = [var.public_subnet_cidr]
}

run "rfc1918_public_172_16_0_0_11_rejected" {
  command = plan
  variables {
    public_subnet_cidr  = "172.16.0.0/11"
    private_subnet_cidr = "10.200.0.0/24"
  }
  expect_failures = [var.public_subnet_cidr]
}

run "rfc1918_public_10_0_0_0_7_rejected" {
  command = plan
  variables {
    public_subnet_cidr  = "10.0.0.0/7"
    private_subnet_cidr = "10.200.0.0/24"
  }
  expect_failures = [var.public_subnet_cidr]
}

run "rfc1918_public_8_8_8_0_24_rejected" {
  command = plan
  variables {
    public_subnet_cidr  = "8.8.8.0/24"
    private_subnet_cidr = "10.200.0.0/24"
  }
  expect_failures = [var.public_subnet_cidr]
}

run "rfc1918_public_172_32_0_0_24_rejected" {
  command = plan
  variables {
    public_subnet_cidr  = "172.32.0.0/24"
    private_subnet_cidr = "10.200.0.0/24"
  }
  expect_failures = [var.public_subnet_cidr]
}

run "rfc1918_public_11_0_0_0_8_rejected" {
  command = plan
  variables {
    public_subnet_cidr  = "11.0.0.0/8"
    private_subnet_cidr = "10.200.0.0/24"
  }
  expect_failures = [var.public_subnet_cidr]
}

run "rfc1918_public_fd00_64_rejected" {
  command = plan
  variables {
    public_subnet_cidr  = "fd00::/64"
    private_subnet_cidr = "10.200.0.0/24"
  }
  expect_failures = [var.public_subnet_cidr]
}

run "rfc1918_public_10_0_0_0_rejected" {
  command = plan
  variables {
    public_subnet_cidr  = "10.0.0.0"
    private_subnet_cidr = "10.200.0.0/24"
  }
  expect_failures = [var.public_subnet_cidr]
}

run "rfc1918_public_10_0_0_256_24_rejected" {
  command = plan
  variables {
    public_subnet_cidr  = "10.0.0.256/24"
    private_subnet_cidr = "10.200.0.0/24"
  }
  expect_failures = [var.public_subnet_cidr]
}

run "rfc1918_public_10_0_0_0_8_accepted" {
  command = plan
  variables {
    public_subnet_cidr  = "10.0.0.0/8"
    private_subnet_cidr = "192.168.50.0/24"
  }
  assert {
    condition     = google_compute_subnetwork.public.ip_cidr_range == "10.0.0.0/8"
    error_message = "10.0.0.0/8 lies inside an RFC 1918 block and must be accepted for public_subnet_cidr."
  }
}

run "rfc1918_public_172_16_0_0_12_accepted" {
  command = plan
  variables {
    public_subnet_cidr  = "172.16.0.0/12"
    private_subnet_cidr = "10.200.0.0/24"
  }
  assert {
    condition     = google_compute_subnetwork.public.ip_cidr_range == "172.16.0.0/12"
    error_message = "172.16.0.0/12 lies inside an RFC 1918 block and must be accepted for public_subnet_cidr."
  }
}

run "rfc1918_public_172_31_255_0_24_accepted" {
  command = plan
  variables {
    public_subnet_cidr  = "172.31.255.0/24"
    private_subnet_cidr = "10.200.0.0/24"
  }
  assert {
    condition     = google_compute_subnetwork.public.ip_cidr_range == "172.31.255.0/24"
    error_message = "172.31.255.0/24 lies inside an RFC 1918 block and must be accepted for public_subnet_cidr."
  }
}

run "rfc1918_public_192_168_0_0_16_accepted" {
  command = plan
  variables {
    public_subnet_cidr  = "192.168.0.0/16"
    private_subnet_cidr = "10.200.0.0/24"
  }
  assert {
    condition     = google_compute_subnetwork.public.ip_cidr_range == "192.168.0.0/16"
    error_message = "192.168.0.0/16 lies inside an RFC 1918 block and must be accepted for public_subnet_cidr."
  }
}

run "rfc1918_public_192_168_255_248_29_accepted" {
  command = plan
  variables {
    public_subnet_cidr  = "192.168.255.248/29"
    private_subnet_cidr = "10.200.0.0/24"
  }
  assert {
    condition     = google_compute_subnetwork.public.ip_cidr_range == "192.168.255.248/29"
    error_message = "192.168.255.248/29 lies inside an RFC 1918 block and must be accepted for public_subnet_cidr."
  }
}

run "rfc1918_private_192_168_0_0_15_rejected" {
  command = plan
  variables {
    private_subnet_cidr = "192.168.0.0/15"
    public_subnet_cidr  = "10.200.0.0/24"
  }
  expect_failures = [var.private_subnet_cidr]
}

run "rfc1918_private_192_168_0_0_14_rejected" {
  command = plan
  variables {
    private_subnet_cidr = "192.168.0.0/14"
    public_subnet_cidr  = "10.200.0.0/24"
  }
  expect_failures = [var.private_subnet_cidr]
}

run "rfc1918_private_172_16_0_0_11_rejected" {
  command = plan
  variables {
    private_subnet_cidr = "172.16.0.0/11"
    public_subnet_cidr  = "10.200.0.0/24"
  }
  expect_failures = [var.private_subnet_cidr]
}

run "rfc1918_private_10_0_0_0_7_rejected" {
  command = plan
  variables {
    private_subnet_cidr = "10.0.0.0/7"
    public_subnet_cidr  = "10.200.0.0/24"
  }
  expect_failures = [var.private_subnet_cidr]
}

run "rfc1918_private_8_8_8_0_24_rejected" {
  command = plan
  variables {
    private_subnet_cidr = "8.8.8.0/24"
    public_subnet_cidr  = "10.200.0.0/24"
  }
  expect_failures = [var.private_subnet_cidr]
}

run "rfc1918_private_172_32_0_0_24_rejected" {
  command = plan
  variables {
    private_subnet_cidr = "172.32.0.0/24"
    public_subnet_cidr  = "10.200.0.0/24"
  }
  expect_failures = [var.private_subnet_cidr]
}

run "rfc1918_private_11_0_0_0_8_rejected" {
  command = plan
  variables {
    private_subnet_cidr = "11.0.0.0/8"
    public_subnet_cidr  = "10.200.0.0/24"
  }
  expect_failures = [var.private_subnet_cidr]
}

run "rfc1918_private_fd00_64_rejected" {
  command = plan
  variables {
    private_subnet_cidr = "fd00::/64"
    public_subnet_cidr  = "10.200.0.0/24"
  }
  expect_failures = [var.private_subnet_cidr]
}

run "rfc1918_private_10_0_0_0_rejected" {
  command = plan
  variables {
    private_subnet_cidr = "10.0.0.0"
    public_subnet_cidr  = "10.200.0.0/24"
  }
  expect_failures = [var.private_subnet_cidr]
}

run "rfc1918_private_10_0_0_256_24_rejected" {
  command = plan
  variables {
    private_subnet_cidr = "10.0.0.256/24"
    public_subnet_cidr  = "10.200.0.0/24"
  }
  expect_failures = [var.private_subnet_cidr]
}

run "rfc1918_private_10_0_0_0_8_accepted" {
  command = plan
  variables {
    private_subnet_cidr = "10.0.0.0/8"
    public_subnet_cidr  = "192.168.50.0/24"
  }
  assert {
    condition     = google_compute_subnetwork.private.ip_cidr_range == "10.0.0.0/8"
    error_message = "10.0.0.0/8 lies inside an RFC 1918 block and must be accepted for private_subnet_cidr."
  }
}

run "rfc1918_private_172_16_0_0_12_accepted" {
  command = plan
  variables {
    private_subnet_cidr = "172.16.0.0/12"
    public_subnet_cidr  = "10.200.0.0/24"
  }
  assert {
    condition     = google_compute_subnetwork.private.ip_cidr_range == "172.16.0.0/12"
    error_message = "172.16.0.0/12 lies inside an RFC 1918 block and must be accepted for private_subnet_cidr."
  }
}

run "rfc1918_private_172_31_255_0_24_accepted" {
  command = plan
  variables {
    private_subnet_cidr = "172.31.255.0/24"
    public_subnet_cidr  = "10.200.0.0/24"
  }
  assert {
    condition     = google_compute_subnetwork.private.ip_cidr_range == "172.31.255.0/24"
    error_message = "172.31.255.0/24 lies inside an RFC 1918 block and must be accepted for private_subnet_cidr."
  }
}

run "rfc1918_private_192_168_0_0_16_accepted" {
  command = plan
  variables {
    private_subnet_cidr = "192.168.0.0/16"
    public_subnet_cidr  = "10.200.0.0/24"
  }
  assert {
    condition     = google_compute_subnetwork.private.ip_cidr_range == "192.168.0.0/16"
    error_message = "192.168.0.0/16 lies inside an RFC 1918 block and must be accepted for private_subnet_cidr."
  }
}

run "rfc1918_private_192_168_255_248_29_accepted" {
  command = plan
  variables {
    private_subnet_cidr = "192.168.255.248/29"
    public_subnet_cidr  = "10.200.0.0/24"
  }
  assert {
    condition     = google_compute_subnetwork.private.ip_cidr_range == "192.168.255.248/29"
    error_message = "192.168.255.248/29 lies inside an RFC 1918 block and must be accepted for private_subnet_cidr."
  }
}
