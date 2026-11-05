# Custom-mode VPC. GCP subnets are regional and have no "public" flag; the
# public/private split is enforced by external-IP policy, service-account
# firewall targets and NAT scope (see DESIGN.md §2.1).
resource "google_compute_network" "this" {
  project                 = var.project_id
  name                    = local.names.network
  description             = "Custom VPC for the secure web backend (Terraform-managed)."
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"

  # Keep the system default route (0.0.0.0/0 -> default internet gateway).
  # Cloud NAT depends on it. VMs without an external IP can only use it
  # through Cloud NAT, so it does not expose the private VM.
  delete_default_routes_on_create = false
}

# Public tier: reserved for internet-facing workloads. The module places no
# VM here, and the global load balancer cannot live in a subnet.
resource "google_compute_subnetwork" "public" {
  project       = var.project_id
  name          = local.names.public_subnet
  description   = "Public tier (no workloads by default; no NAT; no ingress allow rules)."
  region        = var.region
  network       = google_compute_network.this.id
  ip_cidr_range = var.public_subnet_cidr
  stack_type    = "IPV4_ONLY"
  # Private Google Access only affects VMs WITHOUT external IPs, so enabling it
  # exposes nothing; it keeps any internal-only VM here off the internet path
  # for Google APIs (trivy GCP-0075).
  private_ip_google_access = true

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# Private tier: the backend VM (no external IP). Google APIs via Private
# Google Access; internet egress only through Cloud NAT.
resource "google_compute_subnetwork" "private" {
  project                  = var.project_id
  name                     = local.names.private_subnet
  description              = "Private tier for the backend VM (no external IPs)."
  region                   = var.region
  network                  = google_compute_network.this.id
  ip_cidr_range            = var.private_subnet_cidr
  stack_type               = "IPV4_ONLY"
  private_ip_google_access = true

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_router" "nat" {
  count = var.enable_cloud_nat ? 1 : 0

  project     = var.project_id
  name        = local.names.router
  description = "Cloud Router for Cloud NAT (private subnet egress)."
  region      = var.region
  network     = google_compute_network.this.id
}

# Outbound-only NAT for the private subnet's primary range. The public subnet
# is deliberately not listed.
resource "google_compute_router_nat" "this" {
  count = var.enable_cloud_nat ? 1 : 0

  project                            = var.project_id
  name                               = local.names.nat
  region                             = var.region
  router                             = google_compute_router.nat[0].name
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"

  subnetwork {
    name                    = google_compute_subnetwork.private.self_link
    source_ip_ranges_to_nat = ["PRIMARY_IP_RANGE"]
  }

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}
