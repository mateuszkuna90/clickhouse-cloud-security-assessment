module "secure_web" {
  source = "../.."

  project_id  = var.project_id
  region      = var.region
  zone        = var.zone
  name_prefix = var.name_prefix

  # SSH: IAP by default. Add private VPN/Interconnect CIDRs here only if that
  # connectivity already exists.
  ssh_source_ranges = var.ssh_source_ranges
  ssh_admin_members = var.ssh_admin_members

  # TLS: Google-managed certificate. DNS A record(s) must point to the
  # load_balancer_ip output before the certificate can become ACTIVE.
  managed_certificate_domains = var.managed_certificate_domains
  ssl_policy_profile          = "RESTRICTED"
  ssl_min_tls_version         = "TLS_1_2"

  deletion_protection = var.deletion_protection

  labels = {
    environment = "assessment"
  }
}
