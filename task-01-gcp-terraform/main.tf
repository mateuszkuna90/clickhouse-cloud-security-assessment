# Secure GCP web backend module (assessment Task 1).
#
# File layout:
#   main.tf          shared locals (names, Google source ranges, labels)
#   network.tf       custom VPC, public/private subnets, Cloud Router + NAT
#   firewall.tf      ingress rules (LB->80, trusted->22, logged deny-all)
#   iam.tf           VM service account and resource-scoped admin grants
#   compute.tf       private VM and unmanaged instance group
#   load_balancer.tf global external HTTPS load balancer and TLS policy
#
# The IAP TCP forwarding range (35.235.240.0/20) is the default of
# var.ssh_source_ranges in variables.tf.
# https://docs.cloud.google.com/iap/docs/using-tcp-forwarding

locals {
  # Source ranges for traffic from the global external Application Load
  # Balancer to instance-group backends, and for its health-check probes.
  # https://docs.cloud.google.com/load-balancing/docs/https (firewall rules)
  # https://docs.cloud.google.com/load-balancing/docs/health-check-concepts
  # Google can add probers without notice; re-check these ranges on upgrade.
  lb_proxy_ranges          = ["130.211.0.0/22", "35.191.0.0/16"]
  lb_health_check_ranges   = ["35.191.0.0/16"]
  lb_backend_source_ranges = sort(distinct(concat(local.lb_proxy_ranges, local.lb_health_check_ranges)))

  backend_port      = 80
  backend_port_name = "http"

  names = {
    network          = "${var.name_prefix}-vpc"
    public_subnet    = "${var.name_prefix}-public"
    private_subnet   = "${var.name_prefix}-private"
    router           = "${var.name_prefix}-router"
    nat              = "${var.name_prefix}-nat"
    fw_lb_to_backend = "${var.name_prefix}-allow-lb-to-backend-http"
    fw_ssh           = "${var.name_prefix}-allow-ssh-trusted"
    fw_deny_all      = "${var.name_prefix}-deny-all-ingress"
    vm_sa            = "${var.name_prefix}-vm"
    instance         = "${var.name_prefix}-backend"
    instance_group   = "${var.name_prefix}-backend-uig"
    health_check     = "${var.name_prefix}-http-hc"
    backend_service  = "${var.name_prefix}-backend-svc"
    url_map          = "${var.name_prefix}-url-map"
    ssl_policy       = "${var.name_prefix}-ssl-policy"
    managed_cert     = "${var.name_prefix}-managed-cert"
    https_proxy      = "${var.name_prefix}-https-proxy"
    address          = "${var.name_prefix}-lb-ip"
    forwarding_rule  = "${var.name_prefix}-https-fr"
  }

  labels = merge(var.labels, {
    managed-by = "terraform"
    component  = "secure-web"
  })

  use_managed_certificate = length(var.managed_certificate_domains) > 0
  ssl_certificates = (
    local.use_managed_certificate
    ? [google_compute_managed_ssl_certificate.this[0].id]
    : var.ssl_certificate_self_links
  )

  # The only project roles the VM service account may ever receive. Both are
  # write-only telemetry roles used by the Ops Agent. Mirrors the validation
  # of var.vm_service_account_roles.
  allowed_vm_project_roles = ["roles/logging.logWriter", "roles/monitoring.metricWriter"]

  ssh_admin_members = toset(var.ssh_admin_members)
  os_login_role     = var.ssh_admin_sudo ? "roles/compute.osAdminLogin" : "roles/compute.osLogin"
}
