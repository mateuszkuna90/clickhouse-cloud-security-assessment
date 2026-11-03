# Global external Application Load Balancer (EXTERNAL_MANAGED). All frontend
# resources are global and live on Google's edge, not in a VPC subnet.
# Chain: global IP -> forwarding rule :443 -> HTTPS proxy (cert + SSL policy)
#        -> URL map -> backend service (HTTP) -> instance group -> VM :80.

resource "google_compute_health_check" "http" {
  project             = var.project_id
  name                = local.names.health_check
  description         = "HTTP ${local.backend_port} health check for the nginx backend."
  check_interval_sec  = 10
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 3

  http_health_check {
    port         = local.backend_port
    request_path = var.health_check_path
  }

  log_config {
    enable = true
  }
}

resource "google_compute_backend_service" "this" {
  project               = var.project_id
  name                  = local.names.backend_service
  description           = "Backend service for the private nginx VM."
  load_balancing_scheme = "EXTERNAL_MANAGED"
  protocol              = "HTTP"
  port_name             = local.backend_port_name
  timeout_sec           = 30
  health_checks         = [google_compute_health_check.http.id]
  security_policy       = var.security_policy

  backend {
    group           = google_compute_instance_group.this.self_link
    balancing_mode  = "UTILIZATION"
    capacity_scaler = 1.0
  }

  log_config {
    enable      = true
    sample_rate = 1.0
  }
}

resource "google_compute_url_map" "this" {
  project         = var.project_id
  name            = local.names.url_map
  description     = "Routes all requests to the backend service."
  default_service = google_compute_backend_service.this.id
}

resource "google_compute_ssl_policy" "this" {
  project         = var.project_id
  name            = local.names.ssl_policy
  description     = "TLS policy for the HTTPS frontend."
  profile         = var.ssl_policy_profile
  min_tls_version = var.ssl_min_tls_version

  lifecycle {
    # Defence in depth for the cross-variable validation in variables.tf.
    precondition {
      condition     = var.ssl_min_tls_version != "TLS_1_3" || var.ssl_policy_profile == "RESTRICTED"
      error_message = "min_tls_version TLS_1_3 requires profile RESTRICTED (Google Cloud SSL policy constraint)."
    }
    precondition {
      condition = contains([
        "RESTRICTED/TLS_1_2",
        "RESTRICTED/TLS_1_3",
        "MODERN/TLS_1_2",
      ], "${var.ssl_policy_profile}/${var.ssl_min_tls_version}")
      error_message = "Only RESTRICTED+TLS_1_2, RESTRICTED+TLS_1_3 and MODERN+TLS_1_2 are allowed."
    }
  }
}

# Google-managed certificate: issued and renewed by Google; no private key in
# Terraform state or the repository. Becomes ACTIVE only after public DNS for
# every domain points to the load balancer IP.
resource "google_compute_managed_ssl_certificate" "this" {
  count = local.use_managed_certificate ? 1 : 0

  project = var.project_id
  # The domain list cannot be changed in place, so a change replaces the
  # certificate. The domain-derived suffix gives the replacement a new name and
  # create_before_destroy lets Terraform create it and repoint the proxy before
  # deleting the old one (which avoids a "resource in use" delete failure).
  #
  # This is NOT a zero-downtime rotation: in that single apply the proxy is
  # switched to the NEW certificate only, which stays PROVISIONING until DNS
  # validation succeeds (up to 60 min after DNS propagates, then up to 30 min
  # before the LB serves it). HTTPS can fail in that window. For a staged
  # rotation, see README.md "Certificate rotation": create the new certificate
  # outside this module, reference old + new via ssl_certificate_self_links,
  # wait for ACTIVE, then remove the old one. The module does not automate it.
  name        = "${local.names.managed_cert}-${substr(sha256(join(",", var.managed_certificate_domains)), 0, 8)}"
  description = "Google-managed certificate for the HTTPS frontend."

  managed {
    domains = var.managed_certificate_domains
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "google_compute_target_https_proxy" "this" {
  project          = var.project_id
  name             = local.names.https_proxy
  description      = "Terminates TLS for the frontend."
  url_map          = google_compute_url_map.this.id
  ssl_certificates = local.ssl_certificates
  ssl_policy       = google_compute_ssl_policy.this.id
}

resource "google_compute_global_address" "this" {
  project      = var.project_id
  name         = local.names.address
  description  = "Public IPv4 address of the HTTPS load balancer."
  address_type = "EXTERNAL"
  ip_version   = "IPV4"
  labels       = local.labels
}

# PDF: "Allow only HTTPS (443) from the internet to the Load Balancer."
# This is the only frontend. There is no port 80 forwarding rule.
resource "google_compute_global_forwarding_rule" "https" {
  project               = var.project_id
  name                  = local.names.forwarding_rule
  description           = "HTTPS 443 frontend."
  load_balancing_scheme = "EXTERNAL_MANAGED"
  ip_protocol           = "TCP"
  port_range            = "443"
  ip_address            = google_compute_global_address.this.id
  target                = google_compute_target_https_proxy.this.id
  labels                = local.labels
}
