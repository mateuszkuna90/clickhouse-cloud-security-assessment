# Default secure configuration, network, compute, firewall, load balancer and
# outputs. Runs against a MOCK provider: `command = apply` creates nothing and
# calls no Google API; it only lets computed values (IDs, self-links) be known.

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

override_resource {
  target = google_compute_global_address.this
  values = {
    address = "203.0.113.10"
  }
}

run "vpc_and_subnets" {
  command = apply

  assert {
    condition     = google_compute_network.this.auto_create_subnetworks == false
    error_message = "VPC must be custom mode."
  }
  assert {
    condition     = google_compute_network.this.routing_mode == "REGIONAL"
    error_message = "VPC routing mode must be REGIONAL."
  }
  assert {
    condition     = google_compute_network.this.delete_default_routes_on_create == false
    error_message = "The default internet route must be preserved (Cloud NAT depends on it)."
  }
  assert {
    condition     = google_compute_subnetwork.public.network == google_compute_network.this.id && google_compute_subnetwork.private.network == google_compute_network.this.id
    error_message = "Both subnets must belong to the custom VPC."
  }
  assert {
    condition     = google_compute_subnetwork.public.region == "europe-west1" && google_compute_subnetwork.private.region == "europe-west1"
    error_message = "Subnets must be in var.region."
  }
  assert {
    condition     = google_compute_subnetwork.public.ip_cidr_range == "10.10.0.0/24" && google_compute_subnetwork.private.ip_cidr_range == "10.10.1.0/24"
    error_message = "Unexpected default subnet CIDRs."
  }
  assert {
    condition     = google_compute_subnetwork.private.private_ip_google_access == true && google_compute_subnetwork.public.private_ip_google_access == true
    error_message = "Private Google Access must be on for both subnets (it only affects VMs without external IPs)."
  }
  assert {
    condition     = length(google_compute_subnetwork.public.log_config) == 1 && length(google_compute_subnetwork.private.log_config) == 1
    error_message = "VPC Flow Logs must be enabled on both subnets."
  }
  assert {
    condition     = google_compute_subnetwork.public.stack_type == "IPV4_ONLY" && google_compute_subnetwork.private.stack_type == "IPV4_ONLY"
    error_message = "Subnets must be IPv4-only."
  }
}

run "private_vm_hardening" {
  command = apply

  assert {
    condition     = length(google_compute_instance.this.network_interface) == 1
    error_message = "VM must have exactly one network interface."
  }
  assert {
    condition     = length(google_compute_instance.this.network_interface[0].access_config) == 0
    error_message = "VM must have NO external IP (no access_config)."
  }
  assert {
    condition     = google_compute_instance.this.network_interface[0].subnetwork == google_compute_subnetwork.private.self_link
    error_message = "VM must be in the private subnet."
  }
  assert {
    condition     = google_compute_instance.this.can_ip_forward == false
    error_message = "IP forwarding must be off."
  }
  assert {
    condition = (
      google_compute_instance.this.shielded_instance_config[0].enable_secure_boot &&
      google_compute_instance.this.shielded_instance_config[0].enable_vtpm &&
      google_compute_instance.this.shielded_instance_config[0].enable_integrity_monitoring
    )
    error_message = "Shielded VM (secure boot, vTPM, integrity monitoring) must be on."
  }
  assert {
    condition = (
      google_compute_instance.this.metadata["enable-oslogin"] == "TRUE" &&
      google_compute_instance.this.metadata["block-project-ssh-keys"] == "TRUE" &&
      google_compute_instance.this.metadata["serial-port-enable"] == "FALSE"
    )
    error_message = "OS Login on, project SSH keys blocked, serial port off."
  }
  assert {
    condition     = google_compute_instance.this.service_account[0].email == google_service_account.vm.email
    error_message = "VM must run as the dedicated service account."
  }
  assert {
    condition     = !endswith(google_compute_instance.this.service_account[0].email, "-compute@developer.gserviceaccount.com")
    error_message = "VM must not use the default Compute Engine service account."
  }
  assert {
    condition     = toset(google_compute_instance.this.service_account[0].scopes) == toset(["cloud-platform"])
    error_message = "Scope must be cloud-platform only (access limited by IAM)."
  }
  assert {
    condition     = google_compute_instance.this.deletion_protection == true
    error_message = "Deletion protection must default to true."
  }
  # kms_key_self_link is optional+computed, so the mock fills it with a random
  # value; the default (Google-managed encryption) cannot be asserted here.
  assert {
    condition = (
      google_compute_instance.this.boot_disk[0].initialize_params[0].image == "debian-cloud/debian-12" &&
      google_compute_instance.this.boot_disk[0].initialize_params[0].type == "pd-balanced" &&
      google_compute_instance.this.boot_disk[0].auto_delete == true
    )
    error_message = "Unexpected boot disk configuration."
  }
  assert {
    condition     = google_compute_instance.this.zone == "europe-west1-b" && google_compute_instance.this.machine_type == "e2-small"
    error_message = "Unexpected VM placement or machine type."
  }
}

run "unmanaged_instance_group" {
  command = apply

  assert {
    condition     = google_compute_instance_group.this.zone == "europe-west1-b"
    error_message = "Instance group must be in var.zone."
  }
  assert {
    condition     = toset(google_compute_instance_group.this.instances) == toset([google_compute_instance.this.self_link])
    error_message = "Instance group must contain exactly the backend VM."
  }
  assert {
    condition     = length(google_compute_instance_group.this.named_port) == 1 && google_compute_instance_group.this.named_port[0].name == "http" && google_compute_instance_group.this.named_port[0].port == 80
    error_message = "Instance group must expose exactly one named port http:80."
  }
  assert {
    condition     = google_compute_instance_group.this.network == google_compute_network.this.self_link
    error_message = "Instance group must be in the custom VPC."
  }
}

run "firewall_rules" {
  command = apply

  # HTTP 80 from Google LB proxy + health-check ranges only.
  assert {
    condition     = google_compute_firewall.allow_lb_to_backend_http.direction == "INGRESS"
    error_message = "LB rule must be ingress."
  }
  assert {
    condition     = toset(google_compute_firewall.allow_lb_to_backend_http.source_ranges) == toset(["130.211.0.0/22", "35.191.0.0/16"])
    error_message = "HTTP backend rule must allow exactly the Google Front End / health-check ranges."
  }
  assert {
    condition     = length(google_compute_firewall.allow_lb_to_backend_http.allow) == 1 && one(google_compute_firewall.allow_lb_to_backend_http.allow).protocol == "tcp" && one(google_compute_firewall.allow_lb_to_backend_http.allow).ports == tolist(["80"])
    error_message = "HTTP backend rule must allow only tcp:80."
  }
  assert {
    condition     = toset(google_compute_firewall.allow_lb_to_backend_http.target_service_accounts) == toset([google_service_account.vm.email])
    error_message = "HTTP backend rule must target only the VM service account."
  }
  assert {
    condition     = try(length(google_compute_firewall.allow_lb_to_backend_http.target_tags), 0) == 0 && try(length(google_compute_firewall.allow_ssh_trusted.target_tags), 0) == 0
    error_message = "Rules must not use network tags as targets."
  }

  # SSH 22 from IAP only by default.
  assert {
    condition     = toset(google_compute_firewall.allow_ssh_trusted.source_ranges) == toset(["35.235.240.0/20"])
    error_message = "Default SSH source must be the IAP TCP forwarding range only."
  }
  assert {
    condition     = length(google_compute_firewall.allow_ssh_trusted.allow) == 1 && one(google_compute_firewall.allow_ssh_trusted.allow).protocol == "tcp" && one(google_compute_firewall.allow_ssh_trusted.allow).ports == tolist(["22"])
    error_message = "SSH rule must allow only tcp:22."
  }
  assert {
    condition     = toset(google_compute_firewall.allow_ssh_trusted.target_service_accounts) == toset([google_service_account.vm.email])
    error_message = "SSH rule must target only the VM service account."
  }

  # No allow rule is open to the internet.
  assert {
    condition = alltrue([
      for r in [google_compute_firewall.allow_lb_to_backend_http, google_compute_firewall.allow_ssh_trusted] :
      !contains(tolist(r.source_ranges), "0.0.0.0/0") && !contains(tolist(r.source_ranges), "::/0")
    ])
    error_message = "No allow rule may have 0.0.0.0/0 or ::/0 as a source."
  }

  # Logged default deny.
  assert {
    condition     = google_compute_firewall.deny_all_ingress.priority == 65534 && length(google_compute_firewall.deny_all_ingress.allow) == 0 && one(google_compute_firewall.deny_all_ingress.deny).protocol == "all"
    error_message = "Deny-all rule must be priority 65534 and deny all protocols."
  }
  assert {
    condition = alltrue([
      for r in [google_compute_firewall.allow_lb_to_backend_http, google_compute_firewall.allow_ssh_trusted, google_compute_firewall.deny_all_ingress] :
      length(r.log_config) == 1 && r.network == google_compute_network.this.id
    ])
    error_message = "All firewall rules must be in the custom VPC and have logging enabled."
  }
}

run "https_load_balancer" {
  command = apply

  assert {
    condition     = google_compute_global_forwarding_rule.https.port_range == "443"
    error_message = "Frontend must listen on 443 only."
  }
  assert {
    condition     = google_compute_global_forwarding_rule.https.load_balancing_scheme == "EXTERNAL_MANAGED" && google_compute_global_forwarding_rule.https.ip_protocol == "TCP"
    error_message = "Frontend must be a global external Application LB (EXTERNAL_MANAGED, TCP)."
  }
  assert {
    condition     = google_compute_global_forwarding_rule.https.target == google_compute_target_https_proxy.this.id && google_compute_global_forwarding_rule.https.ip_address == google_compute_global_address.this.id
    error_message = "Forwarding rule must use the reserved global IP and the HTTPS proxy."
  }
  assert {
    condition     = google_compute_global_address.this.address_type == "EXTERNAL" && google_compute_global_address.this.ip_version == "IPV4"
    error_message = "Global address must be external IPv4."
  }
  assert {
    condition     = google_compute_target_https_proxy.this.url_map == google_compute_url_map.this.id && google_compute_target_https_proxy.this.ssl_policy == google_compute_ssl_policy.this.id
    error_message = "HTTPS proxy must use the URL map and SSL policy."
  }
  assert {
    condition     = google_compute_target_https_proxy.this.ssl_certificates == tolist([google_compute_managed_ssl_certificate.this[0].id])
    error_message = "HTTPS proxy must use the managed certificate."
  }
  assert {
    condition     = google_compute_managed_ssl_certificate.this[0].managed[0].domains == tolist(["app.example.com"])
    error_message = "Managed certificate must cover the configured domain."
  }
  assert {
    condition     = google_compute_url_map.this.default_service == google_compute_backend_service.this.id
    error_message = "URL map must route to the backend service."
  }
  assert {
    condition = (
      google_compute_backend_service.this.load_balancing_scheme == "EXTERNAL_MANAGED" &&
      google_compute_backend_service.this.protocol == "HTTP" &&
      google_compute_backend_service.this.port_name == "http"
    )
    error_message = "Backend service must be EXTERNAL_MANAGED, HTTP, named port http."
  }
  assert {
    condition     = length(google_compute_backend_service.this.backend) == 1 && one(google_compute_backend_service.this.backend).group == google_compute_instance_group.this.self_link
    error_message = "Backend service must have exactly the unmanaged instance group as backend."
  }
  assert {
    condition     = toset(google_compute_backend_service.this.health_checks) == toset([google_compute_health_check.http.id])
    error_message = "Backend service must use the HTTP health check."
  }
  assert {
    condition     = google_compute_backend_service.this.log_config[0].enable == true && google_compute_backend_service.this.security_policy == null
    error_message = "Backend logging on; no Cloud Armor policy unless provided."
  }
  assert {
    condition     = google_compute_health_check.http.http_health_check[0].port == 80 && google_compute_health_check.http.http_health_check[0].request_path == "/" && google_compute_health_check.http.log_config[0].enable == true
    error_message = "Health check must probe HTTP 80 at / with logging on."
  }
}

run "outputs" {
  command = apply

  assert {
    condition     = output.load_balancer_ip == "203.0.113.10"
    error_message = "load_balancer_ip must be the reserved global address."
  }
  assert {
    condition     = output.https_url == "https://app.example.com/"
    error_message = "https_url must use the first managed domain."
  }
  assert {
    condition     = output.ssh_command_iap == "gcloud compute ssh secure-web-backend --zone europe-west1-b --project example-project-id --tunnel-through-iap"
    error_message = "Unexpected IAP SSH command."
  }
  assert {
    condition     = output.ssh_command_internal_ip == "gcloud compute ssh secure-web-backend --zone europe-west1-b --project example-project-id --internal-ip"
    error_message = "Unexpected private-connectivity SSH command."
  }
  assert {
    condition = (
      output.network_id == google_compute_network.this.id &&
      output.public_subnet_id == google_compute_subnetwork.public.id &&
      output.private_subnet_id == google_compute_subnetwork.private.id &&
      output.instance_id == google_compute_instance.this.id &&
      output.instance_internal_ip == google_compute_instance.this.network_interface[0].network_ip &&
      output.backend_service_id == google_compute_backend_service.this.id &&
      output.vm_service_account_email == google_service_account.vm.email
    )
    error_message = "Identifier outputs must match their resources."
  }
  assert {
    condition     = startswith(output.managed_certificate_name, "secure-web-managed-cert-")
    error_message = "Managed certificate name must use the prefix and a domain hash."
  }
}

run "byo_certificate" {
  command = apply

  variables {
    managed_certificate_domains = []
    ssl_certificate_self_links  = ["projects/example-project-id/global/sslCertificates/example-cert"]
  }

  assert {
    condition     = length(google_compute_managed_ssl_certificate.this) == 0
    error_message = "No managed certificate when a BYO certificate is referenced."
  }
  assert {
    condition     = google_compute_target_https_proxy.this.ssl_certificates == tolist(["projects/example-project-id/global/sslCertificates/example-cert"])
    error_message = "HTTPS proxy must reference the provided certificate."
  }
  assert {
    condition     = output.https_url == null && output.managed_certificate_name == null
    error_message = "https_url and managed_certificate_name are null for BYO certificates."
  }
}
