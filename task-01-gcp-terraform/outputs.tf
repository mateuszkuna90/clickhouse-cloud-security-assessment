# None of these values is secret (IDs, a public IP, a private IP, commands),
# so no output is marked sensitive. The module produces no credentials.

output "network_id" {
  description = "ID of the custom VPC."
  value       = google_compute_network.this.id
}

output "network_self_link" {
  description = "Self-link of the custom VPC."
  value       = google_compute_network.this.self_link
}

output "public_subnet_id" {
  description = "ID of the public subnet."
  value       = google_compute_subnetwork.public.id
}

output "private_subnet_id" {
  description = "ID of the private subnet."
  value       = google_compute_subnetwork.private.id
}

output "public_subnet_self_link" {
  description = "Self-link of the public subnet."
  value       = google_compute_subnetwork.public.self_link
}

output "private_subnet_self_link" {
  description = "Self-link of the private subnet."
  value       = google_compute_subnetwork.private.self_link
}

output "instance_id" {
  description = "Resource ID of the backend VM."
  value       = google_compute_instance.this.id
}

output "instance_name" {
  description = "Name of the backend VM."
  value       = google_compute_instance.this.name
}

output "instance_self_link" {
  description = "Self-link of the backend VM."
  value       = google_compute_instance.this.self_link
}

output "instance_internal_ip" {
  description = "Private IPv4 address of the backend VM (it has no external IP)."
  value       = google_compute_instance.this.network_interface[0].network_ip
}

output "instance_group_self_link" {
  description = "Self-link of the unmanaged instance group."
  value       = google_compute_instance_group.this.self_link
}

output "vm_service_account_email" {
  description = "Email of the dedicated VM service account."
  value       = google_service_account.vm.email
}

output "load_balancer_ip" {
  description = "Public IPv4 address of the HTTPS load balancer. Create a DNS A record for each certificate domain pointing here."
  value       = google_compute_global_address.this.address
}

output "https_url" {
  description = "HTTPS URL of the service (first managed-certificate domain), or null when a bring-your-own certificate is used. Works only after DNS and certificate issuance."
  value       = local.use_managed_certificate ? "https://${var.managed_certificate_domains[0]}/" : null
}

output "backend_service_id" {
  description = "ID of the backend service (use with `gcloud compute backend-services get-health`)."
  value       = google_compute_backend_service.this.id
}

output "managed_certificate_name" {
  description = "Name of the Google-managed certificate, or null when ssl_certificate_self_links is used."
  value       = local.use_managed_certificate ? google_compute_managed_ssl_certificate.this[0].name : null
}

output "ssl_policy_id" {
  description = "ID of the SSL policy attached to the HTTPS proxy."
  value       = google_compute_ssl_policy.this.id
}

output "ssh_command_iap" {
  description = "Default SSH path: IAP TCP forwarding + OS Login. Needs the IAP/OS Login grants from ssh_admin_members and project-level compute read access."
  value       = "gcloud compute ssh ${google_compute_instance.this.name} --zone ${var.zone} --project ${var.project_id} --tunnel-through-iap"
}

output "ssh_command_internal_ip" {
  description = "Optional SSH over EXISTING private connectivity (Cloud VPN/Interconnect). Works only if your network routes to the private subnet and its private CIDR is in ssh_source_ranges."
  value       = "gcloud compute ssh ${google_compute_instance.this.name} --zone ${var.zone} --project ${var.project_id} --internal-ip"
}
