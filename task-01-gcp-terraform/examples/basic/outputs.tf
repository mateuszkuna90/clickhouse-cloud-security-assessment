output "load_balancer_ip" {
  description = "Create DNS A records for the certificate domains pointing here."
  value       = module.secure_web.load_balancer_ip
}

output "https_url" {
  description = "Service URL (after DNS and certificate issuance)."
  value       = module.secure_web.https_url
}

output "instance_internal_ip" {
  description = "Private IP of the backend VM."
  value       = module.secure_web.instance_internal_ip
}

output "backend_service_id" {
  description = "Backend service ID, for health checks."
  value       = module.secure_web.backend_service_id
}

output "ssh_command_iap" {
  description = "Default SSH command (IAP + OS Login)."
  value       = module.secure_web.ssh_command_iap
}

output "ssh_command_internal_ip" {
  description = "SSH command for existing private connectivity only."
  value       = module.secure_web.ssh_command_internal_ip
}
