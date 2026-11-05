# Validation of these values happens in the module; this root only passes
# them through.

variable "project_id" {
  description = "Existing GCP project ID."
  type        = string
}

variable "region" {
  description = "GCP region, for example europe-west1."
  type        = string
}

variable "zone" {
  description = "GCP zone inside var.region, for example europe-west1-b."
  type        = string
}

variable "name_prefix" {
  description = "Prefix for resource names (4-20 chars)."
  type        = string
  default     = "secure-web"
}

variable "managed_certificate_domains" {
  description = "Domains you control, for the Google-managed certificate."
  type        = list(string)
}

variable "ssh_source_ranges" {
  description = "Trusted SSH source ranges. Default: IAP TCP forwarding range."
  type        = list(string)
  default     = ["35.235.240.0/20"]
}

variable "ssh_admin_members" {
  description = "Principals allowed to SSH via IAP + OS Login (prefer group:)."
  type        = list(string)
  default     = []
}

variable "deletion_protection" {
  description = "Deletion protection for the VM."
  type        = bool
  default     = true
}

variable "impersonate_service_account" {
  description = "Optional deployer service account to impersonate (short-lived credentials). Null uses your ADC identity directly."
  type        = string
  default     = null
}
