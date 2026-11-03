# ---------------------------------------------------------------------------
# Placement
# ---------------------------------------------------------------------------

variable "project_id" {
  description = "ID of the existing GCP project to deploy into."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a valid GCP project ID (6-30 chars, lowercase letters, digits, hyphens)."
  }
}

variable "region" {
  description = "Region for the subnets, Cloud Router and Cloud NAT (for example europe-west1)."
  type        = string

  validation {
    condition     = can(regex("^[a-z]+-[a-z]+[0-9]+$", var.region))
    error_message = "region must look like a GCP region, for example europe-west1."
  }
}

variable "zone" {
  description = "Zone for the backend VM and its unmanaged instance group. Must be inside var.region."
  type        = string

  validation {
    condition     = can(regex("^[a-z]+-[a-z]+[0-9]+-[a-z]$", var.zone)) && startswith(var.zone, "${var.region}-")
    error_message = "zone must be a GCP zone inside var.region (for example europe-west1-b for europe-west1)."
  }
}

variable "name_prefix" {
  description = "Prefix for all resource names. 4-20 chars; also used for the service account ID."
  type        = string
  default     = "secure-web"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,18}[a-z0-9]$", var.name_prefix))
    error_message = "name_prefix must be 4-20 chars: lowercase letters, digits, hyphens; start with a letter; not end with a hyphen."
  }
}

variable "labels" {
  description = "Extra labels applied to resources that support labels."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for k, v in var.labels :
      can(regex("^[a-z][a-z0-9_-]{0,62}$", k)) && can(regex("^[a-z0-9_-]{0,63}$", v))
    ])
    error_message = "Label keys must match ^[a-z][a-z0-9_-]{0,62}$ and values ^[a-z0-9_-]{0,63}$."
  }
}

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

# RFC 1918 containment (both subnet variables). A CIDR c lies ENTIRELY inside
# block B when c's prefix is at least B's prefix AND c's network address,
# truncated to B's prefix, equals B's network address. Checking only the first
# address or a text prefix is not enough: 192.168.0.0/15 starts inside
# 192.168.0.0/16 but extends to 192.169.255.255.
variable "public_subnet_cidr" {
  description = "Primary IPv4 range of the public subnet. Canonical CIDR, /8 to /29, entirely inside 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16."
  type        = string
  default     = "10.10.0.0/24"

  validation {
    condition = (
      can(cidrnetmask(var.public_subnet_cidr)) &&
      try(tonumber(split("/", var.public_subnet_cidr)[1]) >= 8 && tonumber(split("/", var.public_subnet_cidr)[1]) <= 29, false) &&
      try(cidrsubnet(var.public_subnet_cidr, 0, 0) == var.public_subnet_cidr, false)
    )
    error_message = "public_subnet_cidr must be a canonical IPv4 CIDR between /8 and /29 (for example 10.10.0.0/24)."
  }

  validation {
    condition = try(anytrue([
      for block in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] :
      tonumber(split("/", var.public_subnet_cidr)[1]) >= tonumber(split("/", block)[1]) &&
      cidrhost("${cidrhost(var.public_subnet_cidr, 0)}/${split("/", block)[1]}", 0) == cidrhost(block, 0)
    ]), false)
    error_message = "public_subnet_cidr must lie entirely inside one RFC 1918 block: 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16."
  }
}

variable "private_subnet_cidr" {
  description = "Primary IPv4 range of the private subnet. Canonical CIDR, /8 to /29, entirely inside 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16, not overlapping the public subnet."
  type        = string
  default     = "10.10.1.0/24"

  validation {
    condition = (
      can(cidrnetmask(var.private_subnet_cidr)) &&
      try(tonumber(split("/", var.private_subnet_cidr)[1]) >= 8 && tonumber(split("/", var.private_subnet_cidr)[1]) <= 29, false) &&
      try(cidrsubnet(var.private_subnet_cidr, 0, 0) == var.private_subnet_cidr, false)
    )
    error_message = "private_subnet_cidr must be a canonical IPv4 CIDR between /8 and /29 (for example 10.10.1.0/24)."
  }

  validation {
    condition = try(anytrue([
      for block in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] :
      tonumber(split("/", var.private_subnet_cidr)[1]) >= tonumber(split("/", block)[1]) &&
      cidrhost("${cidrhost(var.private_subnet_cidr, 0)}/${split("/", block)[1]}", 0) == cidrhost(block, 0)
    ]), false)
    error_message = "private_subnet_cidr must lie entirely inside one RFC 1918 block: 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16."
  }

  # Two CIDRs overlap if their network addresses are equal when both are
  # truncated to the shorter prefix.
  validation {
    condition = try(
      cidrhost("${cidrhost(var.private_subnet_cidr, 0)}/${min(tonumber(split("/", var.private_subnet_cidr)[1]), tonumber(split("/", var.public_subnet_cidr)[1]))}", 0)
      != cidrhost("${cidrhost(var.public_subnet_cidr, 0)}/${min(tonumber(split("/", var.private_subnet_cidr)[1]), tonumber(split("/", var.public_subnet_cidr)[1]))}", 0),
      false
    )
    error_message = "private_subnet_cidr must not overlap public_subnet_cidr."
  }
}

variable "enable_cloud_nat" {
  description = "Create Cloud Router + Cloud NAT for the private subnet so the VM can install nginx on first boot. Disabling it requires boot_image_includes_nginx = true."
  type        = bool
  default     = true

  validation {
    condition     = var.enable_cloud_nat || var.boot_image_includes_nginx
    error_message = "enable_cloud_nat = false leaves the VM with no internet egress, so the startup script cannot install nginx. Keep Cloud NAT, or use an image that already contains nginx and set boot_image_includes_nginx = true."
  }
}

# ---------------------------------------------------------------------------
# SSH administration
# ---------------------------------------------------------------------------

variable "ssh_source_ranges" {
  description = <<-EOT
    Trusted source ranges allowed to reach the VM on TCP 22. Default: the IAP
    TCP forwarding range (35.235.240.0/20). For SSH over Cloud VPN/Interconnect,
    add the administrators' PRIVATE network ranges. The VM has no external IP,
    so a public office CIDR here would not make it reachable.
  EOT
  type        = list(string)
  default     = ["35.235.240.0/20"]

  validation {
    condition     = length(var.ssh_source_ranges) > 0
    error_message = "ssh_source_ranges must contain at least one trusted range."
  }

  validation {
    condition = alltrue([
      for r in var.ssh_source_ranges :
      can(cidrnetmask(r)) &&
      try(tonumber(split("/", r)[1]) >= 8, false) &&
      try(cidrsubnet(r, 0, 0) == r, false)
    ])
    error_message = "Each ssh_source_ranges entry must be a canonical IPv4 CIDR with a prefix of /8 or longer. 0.0.0.0/0, ::/0 and other very broad ranges are rejected."
  }
}

variable "ssh_admin_members" {
  description = "Principals allowed to SSH through IAP with OS Login (user:, group: or serviceAccount:). Grants are scoped to this VM and its service account."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for m in var.ssh_admin_members :
      can(regex("^(user|group|serviceAccount):[^@\\s:]+@[^@\\s:]+\\.[^@\\s:]+$", m))
    ])
    error_message = "ssh_admin_members entries must be user:, group: or serviceAccount: principals with an email. allUsers, allAuthenticatedUsers and domain: are not allowed."
  }
}

variable "ssh_admin_sudo" {
  description = "Grant roles/compute.osAdminLogin (sudo) instead of roles/compute.osLogin to ssh_admin_members."
  type        = bool
  default     = false
}

# ---------------------------------------------------------------------------
# Compute
# ---------------------------------------------------------------------------

variable "machine_type" {
  description = "Machine type of the backend VM."
  type        = string
  default     = "e2-small"

  validation {
    condition     = can(regex("^[a-z][a-z0-9]*-[a-z0-9-]+$", var.machine_type))
    error_message = "machine_type must be a machine type name such as e2-small."
  }
}

variable "boot_image" {
  description = "Boot image (project/family or self-link). The startup script uses apt, so the image must be Debian-based."
  type        = string
  default     = "debian-cloud/debian-12"

  validation {
    condition     = length(trimspace(var.boot_image)) > 0
    error_message = "boot_image must not be empty."
  }
}

variable "boot_image_includes_nginx" {
  description = "Set true only if boot_image already contains nginx. Required when enable_cloud_nat = false."
  type        = bool
  default     = false
}

variable "boot_disk_size_gb" {
  description = "Boot disk size in GB."
  type        = number
  default     = 20

  validation {
    condition     = var.boot_disk_size_gb >= 10 && var.boot_disk_size_gb <= 100 && floor(var.boot_disk_size_gb) == var.boot_disk_size_gb
    error_message = "boot_disk_size_gb must be a whole number between 10 and 100."
  }
}

variable "boot_disk_kms_key_self_link" {
  description = "Optional Cloud KMS key for the boot disk (CMEK). Null uses Google-managed encryption. The Compute Engine service agent needs roles/cloudkms.cryptoKeyEncrypterDecrypter on the key."
  type        = string
  default     = null

  validation {
    condition     = var.boot_disk_kms_key_self_link == null || can(regex("^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$", var.boot_disk_kms_key_self_link))
    error_message = "boot_disk_kms_key_self_link must be null or projects/P/locations/L/keyRings/R/cryptoKeys/K."
  }
}

variable "vm_service_account_roles" {
  description = <<-EOT
    Optional project roles for the VM service account. Default: none, because
    nginx serving a static page calls no Google APIs. Only an explicit
    allowlist is accepted: roles/logging.logWriter and
    roles/monitoring.metricWriter (what an Ops Agent needs to write logs and
    metrics). Any other role, including custom roles, is rejected.
  EOT
  type        = set(string)
  default     = []

  # Explicit allowlist rather than a name-pattern denylist: a role name does not
  # prove a role is low-privilege (for example roles/compute.instanceAdmin.v1
  # does not end in "admin"). Keep in sync with local.allowed_vm_project_roles,
  # which the IAM resource enforces again as a precondition.
  validation {
    condition = alltrue([
      for r in var.vm_service_account_roles :
      contains(["roles/logging.logWriter", "roles/monitoring.metricWriter"], r)
    ])
    error_message = "vm_service_account_roles may only contain roles/logging.logWriter and/or roles/monitoring.metricWriter. All other roles (owner, editor, viewer, any admin role, impersonation roles, custom roles) are rejected."
  }
}

variable "deletion_protection" {
  description = "Enable deletion protection on the VM."
  type        = bool
  default     = true
}

# ---------------------------------------------------------------------------
# Load balancer and TLS
# ---------------------------------------------------------------------------

variable "managed_certificate_domains" {
  description = "Domains for a Google-managed certificate. Each must have a public DNS A record pointing to the load balancer IP. Exactly one of this or ssl_certificate_self_links must be set."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for d in var.managed_certificate_domains :
      can(regex("^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$", d))
    ])
    error_message = "managed_certificate_domains entries must be lowercase fully qualified domain names (no wildcards)."
  }

  validation {
    condition     = (length(var.managed_certificate_domains) > 0) != (length(var.ssl_certificate_self_links) > 0)
    error_message = "Set exactly one of managed_certificate_domains or ssl_certificate_self_links."
  }
}

variable "ssl_certificate_self_links" {
  description = "Existing global SSL certificate resources (created outside this module, for example by a PKI team). Private keys never pass through this module."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for c in var.ssl_certificate_self_links :
      can(regex("^(https://www\\.googleapis\\.com/compute/v1/)?projects/[^/]+/global/sslCertificates/[a-z]([-a-z0-9]*[a-z0-9])?$", c))
    ])
    error_message = "ssl_certificate_self_links entries must be global sslCertificates self-links or IDs."
  }
}

variable "ssl_policy_profile" {
  description = "SSL policy profile. Allowed: RESTRICTED (default) or MODERN. TLS_1_3 requires RESTRICTED."
  type        = string
  default     = "RESTRICTED"

  validation {
    condition     = contains(["RESTRICTED", "MODERN"], var.ssl_policy_profile)
    error_message = "ssl_policy_profile must be RESTRICTED or MODERN."
  }
}

variable "ssl_min_tls_version" {
  description = "Minimum TLS version. Allowed: TLS_1_2 (default) or TLS_1_3. TLS_1_3 requires ssl_policy_profile = RESTRICTED."
  type        = string
  default     = "TLS_1_2"

  validation {
    condition     = contains(["TLS_1_2", "TLS_1_3"], var.ssl_min_tls_version)
    error_message = "ssl_min_tls_version must be TLS_1_2 or TLS_1_3."
  }

  # Google Cloud constraint: a minimum of TLS 1.3 is only valid with RESTRICTED.
  validation {
    condition     = var.ssl_min_tls_version != "TLS_1_3" || var.ssl_policy_profile == "RESTRICTED"
    error_message = "ssl_min_tls_version = TLS_1_3 requires ssl_policy_profile = RESTRICTED (Google Cloud SSL policy constraint)."
  }
}

variable "health_check_path" {
  description = "HTTP path probed by the load balancer health check on port 80."
  type        = string
  default     = "/"

  validation {
    condition     = can(regex("^/[A-Za-z0-9._~/-]*$", var.health_check_path))
    error_message = "health_check_path must start with / and contain only URL-safe path characters."
  }
}

variable "security_policy" {
  description = "Optional existing Cloud Armor security policy (self-link or ID) attached to the backend service."
  type        = string
  default     = null

  validation {
    condition     = var.security_policy == null || can(regex("^(https://www\\.googleapis\\.com/compute/v1/)?projects/[^/]+/global/securityPolicies/[^/]+$", var.security_policy))
    error_message = "security_policy must be null or a global securityPolicies self-link/ID."
  }
}
