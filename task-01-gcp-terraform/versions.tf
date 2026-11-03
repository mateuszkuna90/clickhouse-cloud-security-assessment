# Reusable module: declares requirements only. Provider configuration and the
# state backend belong to the root module (see examples/basic).
terraform {
  # >= 1.9: input-variable validation rules that refer to other variables
  # (TLS profile/version rule, zone/region rule, NAT/image rule).
  required_version = ">= 1.9"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 8.9"
    }
  }
}
