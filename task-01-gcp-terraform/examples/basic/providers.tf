# Authentication: Application Default Credentials only, for example
#   gcloud auth application-default login
# optionally combined with service account impersonation (short-lived tokens).
# Never configure a service account JSON key here or in the repository.
provider "google" {
  project = var.project_id
  region  = var.region

  impersonate_service_account = var.impersonate_service_account
}
