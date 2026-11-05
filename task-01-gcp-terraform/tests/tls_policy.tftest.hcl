# TLS combination matrix (DESIGN.md §7.3). Accepted: RESTRICTED+TLS_1_2
# (default), RESTRICTED+TLS_1_3, MODERN+TLS_1_2. Everything else is rejected.

mock_provider "google" {}

variables {
  project_id                  = "example-project-id"
  region                      = "europe-west1"
  zone                        = "europe-west1-b"
  managed_certificate_domains = ["app.example.com"]
}

run "t_tls_1_default_restricted_tls12" {
  command = plan

  assert {
    condition     = google_compute_ssl_policy.this.profile == "RESTRICTED" && google_compute_ssl_policy.this.min_tls_version == "TLS_1_2"
    error_message = "Default must be RESTRICTED + TLS_1_2."
  }
}

run "t_tls_2_restricted_tls13_accepted" {
  command = plan

  variables {
    ssl_policy_profile  = "RESTRICTED"
    ssl_min_tls_version = "TLS_1_3"
  }

  assert {
    condition     = google_compute_ssl_policy.this.profile == "RESTRICTED" && google_compute_ssl_policy.this.min_tls_version == "TLS_1_3"
    error_message = "RESTRICTED + TLS_1_3 must be accepted."
  }
}

run "t_tls_3_modern_tls12_accepted" {
  command = plan

  variables {
    ssl_policy_profile  = "MODERN"
    ssl_min_tls_version = "TLS_1_2"
  }

  assert {
    condition     = google_compute_ssl_policy.this.profile == "MODERN" && google_compute_ssl_policy.this.min_tls_version == "TLS_1_2"
    error_message = "MODERN + TLS_1_2 must be accepted."
  }
}

run "t_tls_4_modern_tls13_rejected" {
  command = plan

  variables {
    ssl_policy_profile  = "MODERN"
    ssl_min_tls_version = "TLS_1_3"
  }

  expect_failures = [var.ssl_min_tls_version]
}

run "t_tls_5_tls10_rejected" {
  command = plan

  variables {
    ssl_min_tls_version = "TLS_1_0"
  }

  expect_failures = [var.ssl_min_tls_version]
}

run "t_tls_6_tls11_rejected" {
  command = plan

  variables {
    ssl_min_tls_version = "TLS_1_1"
  }

  expect_failures = [var.ssl_min_tls_version]
}

run "t_tls_7a_compatible_rejected" {
  command = plan

  variables {
    ssl_policy_profile = "COMPATIBLE"
  }

  expect_failures = [var.ssl_policy_profile]
}

run "t_tls_7b_fips_rejected" {
  command = plan

  variables {
    ssl_policy_profile = "FIPS_202205"
  }

  expect_failures = [var.ssl_policy_profile]
}

run "t_tls_7c_custom_rejected" {
  command = plan

  variables {
    ssl_policy_profile = "CUSTOM"
  }

  expect_failures = [var.ssl_policy_profile]
}

run "t_tls_7d_lowercase_rejected" {
  command = plan

  variables {
    ssl_min_tls_version = "tls_1_2"
  }

  expect_failures = [var.ssl_min_tls_version]
}
