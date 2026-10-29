# ArchLens reference architecture 14 (GCP) — Workforce applications
#
# An internal business app fronted by Identity-Aware Proxy instead of a VPN
# — employees authenticate with their corporate identity, IAP checks the
# request before it ever reaches the app, and Cloud Armor adds a rate-limit
# layer in front of that. Cloud SQL backs the app; Looker sits beside it for
# the BI side employees actually ask for.
#
# Services: IAP-secured External LB (backend service with iap{} enabled),
# Cloud Run (app), Cloud Armor, Identity Platform (customer/partner auth
# for a separate portal), Looker instance (BI), Cloud SQL, Secret Manager,
# KMS, Logging, Monitoring.
#
# Expected ArchLens findings: clean.

terraform {
  required_version = ">= 1.6"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
  }
}

provider "google" {
  project = "example-project"
  region  = "us-central1"
}

resource "google_compute_network" "main" {
  name                    = "vpc-workforce"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "app" {
  name          = "snet-workforce-app"
  network       = google_compute_network.main.id
  ip_cidr_range = "10.90.0.0/24"
  region        = "us-central1"

  private_ip_google_access = true
}

resource "google_kms_key_ring" "main" {
  name     = "workforce-keyring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "workforce" {
  name            = "workforce-key"
  key_ring        = google_kms_key_ring.main.id
  rotation_period = "7776000s"
}

# ------------------------------------------------------------------ Identity

resource "google_iam_workload_identity_pool" "workforce" {
  workload_identity_pool_id = "workforce-pool"
  display_name              = "Workforce Identity Federation"
}

resource "google_identity_platform_config" "partner_portal" {
  sign_in {
    allow_duplicate_emails = false

    email {
      enabled           = true
      password_required = true
    }
  }
}

resource "google_service_account" "app" {
  account_id   = "workforce-app-sa"
  display_name = "Workforce App Service Account"
}

resource "google_project_iam_member" "app_sql" {
  project = "example-project"
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.app.email}"
}

# --------------------------------------------------------------------- App

resource "google_cloud_run_v2_service" "app" {
  name     = "workforce-portal"
  location = "us-central1"

  template {
    service_account = google_service_account.app.email

    containers {
      image = "us-central1-docker.pkg.dev/example-project/workforce/portal:1.0.0"

      resources {
        limits = {
          cpu    = "1"
          memory = "1Gi"
        }
      }
    }

    scaling {
      min_instance_count = 1
      max_instance_count = 15
    }
  }
}

resource "google_compute_region_network_endpoint_group" "app" {
  name                  = "workforce-app-neg"
  region                = "us-central1"
  network_endpoint_type = "SERVERLESS"

  cloud_run {
    service = google_cloud_run_v2_service.app.name
  }
}

resource "google_compute_backend_service" "app" {
  name                  = "workforce-app-backend"
  protocol              = "HTTPS"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  security_policy       = google_compute_security_policy.main.id

  backend {
    group = google_compute_region_network_endpoint_group.app.id
  }

  # IAP sits in front of the backend — only a corporate-identity-verified
  # request reaches the Cloud Run service at all.
  iap {
    oauth2_client_id     = "example-oauth-client-id.apps.googleusercontent.com"
    oauth2_client_secret = data.google_secret_manager_secret_version.iap_oauth_secret.secret_data
  }

  log_config {
    enable      = true
    sample_rate = 1.0
  }
}

resource "google_secret_manager_secret" "iap_oauth_secret" {
  secret_id = "iap-oauth-client-secret"

  replication {
    auto {}
  }
}

data "google_secret_manager_secret_version" "iap_oauth_secret" {
  secret = google_secret_manager_secret.iap_oauth_secret.secret_id
}

resource "google_project_iam_member" "iap_access" {
  project = "example-project"
  role    = "roles/iap.httpsResourceAccessor"
  member  = "group:employees@example.com"
}

resource "google_compute_url_map" "app" {
  name            = "workforce-url-map"
  default_service = google_compute_backend_service.app.id
}

resource "google_compute_managed_ssl_certificate" "app" {
  name = "workforce-managed-cert"

  managed {
    domains = ["portal.example.com"]
  }
}

resource "google_compute_ssl_policy" "app" {
  name            = "workforce-modern-tls"
  min_tls_version = "TLS_1_2"
  profile         = "MODERN"
}

resource "google_compute_target_https_proxy" "app" {
  name             = "workforce-https-proxy"
  url_map          = google_compute_url_map.app.id
  ssl_certificates = [google_compute_managed_ssl_certificate.app.id]
  ssl_policy       = google_compute_ssl_policy.app.id
}

resource "google_compute_global_address" "app" {
  name = "workforce-lb-ip"
}

resource "google_compute_global_forwarding_rule" "app" {
  name       = "workforce-forwarding-rule"
  target     = google_compute_target_https_proxy.app.id
  port_range = "443"
  ip_address = google_compute_global_address.app.id
}

resource "google_compute_security_policy" "main" {
  name = "workforce-armor-policy"

  rule {
    action   = "throttle"
    priority = 1000

    match {
      versioned_expr = "SRC_IPS_V1"

      config {
        src_ip_ranges = ["*"]
      }
    }

    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"

      rate_limit_threshold {
        count        = 300
        interval_sec = 60
      }
    }

    description = "Rate limit"
  }
}

# --------------------------------------------------------------------- Data

resource "google_sql_database_instance" "main" {
  name                = "workforce-db"
  database_version    = "POSTGRES_15"
  region              = "us-central1"
  deletion_protection = true

  settings {
    tier              = "db-custom-2-7680"
    availability_type = "REGIONAL"

    backup_configuration {
      enabled = true
    }

    ip_configuration {
      ipv4_enabled    = false
      ssl_mode        = "ENCRYPTED_ONLY"
      private_network = google_compute_network.main.id
    }

    database_flags {
      name  = "cloudsql.enable_pgaudit"
      value = "on"
    }
  }
}

resource "google_looker_instance" "bi" {
  name             = "workforce-bi"
  region           = "us-central1"
  platform_edition = "LOOKER_CORE_TRIAL"

  oauth_config {
    client_id     = "example-looker-client-id"
    client_secret = data.google_secret_manager_secret_version.looker_oauth_secret.secret_data
  }
}

resource "google_secret_manager_secret" "looker_oauth_secret" {
  secret_id = "looker-oauth-client-secret"

  replication {
    auto {}
  }
}

data "google_secret_manager_secret_version" "looker_oauth_secret" {
  secret = google_secret_manager_secret.looker_oauth_secret.secret_id
}

# ------------------------------------------------------------- Observability

resource "google_logging_project_sink" "workforce" {
  name        = "workforce-sink"
  destination = "logging.googleapis.com/projects/example-project/locations/us-central1/buckets/_Default"
  filter      = "resource.type=\"iap\" OR resource.type=\"cloud_run_revision\""
}

resource "google_monitoring_alert_policy" "iap_denied" {
  display_name = "IAP access denials spike"
  combiner      = "OR"

  conditions {
    display_name = "Denied requests above baseline"

    condition_threshold {
      filter          = "resource.type = \"iap\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
    }
  }
}
