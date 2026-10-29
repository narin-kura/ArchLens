# ArchLens reference architecture 01 (GCP) — Three-tier web application
#
# The classic production web stack on Google Cloud: a global external HTTPS
# load balancer with Cloud Armor in front, a managed instance group of app
# servers in a private subnet, and an isolated data tier (Cloud SQL +
# Memorystore). Secure-by-default: Cloud SQL has no public IP, TLS is
# enforced everywhere, and every tier ships logs to Cloud Logging.
#
# Services: VPC, Subnetwork, Firewall Rules, Cloud Router + NAT, Managed
# Instance Group, Autoscaler, Instance Template, Global External LB
# (forwarding rule + target proxy + URL map + backend service + health
# check), Cloud Armor, Cloud SQL (Postgres), Memorystore for Redis, Cloud
# Storage, KMS, Secret Manager, Logging, Monitoring.
#
# Expected ArchLens findings: the public load balancer's firewall rule
# intentionally accepts 0.0.0.0/0 on 443 — that is what a public web tier is
# for. Everything else should come back clean.

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

data "google_client_config" "current" {}

# ------------------------------------------------------------------- Network

resource "google_compute_network" "main" {
  name                    = "vpc-three-tier"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "app" {
  name          = "snet-app"
  network       = google_compute_network.main.id
  ip_cidr_range = "10.10.0.0/24"
  region        = "us-central1"

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 1.0
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_subnetwork" "data" {
  name          = "snet-data"
  network       = google_compute_network.main.id
  ip_cidr_range = "10.10.10.0/24"
  region        = "us-central1"
}

resource "google_compute_firewall" "allow_lb_to_app" {
  name    = "allow-lb-https"
  network = google_compute_network.main.id

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  # Google's documented health-check/LB source ranges — this is the public
  # entry point, which is exactly what a load-balanced web tier is for.
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["app-server"]
}

resource "google_compute_firewall" "allow_internal" {
  name    = "allow-internal"
  network = google_compute_network.main.id

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }

  source_ranges = ["10.10.0.0/16"]
}

resource "google_compute_router" "main" {
  name    = "router-three-tier"
  network = google_compute_network.main.id
  region  = "us-central1"
}

resource "google_compute_router_nat" "main" {
  name                               = "nat-three-tier"
  router                             = google_compute_router.main.name
  region                             = "us-central1"
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# --------------------------------------------------------------- Application

resource "google_compute_instance_template" "app" {
  name_prefix  = "app-tmpl-"
  machine_type = "e2-standard-2"
  tags         = ["app-server"]

  disk {
    source_image = "debian-cloud/debian-12"
    auto_delete  = true
    boot         = true

    disk_encryption_key {
      kms_key_self_link = google_kms_crypto_key.disks.id
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.app.id
    # No access_config — app servers have no public IP, reached only via the LB.
  }

  service_account {
    email  = google_service_account.app.email
    scopes = ["cloud-platform"]
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "google_compute_instance_group_manager" "app" {
  name               = "app-mig"
  base_instance_name = "app"
  zone               = "us-central1-a"
  target_size        = 3

  version {
    instance_template = google_compute_instance_template.app.id
  }

  named_port {
    name = "https"
    port = 443
  }

  auto_healing_policies {
    health_check      = google_compute_health_check.app.id
    initial_delay_sec = 60
  }
}

resource "google_compute_autoscaler" "app" {
  name   = "app-autoscaler"
  zone   = "us-central1-a"
  target = google_compute_instance_group_manager.app.id

  autoscaling_policy {
    min_replicas    = 3
    max_replicas    = 10
    cooldown_period = 60

    cpu_utilization {
      target = 0.6
    }
  }
}

resource "google_service_account" "app" {
  account_id   = "app-tier-sa"
  display_name = "App Tier Service Account"
}

resource "google_project_iam_member" "app_sa_sql" {
  project = "example-project"
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.app.email}"
}

# ---------------------------------------------------------------- Edge / LB

resource "google_compute_health_check" "app" {
  name = "app-health-check"

  https_health_check {
    port = 443
  }
}

resource "google_compute_backend_service" "app" {
  name                  = "app-backend"
  protocol              = "HTTPS"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  health_checks         = [google_compute_health_check.app.id]
  security_policy       = google_compute_security_policy.main.id

  backend {
    group = google_compute_instance_group_manager.app.instance_group
  }

  log_config {
    enable      = true
    sample_rate = 1.0
  }
}

resource "google_compute_url_map" "main" {
  name            = "app-url-map"
  default_service = google_compute_backend_service.app.id
}

resource "google_compute_ssl_policy" "main" {
  name            = "modern-tls"
  min_tls_version = "TLS_1_2"
  profile         = "MODERN"
}

resource "google_compute_target_https_proxy" "main" {
  name             = "app-https-proxy"
  url_map          = google_compute_url_map.main.id
  ssl_certificates = [google_compute_ssl_certificate.main.id]
  ssl_policy       = google_compute_ssl_policy.main.id
}

resource "google_compute_ssl_certificate" "main" {
  name_prefix = "app-cert-"
  private_key = file("app.key")
  certificate = file("app.crt")

  lifecycle {
    create_before_destroy = true
  }
}

resource "google_compute_global_address" "main" {
  name = "app-lb-ip"
}

resource "google_compute_global_forwarding_rule" "main" {
  name       = "app-forwarding-rule"
  target     = google_compute_target_https_proxy.main.id
  port_range = "443"
  ip_address = google_compute_global_address.main.id
}

resource "google_compute_security_policy" "main" {
  name = "app-armor-policy"

  rule {
    action   = "deny(403)"
    priority = 1000

    match {
      versioned_expr = "SRC_IPS_V1"

      config {
        src_ip_ranges = ["9.9.9.0/24"]
      }
    }
    description = "Example deny rule for a known-bad range"
  }

  rule {
    action   = "allow"
    priority = 2147483647

    match {
      versioned_expr = "SRC_IPS_V1"

      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Default allow"
  }
}

# -------------------------------------------------------------------- Data

resource "google_kms_key_ring" "main" {
  name     = "three-tier-keyring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "disks" {
  name            = "disk-encryption-key"
  key_ring        = google_kms_key_ring.main.id
  rotation_period = "7776000s"
}

resource "google_kms_crypto_key" "sql" {
  name            = "sql-encryption-key"
  key_ring        = google_kms_key_ring.main.id
  rotation_period = "7776000s"
}

resource "google_sql_database_instance" "main" {
  name                = "app-db"
  database_version    = "POSTGRES_15"
  region              = "us-central1"
  deletion_protection = true
  encryption_key_name = google_kms_crypto_key.sql.id

  settings {
    tier              = "db-custom-4-16384"
    availability_type = "REGIONAL"

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
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

resource "google_sql_database" "app" {
  name     = "appdb"
  instance = google_sql_database_instance.main.name
}

resource "google_redis_instance" "cache" {
  name           = "app-cache"
  tier           = "STANDARD_HA"
  memory_size_gb = 2
  region         = "us-central1"

  authorized_network      = google_compute_network.main.id
  transit_encryption_mode = "SERVER_AUTHENTICATION"
  auth_enabled             = true
}

resource "google_storage_bucket" "logs" {
  name     = "example-app-logs-bucket"
  location = "US"

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type = "Delete"
    }
  }
}

resource "google_storage_bucket" "assets" {
  name     = "example-app-static-assets"
  location = "US"

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  logging {
    log_bucket = google_storage_bucket.logs.name
  }
}

resource "google_secret_manager_secret" "db_password" {
  secret_id = "db-password"

  replication {
    auto {}
  }
}

# ------------------------------------------------------------- Observability

resource "google_logging_project_sink" "main" {
  name        = "app-sink"
  destination = "storage.googleapis.com/${google_storage_bucket.logs.name}"
  filter      = "resource.type=\"gce_instance\""
}

resource "google_monitoring_alert_policy" "app_cpu" {
  display_name = "App tier high CPU"
  combiner      = "OR"

  conditions {
    display_name = "CPU above 80%"

    condition_threshold {
      filter          = "resource.type = \"gce_instance\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0.8
    }
  }
}

resource "google_monitoring_uptime_check_config" "app" {
  display_name = "app-uptime"
  timeout      = "10s"

  http_check {
    path = "/health"
    port = 443
    use_ssl = true
  }

  monitored_resource {
    type = "uptime_url"
    labels = {
      host = "app.example.com"
    }
  }
}
