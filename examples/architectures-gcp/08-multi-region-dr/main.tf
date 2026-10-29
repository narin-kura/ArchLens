# ArchLens reference architecture 08 (GCP) — Multi-region disaster recovery
#
# Spanner is multi-region by construction; everything built around it
# follows. A dual-region GCS bucket holds artifacts, Cloud SQL runs a
# cross-region read replica for the pieces that still need Postgres, and a
# global LB fronts app instances in two regions so losing one region loses
# half the capacity, not the whole service.
#
# Services: Spanner (multi-region instance), Cloud SQL (primary + cross-
# region replica), Cloud Storage (dual-region), MIGs in two regions behind
# one global LB, Cloud DNS, KMS, Logging, Monitoring.
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
}

resource "google_compute_network" "main" {
  name                    = "vpc-dr"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "us_central1" {
  name          = "snet-us-central1"
  network       = google_compute_network.main.id
  ip_cidr_range = "10.50.0.0/20"
  region        = "us-central1"
}

resource "google_compute_subnetwork" "us_east1" {
  name          = "snet-us-east1"
  network       = google_compute_network.main.id
  ip_cidr_range = "10.51.0.0/20"
  region        = "us-east1"
}

resource "google_compute_firewall" "allow_lb" {
  name    = "allow-lb-https"
  network = google_compute_network.main.id

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["app-server"]
}

resource "google_kms_key_ring" "main" {
  name     = "dr-keyring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "dr" {
  name            = "dr-key"
  key_ring        = google_kms_key_ring.main.id
  rotation_period = "7776000s"
}

# --------------------------------------------------------------------- Data

resource "google_spanner_instance" "main" {
  name             = "global-ledger"
  config           = "nam3" # multi-region: us-central, us-east, us-west
  display_name     = "Global Ledger"
  processing_units = 1000
}

resource "google_spanner_database" "ledger" {
  instance = google_spanner_instance.main.name
  name     = "ledger"

  encryption_config {
    kms_key_name = google_kms_crypto_key.dr.id
  }
}

resource "google_sql_database_instance" "primary" {
  name                = "orders-db-primary"
  database_version    = "POSTGRES_15"
  region              = "us-central1"
  deletion_protection = true

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

resource "google_sql_database_instance" "replica" {
  name                 = "orders-db-replica-east"
  database_version     = "POSTGRES_15"
  region                = "us-east1"
  master_instance_name  = google_sql_database_instance.primary.name
  deletion_protection   = true

  replica_configuration {
    failover_target = true
  }

  settings {
    tier = "db-custom-4-16384"

    ip_configuration {
      ipv4_enabled    = false
      ssl_mode        = "ENCRYPTED_ONLY"
      private_network = google_compute_network.main.id
    }
  }
}

resource "google_storage_bucket" "artifacts" {
  name          = "example-dr-artifacts"
  location      = "NAM4" # dual-region: us-central1 + us-east1

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  encryption {
    default_kms_key_name = google_kms_crypto_key.dr.id
  }

  versioning {
    enabled = true
  }

  logging {
    log_bucket = google_storage_bucket.logs.name
  }
}

resource "google_storage_bucket" "logs" {
  name     = "example-dr-logs"
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

# --------------------------------------------------------------- Application

resource "google_service_account" "app" {
  account_id   = "dr-app-sa"
  display_name = "DR App Service Account"
}

resource "google_compute_instance_template" "us_central1" {
  name_prefix  = "app-us-central1-"
  machine_type = "e2-standard-2"
  tags         = ["app-server"]
  region       = "us-central1"

  disk {
    source_image = "debian-cloud/debian-12"
    auto_delete  = true
    boot         = true
  }

  network_interface {
    subnetwork = google_compute_subnetwork.us_central1.id
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

resource "google_compute_instance_template" "us_east1" {
  name_prefix  = "app-us-east1-"
  machine_type = "e2-standard-2"
  tags         = ["app-server"]
  region       = "us-east1"

  disk {
    source_image = "debian-cloud/debian-12"
    auto_delete  = true
    boot         = true
  }

  network_interface {
    subnetwork = google_compute_subnetwork.us_east1.id
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

resource "google_compute_instance_group_manager" "us_central1" {
  name               = "app-mig-us-central1"
  base_instance_name = "app-central"
  zone               = "us-central1-a"
  target_size        = 3

  version {
    instance_template = google_compute_instance_template.us_central1.id
  }

  auto_healing_policies {
    health_check      = google_compute_health_check.app.id
    initial_delay_sec = 60
  }
}

resource "google_compute_instance_group_manager" "us_east1" {
  name               = "app-mig-us-east1"
  base_instance_name = "app-east"
  zone               = "us-east1-b"
  target_size        = 3

  version {
    instance_template = google_compute_instance_template.us_east1.id
  }

  auto_healing_policies {
    health_check      = google_compute_health_check.app.id
    initial_delay_sec = 60
  }
}

resource "google_compute_autoscaler" "us_central1" {
  name   = "app-autoscaler-us-central1"
  zone   = "us-central1-a"
  target = google_compute_instance_group_manager.us_central1.id

  autoscaling_policy {
    min_replicas = 3
    max_replicas = 10

    cpu_utilization {
      target = 0.6
    }
  }
}

resource "google_compute_autoscaler" "us_east1" {
  name   = "app-autoscaler-us-east1"
  zone   = "us-east1-b"
  target = google_compute_instance_group_manager.us_east1.id

  autoscaling_policy {
    min_replicas = 3
    max_replicas = 10

    cpu_utilization {
      target = 0.6
    }
  }
}

# ---------------------------------------------------------------------- Edge

resource "google_compute_health_check" "app" {
  name = "dr-app-health-check"

  https_health_check {
    port = 443
  }
}

resource "google_compute_backend_service" "app" {
  name                  = "dr-app-backend"
  protocol              = "HTTPS"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  health_checks         = [google_compute_health_check.app.id]
  security_policy       = google_compute_security_policy.main.id

  backend {
    group = google_compute_instance_group_manager.us_central1.instance_group
  }

  backend {
    group = google_compute_instance_group_manager.us_east1.instance_group
  }

  log_config {
    enable      = true
    sample_rate = 1.0
  }
}

resource "google_compute_url_map" "main" {
  name            = "dr-url-map"
  default_service = google_compute_backend_service.app.id
}

resource "google_compute_ssl_policy" "main" {
  name            = "dr-modern-tls"
  min_tls_version = "TLS_1_2"
  profile         = "MODERN"
}

resource "google_compute_managed_ssl_certificate" "main" {
  name = "dr-managed-cert"

  managed {
    domains = ["orders.example.com"]
  }
}

resource "google_compute_target_https_proxy" "main" {
  name             = "dr-https-proxy"
  url_map          = google_compute_url_map.main.id
  ssl_certificates = [google_compute_managed_ssl_certificate.main.id]
  ssl_policy       = google_compute_ssl_policy.main.id
}

resource "google_compute_global_address" "main" {
  name = "dr-lb-ip"
}

resource "google_compute_global_forwarding_rule" "main" {
  name       = "dr-forwarding-rule"
  target     = google_compute_target_https_proxy.main.id
  port_range = "443"
  ip_address = google_compute_global_address.main.id
}

resource "google_compute_security_policy" "main" {
  name = "dr-armor-policy"

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

resource "google_dns_managed_zone" "main" {
  name     = "orders-example-com-zone"
  dns_name = "orders.example.com."
}

resource "google_dns_record_set" "orders" {
  name         = "orders.example.com."
  type         = "A"
  ttl          = 300
  managed_zone = google_dns_managed_zone.main.name
  rrdatas      = [google_compute_global_address.main.address]
}

# ------------------------------------------------------------- Observability

resource "google_logging_project_sink" "dr" {
  name        = "dr-sink"
  destination = "storage.googleapis.com/${google_storage_bucket.logs.name}"
  filter      = "resource.type=\"cloudsql_database\" OR resource.type=\"spanner_instance\""
}

resource "google_monitoring_alert_policy" "replica_lag" {
  display_name = "Cross-region replica lag high"
  combiner      = "OR"

  conditions {
    display_name = "Replication lag above 60s"

    condition_threshold {
      filter          = "resource.type = \"cloudsql_database\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 60
    }
  }
}
