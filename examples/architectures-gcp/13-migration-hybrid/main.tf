# ArchLens reference architecture 13 (GCP) — Migration and hybrid connectivity
#
# An on-prem data center connects to GCP over HA VPN, a Database Migration
# Service job replicates an on-prem Postgres instance into Cloud SQL with
# minimal downtime, and Storage Transfer Service moves the historical file
# archive into Cloud Storage. Cloud DNS forwarding keeps name resolution
# working across the boundary during the cutover window.
#
# Services: HA VPN Gateway + Tunnel + Cloud Router (BGP), Database
# Migration Service (connection profile + job), Cloud SQL (migration
# target), Storage Transfer Service, Cloud Storage, Cloud DNS (forwarding
# zone), KMS, Secret Manager, Logging.
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
  name                    = "vpc-migration"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "data" {
  name          = "snet-data"
  network       = google_compute_network.main.id
  ip_cidr_range = "10.80.0.0/24"
  region        = "us-central1"

  private_ip_google_access = true
}

resource "google_kms_key_ring" "main" {
  name     = "migration-keyring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "migration" {
  name            = "migration-key"
  key_ring        = google_kms_key_ring.main.id
  rotation_period = "7776000s"
}

# ---------------------------------------------------------------- Connectivity

resource "google_compute_ha_vpn_gateway" "main" {
  name    = "onprem-ha-vpn-gw"
  network = google_compute_network.main.id
}

resource "google_compute_router" "main" {
  name    = "migration-router"
  network = google_compute_network.main.id
  region  = "us-central1"

  bgp {
    asn = 65001
  }
}

resource "google_compute_vpn_tunnel" "tunnel1" {
  name                            = "onprem-tunnel-1"
  region                          = "us-central1"
  vpn_gateway                     = google_compute_ha_vpn_gateway.main.id
  shared_secret                   = data.google_secret_manager_secret_version.vpn_shared_secret.secret_data
  router                          = google_compute_router.main.id
  vpn_gateway_interface           = 0
}

resource "google_compute_vpn_tunnel" "tunnel2" {
  name                   = "onprem-tunnel-2"
  region                 = "us-central1"
  vpn_gateway            = google_compute_ha_vpn_gateway.main.id
  shared_secret          = data.google_secret_manager_secret_version.vpn_shared_secret.secret_data
  router                 = google_compute_router.main.id
  vpn_gateway_interface  = 1
}

resource "google_secret_manager_secret" "vpn_shared_secret" {
  secret_id = "vpn-shared-secret"

  replication {
    auto {}
  }
}

data "google_secret_manager_secret_version" "vpn_shared_secret" {
  secret = google_secret_manager_secret.vpn_shared_secret.secret_id
}

resource "google_compute_router_peer" "onprem1" {
  name                      = "onprem-peer-1"
  router                    = google_compute_router.main.name
  region                    = "us-central1"
  peer_ip_address           = "169.254.0.2"
  peer_asn                  = 65002
  interface                 = google_compute_router_interface.tunnel1.name
}

resource "google_compute_router_interface" "tunnel1" {
  name       = "tunnel1-if"
  router     = google_compute_router.main.name
  region     = "us-central1"
  ip_range   = "169.254.0.1/30"
  vpn_tunnel = google_compute_vpn_tunnel.tunnel1.name
}

resource "google_dns_managed_zone" "onprem_forwarding" {
  name        = "onprem-forwarding-zone"
  dns_name    = "corp.internal."
  visibility  = "private"

  private_visibility_config {
    networks {
      network_url = google_compute_network.main.id
    }
  }

  forwarding_config {
    target_name_servers {
      ipv4_address = "10.0.0.53"
    }
  }
}

# ----------------------------------------------------------------- Migration

resource "google_sql_database_instance" "target" {
  name                = "orders-db-migrated"
  database_version    = "POSTGRES_15"
  region              = "us-central1"
  deletion_protection = true

  settings {
    tier              = "db-custom-4-16384"
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

resource "google_database_migration_service_connection_profile" "onprem_source" {
  connection_profile_id = "onprem-postgres-source"
  location              = "us-central1"

  postgresql {
    host     = "10.0.0.20"
    port     = 5432
    username = "migration_user"
    password = data.google_secret_manager_secret_version.migration_db_password.secret_data

    ssl {
      type = "SERVER_CLIENT"
    }
  }
}

data "google_secret_manager_secret_version" "migration_db_password" {
  secret = google_secret_manager_secret.migration_db_password.secret_id
}

resource "google_database_migration_service_connection_profile" "cloudsql_target" {
  connection_profile_id = "cloudsql-target"
  location              = "us-central1"

  cloudsql {
    settings {
      database_version = "POSTGRES_15"

      ip_config {
        enable_ipv4 = false
      }
    }
  }
}

resource "google_database_migration_service_migration_job" "orders_migration" {
  migration_job_id = "orders-migration"
  location         = "us-central1"
  type             = "CONTINUOUS"

  source      = google_database_migration_service_connection_profile.onprem_source.name
  destination = google_database_migration_service_connection_profile.cloudsql_target.name
}

# ------------------------------------------------------------------ Transfer

resource "google_storage_bucket" "archive" {
  name     = "example-migration-archive"
  location = "US"

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  encryption {
    default_kms_key_name = google_kms_crypto_key.migration.id
  }

  versioning {
    enabled = true
  }

  logging {
    log_bucket = google_storage_bucket.logs.name
  }
}

resource "google_storage_bucket" "logs" {
  name     = "example-migration-logs"
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

resource "google_service_account" "transfer" {
  account_id   = "storage-transfer-sa"
  display_name = "Storage Transfer Service Account"
}

resource "google_storage_transfer_job" "file_archive" {
  description = "On-prem file archive to Cloud Storage"

  transfer_spec {
    gcs_data_sink {
      bucket_name = google_storage_bucket.archive.name
    }

    transfer_options {
      overwrite_objects_already_existing_in_sink = false
    }
  }

  schedule {
    schedule_start_date {
      year  = 2026
      month = 1
      day   = 1
    }
  }
}

resource "google_secret_manager_secret" "migration_db_password" {
  secret_id = "migration-db-password"

  replication {
    auto {}
  }
}

# ------------------------------------------------------------- Observability

resource "google_logging_project_sink" "migration" {
  name        = "migration-sink"
  destination = "storage.googleapis.com/${google_storage_bucket.logs.name}"
  filter      = "resource.type=\"datamigration.googleapis.com/MigrationJob\""
}

resource "google_monitoring_alert_policy" "migration_lag" {
  display_name = "Migration replication lag high"
  combiner      = "OR"

  conditions {
    display_name = "Lag above 5 minutes"

    condition_threshold {
      filter          = "resource.type = \"datamigration.googleapis.com/MigrationJob\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 300
    }
  }
}
