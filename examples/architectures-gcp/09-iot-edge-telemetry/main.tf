# ArchLens reference architecture 09 (GCP) — IoT edge telemetry
#
# Cloud IoT Core was retired in 2023, so device telemetry here lands the way
# Google now recommends: devices publish straight to Pub/Sub over MQTT-over-
# a-gateway or HTTPS with per-device service-account credentials, a
# streaming Dataflow job fans it out to Bigtable (hot path) and BigQuery
# (cold path), and Cloud Functions handles device-command dispatch.
#
# Services: Pub/Sub (telemetry + commands + DLQ), Dataflow, Bigtable,
# BigQuery, Cloud Functions (command dispatch), Cloud Storage (firmware),
# KMS, Secret Manager, Logging, Monitoring.
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
  name                    = "vpc-iot-edge"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "connector" {
  name          = "snet-serverless-connector"
  network       = google_compute_network.main.id
  ip_cidr_range = "10.60.0.0/28"
  region        = "us-central1"
}

resource "google_vpc_access_connector" "main" {
  name    = "iot-serverless-connector"
  region  = "us-central1"
  subnet {
    name = google_compute_subnetwork.connector.name
  }
}

resource "google_kms_key_ring" "main" {
  name     = "iot-edge-keyring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "iot" {
  name            = "iot-encryption-key"
  key_ring        = google_kms_key_ring.main.id
  rotation_period = "7776000s"
}

# ------------------------------------------------------------------- Ingest

resource "google_pubsub_topic" "telemetry" {
  name         = "device-telemetry"
  kms_key_name = google_kms_crypto_key.iot.id

  message_retention_duration = "86400s"
}

resource "google_pubsub_topic" "telemetry_dlq" {
  name         = "device-telemetry-dlq"
  kms_key_name = google_kms_crypto_key.iot.id
}

resource "google_pubsub_subscription" "dataflow" {
  name  = "telemetry-dataflow-sub"
  topic = google_pubsub_topic.telemetry.name

  ack_deadline_seconds = 60

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.telemetry_dlq.id
    max_delivery_attempts = 5
  }
}

resource "google_pubsub_topic" "commands" {
  name         = "device-commands"
  kms_key_name = google_kms_crypto_key.iot.id
}

# -------------------------------------------------------------- Per-device IAM

resource "google_service_account" "device_fleet" {
  account_id   = "device-fleet-publisher"
  display_name = "Device Fleet Publisher"
}

resource "google_pubsub_topic_iam_member" "device_publish" {
  topic  = google_pubsub_topic.telemetry.name
  role   = "roles/pubsub.publisher"
  member = "serviceAccount:${google_service_account.device_fleet.email}"
}

# --------------------------------------------------------------- Processing

resource "google_storage_bucket" "firmware" {
  name     = "example-iot-firmware"
  location = "US"

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  encryption {
    default_kms_key_name = google_kms_crypto_key.iot.id
  }

  versioning {
    enabled = true
  }

  logging {
    log_bucket = google_storage_bucket.logs.name
  }
}

resource "google_storage_bucket" "staging" {
  name     = "example-iot-staging"
  location = "US"

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  encryption {
    default_kms_key_name = google_kms_crypto_key.iot.id
  }

  versioning {
    enabled = true
  }

  logging {
    log_bucket = google_storage_bucket.logs.name
  }

  lifecycle_rule {
    condition {
      age = 7
    }
    action {
      type = "Delete"
    }
  }
}

resource "google_storage_bucket" "logs" {
  name     = "example-iot-logs"
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

resource "google_service_account" "dataflow" {
  account_id   = "iot-dataflow-sa"
  display_name = "IoT Dataflow Service Account"
}

resource "google_dataflow_job" "fanout" {
  name              = "telemetry-fanout"
  region            = "us-central1"
  template_gcs_path = "gs://dataflow-templates/latest/PubSub_to_BigQuery"
  temp_gcs_location = "gs://${google_storage_bucket.staging.name}/tmp"

  service_account_email = google_service_account.dataflow.email
  kms_key_name           = google_kms_crypto_key.iot.id

  parameters = {
    inputSubscription = google_pubsub_subscription.dataflow.id
    outputTableSpec    = "${google_bigquery_dataset.telemetry.dataset_id}.readings"
  }
}

resource "google_bigtable_instance" "hot_path" {
  name                = "device-state"
  deletion_protection = true

  cluster {
    cluster_id   = "device-state-c1"
    zone         = "us-central1-a"
    num_nodes    = 3
    storage_type = "SSD"
  }
}

resource "google_bigquery_dataset" "telemetry" {
  dataset_id  = "device_telemetry"
  location    = "US"
  description = "Cold-path device telemetry"

  default_encryption_configuration {
    kms_key_name = google_kms_crypto_key.iot.id
  }
}

resource "google_bigquery_table" "readings" {
  dataset_id = google_bigquery_dataset.telemetry.dataset_id
  table_id   = "readings"

  encryption_configuration {
    kms_key_name = google_kms_crypto_key.iot.id
  }

  time_partitioning {
    type = "DAY"
  }

  schema = jsonencode([
    { name = "device_id", type = "STRING", mode = "REQUIRED" },
    { name = "reading_time", type = "TIMESTAMP", mode = "REQUIRED" },
  ])
}

# --------------------------------------------------------------- Dispatch

resource "google_service_account" "dispatcher" {
  account_id   = "command-dispatcher-sa"
  display_name = "Command Dispatcher"
}

resource "google_cloudfunctions2_function" "dispatch" {
  name     = "command-dispatch"
  location = "us-central1"

  build_config {
    runtime     = "python312"
    entry_point = "dispatch"

    source {
      storage_source {
        bucket = google_storage_bucket.firmware.name
        object = "dispatch-source.zip"
      }
    }
  }

  service_config {
    service_account_email         = google_service_account.dispatcher.email
    ingress_settings               = "ALLOW_INTERNAL_ONLY"
    all_traffic_on_latest_revision = true
    vpc_connector                  = google_vpc_access_connector.main.id

    secret_environment_variables {
      key        = "DEVICE_SIGNING_KEY"
      secret      = google_secret_manager_secret.device_signing_key.secret_id
      version     = "latest"
      project_id  = "example-project"
    }
  }

  event_trigger {
    event_type = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic = google_pubsub_topic.commands.id
  }
}

resource "google_secret_manager_secret" "device_signing_key" {
  secret_id = "device-signing-key"

  replication {
    auto {}
  }
}

# ------------------------------------------------------------- Observability

resource "google_logging_project_sink" "iot" {
  name        = "iot-sink"
  destination = "storage.googleapis.com/${google_storage_bucket.logs.name}"
  filter      = "resource.type=\"cloud_function\" OR resource.type=\"dataflow_step\""
}

resource "google_monitoring_alert_policy" "telemetry_gap" {
  display_name = "Telemetry ingestion gap"
  combiner      = "OR"

  conditions {
    display_name = "No messages published in 5 minutes"

    condition_threshold {
      filter          = "resource.type = \"pubsub_topic\""
      duration        = "300s"
      comparison      = "COMPARISON_LT"
      threshold_value = 1
    }
  }
}
