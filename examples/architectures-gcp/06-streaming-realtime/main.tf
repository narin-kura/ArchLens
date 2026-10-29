# ArchLens reference architecture 06 (GCP) — Real-time streaming
#
# Clickstream events land on Pub/Sub, a streaming Dataflow job
# aggregates them into Bigtable for low-latency lookups and BigQuery for
# analytics, with a dead-letter topic for anything the pipeline can't
# process.
#
# Services: Pub/Sub (topic + DLQ + subscription), Dataflow (streaming job),
# Bigtable, BigQuery, Cloud Storage (pipeline staging), KMS, Logging,
# Monitoring.
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

resource "google_kms_key_ring" "main" {
  name     = "streaming-keyring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "stream" {
  name            = "stream-key"
  key_ring        = google_kms_key_ring.main.id
  rotation_period = "7776000s"
}

# ------------------------------------------------------------------- Ingest

resource "google_pubsub_topic" "clickstream" {
  name         = "clickstream-events"
  kms_key_name = google_kms_crypto_key.stream.id

  message_retention_duration = "86400s"
}

resource "google_pubsub_topic" "clickstream_dlq" {
  name         = "clickstream-events-dlq"
  kms_key_name = google_kms_crypto_key.stream.id
}

resource "google_pubsub_subscription" "dataflow" {
  name  = "clickstream-dataflow-sub"
  topic = google_pubsub_topic.clickstream.name

  ack_deadline_seconds = 60

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.clickstream_dlq.id
    max_delivery_attempts = 5
  }

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }
}

# --------------------------------------------------------------- Processing

resource "google_storage_bucket" "staging" {
  name     = "example-streaming-staging"
  location = "US"

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  encryption {
    default_kms_key_name = google_kms_crypto_key.stream.id
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
  name     = "example-streaming-logs"
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
  account_id   = "streaming-dataflow-sa"
  display_name = "Streaming Dataflow Service Account"
}

resource "google_dataflow_job" "aggregate" {
  name              = "clickstream-aggregate"
  region            = "us-central1"
  template_gcs_path = "gs://dataflow-templates/latest/PubSub_to_BigQuery"
  temp_gcs_location = "gs://${google_storage_bucket.staging.name}/tmp"

  service_account_email = google_service_account.dataflow.email
  kms_key_name           = google_kms_crypto_key.stream.id

  parameters = {
    inputSubscription = google_pubsub_subscription.dataflow.id
    outputTableSpec    = "${google_bigquery_dataset.streaming.dataset_id}.events"
  }
}

# --------------------------------------------------------------------- Data

resource "google_bigtable_instance" "lookups" {
  name                = "clickstream-lookups"
  deletion_protection = true

  cluster {
    cluster_id   = "lookups-c1"
    zone         = "us-central1-a"
    num_nodes    = 3
    storage_type = "SSD"
  }
}

resource "google_bigtable_table" "sessions" {
  name          = "sessions"
  instance_name = google_bigtable_instance.lookups.name

  column_family {
    family = "session_data"
  }
}

resource "google_bigquery_dataset" "streaming" {
  dataset_id  = "streaming_analytics"
  location    = "US"
  description = "Streaming clickstream analytics"

  default_encryption_configuration {
    kms_key_name = google_kms_crypto_key.stream.id
  }
}

resource "google_bigquery_table" "events" {
  dataset_id = google_bigquery_dataset.streaming.dataset_id
  table_id   = "events"

  encryption_configuration {
    kms_key_name = google_kms_crypto_key.stream.id
  }

  time_partitioning {
    type = "DAY"
  }

  schema = jsonencode([
    { name = "event_id", type = "STRING", mode = "REQUIRED" },
    { name = "event_time", type = "TIMESTAMP", mode = "REQUIRED" },
  ])
}

# ------------------------------------------------------------- Observability

resource "google_logging_project_sink" "streaming" {
  name        = "streaming-sink"
  destination = "storage.googleapis.com/${google_storage_bucket.logs.name}"
  filter      = "resource.type=\"dataflow_step\""
}

resource "google_monitoring_alert_policy" "pipeline_lag" {
  display_name = "Dataflow pipeline lag high"
  combiner      = "OR"

  conditions {
    display_name = "System lag above 5 minutes"

    condition_threshold {
      filter          = "resource.type = \"dataflow_step\" AND metric.type = \"dataflow.googleapis.com/job/system_lag\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 300
    }
  }
}
