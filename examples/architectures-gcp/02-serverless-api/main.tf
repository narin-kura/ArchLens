# ArchLens reference architecture 02 (GCP) — Serverless API
#
# A fully serverless request path: Cloud Run for the synchronous API,
# Firestore for request-scoped data, Cloud Tasks for deferred work, and
# Pub/Sub + a second Cloud Run service for the async side. No VM, no
# cluster, nothing to patch.
#
# Services: Cloud Run (API + worker), Firestore, Cloud Tasks, Pub/Sub,
# Secret Manager, KMS, Cloud Build (CI), Artifact Registry, Service Account,
# Cloud Armor, Logging, Monitoring.
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
  name     = "serverless-api-keyring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "data" {
  name            = "data-key"
  key_ring        = google_kms_key_ring.main.id
  rotation_period = "7776000s"
}

# --------------------------------------------------------------------- Data

resource "google_firestore_database" "main" {
  name        = "(default)"
  location_id = "nam5"
  type        = "FIRESTORE_NATIVE"

  app_engine_integration_mode = "DISABLED"
}

resource "google_cloud_tasks_queue" "deferred" {
  name     = "deferred-work"
  location = "us-central1"

  rate_limits {
    max_dispatches_per_second = 50
  }

  retry_config {
    max_attempts = 5
  }
}

resource "google_pubsub_topic" "events" {
  name         = "api-events"
  kms_key_name = google_kms_crypto_key.data.id
}

resource "google_pubsub_subscription" "worker" {
  name  = "worker-sub"
  topic = google_pubsub_topic.events.name

  ack_deadline_seconds = 30

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.dlq.id
    max_delivery_attempts = 5
  }

  expiration_policy {
    ttl = ""
  }
}

resource "google_pubsub_topic" "dlq" {
  name         = "api-events-dlq"
  kms_key_name = google_kms_crypto_key.data.id
}

# ------------------------------------------------------------------ Compute

resource "google_service_account" "api" {
  account_id   = "serverless-api-sa"
  display_name = "Serverless API Service Account"
}

resource "google_project_iam_member" "api_firestore" {
  project = "example-project"
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.api.email}"
}

resource "google_project_iam_member" "api_tasks" {
  project = "example-project"
  role    = "roles/cloudtasks.enqueuer"
  member  = "serviceAccount:${google_service_account.api.email}"
}

resource "google_cloud_run_v2_service" "api" {
  name     = "api"
  location = "us-central1"

  template {
    service_account = google_service_account.api.email

    containers {
      image = "us-central1-docker.pkg.dev/example-project/api/api:1.0.0"

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }

      env {
        name  = "FIRESTORE_DB"
        value = google_firestore_database.main.name
      }
    }

    scaling {
      min_instance_count = 1
      max_instance_count = 20
    }
  }

  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }
}

resource "google_cloud_run_v2_service" "worker" {
  name     = "events-worker"
  location = "us-central1"

  template {
    service_account = google_service_account.api.email

    containers {
      image = "us-central1-docker.pkg.dev/example-project/api/worker:1.0.0"

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }
    }

    scaling {
      min_instance_count = 0
      max_instance_count = 10
    }
  }
}

resource "google_cloud_run_v2_service_iam_member" "public_api" {
  name     = google_cloud_run_v2_service.api.name
  location = "us-central1"
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# ----------------------------------------------------------------- Artefacts

resource "google_artifact_registry_repository" "api" {
  repository_id = "api"
  location      = "us-central1"
  format        = "DOCKER"

  cleanup_policy_dry_run = false
}

resource "google_cloudbuild_trigger" "api" {
  name     = "api-ci"
  location = "us-central1"

  github {
    owner = "example-org"
    name  = "serverless-api"

    push {
      branch = "^main$"
    }
  }

  build {
    step {
      name = "gcr.io/cloud-builders/docker"
      args = ["build", "-t", "us-central1-docker.pkg.dev/example-project/api/api:$SHORT_SHA", "."]
    }
  }
}

resource "google_secret_manager_secret" "api_key" {
  secret_id = "third-party-api-key"

  replication {
    auto {}
  }
}

# ---------------------------------------------------------------------- Edge

resource "google_compute_security_policy" "api" {
  name = "api-armor-policy"

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
        count        = 100
        interval_sec = 60
      }
    }

    description = "Rate limit all traffic"
  }
}

# ------------------------------------------------------------- Observability

resource "google_logging_project_sink" "api" {
  name        = "api-sink"
  destination = "logging.googleapis.com/projects/example-project/locations/us-central1/buckets/_Default"
  filter      = "resource.type=\"cloud_run_revision\""
}

resource "google_monitoring_alert_policy" "api_errors" {
  display_name = "API 5xx error rate"
  combiner      = "OR"

  conditions {
    display_name = "5xx rate above 1%"

    condition_threshold {
      filter          = "resource.type = \"cloud_run_revision\" AND metric.type = \"run.googleapis.com/request_count\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0.01
    }
  }
}
