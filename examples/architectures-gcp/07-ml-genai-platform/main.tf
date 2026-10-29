# ArchLens reference architecture 07 (GCP) — ML / GenAI platform
#
# A Vertex AI training-to-serving loop: a feature store for shared
# features, a private Workbench notebook for experimentation, a training
# dataset and endpoint for serving, and a vector index for RAG retrieval
# over company documents.
#
# Services: Vertex AI (Feature Store, Dataset, Endpoint, Index + Index
# Endpoint, Workbench Notebook), Cloud Storage (training data + model
# artifacts), BigQuery (feature source), KMS, Secret Manager, Logging,
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

resource "google_compute_network" "main" {
  name                    = "vpc-ml-platform"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "ml" {
  name          = "snet-ml"
  network       = google_compute_network.main.id
  ip_cidr_range = "10.40.0.0/20"
  region        = "us-central1"

  private_ip_google_access = true
}

resource "google_kms_key_ring" "main" {
  name     = "ml-platform-keyring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "ml" {
  name            = "ml-encryption-key"
  key_ring        = google_kms_key_ring.main.id
  rotation_period = "7776000s"
}

resource "google_service_account" "ml" {
  account_id   = "ml-platform-sa"
  display_name = "ML Platform Service Account"
}

# ---------------------------------------------------------------- Data / FS

resource "google_storage_bucket" "artifacts" {
  name     = "example-ml-artifacts"
  location = "US"

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  encryption {
    default_kms_key_name = google_kms_crypto_key.ml.id
  }

  versioning {
    enabled = true
  }

  logging {
    log_bucket = google_storage_bucket.logs.name
  }
}

resource "google_storage_bucket" "logs" {
  name     = "example-ml-logs"
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

resource "google_bigquery_dataset" "features" {
  dataset_id  = "feature_source"
  location    = "US"
  description = "Source tables for the feature store"

  default_encryption_configuration {
    kms_key_name = google_kms_crypto_key.ml.id
  }
}

resource "google_vertex_ai_featurestore" "main" {
  name   = "ml-platform-featurestore"
  region = "us-central1"

  online_serving_config {
    fixed_node_count = 2
  }

  encryption_spec {
    kms_key_name = google_kms_crypto_key.ml.id
  }
}

resource "google_vertex_ai_dataset" "training" {
  display_name        = "training-dataset"
  region               = "us-central1"
  metadata_schema_uri  = "gs://google-cloud-aiplatform/schema/dataset/metadata/tabular_1.0.0.yaml"

  encryption_spec {
    kms_key_name = google_kms_crypto_key.ml.id
  }
}

# ------------------------------------------------------------- Experimentation

resource "google_notebooks_instance" "workbench" {
  name         = "ml-workbench"
  location     = "us-central1-a"
  machine_type = "n1-standard-4"

  vm_image {
    project      = "deeplearning-platform-release"
    image_family = "common-cpu-notebooks"
  }

  network    = google_compute_network.main.id
  subnet     = google_compute_subnetwork.ml.id
  no_public_ip = true

  service_account = google_service_account.ml.email

  encryption_config {
    kms_key = google_kms_crypto_key.ml.id
  }
}

# ------------------------------------------------------------------ Serving

resource "google_vertex_ai_endpoint" "serving" {
  display_name = "model-serving-endpoint"
  location      = "us-central1"

  encryption_spec {
    kms_key_name = google_kms_crypto_key.ml.id
  }

  network = google_compute_network.main.id
}

resource "google_vertex_ai_index" "rag" {
  display_name = "document-embeddings"
  region       = "us-central1"

  metadata {
    config {
      dimensions = 768

      algorithm_config {
        tree_ah_config {}
      }
    }
  }
}

resource "google_vertex_ai_index_endpoint" "rag" {
  display_name = "rag-index-endpoint"
  region       = "us-central1"
  network      = google_compute_network.main.id
}

resource "google_vertex_ai_metadata_store" "main" {
  name   = "ml-platform-metadata"
  region = "us-central1"

  encryption_spec {
    kms_key_name = google_kms_crypto_key.ml.id
  }
}

resource "google_secret_manager_secret" "model_api_key" {
  secret_id = "model-api-key"

  replication {
    auto {}
  }
}

# ------------------------------------------------------------- Observability

resource "google_vertex_ai_tensorboard" "main" {
  display_name = "ml-platform-tensorboard"
  region        = "us-central1"

  encryption_spec {
    kms_key_name = google_kms_crypto_key.ml.id
  }
}

resource "google_logging_project_sink" "ml" {
  name        = "ml-sink"
  destination = "storage.googleapis.com/${google_storage_bucket.logs.name}"
  filter      = "resource.type=\"aiplatform.googleapis.com/Endpoint\""
}

resource "google_monitoring_alert_policy" "endpoint_latency" {
  display_name = "Serving endpoint latency high"
  combiner      = "OR"

  conditions {
    display_name = "p99 latency above 2s"

    condition_threshold {
      filter          = "resource.type = \"aiplatform.googleapis.com/Endpoint\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 2000
    }
  }
}
