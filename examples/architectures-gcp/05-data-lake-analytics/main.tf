# ArchLens reference architecture 05 (GCP) — Data lake and analytics
#
# A medallion-style lake on Cloud Storage, cataloged and governed by
# Dataplex, loaded by Dataproc/Dataflow, and queried through BigQuery
# external + native tables. CMEK everywhere data lands.
#
# Services: Cloud Storage (raw/curated/analytics zones), Dataplex (lake +
# zones), Dataproc, Dataflow, BigQuery (dataset + tables), KMS, Secret
# Manager, Logging, Monitoring.
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
  name                    = "vpc-data-lake"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "processing" {
  name          = "snet-processing"
  network       = google_compute_network.main.id
  ip_cidr_range = "10.30.0.0/20"
  region        = "us-central1"

  private_ip_google_access = true
}

resource "google_kms_key_ring" "main" {
  name     = "data-lake-keyring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "lake" {
  name            = "lake-encryption-key"
  key_ring        = google_kms_key_ring.main.id
  rotation_period = "7776000s"
}

# -------------------------------------------------------------------- Lake

resource "google_storage_bucket" "raw" {
  name     = "example-lake-raw"
  location = "US"

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  encryption {
    default_kms_key_name = google_kms_crypto_key.lake.id
  }

  versioning {
    enabled = true
  }

  logging {
    log_bucket = google_storage_bucket.logs.name
  }
}

resource "google_storage_bucket" "curated" {
  name     = "example-lake-curated"
  location = "US"

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  encryption {
    default_kms_key_name = google_kms_crypto_key.lake.id
  }

  versioning {
    enabled = true
  }

  logging {
    log_bucket = google_storage_bucket.logs.name
  }
}

resource "google_storage_bucket" "logs" {
  name     = "example-lake-logs"
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

resource "google_dataplex_lake" "main" {
  name     = "example-lake"
  location = "us-central1"
}

resource "google_dataplex_zone" "raw" {
  name     = "raw-zone"
  lake     = google_dataplex_lake.main.name
  location = "us-central1"
  type     = "RAW"

  discovery_spec {
    enabled = true
  }

  resource_spec {
    location_type = "SINGLE_REGION"
  }
}

resource "google_dataplex_zone" "curated" {
  name     = "curated-zone"
  lake     = google_dataplex_lake.main.name
  location = "us-central1"
  type     = "CURATED"

  discovery_spec {
    enabled = true
  }

  resource_spec {
    location_type = "SINGLE_REGION"
  }
}

# -------------------------------------------------------------- Processing

resource "google_service_account" "dataproc" {
  account_id   = "dataproc-sa"
  display_name = "Dataproc Service Account"
}

resource "google_dataproc_autoscaling_policy" "etl" {
  policy_id = "etl-autoscaling"
  location  = "us-central1"

  basic_algorithm {
    yarn_config {
      graceful_decommission_timeout = "30s"
      scale_up_factor                = 0.5
      scale_down_factor              = 0.5
    }
  }

  worker_config {
    min_instances = 2
    max_instances = 10
  }
}

resource "google_dataproc_cluster" "etl" {
  name   = "etl-cluster"
  region = "us-central1"

  cluster_config {
    master_config {
      num_instances = 1
      machine_type  = "n2-standard-4"
    }

    worker_config {
      num_instances = 3
      machine_type  = "n2-standard-8"
    }

    autoscaling_config {
      policy_uri = google_dataproc_autoscaling_policy.etl.name
    }

    gce_cluster_config {
      subnetwork             = google_compute_subnetwork.processing.id
      internal_ip_only       = true
      service_account        = google_service_account.dataproc.email
      service_account_scopes = ["cloud-platform"]
    }

    encryption_config {
      kms_key_name = google_kms_crypto_key.lake.id
    }

    software_config {
      image_version = "2.1-debian11"
    }
  }
}

resource "google_dataflow_job" "ingest" {
  name              = "raw-to-curated"
  region            = "us-central1"
  template_gcs_path = "gs://dataflow-templates/latest/GCS_Text_to_BigQuery"
  temp_gcs_location = "gs://${google_storage_bucket.raw.name}/tmp"

  service_account_email = google_service_account.dataproc.email

  kms_key_name = google_kms_crypto_key.lake.id

  parameters = {
    javascriptTextTransformGcsPath = "gs://${google_storage_bucket.raw.name}/transform.js"
  }
}

# ------------------------------------------------------------------- BigQuery

resource "google_bigquery_dataset" "analytics" {
  dataset_id    = "analytics"
  location      = "US"
  description   = "Curated analytics tables"

  default_encryption_configuration {
    kms_key_name = google_kms_crypto_key.lake.id
  }

  access {
    role          = "READER"
    special_group = "projectReaders"
  }
}

resource "google_bigquery_table" "events" {
  dataset_id = google_bigquery_dataset.analytics.dataset_id
  table_id   = "events"

  encryption_configuration {
    kms_key_name = google_kms_crypto_key.lake.id
  }

  schema = jsonencode([
    { name = "event_id", type = "STRING", mode = "REQUIRED" },
    { name = "event_time", type = "TIMESTAMP", mode = "REQUIRED" },
  ])
}

resource "google_bigquery_connection" "lake" {
  connection_id = "lake-connection"
  location      = "US"

  cloud_resource {}
}

resource "google_secret_manager_secret" "pipeline_creds" {
  secret_id = "pipeline-creds"

  replication {
    auto {}
  }
}

# ------------------------------------------------------------- Observability

resource "google_logging_project_sink" "lake" {
  name        = "lake-sink"
  destination = "storage.googleapis.com/${google_storage_bucket.logs.name}"
  filter      = "resource.type=\"dataproc_cluster\" OR resource.type=\"dataflow_step\""
}

resource "google_monitoring_alert_policy" "dataproc_health" {
  display_name = "Dataproc cluster unhealthy"
  combiner      = "OR"

  conditions {
    display_name = "Cluster not running"

    condition_threshold {
      filter          = "resource.type = \"dataproc_cluster\""
      duration        = "300s"
      comparison      = "COMPARISON_LT"
      threshold_value = 1
    }
  }
}
