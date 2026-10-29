# ArchLens reference architecture 12 (GCP) — CI/CD and developer platform
#
# Cloud Build moves a commit through build, scan and deploy; Cloud Deploy
# promotes the same artefact through staging and production delivery
# pipelines with a manual approval gate in front of production. Private
# pool workers keep builds inside the VNet so they can reach private
# dependencies.
#
# Services: Cloud Build (trigger + private pool), Artifact Registry, Cloud
# Deploy (delivery pipeline + targets), Cloud Source Repositories, KMS,
# Secret Manager, Logging.
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
  name                    = "vpc-cicd"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "build_workers" {
  name          = "snet-build-workers"
  network       = google_compute_network.main.id
  ip_cidr_range = "10.70.0.0/24"
  region        = "us-central1"

  private_ip_google_access = true
}

resource "google_kms_key_ring" "main" {
  name     = "cicd-keyring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "cicd" {
  name            = "cicd-key"
  key_ring        = google_kms_key_ring.main.id
  rotation_period = "7776000s"
}

# ----------------------------------------------------------------- Artefacts

resource "google_artifact_registry_repository" "app" {
  repository_id = "app"
  location      = "us-central1"
  format        = "DOCKER"

  kms_key_name = google_kms_crypto_key.cicd.id
}

resource "google_sourcerepo_repository" "app" {
  name = "app"
}

# ---------------------------------------------------------------------- Build

resource "google_service_account" "build" {
  account_id   = "cicd-build-sa"
  display_name = "Cloud Build Service Account"
}

resource "google_project_iam_member" "build_artifact_push" {
  project = "example-project"
  role    = "roles/artifactregistry.writer"
  member  = "serviceAccount:${google_service_account.build.email}"
}

resource "google_cloudbuildv2_connection" "github" {
  location = "us-central1"
  name     = "github-connection"

  github_config {
    app_installation_id = 123456
    authorizer_credential {
      oauth_token_secret_version = google_secret_manager_secret_version.github_token.id
    }
  }
}

resource "google_secret_manager_secret" "github_token" {
  secret_id = "github-oauth-token"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "github_token" {
  secret      = google_secret_manager_secret.github_token.id
  secret_data = "placeholder-populated-out-of-band"
}

resource "google_cloudbuild_trigger" "app" {
  name     = "app-ci"
  location = "us-central1"

  service_account = google_service_account.build.id

  repository_event_config {
    repository = google_cloudbuildv2_connection.github.id

    push {
      branch = "^main$"
    }
  }

  build {
    step {
      name = "gcr.io/cloud-builders/docker"
      args = ["build", "-t", "us-central1-docker.pkg.dev/example-project/app/app:$SHORT_SHA", "."]
    }

    step {
      name = "gcr.io/cloud-builders/docker"
      args = ["push", "us-central1-docker.pkg.dev/example-project/app/app:$SHORT_SHA"]
    }

    options {
      worker_pool = google_cloudbuild_worker_pool.private.id
    }
  }
}

resource "google_cloudbuild_worker_pool" "private" {
  name     = "private-build-pool"
  location = "us-central1"

  network_config {
    peered_network = google_compute_network.main.id
  }

  worker_config {
    disk_size_gb   = 100
    machine_type   = "e2-standard-4"
    no_external_ip = true
  }
}

# -------------------------------------------------------------------- Deploy

resource "google_clouddeploy_delivery_pipeline" "app" {
  name     = "app-pipeline"
  location = "us-central1"

  serial_pipeline {
    stages {
      target_id = google_clouddeploy_target.staging.target_id
    }

    stages {
      target_id = google_clouddeploy_target.production.target_id

      strategy {
        standard {
          verify = true
        }
      }
    }
  }
}

resource "google_clouddeploy_target" "staging" {
  name     = "staging"
  location = "us-central1"

  gke {
    cluster = "projects/example-project/locations/us-central1/clusters/staging"
  }

  require_approval = false
}

resource "google_clouddeploy_target" "production" {
  name     = "production"
  location = "us-central1"

  gke {
    cluster = "projects/example-project/locations/us-central1/clusters/production"
  }

  require_approval = true
}

# ------------------------------------------------------------- Observability

resource "google_logging_project_sink" "cicd" {
  name        = "cicd-sink"
  destination = "logging.googleapis.com/projects/example-project/locations/us-central1/buckets/_Default"
  filter      = "resource.type=\"build\" OR resource.type=\"clouddeploy.googleapis.com/DeliveryPipeline\""
}
