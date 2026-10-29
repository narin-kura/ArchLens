# ArchLens reference architecture 04 (GCP) — GKE platform
#
# A private GKE cluster running a multi-service application: Workload
# Identity instead of node service-account keys, a dedicated node pool per
# workload tier, and Binary Authorization gating what images can even run.
# Artifact Registry + Cloud Build round out the inner loop.
#
# Services: GKE (private cluster + 2 node pools), Workload Identity,
# Binary Authorization, Artifact Registry, Cloud Build, Cloud SQL (shared
# data tier), Secret Manager, KMS, Cloud Armor + external LB in front of the
# cluster's ingress, Logging, Monitoring.
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
  name                    = "vpc-gke"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "gke" {
  name          = "snet-gke"
  network       = google_compute_network.main.id
  ip_cidr_range = "10.20.0.0/20"
  region        = "us-central1"

  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = "10.21.0.0/16"
  }

  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = "10.22.0.0/20"
  }

  private_ip_google_access = true
}

resource "google_kms_key_ring" "main" {
  name     = "gke-platform-keyring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "gke_secrets" {
  name            = "gke-secrets-key"
  key_ring        = google_kms_key_ring.main.id
  rotation_period = "7776000s"
}

resource "google_container_cluster" "main" {
  name     = "app-platform"
  location = "us-central1"

  remove_default_node_pool = true
  initial_node_count       = 1

  network    = google_compute_network.main.id
  subnetwork = google_compute_subnetwork.gke.id

  networking_mode = "VPC_NATIVE"

  ip_allocation_policy {
    cluster_secondary_range_name  = "pods"
    services_secondary_range_name = "services"
  }

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = "10.0.0.0/8"
      display_name = "internal-only"
    }
  }

  workload_identity_config {
    workload_pool = "example-project.svc.id.goog"
  }

  database_encryption {
    state    = "ENCRYPTED"
    key_name = google_kms_crypto_key.gke_secrets.id
  }

  binary_authorization {
    evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"
  }

  release_channel {
    channel = "REGULAR"
  }

  logging_config {
    enable_components = ["SYSTEM_COMPONENTS", "WORKLOADS"]
  }

  monitoring_config {
    enable_components = ["SYSTEM_COMPONENTS"]
  }
}

resource "google_container_node_pool" "frontend" {
  name     = "frontend-pool"
  cluster  = google_container_cluster.main.name
  location = "us-central1"

  node_config {
    machine_type    = "e2-standard-4"
    service_account = google_service_account.gke_nodes.email
    oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    workload_metadata_config {
      mode = "GKE_METADATA"
    }
  }

  autoscaling {
    min_node_count = 2
    max_node_count = 8
  }
}

resource "google_container_node_pool" "backend" {
  name     = "backend-pool"
  cluster  = google_container_cluster.main.name
  location = "us-central1"

  node_config {
    machine_type    = "e2-standard-8"
    service_account = google_service_account.gke_nodes.email
    oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    workload_metadata_config {
      mode = "GKE_METADATA"
    }
  }

  autoscaling {
    min_node_count = 2
    max_node_count = 12
  }
}

resource "google_service_account" "gke_nodes" {
  account_id   = "gke-nodes-sa"
  display_name = "GKE Node Service Account"
}

resource "google_service_account" "workload" {
  account_id   = "app-workload-sa"
  display_name = "App Workload Identity"
}

resource "google_project_iam_member" "workload_sql" {
  project = "example-project"
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.workload.email}"
}

resource "google_service_account_iam_member" "workload_identity_binding" {
  service_account_id = google_service_account.workload.name
  role                = "roles/iam.workloadIdentityUser"
  member              = "serviceAccount:example-project.svc.id.goog[default/app-ksa]"
}

# ----------------------------------------------------------------- Artefacts

resource "google_artifact_registry_repository" "app" {
  repository_id = "app"
  location      = "us-central1"
  format        = "DOCKER"
}

resource "google_binary_authorization_policy" "main" {
  default_admission_rule {
    evaluation_mode  = "REQUIRE_ATTESTATION"
    enforcement_mode = "ENFORCED_BLOCK_AND_AUDIT_LOG"

    require_attestations_by = [google_binary_authorization_attestor.build.name]
  }

  global_policy_evaluation_mode = "ENABLE"
}

resource "google_binary_authorization_attestor" "build" {
  name = "build-attestor"

  attestation_authority_note {
    note_reference = google_container_analysis_note.build.name
  }
}

resource "google_container_analysis_note" "build" {
  name = "build-attestor-note"

  attestation_authority {
    hint {
      human_readable_name = "Build attestor"
    }
  }
}

resource "google_cloudbuild_trigger" "app" {
  name     = "app-ci"
  location = "us-central1"

  github {
    owner = "example-org"
    name  = "gke-app"

    push {
      branch = "^main$"
    }
  }

  build {
    step {
      name = "gcr.io/cloud-builders/docker"
      args = ["build", "-t", "us-central1-docker.pkg.dev/example-project/app/app:$SHORT_SHA", "."]
    }
  }
}

# -------------------------------------------------------------------- Data

resource "google_sql_database_instance" "main" {
  name                = "platform-db"
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

resource "google_secret_manager_secret" "db_password" {
  secret_id = "platform-db-password"

  replication {
    auto {}
  }
}

# ---------------------------------------------------------------------- Edge

resource "google_compute_security_policy" "ingress" {
  name = "gke-ingress-armor"

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

# ------------------------------------------------------------- Observability

resource "google_monitoring_alert_policy" "node_cpu" {
  display_name = "GKE node CPU high"
  combiner      = "OR"

  conditions {
    display_name = "CPU above 85%"

    condition_threshold {
      filter          = "resource.type = \"k8s_node\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0.85
    }
  }
}
