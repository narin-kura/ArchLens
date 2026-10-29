# ArchLens reference architecture 15 (GCP) — Batch compute and HPC
#
# Cloud Batch runs the nightly risk calculation on Spot VMs; an HPC VM pool
# with tier-1 networking and a Filestore-backed shared scratch filesystem
# handles the tightly-coupled MPI simulations.
#
# Services: Cloud Batch (job), Compute Engine (Spot VMs via MIG), Filestore
# (HPC scratch), Cloud Storage, KMS, Logging, Monitoring.
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
  name                    = "vpc-batch-hpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "compute" {
  name          = "snet-hpc-compute"
  network       = google_compute_network.main.id
  ip_cidr_range = "10.100.0.0/22"
  region        = "us-central1"

  private_ip_google_access = true
}

resource "google_compute_firewall" "allow_intra_cluster" {
  name    = "allow-intra-cluster-mpi"
  network = google_compute_network.main.id

  allow {
    protocol = "all"
  }

  source_ranges = ["10.100.0.0/22"]
}

resource "google_kms_key_ring" "main" {
  name     = "batch-hpc-keyring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "batch" {
  name            = "batch-hpc-key"
  key_ring        = google_kms_key_ring.main.id
  rotation_period = "7776000s"
}

# ------------------------------------------------------------------- Storage

resource "google_storage_bucket" "results" {
  name     = "example-batch-hpc-results"
  location = "US"

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  encryption {
    default_kms_key_name = google_kms_crypto_key.batch.id
  }

  versioning {
    enabled = true
  }

  logging {
    log_bucket = google_storage_bucket.logs.name
  }

  lifecycle_rule {
    condition {
      age = 30
    }
    action {
      type          = "SetStorageClass"
      storage_class = "NEARLINE"
    }
  }
}

resource "google_storage_bucket" "logs" {
  name     = "example-batch-hpc-logs"
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

resource "google_filestore_instance" "scratch" {
  name     = "hpc-scratch"
  location = "us-central1-a"
  tier     = "HIGH_SCALE_SSD"

  file_shares {
    capacity_gb = 10240
    name        = "scratch"
  }

  networks {
    network = google_compute_network.main.id
    modes   = ["MODE_IPV4"]
  }

  kms_key_name = google_kms_crypto_key.batch.id
}

resource "google_filestore_backup" "scratch_daily" {
  name            = "hpc-scratch-daily"
  location        = "us-central1"
  source_instance = google_filestore_instance.scratch.id
  source_file_share = "scratch"
  kms_key_name    = google_kms_crypto_key.batch.id
}

# --------------------------------------------------------------------- Batch

resource "google_service_account" "batch" {
  account_id   = "batch-hpc-sa"
  display_name = "Batch Job Service Account"
}

resource "google_project_iam_member" "batch_storage" {
  project = "example-project"
  role    = "roles/storage.objectAdmin"
  member  = "serviceAccount:${google_service_account.batch.email}"
}

resource "google_batch_job" "risk_calc" {
  job_id   = "nightly-risk-calc"
  location = "us-central1"

  task_groups {
    task_count = 20

    task_spec {
      compute_resource {
        cpu_milli  = 4000
        memory_mib = 16384
      }

      runnables {
        container {
          image_uri = "us-central1-docker.pkg.dev/example-project/batch/risk:4.2.0"
        }
      }

      max_retry_count = 2
    }
  }

  allocation_policy {
    service_account {
      email = google_service_account.batch.email
    }

    instances {
      policy {
        provisioning_model = "SPOT"
        machine_type       = "n2-standard-4"
      }
    }

    network {
      network_interfaces {
        network    = google_compute_network.main.id
        subnetwork = google_compute_subnetwork.compute.id
      }
    }
  }

  logs_policy {
    destination = "CLOUD_LOGGING"
  }
}

# ------------------------------------------------------------------------- HPC

resource "google_compute_instance_template" "hpc" {
  name_prefix  = "hpc-sim-"
  machine_type = "h3-standard-88"

  scheduling {
    provisioning_model = "SPOT"
    preemptible         = true
  }

  disk {
    source_image = "projects/cloud-hpc-image-public/global/images/family/hpc-rocky-linux-8"
    auto_delete  = true
    boot         = true

    disk_encryption_key {
      kms_key_self_link = google_kms_crypto_key.batch.id
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.compute.id
    nic_type   = "GVNIC"
  }

  service_account {
    email  = google_service_account.batch.email
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

resource "google_compute_instance_group_manager" "hpc" {
  name               = "hpc-sim-mig"
  base_instance_name = "hpc-sim"
  zone               = "us-central1-a"
  target_size        = 4

  version {
    instance_template = google_compute_instance_template.hpc.id
  }
}

resource "google_compute_autoscaler" "hpc" {
  name   = "hpc-sim-autoscaler"
  zone   = "us-central1-a"
  target = google_compute_instance_group_manager.hpc.id

  autoscaling_policy {
    min_replicas    = 0
    max_replicas    = 64
    cooldown_period = 120

    cpu_utilization {
      target = 0.8
    }
  }
}

# ------------------------------------------------------------- Observability

resource "google_logging_project_sink" "batch_hpc" {
  name        = "batch-hpc-sink"
  destination = "storage.googleapis.com/${google_storage_bucket.logs.name}"
  filter      = "resource.type=\"batch.googleapis.com/Job\""
}

resource "google_monitoring_alert_policy" "job_failures" {
  display_name = "Batch job task failures"
  combiner      = "OR"

  conditions {
    display_name = "Failed task rate above 5"

    condition_threshold {
      filter          = "resource.type = \"batch.googleapis.com/Job\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
    }
  }
}
