# ArchLens reference architecture 16 (GCP) — Cloud Run microservices
#
# Three independently deployable services (orders, inventory, notifications)
# talking to each other over private service-to-service auth, each with its
# own Cloud SQL database and its own Pub/Sub topic for async events — no
# cluster to operate, Cloud Run scales each service independently.
#
# Services: Cloud Run (3 services + their service accounts), Cloud SQL
# (orders + inventory), Pub/Sub (order events), Artifact Registry, Cloud
# Build, Serverless VPC Access connector, KMS, Secret Manager, Logging,
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
  name                    = "vpc-microservices"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "data" {
  name          = "snet-data"
  network       = google_compute_network.main.id
  ip_cidr_range = "10.110.0.0/24"
  region        = "us-central1"

  private_ip_google_access = true
}

resource "google_compute_subnetwork" "connector" {
  name          = "snet-serverless-connector"
  network       = google_compute_network.main.id
  ip_cidr_range = "10.110.1.0/28"
  region        = "us-central1"
}

resource "google_vpc_access_connector" "main" {
  name   = "microservices-connector"
  region = "us-central1"

  subnet {
    name = google_compute_subnetwork.connector.name
  }
}

resource "google_kms_key_ring" "main" {
  name     = "microservices-keyring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "data" {
  name            = "microservices-data-key"
  key_ring        = google_kms_key_ring.main.id
  rotation_period = "7776000s"
}

resource "google_artifact_registry_repository" "services" {
  repository_id = "services"
  location      = "us-central1"
  format        = "DOCKER"

  kms_key_name = google_kms_crypto_key.data.id
}

# --------------------------------------------------------------------- Data

resource "google_sql_database_instance" "orders" {
  name                = "orders-db"
  database_version    = "POSTGRES_15"
  region              = "us-central1"
  deletion_protection = true

  settings {
    tier              = "db-custom-2-7680"
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

resource "google_sql_database_instance" "inventory" {
  name                = "inventory-db"
  database_version    = "POSTGRES_15"
  region              = "us-central1"
  deletion_protection = true

  settings {
    tier              = "db-custom-2-7680"
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

resource "google_pubsub_topic" "order_events" {
  name         = "order-events"
  kms_key_name = google_kms_crypto_key.data.id
}

resource "google_pubsub_subscription" "notifications" {
  name  = "order-events-notifications-sub"
  topic = google_pubsub_topic.order_events.name

  ack_deadline_seconds = 30

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.order_events_dlq.id
    max_delivery_attempts = 5
  }
}

resource "google_pubsub_topic" "order_events_dlq" {
  name         = "order-events-dlq"
  kms_key_name = google_kms_crypto_key.data.id
}

# ----------------------------------------------------------------- Services

resource "google_service_account" "orders" {
  account_id   = "orders-svc-sa"
  display_name = "Orders Service Account"
}

resource "google_service_account" "inventory" {
  account_id   = "inventory-svc-sa"
  display_name = "Inventory Service Account"
}

resource "google_service_account" "notifications" {
  account_id   = "notifications-svc-sa"
  display_name = "Notifications Service Account"
}

resource "google_project_iam_member" "orders_sql" {
  project = "example-project"
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.orders.email}"
}

resource "google_project_iam_member" "inventory_sql" {
  project = "example-project"
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.inventory.email}"
}

resource "google_cloud_run_v2_service" "orders" {
  name     = "orders"
  location = "us-central1"

  template {
    service_account = google_service_account.orders.email

    vpc_access {
      connector = google_vpc_access_connector.main.id
      egress    = "PRIVATE_RANGES_ONLY"
    }

    containers {
      image = "us-central1-docker.pkg.dev/example-project/services/orders:1.0.0"

      resources {
        limits = {
          cpu    = "1"
          memory = "1Gi"
        }
      }
    }

    scaling {
      min_instance_count = 1
      max_instance_count = 20
    }
  }
}

resource "google_cloud_run_v2_service" "inventory" {
  name     = "inventory"
  location = "us-central1"

  template {
    service_account = google_service_account.inventory.email

    vpc_access {
      connector = google_vpc_access_connector.main.id
      egress    = "PRIVATE_RANGES_ONLY"
    }

    containers {
      image = "us-central1-docker.pkg.dev/example-project/services/inventory:1.0.0"

      resources {
        limits = {
          cpu    = "1"
          memory = "1Gi"
        }
      }
    }

    scaling {
      min_instance_count = 1
      max_instance_count = 20
    }
  }
}

resource "google_cloud_run_v2_service" "notifications" {
  name     = "notifications"
  location = "us-central1"

  template {
    service_account = google_service_account.notifications.email

    containers {
      image = "us-central1-docker.pkg.dev/example-project/services/notifications:1.0.0"

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

# orders -> inventory calls are service-to-service, authenticated by ID
# token rather than being open to the internet; only orders may invoke it.
resource "google_cloud_run_v2_service_iam_member" "orders_calls_inventory" {
  name     = google_cloud_run_v2_service.inventory.name
  location = "us-central1"
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.orders.email}"
}

resource "google_cloud_run_v2_service_iam_member" "public_orders" {
  name     = google_cloud_run_v2_service.orders.name
  location = "us-central1"
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# ----------------------------------------------------------------- Build

resource "google_service_account" "build" {
  account_id   = "microservices-build-sa"
  display_name = "Microservices Build Service Account"
}

resource "google_cloudbuild_trigger" "services" {
  name     = "services-ci"
  location = "us-central1"

  service_account = google_service_account.build.id

  github {
    owner = "example-org"
    name  = "microservices"

    push {
      branch = "^main$"
    }
  }

  build {
    step {
      name = "gcr.io/cloud-builders/docker"
      args = ["build", "-t", "us-central1-docker.pkg.dev/example-project/services/orders:$SHORT_SHA", "orders/"]
    }
  }
}

resource "google_secret_manager_secret" "shared_signing_key" {
  secret_id = "services-shared-signing-key"

  replication {
    auto {}
  }
}

# ------------------------------------------------------------- Observability

resource "google_logging_project_sink" "services" {
  name        = "microservices-sink"
  destination = "logging.googleapis.com/projects/example-project/locations/us-central1/buckets/_Default"
  filter      = "resource.type=\"cloud_run_revision\""
}

resource "google_monitoring_alert_policy" "service_errors" {
  display_name = "Microservices 5xx error rate"
  combiner      = "OR"

  conditions {
    display_name = "5xx rate above 1%"

    condition_threshold {
      filter          = "resource.type = \"cloud_run_revision\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0.01
    }
  }
}
