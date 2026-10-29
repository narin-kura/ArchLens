# ArchLens reference architecture 10 (GCP) — Media transcoding and streaming
#
# Uploaded video lands in Cloud Storage, Transcoder API produces adaptive
# bitrate renditions, and the results are served through Cloud CDN behind
# the same global LB stack as the other edge-facing architectures.
#
# Services: Cloud Storage (uploads + renditions), Transcoder API, Cloud CDN
# (backend bucket), Global External LB, Cloud Armor, Pub/Sub (job
# completion events), KMS, Logging, Monitoring.
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
  name     = "media-keyring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "media" {
  name            = "media-encryption-key"
  key_ring        = google_kms_key_ring.main.id
  rotation_period = "7776000s"
}

resource "google_storage_bucket" "uploads" {
  name     = "example-media-uploads"
  location = "US"

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  encryption {
    default_kms_key_name = google_kms_crypto_key.media.id
  }

  versioning {
    enabled = true
  }

  logging {
    log_bucket = google_storage_bucket.logs.name
  }
}

resource "google_storage_bucket" "renditions" {
  name     = "example-media-renditions"
  location = "US"

  uniform_bucket_level_access = true
  public_access_prevention    = "inherited" # served publicly via CDN, intentional

  encryption {
    default_kms_key_name = google_kms_crypto_key.media.id
  }

  versioning {
    enabled = true
  }

  logging {
    log_bucket = google_storage_bucket.logs.name
  }
}

resource "google_storage_bucket" "logs" {
  name     = "example-media-logs"
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

resource "google_pubsub_topic" "job_events" {
  name         = "transcode-job-events"
  kms_key_name = google_kms_crypto_key.media.id
}

resource "google_transcoder_job_template" "adaptive_bitrate" {
  job_template_id = "adaptive-bitrate"
  location        = "us-central1"

  config {
    elementary_streams {
      key = "video-stream0"
      video_stream {
        h264 {
          height_pixels = 720
          width_pixels  = 1280
          bitrate_bps   = 2500000
        }
      }
    }

    mux_streams {
      key               = "hd"
      container         = "fmp4"
      elementary_streams = ["video-stream0"]
    }
  }
}

resource "google_compute_backend_bucket" "renditions" {
  name        = "media-backend-bucket"
  bucket_name = google_storage_bucket.renditions.name
  enable_cdn  = true

  cdn_policy {
    cache_mode  = "CACHE_ALL_STATIC"
    default_ttl = 3600
    max_ttl     = 86400
  }
}

resource "google_compute_url_map" "media" {
  name            = "media-url-map"
  default_service = google_compute_backend_bucket.renditions.id
}

resource "google_compute_managed_ssl_certificate" "media" {
  name = "media-managed-cert"

  managed {
    domains = ["media.example.com"]
  }
}

resource "google_compute_ssl_policy" "media" {
  name            = "media-modern-tls"
  min_tls_version = "TLS_1_2"
  profile         = "MODERN"
}

resource "google_compute_target_https_proxy" "media" {
  name             = "media-https-proxy"
  url_map          = google_compute_url_map.media.id
  ssl_certificates = [google_compute_managed_ssl_certificate.media.id]
  ssl_policy       = google_compute_ssl_policy.media.id
}

resource "google_compute_global_address" "media" {
  name = "media-lb-ip"
}

resource "google_compute_global_forwarding_rule" "media" {
  name       = "media-forwarding-rule"
  target     = google_compute_target_https_proxy.media.id
  port_range = "443"
  ip_address = google_compute_global_address.media.id
}

resource "google_compute_security_policy" "media" {
  name = "media-armor-policy"

  rule {
    action   = "allow"
    priority = 2147483647

    match {
      versioned_expr = "SRC_IPS_V1"

      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Default allow for a public media CDN"
  }
}

resource "google_logging_project_sink" "media" {
  name        = "media-sink"
  destination = "storage.googleapis.com/${google_storage_bucket.logs.name}"
  filter      = "resource.type=\"transcoder.googleapis.com/Job\""
}

resource "google_monitoring_alert_policy" "job_failures" {
  display_name = "Transcode job failures"
  combiner      = "OR"

  conditions {
    display_name = "Failed job rate above 5%"

    condition_threshold {
      filter          = "resource.type = \"transcoder.googleapis.com/Job\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0.05
    }
  }
}
