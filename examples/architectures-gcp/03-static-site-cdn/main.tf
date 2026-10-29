# ArchLens reference architecture 03 (GCP) — Static site with CDN
#
# A static site served straight from Cloud Storage through Cloud CDN, behind
# the same global external HTTPS load balancer stack as the dynamic
# architectures, with Cloud Armor and a managed TLS certificate. No origin
# server to patch or scale.
#
# Services: Cloud Storage (static site), Cloud CDN (backend bucket), Global
# External LB, Managed SSL Certificate, Cloud Armor, Cloud DNS, Logging.
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

resource "google_storage_bucket" "site" {
  name     = "example-static-site"
  location = "US"

  uniform_bucket_level_access = true
  public_access_prevention    = "inherited" # public read is intentional, served only via the LB + signed CDN cache

  website {
    main_page_suffix = "index.html"
    not_found_page   = "404.html"
  }

  versioning {
    enabled = true
  }

  logging {
    log_bucket = google_storage_bucket.logs.name
  }
}

resource "google_storage_bucket" "logs" {
  name     = "example-static-site-logs"
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

resource "google_storage_bucket_iam_member" "public_read" {
  bucket = google_storage_bucket.site.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

resource "google_compute_backend_bucket" "site" {
  name        = "site-backend-bucket"
  bucket_name = google_storage_bucket.site.name
  enable_cdn  = true

  cdn_policy {
    cache_mode  = "CACHE_ALL_STATIC"
    default_ttl = 3600
    client_ttl  = 3600
    max_ttl     = 86400
  }
}

resource "google_compute_url_map" "site" {
  name            = "site-url-map"
  default_service = google_compute_backend_bucket.site.id
}

resource "google_compute_managed_ssl_certificate" "site" {
  name = "site-managed-cert"

  managed {
    domains = ["www.example.com"]
  }
}

resource "google_compute_ssl_policy" "site" {
  name            = "site-modern-tls"
  min_tls_version = "TLS_1_2"
  profile         = "MODERN"
}

resource "google_compute_target_https_proxy" "site" {
  name             = "site-https-proxy"
  url_map          = google_compute_url_map.site.id
  ssl_certificates = [google_compute_managed_ssl_certificate.site.id]
  ssl_policy       = google_compute_ssl_policy.site.id
}

resource "google_compute_global_address" "site" {
  name = "site-lb-ip"
}

resource "google_compute_global_forwarding_rule" "site" {
  name       = "site-forwarding-rule"
  target     = google_compute_target_https_proxy.site.id
  port_range = "443"
  ip_address = google_compute_global_address.site.id
}

resource "google_compute_security_policy" "site" {
  name = "site-armor-policy"

  rule {
    action   = "allow"
    priority = 2147483647

    match {
      versioned_expr = "SRC_IPS_V1"

      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Default allow for a public static site"
  }
}

resource "google_dns_managed_zone" "main" {
  name     = "example-com-zone"
  dns_name = "example.com."
}

resource "google_dns_record_set" "www" {
  name         = "www.example.com."
  type         = "A"
  ttl          = 300
  managed_zone = google_dns_managed_zone.main.name
  rrdatas      = [google_compute_global_address.site.address]
}

resource "google_logging_project_sink" "site" {
  name        = "site-sink"
  destination = "storage.googleapis.com/${google_storage_bucket.logs.name}"
  filter      = "resource.type=\"http_load_balancer\""
}
