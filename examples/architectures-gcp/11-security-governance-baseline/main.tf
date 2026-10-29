# ArchLens reference architecture 11 (GCP) — Security and governance baseline
#
# The org-level controls every other GCP architecture in this set assumes
# are already in place: an Org Policy constraining risky defaults, a VPC
# Service Controls perimeter around sensitive data services, Security
# Command Center wired to notify, Cloud Asset Inventory feeds, and a
# locked-down default service-account posture.
#
# Services: Organization Policy, Access Context Manager (VPC-SC policy +
# perimeter), Security Command Center (source + notification), Cloud Asset
# Inventory feed, KMS, Workload Identity Pool, Billing Budget, Logging
# sinks, Resource Manager Folder.
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
}

resource "google_folder" "workloads" {
  display_name = "workloads"
  parent        = "organizations/123456789012"
}

# ----------------------------------------------------------------- Policy

resource "google_org_policy_policy" "disable_sa_key_creation" {
  name   = "projects/example-project/policies/iam.disableServiceAccountKeyCreation"
  parent = "projects/example-project"

  spec {
    rules {
      enforce = "TRUE"
    }
  }
}

resource "google_org_policy_policy" "restrict_public_ips" {
  name   = "projects/example-project/policies/compute.vmExternalIpAccess"
  parent = "projects/example-project"

  spec {
    rules {
      deny_all = "TRUE"
    }
  }
}

resource "google_org_policy_policy" "uniform_bucket_access" {
  name   = "projects/example-project/policies/storage.uniformBucketLevelAccess"
  parent = "projects/example-project"

  spec {
    rules {
      enforce = "TRUE"
    }
  }
}

# --------------------------------------------------------- VPC Service Controls

resource "google_access_context_manager_access_policy" "main" {
  parent = "organizations/123456789012"
  title  = "example-access-policy"
}

resource "google_access_context_manager_service_perimeter" "sensitive_data" {
  parent = "accessPolicies/${google_access_context_manager_access_policy.main.name}"
  name   = "accessPolicies/${google_access_context_manager_access_policy.main.name}/servicePerimeters/sensitive_data"
  title  = "sensitive_data"

  status {
    restricted_services = [
      "bigquery.googleapis.com",
      "storage.googleapis.com",
      "sqladmin.googleapis.com",
    ]

    resources = ["projects/example-project"]
  }
}

# --------------------------------------------------------- Identity & keys

resource "google_kms_key_ring" "governance" {
  name     = "governance-keyring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "org_default" {
  name            = "org-default-key"
  key_ring        = google_kms_key_ring.governance.id
  rotation_period = "7776000s"
}

resource "google_iam_workload_identity_pool" "cicd" {
  workload_identity_pool_id = "cicd-pool"
  display_name              = "CI/CD Workload Identity"
}

resource "google_service_account" "audit" {
  account_id   = "audit-reader-sa"
  display_name = "Audit Log Reader"
}

resource "google_project_iam_member" "audit_reader" {
  project = "example-project"
  role    = "roles/logging.viewer"
  member  = "serviceAccount:${google_service_account.audit.email}"
}

# --------------------------------------------------------- Detection & response

resource "google_scc_source" "custom_findings" {
  organization = "123456789012"
  display_name = "custom-security-findings"
}

resource "google_scc_notification_config" "high_severity" {
  config_id    = "high-severity-notifications"
  organization = "123456789012"
  location     = "global"
  description  = "Notify on high and critical findings"

  pubsub_topic = google_pubsub_topic.scc_findings.id

  streaming_config {
    filter = "severity=\"HIGH\" OR severity=\"CRITICAL\""
  }
}

resource "google_pubsub_topic" "scc_findings" {
  name         = "scc-findings"
  kms_key_name = google_kms_crypto_key.org_default.id
}

resource "google_cloud_asset_project_feed" "inventory" {
  project      = "example-project"
  feed_id      = "asset-inventory-feed"
  content_type = "RESOURCE"

  feed_output_config {
    pubsub_destination {
      topic = google_pubsub_topic.asset_changes.id
    }
  }
}

resource "google_pubsub_topic" "asset_changes" {
  name         = "asset-inventory-changes"
  kms_key_name = google_kms_crypto_key.org_default.id
}

resource "google_essential_contacts_contact" "security_team" {
  parent                             = "projects/example-project"
  email                               = "security@example.com"
  language_tag                       = "en-US"
  notification_category_subscriptions = ["SECURITY"]
}

# --------------------------------------------------------- Cost & logging

resource "google_billing_budget" "monthly" {
  billing_account = "012345-6789AB-CDEF01"
  display_name    = "monthly-governance-budget"

  budget_filter {
    projects = ["projects/example-project"]
  }

  amount {
    specified_amount {
      currency_code = "USD"
      units         = "10000"
    }
  }

  threshold_rules {
    threshold_percent = 0.9
  }
}

resource "google_storage_bucket" "audit_logs" {
  name     = "example-governance-audit-logs"
  location = "US"

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  encryption {
    default_kms_key_name = google_kms_crypto_key.org_default.id
  }

  versioning {
    enabled = true
  }

  logging {
    log_bucket = google_storage_bucket.audit_logs.name
  }

  retention_policy {
    retention_period = 31536000
    is_locked         = true
  }
}

resource "google_logging_project_sink" "org_audit" {
  name        = "org-audit-sink"
  destination = "storage.googleapis.com/${google_storage_bucket.audit_logs.name}"
  filter      = "logName:\"cloudaudit.googleapis.com\""
}

resource "google_monitoring_alert_policy" "policy_violation" {
  display_name = "Org policy violation detected"
  combiner      = "OR"

  conditions {
    display_name = "SCC finding rate above zero"

    condition_threshold {
      filter          = "resource.type = \"securitycenter.googleapis.com/Finding\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }
}
