# ArchLens reference architecture 11 (OCI) — Security and governance baseline
#
# The tenancy-level controls every other OCI architecture assumes: a
# compartment per workload, least-privilege policies granted to groups
# (never to individuals), Cloud Guard watching every compartment and a
# Security Zone that refuses to create public buckets or unencrypted
# volumes, a year of audit retention, mandatory cost-center tags, a budget
# alert, host vulnerability scanning, and an Events rule that pages on IAM
# changes.
#
# Services: Compartments, IAM (groups, policies, dynamic group, tag
# namespace + tag), Cloud Guard (configuration, target, security zone +
# recipe), Audit, Vulnerability Scanning, Budget, Events, Notifications,
# Object Storage (audit archive), Vault (KMS), Logging.
#
# Expected ArchLens findings: clean.

terraform {
  required_version = ">= 1.6"
  required_providers {
    oci = { source = "oracle/oci", version = "~> 6.0" }
  }
}

variable "tenancy_id" {}
variable "tenancy_namespace" {}
variable "security_zone_policy_ids" { type = list(string) }

# -------------------------------------------------------------- Structure

resource "oci_identity_compartment" "security" {
  compartment_id = var.tenancy_id
  name           = "security"
  description    = "Security tooling and audit archive"
}

resource "oci_identity_compartment" "workloads" {
  compartment_id = var.tenancy_id
  name           = "workloads"
  description    = "Application workloads"
}

resource "oci_identity_group" "platform_admins" {
  compartment_id = var.tenancy_id
  name           = "platform-admins"
  description    = "Manage workload infrastructure"
}

resource "oci_identity_group" "auditors" {
  compartment_id = var.tenancy_id
  name           = "auditors"
  description    = "Read-only security review"
}

resource "oci_identity_policy" "platform_admins" {
  compartment_id = var.tenancy_id
  name           = "platform-admins"
  description    = "Admins manage workloads, nothing at tenancy root"
  statements = [
    "Allow group platform-admins to manage all-resources in compartment workloads",
  ]
}

resource "oci_identity_policy" "auditors" {
  compartment_id = var.tenancy_id
  name           = "auditors"
  description    = "Auditors read everything, change nothing"
  statements = [
    "Allow group auditors to inspect all-resources in tenancy",
    "Allow group auditors to read audit-events in tenancy",
  ]
}

resource "oci_identity_dynamic_group" "scanners" {
  compartment_id = var.tenancy_id
  name           = "vss-scanners"
  description    = "Instances that run the scanning agent"
  matching_rule  = "ALL {instance.compartment.id = '${oci_identity_compartment.workloads.id}'}"
}

resource "oci_identity_tag_namespace" "governance" {
  compartment_id = var.tenancy_id
  name           = "governance"
  description    = "Mandatory governance tags"
}

resource "oci_identity_tag" "cost_center" {
  tag_namespace_id = oci_identity_tag_namespace.governance.id
  name             = "cost-center"
  description      = "Billing owner"
}

resource "oci_identity_tag_default" "cost_center" {
  compartment_id    = oci_identity_compartment.workloads.id
  tag_definition_id = oci_identity_tag.cost_center.id
  value             = "unassigned"
  is_required       = true
}

# ----------------------------------------------------------- Detection

resource "oci_cloud_guard_cloud_guard_configuration" "main" {
  compartment_id   = var.tenancy_id
  reporting_region = "us-ashburn-1"
  status           = "ENABLED"
}

resource "oci_cloud_guard_target" "tenancy" {
  compartment_id       = var.tenancy_id
  display_name         = "tenancy-root"
  target_resource_id   = var.tenancy_id
  target_resource_type = "COMPARTMENT"
}

resource "oci_cloud_guard_security_recipe" "baseline" {
  compartment_id    = oci_identity_compartment.security.id
  display_name      = "workload-baseline"
  security_policies = var.security_zone_policy_ids
}

resource "oci_cloud_guard_security_zone" "workloads" {
  compartment_id          = oci_identity_compartment.workloads.id
  display_name            = "workloads-zone"
  security_zone_recipe_id = oci_cloud_guard_security_recipe.baseline.id
}

resource "oci_audit_configuration" "main" {
  compartment_id        = var.tenancy_id
  retention_period_days = 365
}

resource "oci_vulnerability_scanning_host_scan_recipe" "baseline" {
  compartment_id = oci_identity_compartment.security.id
  display_name   = "host-baseline"

  agent_settings {
    scan_level = "STANDARD"

    agent_configuration {
      vendor = "OCI"

      cis_benchmark_settings {
        scan_level = "STRICT"
      }
    }
  }

  port_settings {
    scan_level = "STANDARD"
  }

  schedule {
    type        = "WEEKLY"
    day_of_week = "SUNDAY"
  }
}

resource "oci_vulnerability_scanning_host_scan_target" "workloads" {
  compartment_id        = oci_identity_compartment.security.id
  display_name          = "workloads"
  host_scan_recipe_id   = oci_vulnerability_scanning_host_scan_recipe.baseline.id
  target_compartment_id = oci_identity_compartment.workloads.id
}

# ---------------------------------------------------------------- Alerting

resource "oci_ons_notification_topic" "security" {
  compartment_id = oci_identity_compartment.security.id
  name           = "security-alerts"
}

resource "oci_events_rule" "iam_changes" {
  compartment_id = var.tenancy_id
  display_name   = "iam-changes"
  is_enabled     = true
  condition      = jsonencode({ eventType = ["com.oraclecloud.identitycontrolplane.updatepolicy", "com.oraclecloud.identitycontrolplane.addusertogroup"] })

  actions {
    actions {
      action_type = "ONS"
      is_enabled  = true
      topic_id    = oci_ons_notification_topic.security.id
    }
  }
}

resource "oci_budget_budget" "workloads" {
  compartment_id = var.tenancy_id
  display_name   = "workloads-monthly"
  amount         = 20000
  reset_period   = "MONTHLY"
  target_type    = "COMPARTMENT"
  targets        = [oci_identity_compartment.workloads.id]
}

resource "oci_budget_alert_rule" "workloads_90" {
  budget_id      = oci_budget_budget.workloads.id
  type           = "FORECAST"
  threshold      = 90
  threshold_type = "PERCENTAGE"
  recipients     = "finops@example.com"
}

# -------------------------------------------------------- Audit archive

resource "oci_kms_vault" "security" {
  compartment_id = oci_identity_compartment.security.id
  display_name   = "vault-security"
  vault_type     = "DEFAULT"
}

resource "oci_kms_key" "audit" {
  compartment_id      = oci_identity_compartment.security.id
  display_name        = "key-audit-archive"
  management_endpoint = oci_kms_vault.security.management_endpoint

  key_shape {
    algorithm = "AES"
    length    = 32
  }
}

resource "oci_objectstorage_bucket" "audit_archive" {
  compartment_id = oci_identity_compartment.security.id
  namespace      = var.tenancy_namespace
  name           = "audit-archive"
  access_type    = "NoPublicAccess"
  versioning     = "Enabled"
  kms_key_id     = oci_kms_key.audit.id
}

resource "oci_logging_log_group" "security" {
  compartment_id = oci_identity_compartment.security.id
  display_name   = "lg-security"
}

resource "oci_logging_log" "audit_archive_reads" {
  display_name = "audit-archive-reads"
  log_group_id = oci_logging_log_group.security.id
  log_type     = "SERVICE"

  configuration {
    source {
      category    = "read"
      resource    = oci_objectstorage_bucket.audit_archive.name
      service     = "objectstorage"
      source_type = "OCISERVICE"
    }
  }
}

resource "oci_sch_service_connector" "audit_to_archive" {
  compartment_id = oci_identity_compartment.security.id
  display_name   = "audit-to-archive"

  source {
    kind = "logging"

    log_sources {
      compartment_id = var.tenancy_id
      log_group_id   = "_Audit"
    }
  }

  target {
    kind      = "objectStorage"
    bucket    = oci_objectstorage_bucket.audit_archive.name
    namespace = var.tenancy_namespace
  }
}
