# ArchLens reference architecture 08 (OCI) — Multi-region disaster recovery
#
# Primary in Ashburn, standby in Phoenix. Autonomous Database runs a
# cross-region Data Guard peer, the artefact bucket replicates continuously,
# the Vault (and its keys) is replicated so the standby can decrypt, the two
# VCNs talk over a remote peering connection between their DRGs, and Full
# Stack Disaster Recovery owns the switchover runbook. DNS steering fails the
# public name over when the primary health check goes red.
#
# Services: VCN x2, DRG x2 + attachments, Remote Peering Connection,
# Autonomous Database (+ cross-region Data Guard peer), Object Storage
# (+ replication policy), Vault (+ replication), Full Stack DR (protection
# groups + plan), DNS Steering Policy, Health Check, Logging, Monitoring.
#
# Expected ArchLens findings: clean.

terraform {
  required_version = ">= 1.6"
  required_providers {
    oci = { source = "oracle/oci", version = "~> 6.0" }
  }
}

provider "oci" {
  region = "us-ashburn-1"
}

provider "oci" {
  alias  = "dr"
  region = "us-phoenix-1"
}

variable "compartment_id" {}
variable "tenancy_namespace" {}

# ------------------------------------------------------------------ Network

resource "oci_core_vcn" "primary" {
  compartment_id = var.compartment_id
  cidr_blocks    = ["10.70.0.0/16"]
  display_name   = "vcn-primary"
}

resource "oci_core_vcn" "standby" {
  provider       = oci.dr
  compartment_id = var.compartment_id
  cidr_blocks    = ["10.71.0.0/16"]
  display_name   = "vcn-standby"
}

resource "oci_core_subnet" "primary_data" {
  compartment_id             = var.compartment_id
  vcn_id                     = oci_core_vcn.primary.id
  cidr_block                 = "10.70.0.0/24"
  display_name               = "snet-primary-data"
  prohibit_public_ip_on_vnic = true
}

resource "oci_core_subnet" "standby_data" {
  provider                   = oci.dr
  compartment_id             = var.compartment_id
  vcn_id                     = oci_core_vcn.standby.id
  cidr_block                 = "10.71.0.0/24"
  display_name               = "snet-standby-data"
  prohibit_public_ip_on_vnic = true
}

resource "oci_core_drg" "primary" {
  compartment_id = var.compartment_id
  display_name   = "drg-primary"
}

resource "oci_core_drg" "standby" {
  provider       = oci.dr
  compartment_id = var.compartment_id
  display_name   = "drg-standby"
}

resource "oci_core_drg_attachment" "primary" {
  drg_id = oci_core_drg.primary.id

  network_details {
    id   = oci_core_vcn.primary.id
    type = "VCN"
  }
}

resource "oci_core_drg_attachment" "standby" {
  provider = oci.dr
  drg_id   = oci_core_drg.standby.id

  network_details {
    id   = oci_core_vcn.standby.id
    type = "VCN"
  }
}

resource "oci_core_remote_peering_connection" "standby" {
  provider       = oci.dr
  compartment_id = var.compartment_id
  drg_id         = oci_core_drg.standby.id
  display_name   = "rpc-standby"
}

resource "oci_core_remote_peering_connection" "primary" {
  compartment_id   = var.compartment_id
  drg_id           = oci_core_drg.primary.id
  display_name     = "rpc-primary"
  peer_id          = oci_core_remote_peering_connection.standby.id
  peer_region_name = "us-phoenix-1"
}

# --------------------------------------------------------------------- Keys

resource "oci_kms_vault" "main" {
  compartment_id = var.compartment_id
  display_name   = "vault-dr"
  vault_type     = "VIRTUAL_PRIVATE"
}

resource "oci_kms_vault_replication" "standby" {
  vault_id       = oci_kms_vault.main.id
  replica_region = "us-phoenix-1"
}

resource "oci_kms_key" "data" {
  compartment_id      = var.compartment_id
  display_name        = "key-dr-data"
  management_endpoint = oci_kms_vault.main.management_endpoint

  key_shape {
    algorithm = "AES"
    length    = 32
  }
}

# --------------------------------------------------------------------- Data

resource "oci_database_autonomous_database" "primary" {
  compartment_id              = var.compartment_id
  db_name                     = "ordersdb"
  display_name                = "adb-orders-primary"
  db_workload                 = "OLTP"
  compute_model               = "ECPU"
  compute_count               = 4
  data_storage_size_in_tbs    = 1
  subnet_id                   = oci_core_subnet.primary_data.id
  is_mtls_connection_required = true
  is_local_data_guard_enabled = true
  kms_key_id                  = oci_kms_key.data.id
  vault_id                    = oci_kms_vault.main.id
}

resource "oci_database_autonomous_database" "standby" {
  provider       = oci.dr
  compartment_id = var.compartment_id
  db_name        = "ordersdb"
  display_name   = "adb-orders-standby"
  source         = "CROSS_REGION_DATAGUARD"
  source_id      = oci_database_autonomous_database.primary.id
  subnet_id      = oci_core_subnet.standby_data.id
}

resource "oci_objectstorage_bucket" "artifacts" {
  compartment_id = var.compartment_id
  namespace      = var.tenancy_namespace
  name           = "orders-artifacts"
  access_type    = "NoPublicAccess"
  versioning     = "Enabled"
  kms_key_id     = oci_kms_key.data.id
}

resource "oci_objectstorage_bucket" "artifacts_replica" {
  provider       = oci.dr
  compartment_id = var.compartment_id
  namespace      = var.tenancy_namespace
  name           = "orders-artifacts-replica"
  access_type    = "NoPublicAccess"
  versioning     = "Enabled"
}

resource "oci_objectstorage_replication_policy" "artifacts" {
  namespace               = var.tenancy_namespace
  bucket                  = oci_objectstorage_bucket.artifacts.name
  name                    = "to-phoenix"
  destination_region_name = "us-phoenix-1"
  destination_bucket_name = oci_objectstorage_bucket.artifacts_replica.name
}

resource "oci_objectstorage_bucket" "dr_logs" {
  compartment_id = var.compartment_id
  namespace      = var.tenancy_namespace
  name           = "fsdr-logs"
  access_type    = "NoPublicAccess"
  versioning     = "Enabled"
  kms_key_id     = oci_kms_key.data.id
}

# -------------------------------------------------------- Full Stack DR

resource "oci_disaster_recovery_dr_protection_group" "standby" {
  provider       = oci.dr
  compartment_id = var.compartment_id
  display_name   = "orders-standby"

  log_location {
    bucket    = oci_objectstorage_bucket.artifacts_replica.name
    namespace = var.tenancy_namespace
  }

  members {
    member_id   = oci_database_autonomous_database.standby.id
    member_type = "AUTONOMOUS_DATABASE"
  }
}

resource "oci_disaster_recovery_dr_protection_group" "primary" {
  compartment_id = var.compartment_id
  display_name   = "orders-primary"

  log_location {
    bucket    = oci_objectstorage_bucket.dr_logs.name
    namespace = var.tenancy_namespace
  }

  association {
    role        = "PRIMARY"
    peer_id     = oci_disaster_recovery_dr_protection_group.standby.id
    peer_region = "us-phoenix-1"
  }

  members {
    member_id   = oci_database_autonomous_database.primary.id
    member_type = "AUTONOMOUS_DATABASE"
  }
}

resource "oci_disaster_recovery_dr_plan" "switchover" {
  provider               = oci.dr
  display_name           = "orders-switchover"
  dr_protection_group_id = oci_disaster_recovery_dr_protection_group.standby.id
  type                   = "SWITCHOVER"
}

# ---------------------------------------------------------------------- DNS

resource "oci_health_checks_http_monitor" "primary" {
  compartment_id      = var.compartment_id
  display_name        = "orders-primary-health"
  interval_in_seconds = 30
  protocol            = "HTTPS"
  targets             = ["orders-primary.example.com"]
  path                = "/health"
}

resource "oci_dns_steering_policy" "orders" {
  compartment_id          = var.compartment_id
  display_name            = "orders-failover"
  template                = "FAILOVER"
  health_check_monitor_id = oci_health_checks_http_monitor.primary.id
}

# ------------------------------------------------------------- Observability

resource "oci_logging_log_group" "main" {
  compartment_id = var.compartment_id
  display_name   = "lg-dr"
}

resource "oci_logging_log" "artifacts_writes" {
  display_name = "artifacts-writes"
  log_group_id = oci_logging_log_group.main.id
  log_type     = "SERVICE"

  configuration {
    source {
      category    = "write"
      resource    = oci_objectstorage_bucket.artifacts.name
      service     = "objectstorage"
      source_type = "OCISERVICE"
    }
  }
}

resource "oci_logging_log" "dr_logs_writes" {
  display_name = "fsdr-logs-writes"
  log_group_id = oci_logging_log_group.main.id
  log_type     = "SERVICE"

  configuration {
    source {
      category    = "write"
      resource    = oci_objectstorage_bucket.dr_logs.name
      service     = "objectstorage"
      source_type = "OCISERVICE"
    }
  }
}

resource "oci_logging_log" "replica_writes" {
  provider     = oci.dr
  display_name = "replica-writes"
  log_group_id = oci_logging_log_group.main.id
  log_type     = "SERVICE"

  configuration {
    source {
      category    = "write"
      resource    = oci_objectstorage_bucket.artifacts_replica.name
      service     = "objectstorage"
      source_type = "OCISERVICE"
    }
  }
}

resource "oci_ons_notification_topic" "alerts" {
  compartment_id = var.compartment_id
  name           = "dr-alerts"
}

resource "oci_monitoring_alarm" "dataguard_lag" {
  compartment_id        = var.compartment_id
  display_name          = "dataguard-apply-lag"
  metric_compartment_id = var.compartment_id
  namespace             = "oci_autonomous_database"
  query                 = "ApplyLag[5m].max() > 60"
  severity              = "CRITICAL"
  destinations          = [oci_ons_notification_topic.alerts.id]
  is_enabled            = true
}
