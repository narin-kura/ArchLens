# ArchLens reference architecture 13 (OCI) — Migration and hybrid connectivity
#
# The on-prem data center connects over a redundant IPSec VPN into a DRG.
# OCI Database Migration replicates the on-prem Oracle database into
# Autonomous Database online (GoldenGate under the hood, near-zero
# downtime); Cloud Bridge discovers the VMware estate and Cloud Migrations
# rehosts those VMs onto OCI compute. Credentials for both live in Vault —
# they are variables here, never literals.
#
# Services: DRG + VCN attachment, CPE, Site-to-Site VPN, Database Migration
# (connections + migration), Autonomous Database (target), Cloud Bridge
# (environment), Cloud Migrations (migration), Object Storage (staging),
# Vault (KMS), Logging, Monitoring.
#
# Expected ArchLens findings: clean.

terraform {
  required_version = ">= 1.6"
  required_providers {
    oci = { source = "oracle/oci", version = "~> 6.0" }
  }
}

variable "compartment_id" {}
variable "tenancy_namespace" {}
variable "onprem_vpn_public_ip" {}
variable "source_db_connection_string" {}
variable "source_db_password" { sensitive = true }
variable "target_db_password" { sensitive = true }

# ------------------------------------------------------------- Connectivity

resource "oci_core_vcn" "landing" {
  compartment_id = var.compartment_id
  cidr_blocks    = ["10.100.0.0/16"]
  display_name   = "vcn-landing"
}

resource "oci_core_subnet" "migration" {
  compartment_id             = var.compartment_id
  vcn_id                     = oci_core_vcn.landing.id
  cidr_block                 = "10.100.0.0/24"
  display_name               = "snet-migration"
  prohibit_public_ip_on_vnic = true
}

resource "oci_core_drg" "main" {
  compartment_id = var.compartment_id
  display_name   = "drg-hybrid"
}

resource "oci_core_drg_attachment" "landing" {
  drg_id = oci_core_drg.main.id

  network_details {
    id   = oci_core_vcn.landing.id
    type = "VCN"
  }
}

resource "oci_core_cpe" "datacenter" {
  compartment_id = var.compartment_id
  display_name   = "dc-edge-router"
  ip_address     = var.onprem_vpn_public_ip
}

resource "oci_core_ipsec" "datacenter" {
  compartment_id = var.compartment_id
  cpe_id         = oci_core_cpe.datacenter.id
  drg_id         = oci_core_drg.main.id
  display_name   = "dc-vpn"
  static_routes  = ["192.168.0.0/16"]
}

# --------------------------------------------------------------------- Keys

resource "oci_kms_vault" "main" {
  compartment_id = var.compartment_id
  display_name   = "vault-migration"
  vault_type     = "DEFAULT"
}

resource "oci_kms_key" "migration" {
  compartment_id      = var.compartment_id
  display_name        = "key-migration"
  management_endpoint = oci_kms_vault.main.management_endpoint

  key_shape {
    algorithm = "AES"
    length    = 32
  }
}

# ---------------------------------------------------------- Database move

resource "oci_database_autonomous_database" "target" {
  compartment_id              = var.compartment_id
  db_name                     = "erpdb"
  display_name                = "adb-erp"
  db_workload                 = "OLTP"
  compute_model               = "ECPU"
  compute_count               = 8
  data_storage_size_in_tbs    = 2
  subnet_id                   = oci_core_subnet.migration.id
  is_mtls_connection_required = true
  is_local_data_guard_enabled = true
  kms_key_id                  = oci_kms_key.migration.id
  vault_id                    = oci_kms_vault.main.id
}

resource "oci_database_migration_connection" "source" {
  compartment_id    = var.compartment_id
  display_name      = "onprem-erp"
  connection_type   = "ORACLE"
  technology_type   = "ORACLE_DATABASE"
  connection_string = var.source_db_connection_string
  username          = "migration_admin"
  password          = var.source_db_password
  subnet_id         = oci_core_subnet.migration.id
  key_id            = oci_kms_key.migration.id
  vault_id          = oci_kms_vault.main.id
}

resource "oci_database_migration_connection" "target" {
  compartment_id  = var.compartment_id
  display_name    = "adb-erp"
  connection_type = "ORACLE"
  technology_type = "OCI_AUTONOMOUS_DATABASE"
  database_id     = oci_database_autonomous_database.target.id
  username        = "admin"
  password        = var.target_db_password
  key_id          = oci_kms_key.migration.id
  vault_id        = oci_kms_vault.main.id
}

resource "oci_objectstorage_bucket" "staging" {
  compartment_id = var.compartment_id
  namespace      = var.tenancy_namespace
  name           = "migration-staging"
  access_type    = "NoPublicAccess"
  versioning     = "Enabled"
  kms_key_id     = oci_kms_key.migration.id
}

resource "oci_database_migration_migration" "erp" {
  compartment_id                = var.compartment_id
  display_name                  = "erp-online"
  database_combination          = "ORACLE"
  type                          = "ONLINE"
  source_database_connection_id = oci_database_migration_connection.source.id
  target_database_connection_id = oci_database_migration_connection.target.id

  data_transfer_medium_details {
    type = "OBJECT_STORAGE"

    object_storage_bucket {
      bucket    = oci_objectstorage_bucket.staging.name
      namespace = var.tenancy_namespace
    }
  }
}

# --------------------------------------------------------------- VM rehost

resource "oci_cloud_bridge_environment" "datacenter" {
  compartment_id = var.compartment_id
  display_name   = "dc-vmware"
}

resource "oci_cloud_migrations_migration" "vmware_rehost" {
  compartment_id = var.compartment_id
  display_name   = "vmware-rehost-wave1"
}

# ------------------------------------------------------------- Observability

resource "oci_logging_log_group" "main" {
  compartment_id = var.compartment_id
  display_name   = "lg-migration"
}

resource "oci_logging_log" "staging_writes" {
  display_name = "staging-writes"
  log_group_id = oci_logging_log_group.main.id
  log_type     = "SERVICE"

  configuration {
    source {
      category    = "write"
      resource    = oci_objectstorage_bucket.staging.name
      service     = "objectstorage"
      source_type = "OCISERVICE"
    }
  }
}

resource "oci_ons_notification_topic" "alerts" {
  compartment_id = var.compartment_id
  name           = "migration-alerts"
}

resource "oci_monitoring_alarm" "vpn_down" {
  compartment_id        = var.compartment_id
  display_name          = "dc-vpn-tunnel-down"
  metric_compartment_id = var.compartment_id
  namespace             = "oci_vpn"
  query                 = "TunnelState[1m].min() == 0"
  severity              = "CRITICAL"
  destinations          = [oci_ons_notification_topic.alerts.id]
  is_enabled            = true
}
