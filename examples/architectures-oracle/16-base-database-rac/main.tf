# ArchLens reference architecture 16 (OCI) — Base Database: RAC + Data Guard
#
# The deployment Oracle customers come to OCI for: a two-node RAC DB System
# (Enterprise Edition Extreme Performance) in a private subnet, TDE master
# key held in Vault, automatic backups to the Autonomous Recovery Service
# with a 30-day recovery window, and an Active Data Guard standby in a
# second availability domain. Data Safe registers the database for
# assessment, auditing and masking; DB access logs go to Logging.
#
# Services: DB System (RAC), Data Guard association, Autonomous Recovery
# Service backups, Data Safe (private endpoint + target), Vault (KMS),
# VCN + private subnets + NSG, Logging, Monitoring, Notifications.
#
# Expected ArchLens findings: clean.

terraform {
  required_version = ">= 1.6"
  required_providers {
    oci = { source = "oracle/oci", version = "~> 6.0" }
  }
}

variable "compartment_id" {}
variable "primary_ad" {}
variable "standby_ad" {}
variable "ssh_public_key" {}
variable "db_admin_password" { sensitive = true }
variable "datasafe_password" { sensitive = true }

resource "oci_core_vcn" "main" {
  compartment_id = var.compartment_id
  cidr_blocks    = ["10.130.0.0/16"]
  display_name   = "vcn-basedb"
  dns_label      = "basedb"
}

resource "oci_core_subnet" "db" {
  compartment_id             = var.compartment_id
  vcn_id                     = oci_core_vcn.main.id
  cidr_block                 = "10.130.0.0/24"
  display_name               = "snet-db"
  dns_label                  = "db"
  prohibit_public_ip_on_vnic = true
}

resource "oci_core_subnet" "backup" {
  compartment_id             = var.compartment_id
  vcn_id                     = oci_core_vcn.main.id
  cidr_block                 = "10.130.1.0/24"
  display_name               = "snet-db-backup"
  dns_label                  = "dbbackup"
  prohibit_public_ip_on_vnic = true
}

resource "oci_core_network_security_group" "db" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "nsg-db"
}

resource "oci_core_network_security_group_security_rule" "sqlnet_from_vcn" {
  network_security_group_id = oci_core_network_security_group.db.id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = "10.130.0.0/16"
  source_type               = "CIDR_BLOCK"

  tcp_options {
    destination_port_range {
      min = 1521
      max = 1522
    }
  }
}

resource "oci_kms_vault" "main" {
  compartment_id = var.compartment_id
  display_name   = "vault-basedb"
  vault_type     = "VIRTUAL_PRIVATE"
}

resource "oci_kms_key" "tde" {
  compartment_id      = var.compartment_id
  display_name        = "key-tde"
  management_endpoint = oci_kms_vault.main.management_endpoint

  key_shape {
    algorithm = "AES"
    length    = 32
  }
}

# -------------------------------------------------------------- Database

resource "oci_database_db_system" "erp" {
  compartment_id                  = var.compartment_id
  availability_domain             = var.primary_ad
  display_name                    = "erp-rac"
  hostname                        = "erp"
  shape                           = "VM.Standard.E5.Flex"
  cpu_core_count                  = 8
  node_count                      = 2
  cluster_name                    = "erpclu"
  database_edition                = "ENTERPRISE_EDITION_EXTREME_PERFORMANCE"
  license_model                   = "BRING_YOUR_OWN_LICENSE"
  storage_volume_performance_mode = "HIGH_PERFORMANCE"
  data_storage_size_in_gb         = 1024
  subnet_id                       = oci_core_subnet.db.id
  backup_subnet_id                = oci_core_subnet.backup.id
  nsg_ids                         = [oci_core_network_security_group.db.id]
  ssh_public_keys                 = [var.ssh_public_key]
  kms_key_id                      = oci_kms_key.tde.id

  data_collection_options {
    is_diagnostics_events_enabled = true
    is_health_monitoring_enabled  = true
    is_incident_logs_enabled      = true
  }

  db_home {
    db_version = "23.0.0.0"

    database {
      db_name        = "ERP"
      pdb_name       = "ERPPDB"
      admin_password = var.db_admin_password
      kms_key_id     = oci_kms_key.tde.id

      db_backup_config {
        auto_backup_enabled     = true
        recovery_window_in_days = 30
        backup_deletion_policy  = "DELETE_AFTER_RETENTION_PERIOD"

        backup_destination_details {
          type = "DBRS"
        }
      }
    }
  }
}

resource "oci_database_data_guard_association" "standby" {
  database_id                      = oci_database_db_system.erp.db_home[0].database[0].id
  creation_type                    = "NewDbSystem"
  database_admin_password          = var.db_admin_password
  protection_mode                  = "MAXIMUM_PERFORMANCE"
  transport_type                   = "ASYNC"
  is_active_data_guard_enabled     = true
  delete_standby_db_home_on_delete = "true"
  availability_domain              = var.standby_ad
  display_name                     = "erp-standby"
  hostname                         = "erpstby"
  shape                            = "VM.Standard.E5.Flex"
  cpu_core_count                   = 8
  node_count                       = 2
  subnet_id                        = oci_core_subnet.db.id
  backup_network_nsg_ids           = [oci_core_network_security_group.db.id]
  nsg_ids                          = [oci_core_network_security_group.db.id]
}

# -------------------------------------------------------------- Data Safe

resource "oci_data_safe_data_safe_private_endpoint" "main" {
  compartment_id = var.compartment_id
  display_name   = "datasafe-pe"
  vcn_id         = oci_core_vcn.main.id
  subnet_id      = oci_core_subnet.db.id
  nsg_ids        = [oci_core_network_security_group.db.id]
}

resource "oci_data_safe_target_database" "erp" {
  compartment_id = var.compartment_id
  display_name   = "erp"

  database_details {
    database_type       = "DATABASE_CLOUD_SERVICE"
    infrastructure_type = "ORACLE_CLOUD"
    db_system_id        = oci_database_db_system.erp.id
    service_name        = "ERPPDB"
    listener_port       = 1521
  }

  connection_option {
    connection_type              = "PRIVATE_ENDPOINT"
    datasafe_private_endpoint_id = oci_data_safe_data_safe_private_endpoint.main.id
  }

  credentials {
    user_name = "DATASAFE_ADMIN"
    password  = var.datasafe_password
  }
}

# ------------------------------------------------------------- Observability

resource "oci_logging_log_group" "main" {
  compartment_id = var.compartment_id
  display_name   = "lg-basedb"
}

resource "oci_ons_notification_topic" "alerts" {
  compartment_id = var.compartment_id
  name           = "basedb-alerts"
}

resource "oci_monitoring_alarm" "transport_lag" {
  compartment_id        = var.compartment_id
  display_name          = "dataguard-transport-lag"
  metric_compartment_id = var.compartment_id
  namespace             = "oci_database"
  query                 = "TransportLag[5m].max() > 300"
  severity              = "CRITICAL"
  destinations          = [oci_ons_notification_topic.alerts.id]
  is_enabled            = true
}
