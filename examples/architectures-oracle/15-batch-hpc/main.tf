# ArchLens reference architecture 15 (OCI) — Batch compute and HPC
#
# Two workloads that both care about cost per core. OCI Batch runs the
# nightly risk calculation on a service-managed fleet that exists only while
# tasks are queued. The tightly-coupled simulations run on a cluster network
# (bare-metal HPC shapes on an RDMA fabric), reading a Lustre file system
# with root squash on. Results land in Object Storage.
#
# Services: Batch (context + job pool), Cluster Network (RDMA) + instance
# configuration, File Storage with Lustre, Object Storage, Vault (KMS),
# Logging, Monitoring, Notifications.
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
variable "availability_domain" {}
variable "hpc_image_id" {}

resource "oci_core_vcn" "main" {
  compartment_id = var.compartment_id
  cidr_blocks    = ["10.120.0.0/16"]
  display_name   = "vcn-hpc"
}

resource "oci_core_subnet" "compute" {
  compartment_id             = var.compartment_id
  vcn_id                     = oci_core_vcn.main.id
  cidr_block                 = "10.120.0.0/20"
  display_name               = "snet-hpc"
  prohibit_public_ip_on_vnic = true
}

resource "oci_core_network_security_group" "hpc" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "nsg-hpc"
}

resource "oci_core_network_security_group_security_rule" "intra_cluster" {
  network_security_group_id = oci_core_network_security_group.hpc.id
  direction                 = "INGRESS"
  protocol                  = "all"
  source                    = "10.120.0.0/20"
  source_type               = "CIDR_BLOCK"
}

resource "oci_kms_vault" "main" {
  compartment_id = var.compartment_id
  display_name   = "vault-hpc"
  vault_type     = "DEFAULT"
}

resource "oci_kms_key" "hpc" {
  compartment_id      = var.compartment_id
  display_name        = "key-hpc"
  management_endpoint = oci_kms_vault.main.management_endpoint

  key_shape {
    algorithm = "AES"
    length    = 32
  }
}

# ------------------------------------------------------------------- Batch

resource "oci_logging_log_group" "main" {
  compartment_id = var.compartment_id
  display_name   = "lg-hpc"
}

resource "oci_logging_log" "batch_tasks" {
  display_name = "batch-tasks"
  log_group_id = oci_logging_log_group.main.id
  log_type     = "CUSTOM"
}

resource "oci_batch_batch_context" "risk" {
  compartment_id = var.compartment_id
  display_name   = "nightly-risk"

  fleets {
    name                 = "risk-fleet"
    type                 = "SERVICE_MANAGED_FLEET"
    max_concurrent_tasks = 200

    shape {
      shape_name    = "VM.Standard.E5.Flex"
      ocpus         = 4
      memory_in_gbs = 32
    }
  }

  network {
    subnet_id = oci_core_subnet.compute.id
    nsg_ids   = [oci_core_network_security_group.hpc.id]
  }

  logging_configuration {
    type         = "OCI_LOGGING"
    log_group_id = oci_logging_log_group.main.id
    log_id       = oci_logging_log.batch_tasks.id
  }
}

resource "oci_batch_batch_job_pool" "risk" {
  compartment_id   = var.compartment_id
  batch_context_id = oci_batch_batch_context.risk.id
  display_name     = "risk-jobs"
}

# --------------------------------------------------------------------- HPC

resource "oci_lustre_file_storage_lustre_file_system" "scratch" {
  compartment_id      = var.compartment_id
  availability_domain = var.availability_domain
  file_system_name    = "scratch"
  display_name        = "hpc-scratch"
  capacity_in_gbs     = 31200
  performance_tier    = "MBPS_PER_TB_250"
  subnet_id           = oci_core_subnet.compute.id
  nsg_ids             = [oci_core_network_security_group.hpc.id]
  kms_key_id          = oci_kms_key.hpc.id

  root_squash_configuration {
    identity_squash = "ROOT"
    squash_uid      = 65534
    squash_gid      = 65534
  }
}

# Lustre has no snapshot or backup setting of its own; durable copies of the
# scratch outputs are exported to Object Storage through this link.
resource "oci_lustre_file_storage_object_storage_link" "scratch_export" {
  compartment_id        = var.compartment_id
  availability_domain   = var.availability_domain
  display_name          = "scratch-to-results"
  lustre_file_system_id = oci_lustre_file_storage_lustre_file_system.scratch.id
  file_system_path      = "scratch/outputs"
  object_storage_prefix = "${var.tenancy_namespace}:${oci_objectstorage_bucket.results.name}/lustre/"
  is_overwrite          = false
}

resource "oci_core_instance_configuration" "hpc" {
  compartment_id = var.compartment_id
  display_name   = "hpc-node"

  instance_details {
    instance_type = "compute"

    launch_details {
      compartment_id = var.compartment_id
      shape          = "BM.Optimized3.36"

      create_vnic_details {
        subnet_id        = oci_core_subnet.compute.id
        assign_public_ip = false
        nsg_ids          = [oci_core_network_security_group.hpc.id]
      }

      instance_options {
        are_legacy_imds_endpoints_disabled = true
      }

      source_details {
        source_type = "image"
        image_id    = var.hpc_image_id
        kms_key_id  = oci_kms_key.hpc.id
      }
    }
  }
}

resource "oci_core_cluster_network" "sim" {
  compartment_id = var.compartment_id
  display_name   = "sim-cluster"

  instance_pools {
    instance_configuration_id = oci_core_instance_configuration.hpc.id
    size                      = 8
    display_name              = "sim-nodes"
  }

  placement_configuration {
    availability_domain = var.availability_domain
    primary_subnet_id   = oci_core_subnet.compute.id
  }
}

resource "oci_objectstorage_bucket" "results" {
  compartment_id = var.compartment_id
  namespace      = var.tenancy_namespace
  name           = "hpc-results"
  access_type    = "NoPublicAccess"
  versioning     = "Enabled"
  kms_key_id     = oci_kms_key.hpc.id
}

# ------------------------------------------------------------- Observability

resource "oci_logging_log" "results_writes" {
  display_name = "results-writes"
  log_group_id = oci_logging_log_group.main.id
  log_type     = "SERVICE"

  configuration {
    source {
      category    = "write"
      resource    = oci_objectstorage_bucket.results.name
      service     = "objectstorage"
      source_type = "OCISERVICE"
    }
  }
}

resource "oci_ons_notification_topic" "alerts" {
  compartment_id = var.compartment_id
  name           = "hpc-alerts"
}

resource "oci_monitoring_alarm" "lustre_capacity" {
  compartment_id        = var.compartment_id
  display_name          = "lustre-capacity"
  metric_compartment_id = var.compartment_id
  namespace             = "oci_lustrefilesystem"
  query                 = "FileSystemCapacityUtilization[15m].max() > 85"
  severity              = "WARNING"
  destinations          = [oci_ons_notification_topic.alerts.id]
  is_enabled            = true
}
