# ArchLens reference architecture 05 (OCI) — Data lake and analytics
#
# A medallion lake on Object Storage (raw / curated buckets, each versioned,
# Vault-encrypted and access-logged), Data Flow running Spark jobs between
# zones through a private endpoint, Data Integration for the ELT pipelines,
# Data Catalog harvesting the schema, and Autonomous Data Warehouse serving
# the curated layer to BI.
#
# Services: Object Storage, Data Flow (application + private endpoint),
# Data Integration, Data Catalog, Autonomous Data Warehouse, Vault (KMS),
# Logging, Monitoring.
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

resource "oci_core_vcn" "main" {
  compartment_id = var.compartment_id
  cidr_blocks    = ["10.40.0.0/16"]
  display_name   = "vcn-data-lake"
}

resource "oci_core_subnet" "processing" {
  compartment_id             = var.compartment_id
  vcn_id                     = oci_core_vcn.main.id
  cidr_block                 = "10.40.0.0/24"
  display_name               = "snet-processing"
  prohibit_public_ip_on_vnic = true
}

resource "oci_kms_vault" "main" {
  compartment_id = var.compartment_id
  display_name   = "vault-data-lake"
  vault_type     = "DEFAULT"
}

resource "oci_kms_key" "lake" {
  compartment_id      = var.compartment_id
  display_name        = "key-lake"
  management_endpoint = oci_kms_vault.main.management_endpoint

  key_shape {
    algorithm = "AES"
    length    = 32
  }
}

# -------------------------------------------------------------------- Lake

resource "oci_objectstorage_bucket" "raw" {
  compartment_id = var.compartment_id
  namespace      = var.tenancy_namespace
  name           = "lake-raw"
  access_type    = "NoPublicAccess"
  versioning     = "Enabled"
  kms_key_id     = oci_kms_key.lake.id
}

resource "oci_objectstorage_bucket" "curated" {
  compartment_id = var.compartment_id
  namespace      = var.tenancy_namespace
  name           = "lake-curated"
  access_type    = "NoPublicAccess"
  versioning     = "Enabled"
  kms_key_id     = oci_kms_key.lake.id
}

resource "oci_objectstorage_bucket" "spark_logs" {
  compartment_id = var.compartment_id
  namespace      = var.tenancy_namespace
  name           = "lake-spark-logs"
  access_type    = "NoPublicAccess"
  versioning     = "Enabled"
  kms_key_id     = oci_kms_key.lake.id
}

# -------------------------------------------------------------- Processing

resource "oci_dataflow_private_endpoint" "main" {
  compartment_id = var.compartment_id
  subnet_id      = oci_core_subnet.processing.id
  dns_zones      = ["oraclecloud.com"]
  display_name   = "dataflow-pe"
}

resource "oci_dataflow_application" "raw_to_curated" {
  compartment_id       = var.compartment_id
  display_name         = "raw-to-curated"
  language             = "PYTHON"
  spark_version        = "3.5.0"
  driver_shape         = "VM.Standard.E5.Flex"
  executor_shape       = "VM.Standard.E5.Flex"
  num_executors        = 4
  file_uri             = "oci://${oci_objectstorage_bucket.raw.name}@${var.tenancy_namespace}/jobs/raw_to_curated.py"
  logs_bucket_uri      = "oci://${oci_objectstorage_bucket.spark_logs.name}@${var.tenancy_namespace}/"
  private_endpoint_id  = oci_dataflow_private_endpoint.main.id

  driver_shape_config {
    ocpus         = 2
    memory_in_gbs = 16
  }

  executor_shape_config {
    ocpus         = 4
    memory_in_gbs = 32
  }
}

resource "oci_dataintegration_workspace" "main" {
  compartment_id             = var.compartment_id
  display_name               = "lake-elt"
  is_private_network_enabled = true
  vcn_id                     = oci_core_vcn.main.id
  subnet_id                  = oci_core_subnet.processing.id
}

resource "oci_datacatalog_catalog" "main" {
  compartment_id = var.compartment_id
  display_name   = "lake-catalog"
}

# -------------------------------------------------------------- Warehouse

resource "oci_database_autonomous_database" "warehouse" {
  compartment_id              = var.compartment_id
  db_name                     = "lakedw"
  display_name                = "adw-lake"
  db_workload                 = "DW"
  compute_model               = "ECPU"
  compute_count               = 8
  data_storage_size_in_tbs    = 2
  is_auto_scaling_enabled     = true
  subnet_id                   = oci_core_subnet.processing.id
  is_mtls_connection_required = true
  kms_key_id                  = oci_kms_key.lake.id
  vault_id                    = oci_kms_vault.main.id
}

# ------------------------------------------------------------- Observability

resource "oci_logging_log_group" "main" {
  compartment_id = var.compartment_id
  display_name   = "lg-data-lake"
}

resource "oci_logging_log" "raw_writes" {
  display_name = "raw-writes"
  log_group_id = oci_logging_log_group.main.id
  log_type     = "SERVICE"

  configuration {
    source {
      category    = "write"
      resource    = oci_objectstorage_bucket.raw.name
      service     = "objectstorage"
      source_type = "OCISERVICE"
    }
  }
}

resource "oci_logging_log" "curated_reads" {
  display_name = "curated-reads"
  log_group_id = oci_logging_log_group.main.id
  log_type     = "SERVICE"

  configuration {
    source {
      category    = "read"
      resource    = oci_objectstorage_bucket.curated.name
      service     = "objectstorage"
      source_type = "OCISERVICE"
    }
  }
}

resource "oci_logging_log" "spark_logs_writes" {
  display_name = "spark-logs-writes"
  log_group_id = oci_logging_log_group.main.id
  log_type     = "SERVICE"

  configuration {
    source {
      category    = "write"
      resource    = oci_objectstorage_bucket.spark_logs.name
      service     = "objectstorage"
      source_type = "OCISERVICE"
    }
  }
}

resource "oci_ons_notification_topic" "alerts" {
  compartment_id = var.compartment_id
  name           = "data-lake-alerts"
}

resource "oci_monitoring_alarm" "dataflow_failures" {
  compartment_id        = var.compartment_id
  display_name          = "dataflow-run-failures"
  metric_compartment_id = var.compartment_id
  namespace             = "oci_dataflow"
  query                 = "RunFailed[15m].count() > 0"
  severity              = "CRITICAL"
  destinations          = [oci_ons_notification_topic.alerts.id]
  is_enabled            = true
}
