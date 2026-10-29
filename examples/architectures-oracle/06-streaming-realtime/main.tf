# ArchLens reference architecture 06 (OCI) — Real-time streaming
#
# Clickstream events land on an OCI Streaming stream (Kafka-compatible) in a
# private, Vault-encrypted stream pool. Connector Hub fans each event out
# twice with no consumer code: once through an enrichment Function into
# NoSQL for low-latency lookups, and once straight into Object Storage for
# the batch/analytics layer.
#
# Services: Streaming (stream pool + stream), Connector Hub, Functions,
# NoSQL, Object Storage, Vault (KMS), Logging, Monitoring, Notifications.
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
variable "enrich_image" {}

resource "oci_core_vcn" "main" {
  compartment_id = var.compartment_id
  cidr_blocks    = ["10.50.0.0/16"]
  display_name   = "vcn-streaming"
}

resource "oci_core_subnet" "private" {
  compartment_id             = var.compartment_id
  vcn_id                     = oci_core_vcn.main.id
  cidr_block                 = "10.50.0.0/24"
  display_name               = "snet-streaming"
  prohibit_public_ip_on_vnic = true
}

resource "oci_kms_vault" "main" {
  compartment_id = var.compartment_id
  display_name   = "vault-streaming"
  vault_type     = "DEFAULT"
}

resource "oci_kms_key" "stream" {
  compartment_id      = var.compartment_id
  display_name        = "key-stream"
  management_endpoint = oci_kms_vault.main.management_endpoint

  key_shape {
    algorithm = "AES"
    length    = 32
  }
}

# ------------------------------------------------------------------- Ingest

resource "oci_streaming_stream_pool" "main" {
  compartment_id = var.compartment_id
  name           = "clickstream-pool"

  custom_encryption_key {
    kms_key_id = oci_kms_key.stream.id
  }

  private_endpoint_settings {
    subnet_id = oci_core_subnet.private.id
  }

  kafka_settings {
    auto_create_topics_enable = false
    log_retention_hours       = 24
  }
}

resource "oci_streaming_stream" "clickstream" {
  name               = "clickstream"
  partitions         = 6
  retention_in_hours = 24
  stream_pool_id     = oci_streaming_stream_pool.main.id
}

# --------------------------------------------------------------- Processing

resource "oci_functions_application" "enrich" {
  compartment_id = var.compartment_id
  display_name   = "clickstream-enrich"
  subnet_ids     = [oci_core_subnet.private.id]
}

resource "oci_functions_function" "enrich" {
  application_id     = oci_functions_application.enrich.id
  display_name       = "enrich"
  image              = var.enrich_image
  memory_in_mbs      = 256
  timeout_in_seconds = 30
}

resource "oci_nosql_table" "sessions" {
  compartment_id = var.compartment_id
  name           = "sessions"
  ddl_statement  = "CREATE TABLE IF NOT EXISTS sessions (session_id STRING, last_event JSON, PRIMARY KEY(session_id)) USING TTL 7 DAYS"

  table_limits {
    capacity_mode      = "ON_DEMAND"
    max_storage_in_gbs = 50
  }
}

resource "oci_objectstorage_bucket" "archive" {
  compartment_id = var.compartment_id
  namespace      = var.tenancy_namespace
  name           = "clickstream-archive"
  access_type    = "NoPublicAccess"
  versioning     = "Enabled"
  kms_key_id     = oci_kms_key.stream.id
}

resource "oci_sch_service_connector" "to_enrich" {
  compartment_id = var.compartment_id
  display_name   = "clickstream-to-enrich"

  source {
    kind      = "streaming"
    stream_id = oci_streaming_stream.clickstream.id

    cursor {
      kind = "LATEST"
    }
  }

  target {
    kind              = "functions"
    function_id       = oci_functions_function.enrich.id
    batch_size_in_num = 100
    batch_time_in_sec = 5
  }
}

resource "oci_sch_service_connector" "to_archive" {
  compartment_id = var.compartment_id
  display_name   = "clickstream-to-archive"

  source {
    kind      = "streaming"
    stream_id = oci_streaming_stream.clickstream.id

    cursor {
      kind = "TRIM_HORIZON"
    }
  }

  target {
    kind                       = "objectStorage"
    bucket                     = oci_objectstorage_bucket.archive.name
    namespace                  = var.tenancy_namespace
    object_name_prefix         = "clickstream/"
    batch_rollover_size_in_mbs = 100
    batch_rollover_time_in_ms  = 60000
  }
}

# ------------------------------------------------------------- Observability

resource "oci_logging_log_group" "main" {
  compartment_id = var.compartment_id
  display_name   = "lg-streaming"
}

resource "oci_logging_log" "archive_writes" {
  display_name = "archive-writes"
  log_group_id = oci_logging_log_group.main.id
  log_type     = "SERVICE"

  configuration {
    source {
      category    = "write"
      resource    = oci_objectstorage_bucket.archive.name
      service     = "objectstorage"
      source_type = "OCISERVICE"
    }
  }
}

resource "oci_ons_notification_topic" "alerts" {
  compartment_id = var.compartment_id
  name           = "streaming-alerts"
}

resource "oci_monitoring_alarm" "consumer_lag" {
  compartment_id        = var.compartment_id
  display_name          = "connector-errors"
  metric_compartment_id = var.compartment_id
  namespace             = "oci_service_connector_hub"
  query                 = "ServiceConnectorHubErrors[5m].sum() > 0"
  severity              = "CRITICAL"
  destinations          = [oci_ons_notification_topic.alerts.id]
  is_enabled            = true
}
