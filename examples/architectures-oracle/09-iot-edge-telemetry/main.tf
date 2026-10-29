# ArchLens reference architecture 09 (OCI) — IoT telemetry
#
# Devices connect to an OCI IoT Platform domain, each authenticated by its
# own Vault-stored certificate (auth_id) rather than a shared key. A digital
# twin model + adapter turns raw MQTT payloads into typed telemetry; the
# twin data is published to Streaming, and Connector Hub lands it in Object
# Storage for analytics while a Function raises alerts on threshold breaches.
#
# Services: IoT Platform (domain group, domain, digital twin model / adapter
# / instance), Vault (KMS + device certificates), Streaming, Connector Hub,
# Functions, Object Storage, Logging, Monitoring, Notifications.
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
variable "alert_image" {}
variable "device_certificate_id" {}

resource "oci_core_vcn" "main" {
  compartment_id = var.compartment_id
  cidr_blocks    = ["10.80.0.0/16"]
  display_name   = "vcn-iot"
}

resource "oci_core_subnet" "private" {
  compartment_id             = var.compartment_id
  vcn_id                     = oci_core_vcn.main.id
  cidr_block                 = "10.80.0.0/24"
  display_name               = "snet-iot"
  prohibit_public_ip_on_vnic = true
}

resource "oci_kms_vault" "main" {
  compartment_id = var.compartment_id
  display_name   = "vault-iot"
  vault_type     = "DEFAULT"
}

resource "oci_kms_key" "iot" {
  compartment_id      = var.compartment_id
  display_name        = "key-iot"
  management_endpoint = oci_kms_vault.main.management_endpoint

  key_shape {
    algorithm = "AES"
    length    = 32
  }
}

# ---------------------------------------------------------------------- IoT

resource "oci_iot_iot_domain_group" "main" {
  compartment_id = var.compartment_id
  display_name   = "fleet"
}

resource "oci_iot_iot_domain" "sensors" {
  compartment_id      = var.compartment_id
  iot_domain_group_id = oci_iot_iot_domain_group.main.id
  display_name        = "factory-sensors"
}

resource "oci_iot_digital_twin_model" "sensor" {
  iot_domain_id = oci_iot_iot_domain.sensors.id
  display_name  = "temperature-sensor"
  spec          = file("sensor-model.json")
}

resource "oci_iot_digital_twin_adapter" "sensor" {
  iot_domain_id         = oci_iot_iot_domain.sensors.id
  display_name          = "sensor-mqtt-adapter"
  digital_twin_model_id = oci_iot_digital_twin_model.sensor.id
}

resource "oci_iot_digital_twin_instance" "line1_sensor" {
  iot_domain_id           = oci_iot_iot_domain.sensors.id
  display_name            = "line1-temp-01"
  digital_twin_model_id   = oci_iot_digital_twin_model.sensor.id
  digital_twin_adapter_id = oci_iot_digital_twin_adapter.sensor.id
  auth_id                 = var.device_certificate_id
  external_key            = "line1-temp-01"
}

# ----------------------------------------------------------------- Pipeline

resource "oci_streaming_stream_pool" "telemetry" {
  compartment_id = var.compartment_id
  name           = "telemetry-pool"

  custom_encryption_key {
    kms_key_id = oci_kms_key.iot.id
  }

  private_endpoint_settings {
    subnet_id = oci_core_subnet.private.id
  }
}

resource "oci_streaming_stream" "telemetry" {
  name               = "telemetry"
  partitions         = 4
  retention_in_hours = 48
  stream_pool_id     = oci_streaming_stream_pool.telemetry.id
}

resource "oci_objectstorage_bucket" "telemetry" {
  compartment_id = var.compartment_id
  namespace      = var.tenancy_namespace
  name           = "telemetry-archive"
  access_type    = "NoPublicAccess"
  versioning     = "Enabled"
  kms_key_id     = oci_kms_key.iot.id
}

resource "oci_functions_application" "alerts" {
  compartment_id = var.compartment_id
  display_name   = "iot-alerts"
  subnet_ids     = [oci_core_subnet.private.id]
}

resource "oci_functions_function" "threshold" {
  application_id     = oci_functions_application.alerts.id
  display_name       = "threshold-alert"
  image              = var.alert_image
  memory_in_mbs      = 256
  timeout_in_seconds = 30
}

resource "oci_sch_service_connector" "to_archive" {
  compartment_id = var.compartment_id
  display_name   = "telemetry-to-archive"

  source {
    kind      = "streaming"
    stream_id = oci_streaming_stream.telemetry.id

    cursor {
      kind = "TRIM_HORIZON"
    }
  }

  target {
    kind                       = "objectStorage"
    bucket                     = oci_objectstorage_bucket.telemetry.name
    namespace                  = var.tenancy_namespace
    object_name_prefix         = "raw/"
    batch_rollover_size_in_mbs = 100
    batch_rollover_time_in_ms  = 60000
  }
}

resource "oci_sch_service_connector" "to_alerts" {
  compartment_id = var.compartment_id
  display_name   = "telemetry-to-alerts"

  source {
    kind      = "streaming"
    stream_id = oci_streaming_stream.telemetry.id

    cursor {
      kind = "LATEST"
    }
  }

  target {
    kind              = "functions"
    function_id       = oci_functions_function.threshold.id
    batch_size_in_num = 50
    batch_time_in_sec = 5
  }
}

# ------------------------------------------------------------- Observability

resource "oci_logging_log_group" "main" {
  compartment_id = var.compartment_id
  display_name   = "lg-iot"
}

resource "oci_logging_log" "telemetry_writes" {
  display_name = "telemetry-writes"
  log_group_id = oci_logging_log_group.main.id
  log_type     = "SERVICE"

  configuration {
    source {
      category    = "write"
      resource    = oci_objectstorage_bucket.telemetry.name
      service     = "objectstorage"
      source_type = "OCISERVICE"
    }
  }
}

resource "oci_ons_notification_topic" "alerts" {
  compartment_id = var.compartment_id
  name           = "iot-alerts"
}

resource "oci_monitoring_alarm" "ingest_gap" {
  compartment_id        = var.compartment_id
  display_name          = "telemetry-ingest-gap"
  metric_compartment_id = var.compartment_id
  namespace             = "oci_streaming"
  query                 = "PutMessagesThroughput.Count[5m].sum() < 1"
  severity              = "CRITICAL"
  destinations          = [oci_ons_notification_topic.alerts.id]
  is_enabled            = true
}
