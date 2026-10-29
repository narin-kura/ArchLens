# ArchLens reference architecture 10 (OCI) — Media transcoding and streaming
#
# Uploads land in a private bucket; a Media Flow workflow transcodes them
# into adaptive-bitrate renditions in a second bucket. Media Streams packages
# those renditions as HLS, AES-128-encrypted with a Vault key, and serves
# them through OCI's own edge CDN distribution channel.
#
# Services: Object Storage (uploads + renditions), Media Flow (workflow),
# Media Streams (distribution channel, packaging config, CDN config),
# Vault (KMS), Logging, Monitoring, Notifications.
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

resource "oci_kms_vault" "main" {
  compartment_id = var.compartment_id
  display_name   = "vault-media"
  vault_type     = "DEFAULT"
}

resource "oci_kms_key" "media" {
  compartment_id      = var.compartment_id
  display_name        = "key-media"
  management_endpoint = oci_kms_vault.main.management_endpoint

  key_shape {
    algorithm = "AES"
    length    = 32
  }
}

resource "oci_objectstorage_bucket" "uploads" {
  compartment_id = var.compartment_id
  namespace      = var.tenancy_namespace
  name           = "media-uploads"
  access_type    = "NoPublicAccess"
  versioning     = "Enabled"
  kms_key_id     = oci_kms_key.media.id
}

resource "oci_objectstorage_bucket" "renditions" {
  compartment_id = var.compartment_id
  namespace      = var.tenancy_namespace
  name           = "media-renditions"
  access_type    = "NoPublicAccess"
  versioning     = "Enabled"
  kms_key_id     = oci_kms_key.media.id
}

# ------------------------------------------------------------- Transcoding

resource "oci_media_services_media_workflow" "abr" {
  compartment_id = var.compartment_id
  display_name   = "adaptive-bitrate"

  tasks {
    key     = "transcode"
    type    = "transcode"
    version = 1
    parameters = file("transcode-task.json")
  }
}

# ---------------------------------------------------------------- Delivery

resource "oci_media_services_stream_distribution_channel" "main" {
  compartment_id = var.compartment_id
  display_name   = "vod-channel"
}

resource "oci_media_services_stream_packaging_config" "hls" {
  distribution_channel_id = oci_media_services_stream_distribution_channel.main.id
  display_name            = "hls-aes128"
  stream_packaging_format = "HLS"
  segment_time_in_seconds = 6

  encryption {
    algorithm  = "AES128"
    kms_key_id = oci_kms_key.media.id
  }
}

resource "oci_media_services_stream_cdn_config" "edge" {
  distribution_channel_id = oci_media_services_stream_distribution_channel.main.id
  display_name            = "oci-edge"
  is_enabled              = true

  config {
    type = "EDGE"
  }
}

# ------------------------------------------------------------- Observability

resource "oci_logging_log_group" "main" {
  compartment_id = var.compartment_id
  display_name   = "lg-media"
}

resource "oci_logging_log" "uploads_writes" {
  display_name = "uploads-writes"
  log_group_id = oci_logging_log_group.main.id
  log_type     = "SERVICE"

  configuration {
    source {
      category    = "write"
      resource    = oci_objectstorage_bucket.uploads.name
      service     = "objectstorage"
      source_type = "OCISERVICE"
    }
  }
}

resource "oci_logging_log" "renditions_reads" {
  display_name = "renditions-reads"
  log_group_id = oci_logging_log_group.main.id
  log_type     = "SERVICE"

  configuration {
    source {
      category    = "read"
      resource    = oci_objectstorage_bucket.renditions.name
      service     = "objectstorage"
      source_type = "OCISERVICE"
    }
  }
}

resource "oci_ons_notification_topic" "alerts" {
  compartment_id = var.compartment_id
  name           = "media-alerts"
}

resource "oci_monitoring_alarm" "workflow_failures" {
  compartment_id        = var.compartment_id
  display_name          = "media-workflow-failures"
  metric_compartment_id = var.compartment_id
  namespace             = "oci_mediaservices"
  query                 = "WorkflowJobFailed[15m].count() > 0"
  severity              = "CRITICAL"
  destinations          = [oci_ons_notification_topic.alerts.id]
  is_enabled            = true
}
