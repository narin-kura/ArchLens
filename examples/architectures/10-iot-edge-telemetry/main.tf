# ArchLens reference architecture 10 — IoT fleet telemetry with edge processing
#
# Devices authenticate with per-device X.509 certificates (never a shared
# secret), Greengrass runs the logic that must survive a network outage, and IoT
# Core rules route telemetry to storage and to the industrial data model. Device
# Defender watches for a device that starts behaving unlike its fleet.
#
# Services: IoT Core, IoT Device Management, IoT Device Defender, IoT
# Greengrass, IoT SiteWise, IoT TwinMaker, IoT FleetWise, Data Firehose,
# Timestream, S3, Lambda, SNS, KMS, CloudWatch, IAM.
#
# Expected ArchLens findings: clean.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = var.region
}

variable "region" { default = "eu-west-1" }

resource "aws_kms_key" "iot" {
  description         = "IoT telemetry at rest"
  enable_key_rotation = true
}

# ------------------------------------------------------------ Device identity

resource "aws_iot_thing_type" "sensor" {
  name = "industrial-sensor"

  properties {
    description = "Vibration and temperature sensors on the factory floor"
  }
}

resource "aws_iot_thing_group" "plant_a" {
  name = "plant-a"

  properties {
    attribute_payload {
      attributes = {
        site = "plant-a"
      }
    }
  }
}

resource "aws_iot_thing" "sensor_001" {
  name            = "sensor-001"
  thing_type_name = aws_iot_thing_type.sensor.name

  attributes = {
    line = "assembly-3"
  }
}

# Scoped to the thing's own topics via policy variables, so a stolen
# certificate cannot publish as another device.
data "aws_iam_policy_document" "device" {
  statement {
    actions   = ["iot:Connect"]
    resources = ["arn:aws:iot:${var.region}:123456789012:client/$${iot:Connection.Thing.ThingName}"]
  }

  statement {
    actions   = ["iot:Publish"]
    resources = ["arn:aws:iot:${var.region}:123456789012:topic/telemetry/$${iot:Connection.Thing.ThingName}/*"]
  }
}

resource "aws_iot_policy" "device" {
  name   = "device-least-privilege"
  policy = data.aws_iam_policy_document.device.json
}

resource "aws_iot_certificate" "sensor_001" {
  active = true
}

resource "aws_iot_policy_attachment" "sensor_001" {
  policy = aws_iot_policy.device.name
  target = aws_iot_certificate.sensor_001.arn
}

# ------------------------------------------------------------------ Guardrails

resource "aws_iot_security_profile" "fleet" {
  name = "fleet-baseline"

  behavior {
    name   = "excessive-messages"
    metric = "aws:num-messages-sent"

    criteria {
      comparison_operator = "greater-than"
      duration_seconds    = 300
      consecutive_datapoints_to_alarm = 2

      statistical_threshold {
        statistic = "p90"
      }
    }
  }

  behavior {
    name   = "unauthorized-auth-failures"
    metric = "aws:num-authorization-failures"

    criteria {
      comparison_operator = "greater-than"
      duration_seconds    = 300

      value {
        count = 5
      }
    }
  }

  alert_targets = {
    SNS = {
      alert_target_arn = aws_sns_topic.iot_alerts.arn
      role_arn         = aws_iam_role.device_defender.arn
    }
  }
}

resource "aws_iot_logging_options" "main" {
  default_log_level = "WARN"
  role_arn          = aws_iam_role.iot_logging.arn
}

# ------------------------------------------------------------------- Routing

resource "aws_iot_topic_rule" "to_firehose" {
  name        = "telemetry_to_firehose"
  enabled     = true
  sql         = "SELECT *, topic(2) AS device FROM 'telemetry/+/readings'"
  sql_version = "2016-03-23"

  firehose {
    delivery_stream_name = aws_kinesis_firehose_delivery_stream.telemetry.name
    role_arn             = aws_iam_role.iot_rule.arn
    separator            = "\n"
  }

  error_action {
    sns {
      target_arn = aws_sns_topic.iot_alerts.arn
      role_arn   = aws_iam_role.iot_rule.arn
    }
  }
}

resource "aws_iot_topic_rule" "to_timestream" {
  name        = "telemetry_to_timestream"
  enabled     = true
  sql         = "SELECT temperature, vibration FROM 'telemetry/+/readings'"
  sql_version = "2016-03-23"

  timestream {
    database_name = aws_timestreamwrite_database.telemetry.database_name
    table_name    = aws_timestreamwrite_table.readings.table_name
    role_arn      = aws_iam_role.iot_rule.arn

    dimension {
      name  = "device"
      value = "$${topic(2)}"
    }
  }

  error_action {
    sns {
      target_arn = aws_sns_topic.iot_alerts.arn
      role_arn   = aws_iam_role.iot_rule.arn
    }
  }
}

# --------------------------------------------------------------- Edge runtime

resource "aws_greengrassv2_component_version" "local_inference" {
  inline_recipe = jsonencode({
    RecipeFormatVersion = "2020-01-25"
    ComponentName       = "com.example.LocalInference"
    ComponentVersion    = "1.2.0"
    ComponentType       = "aws.greengrass.generic"
    Manifests           = [{ Platform = { os = "linux" } }]
  })
}

resource "aws_iot_role_alias" "greengrass" {
  alias    = "greengrass-core"
  role_arn = aws_iam_role.greengrass.arn
}

# --------------------------------------------------------- Industrial models

resource "aws_iotsitewise_asset_model" "pump" {
  name        = "pump"
  description = "Pump asset with derived health metric"

  asset_model_property {
    name      = "temperature"
    data_type = "DOUBLE"
    unit      = "Celsius"

    type {
      measurement {}
    }
  }
}

resource "aws_iottwinmaker_workspace" "plant" {
  workspace_id = "plant-a"
  role         = aws_iam_role.twinmaker.arn
  s3_location  = aws_s3_bucket.telemetry.arn
}

resource "aws_iotfleetwise_signal_catalog" "vehicles" {
  name = "fleet-signals"

  node {
    branch {
      fully_qualified_name = "Vehicle"
    }
  }
}

# ---------------------------------------------------------------- Persistence

resource "aws_kinesis_firehose_delivery_stream" "telemetry" {
  name        = "iot-telemetry"
  destination = "extended_s3"

  server_side_encryption {
    enabled  = true
    key_type = "CUSTOMER_MANAGED_CMK"
    key_arn  = aws_kms_key.iot.arn
  }

  extended_s3_configuration {
    role_arn            = aws_iam_role.firehose.arn
    bucket_arn          = aws_s3_bucket.telemetry.arn
    prefix              = "readings/dt=!{timestamp:yyyy-MM-dd}/"
    error_output_prefix = "errors/"
    compression_format  = "GZIP"
    buffering_size      = 64
    buffering_interval  = 300
    kms_key_arn         = aws_kms_key.iot.arn
  }
}

resource "aws_timestreamwrite_database" "telemetry" {
  database_name = "iot_telemetry"
  kms_key_id    = aws_kms_key.iot.arn
}

resource "aws_timestreamwrite_table" "readings" {
  database_name = aws_timestreamwrite_database.telemetry.database_name
  table_name    = "readings"

  retention_properties {
    memory_store_retention_period_in_hours  = 24
    magnetic_store_retention_period_in_days = 365
  }
}

resource "aws_s3_bucket" "telemetry" {
  bucket = "iot-telemetry-archive"
}

resource "aws_s3_bucket_versioning" "telemetry" {
  bucket = aws_s3_bucket.telemetry.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "telemetry" {
  bucket = aws_s3_bucket.telemetry.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.iot.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "telemetry" {
  bucket                  = aws_s3_bucket.telemetry.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "telemetry" {
  bucket        = aws_s3_bucket.telemetry.id
  target_bucket = aws_s3_bucket.telemetry.id
  target_prefix = "s3-access/self/"
}

resource "aws_s3_bucket_lifecycle_configuration" "telemetry" {
  bucket = aws_s3_bucket.telemetry.id

  rule {
    id     = "tier-and-expire-readings"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 180
      storage_class = "DEEP_ARCHIVE"
    }

    expiration {
      days = 2555
    }
  }
}

# ---------------------------------------------------------------- Processing

resource "aws_lambda_function" "anomaly" {
  function_name = "telemetry-anomaly"
  role          = aws_iam_role.lambda.arn
  handler       = "anomaly.handler"
  runtime       = "python3.12"
  timeout       = 30
  memory_size   = 512
  kms_key_arn   = aws_kms_key.iot.arn

  reserved_concurrent_executions = 30

  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.lambda.id]
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  tracing_config {
    mode = "Active"
  }
}

resource "aws_vpc" "main" {
  cidr_block           = "10.90.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index)
  availability_zone = "${var.region}${count.index == 0 ? "a" : "b"}"
}

resource "aws_security_group" "lambda" {
  name        = "iot-lambda-sg"
  description = "Anomaly detection function"
  vpc_id      = aws_vpc.main.id

  egress {
    description = "HTTPS to AWS endpoints inside the VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.90.0.0/16"]
  }
}

resource "aws_sqs_queue" "dlq" {
  name                      = "telemetry-anomaly-dlq"
  kms_master_key_id         = aws_kms_key.iot.arn
  message_retention_seconds = 1209600
  redrive_policy            = "terminal-queue"
}

resource "aws_sns_topic" "iot_alerts" {
  name              = "iot-alerts"
  kms_master_key_id = aws_kms_key.iot.arn
}

# ------------------------------------------------------------------------ IAM

data "aws_iam_policy_document" "service_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type = "Service"
      identifiers = [
        "iot.amazonaws.com",
        "firehose.amazonaws.com",
        "lambda.amazonaws.com",
        "iottwinmaker.amazonaws.com",
        "credentials.iot.amazonaws.com",
      ]
    }
  }
}

resource "aws_iam_role" "iot_rule" {
  name               = "iot-rule-role"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

resource "aws_iam_role" "iot_logging" {
  name               = "iot-logging-role"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

resource "aws_iam_role" "device_defender" {
  name               = "iot-device-defender-role"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

resource "aws_iam_role" "greengrass" {
  name               = "greengrass-core-role"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

resource "aws_iam_role" "twinmaker" {
  name               = "twinmaker-role"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

resource "aws_iam_role" "firehose" {
  name               = "iot-firehose-role"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

resource "aws_iam_role" "lambda" {
  name               = "iot-anomaly-role"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

data "aws_iam_policy_document" "lambda_access" {
  statement {
    actions   = ["timestream:WriteRecords", "timestream:DescribeEndpoints"]
    resources = [aws_timestreamwrite_table.readings.arn]
  }

  statement {
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.iot_alerts.arn]
  }
}

resource "aws_iam_role_policy" "lambda_access" {
  name   = "iot-anomaly-access"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda_access.json
}

# ------------------------------------------------------------- Observability

resource "aws_cloudwatch_log_group" "iot" {
  name              = "/aws/iot/telemetry"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.iot.arn
}

resource "aws_cloudwatch_metric_alarm" "rule_failures" {
  alarm_name          = "iot-rule-action-failures"
  namespace           = "AWS/IoT"
  metric_name         = "RuleMessageThrottled"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  period              = 300
  evaluation_periods  = 1
  statistic           = "Sum"
  alarm_actions       = [aws_sns_topic.iot_alerts.arn]
}
