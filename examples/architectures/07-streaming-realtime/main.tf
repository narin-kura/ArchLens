# ArchLens reference architecture 07 — Real-time streaming pipeline
#
# One ingest path, two fan-outs: Kinesis takes the firehose of events, Managed
# Flink does the windowed aggregation, and Firehose lands the raw stream in S3
# for replay. Hot query paths go to Timestream (metrics) and OpenSearch (search),
# with MSK carrying the events other teams subscribe to.
#
# Services: Kinesis Data Streams, Data Firehose, Managed Service for Apache
# Flink, MSK Serverless, Lambda, DynamoDB, Timestream, OpenSearch Service, S3,
# KMS, VPC, CloudWatch, SNS, IAM.
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

variable "region" { default = "eu-central-1" }

resource "aws_kms_key" "stream" {
  description         = "Streaming pipeline at rest"
  enable_key_rotation = true
}

# ------------------------------------------------------------------- Network

resource "aws_vpc" "main" {
  cidr_block           = "10.70.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}

resource "aws_subnet" "private" {
  count             = 3
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_security_group" "stream" {
  name        = "stream-sg"
  description = "Flink, MSK and OpenSearch interfaces"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Kafka and OpenSearch from inside the VPC"
    from_port   = 9092
    to_port     = 9098
    protocol    = "tcp"
    cidr_blocks = ["10.70.0.0/16"]
  }

  egress {
    description = "HTTPS to AWS endpoints inside the VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.70.0.0/16"]
  }
}

# ------------------------------------------------------------------- Ingestion

resource "aws_kinesis_stream" "events" {
  name             = "telemetry-events"
  retention_period = 48
  encryption_type  = "KMS"
  kms_key_id       = aws_kms_key.stream.arn

  # On-demand scales shards automatically — no capacity planning, and no
  # paying for idle shards overnight.
  stream_mode_details {
    stream_mode = "ON_DEMAND"
  }
}

resource "aws_kinesis_firehose_delivery_stream" "archive" {
  name        = "telemetry-archive"
  destination = "extended_s3"

  server_side_encryption {
    enabled  = true
    key_type = "CUSTOMER_MANAGED_CMK"
    key_arn  = aws_kms_key.stream.arn
  }

  kinesis_source_configuration {
    kinesis_stream_arn = aws_kinesis_stream.events.arn
    role_arn           = aws_iam_role.firehose.arn
  }

  extended_s3_configuration {
    role_arn            = aws_iam_role.firehose.arn
    bucket_arn          = aws_s3_bucket.archive.arn
    prefix              = "raw/dt=!{timestamp:yyyy-MM-dd}/"
    error_output_prefix = "errors/"
    compression_format  = "GZIP"
    buffering_size      = 128
    buffering_interval  = 300
    kms_key_arn         = aws_kms_key.stream.arn
  }
}

resource "aws_msk_serverless_cluster" "events" {
  cluster_name = "telemetry-bus"

  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.stream.id]
  }

  client_authentication {
    sasl {
      iam {
        enabled = true
      }
    }
  }
}

# ------------------------------------------------------------------ Processing

resource "aws_kinesisanalyticsv2_application" "aggregate" {
  name                   = "telemetry-aggregate"
  runtime_environment     = "FLINK-1_19"
  service_execution_role = aws_iam_role.flink.arn

  application_configuration {
    flink_application_configuration {
      checkpoint_configuration {
        configuration_type = "DEFAULT"
      }

      monitoring_configuration {
        configuration_type = "CUSTOM"
        log_level          = "INFO"
        metrics_level      = "APPLICATION"
      }

      parallelism_configuration {
        configuration_type   = "CUSTOM"
        auto_scaling_enabled = true
        parallelism          = 2
        parallelism_per_kpu  = 1
      }
    }

    vpc_configuration {
      subnet_ids         = aws_subnet.private[*].id
      security_group_ids = [aws_security_group.stream.id]
    }
  }

  cloudwatch_logging_options {
    log_stream_arn = "${aws_cloudwatch_log_group.flink.arn}:*"
  }
}

resource "aws_lambda_function" "enrich" {
  function_name = "telemetry-enrich"
  role          = aws_iam_role.lambda.arn
  handler       = "enrich.handler"
  runtime       = "python3.12"
  timeout       = 30
  memory_size   = 512
  kms_key_arn   = aws_kms_key.stream.arn

  reserved_concurrent_executions = 100

  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.stream.id]
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  tracing_config {
    mode = "Active"
  }
}

resource "aws_lambda_event_source_mapping" "enrich" {
  event_source_arn                   = aws_kinesis_stream.events.arn
  function_name                      = aws_lambda_function.enrich.arn
  starting_position                  = "LATEST"
  batch_size                         = 200
  maximum_batching_window_in_seconds = 5
  maximum_retry_attempts             = 3
  parallelization_factor             = 2
  function_response_types            = ["ReportBatchItemFailures"]

  destination_config {
    on_failure {
      destination_arn = aws_sqs_queue.dlq.arn
    }
  }
}

resource "aws_sqs_queue" "dlq" {
  name                      = "telemetry-dlq"
  kms_master_key_id         = aws_kms_key.stream.arn
  message_retention_seconds = 1209600
  redrive_policy            = "terminal-queue"
}

# ------------------------------------------------------------------ Serving

resource "aws_dynamodb_table" "state" {
  name                        = "telemetry-state"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "device_id"
  deletion_protection_enabled = true

  attribute {
    name = "device_id"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.stream.arn
  }

  point_in_time_recovery {
    enabled = true
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
}

resource "aws_timestreamwrite_database" "metrics" {
  database_name = "telemetry"
  kms_key_id    = aws_kms_key.stream.arn
}

resource "aws_timestreamwrite_table" "readings" {
  database_name = aws_timestreamwrite_database.metrics.database_name
  table_name    = "readings"

  # Memory store for the live dashboards, magnetic for the long tail — the
  # retention split is the main cost control in Timestream.
  retention_properties {
    memory_store_retention_period_in_hours  = 12
    magnetic_store_retention_period_in_days = 180
  }

  magnetic_store_write_properties {
    enable_magnetic_store_writes = true
  }
}

resource "aws_opensearch_domain" "search" {
  domain_name    = "telemetry-search"
  engine_version = "OpenSearch_2.15"

  cluster_config {
    instance_type            = "or1.medium.search"
    instance_count           = 3
    zone_awareness_enabled   = true
    dedicated_master_enabled = true
    dedicated_master_type    = "m6g.large.search"
    dedicated_master_count   = 3

    zone_awareness_config {
      availability_zone_count = 3
    }
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 100
    volume_type = "gp3"
  }

  encrypt_at_rest {
    enabled    = true
    kms_key_id = aws_kms_key.stream.arn
  }

  node_to_node_encryption {
    enabled = true
  }

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-PFS-2023-10"
  }

  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = false
  }

  vpc_options {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.stream.id]
  }

  log_publishing_options {
    log_type                 = "AUDIT_LOGS"
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch.arn
  }

  snapshot_options {
    automated_snapshot_start_hour = 3
  }
}

# ------------------------------------------------------------------- Storage

resource "aws_s3_bucket" "archive" {
  bucket = "telemetry-archive"
}

resource "aws_s3_bucket_versioning" "archive" {
  bucket = aws_s3_bucket.archive.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "archive" {
  bucket = aws_s3_bucket.archive.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.stream.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "archive" {
  bucket                  = aws_s3_bucket.archive.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "archive" {
  bucket        = aws_s3_bucket.archive.id
  target_bucket = aws_s3_bucket.archive.id
  target_prefix = "s3-access/self/"
}

resource "aws_s3_bucket_lifecycle_configuration" "archive" {
  bucket = aws_s3_bucket.archive.id

  rule {
    id     = "tier-raw-events"
    status = "Enabled"

    transition {
      days          = 14
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER_IR"
    }

    expiration {
      days = 1095
    }
  }
}

# ------------------------------------------------------------------------ IAM

data "aws_iam_policy_document" "service_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type = "Service"
      identifiers = [
        "firehose.amazonaws.com",
        "kinesisanalytics.amazonaws.com",
        "lambda.amazonaws.com",
      ]
    }
  }
}

resource "aws_iam_role" "firehose" {
  name               = "telemetry-firehose"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

resource "aws_iam_role" "flink" {
  name               = "telemetry-flink"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

resource "aws_iam_role" "lambda" {
  name               = "telemetry-enrich"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

data "aws_iam_policy_document" "lambda_access" {
  statement {
    actions   = ["kinesis:GetRecords", "kinesis:GetShardIterator", "kinesis:DescribeStream"]
    resources = [aws_kinesis_stream.events.arn]
  }

  statement {
    actions   = ["dynamodb:UpdateItem", "dynamodb:GetItem"]
    resources = [aws_dynamodb_table.state.arn]
  }

  statement {
    actions   = ["timestream:WriteRecords"]
    resources = [aws_timestreamwrite_table.readings.arn]
  }
}

resource "aws_iam_role_policy" "lambda_access" {
  name   = "telemetry-enrich-access"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda_access.json
}

# ------------------------------------------------------------- Observability

resource "aws_cloudwatch_log_group" "flink" {
  name              = "/aws/kinesis-analytics/telemetry-aggregate"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.stream.arn
}

resource "aws_cloudwatch_log_group" "opensearch" {
  name              = "/aws/opensearch/telemetry-search/audit"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.stream.arn
}

resource "aws_sns_topic" "alerts" {
  name              = "telemetry-alerts"
  kms_master_key_id = aws_kms_key.stream.arn
}

resource "aws_cloudwatch_metric_alarm" "iterator_age" {
  alarm_name          = "telemetry-consumer-falling-behind"
  namespace           = "AWS/Lambda"
  metric_name         = "IteratorAge"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 60000
  period              = 60
  evaluation_periods  = 3
  statistic           = "Maximum"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "write_throttles" {
  alarm_name          = "telemetry-kinesis-throttles"
  namespace           = "AWS/Kinesis"
  metric_name         = "WriteProvisionedThroughputExceeded"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  period              = 300
  evaluation_periods  = 1
  statistic           = "Sum"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}
