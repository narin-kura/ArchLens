# ArchLens reference architecture 15 — Workforce desktops and customer contact
#
# The internal-facing half of an AWS estate. WorkSpaces gives contractors a
# managed desktop that never holds data locally, AppStream streams the two legacy
# Windows applications, and Connect runs the contact centre with Lex, Transcribe
# and Comprehend doing the language work. Outbound customer email and SMS go
# through SES and End User Messaging.
#
# Services: Directory Service, WorkSpaces, WorkSpaces Secure Browser, AppStream
# 2.0, FSx for Windows File Server, Connect, Lex, Polly, Transcribe, Comprehend,
# SES, Pinpoint, Chime SDK, Kinesis Video Streams, S3, KMS, CloudWatch, IAM.
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

variable "region" { default = "eu-west-2" }

resource "aws_kms_key" "workforce" {
  description         = "Workforce desktops and contact-centre recordings"
  enable_key_rotation = true
}

# ------------------------------------------------------------------- Network

resource "aws_vpc" "main" {
  cidr_block           = "10.130.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index)
  availability_zone = "${var.region}${count.index == 0 ? "a" : "b"}"
}

resource "aws_security_group" "desktops" {
  name        = "workforce-sg"
  description = "WorkSpaces, AppStream fleets and file storage"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SMB to the shared file system"
    from_port   = 445
    to_port     = 445
    protocol    = "tcp"
    cidr_blocks = ["10.130.0.0/16"]
  }

  egress {
    description = "HTTPS to AWS endpoints and approved SaaS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.130.0.0/16"]
  }
}

resource "aws_flow_log" "main" {
  vpc_id               = aws_vpc.main.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.flow.arn
  iam_role_arn         = aws_iam_role.flow_logs.arn
}

# ------------------------------------------------------------------ Directory

resource "aws_directory_service_directory" "corp" {
  name       = "corp.example.com"
  short_name = "CORP"
  type       = "MicrosoftAD"
  edition    = "Standard"
  password   = aws_secretsmanager_secret_version.directory.secret_string

  vpc_settings {
    vpc_id     = aws_vpc.main.id
    subnet_ids = aws_subnet.private[*].id
  }
}

resource "aws_secretsmanager_secret" "directory" {
  name       = "workforce/directory-admin"
  kms_key_id = aws_kms_key.workforce.arn
}

resource "aws_secretsmanager_secret_version" "directory" {
  secret_id     = aws_secretsmanager_secret.directory.id
  secret_string = random_password.directory.result
}

resource "random_password" "directory" {
  length  = 32
  special = true
}

# ------------------------------------------------------------------- Desktops

resource "aws_workspaces_directory" "corp" {
  directory_id = aws_directory_service_directory.corp.id
  subnet_ids   = aws_subnet.private[*].id

  self_service_permissions {
    change_compute_type  = false
    increase_volume_size = false
    rebuild_workspace    = true
    restart_workspace    = true
    switch_running_mode  = true
  }

  workspace_creation_properties {
    enable_internet_access              = false
    enable_maintenance_mode             = true
    user_enabled_as_local_administrator = false
    custom_security_group_id            = aws_security_group.desktops.id
  }
}

resource "aws_workspaces_workspace" "contractor" {
  directory_id = aws_workspaces_directory.corp.id
  bundle_id    = "wsb-bh8rsxt14"
  user_name    = "contractor1"

  # Both volumes encrypted: nothing on a desktop survives in the clear.
  root_volume_encryption_enabled = true
  user_volume_encryption_enabled = true
  volume_encryption_key          = aws_kms_key.workforce.arn

  workspace_properties {
    # AUTO_STOP bills by the hour instead of the month — the single biggest
    # WorkSpaces cost lever for part-time users.
    running_mode                              = "AUTO_STOP"
    running_mode_auto_stop_timeout_in_minutes = 60
    compute_type_name                         = "STANDARD"
    root_volume_size_gib                      = 80
    user_volume_size_gib                      = 50
  }
}

resource "aws_appstream_fleet" "legacy_apps" {
  name          = "legacy-windows-apps"
  instance_type = "stream.standard.medium"
  fleet_type    = "ON_DEMAND"
  image_name    = "AppStream-WinServer2019-06-17-2024"

  compute_capacity {
    desired_instances = 2
  }

  vpc_config {
    subnet_ids          = aws_subnet.private[*].id
    security_group_ids  = [aws_security_group.desktops.id]
  }

  disconnect_timeout_in_seconds      = 900
  idle_disconnect_timeout_in_seconds = 600
  max_user_duration_in_seconds       = 28800
  enable_default_internet_access     = false
}

resource "aws_appstream_stack" "legacy_apps" {
  name = "legacy-apps"

  storage_connectors {
    connector_type = "HOMEFOLDERS"
  }

  user_settings {
    action     = "CLIPBOARD_COPY_TO_LOCAL_DEVICE"
    permission = "DISABLED"
  }

  user_settings {
    action     = "FILE_DOWNLOAD"
    permission = "DISABLED"
  }

  application_settings {
    enabled        = true
    settings_group = "legacy-apps"
  }
}

resource "aws_fsx_windows_file_system" "home" {
  storage_capacity                  = 2048
  storage_type                      = "SSD"
  throughput_capacity               = 64
  subnet_ids                        = [aws_subnet.private[0].id]
  security_group_ids                = [aws_security_group.desktops.id]
  active_directory_id               = aws_directory_service_directory.corp.id
  kms_key_id                        = aws_kms_key.workforce.arn
  encrypted                         = true
  automatic_backup_retention_days   = 35
  backup_retention_period           = 35
  daily_automatic_backup_start_time = "02:00"
  copy_tags_to_backups              = true

  audit_log_configuration {
    file_access_audit_log_level       = "SUCCESS_AND_FAILURE"
    file_share_access_audit_log_level = "SUCCESS_AND_FAILURE"
    audit_log_destination             = aws_cloudwatch_log_group.fsx.arn
  }
}

# ------------------------------------------------------------- Contact centre

resource "aws_connect_instance" "support" {
  identity_management_type = "EXISTING_DIRECTORY"
  directory_id             = aws_directory_service_directory.corp.id
  instance_alias           = "example-support"
  inbound_calls_enabled    = true
  outbound_calls_enabled   = true
  contact_flow_logs_enabled = true
  contact_lens_enabled      = true
  early_media_enabled       = true
  auto_resolve_best_voices_enabled = true
}

resource "aws_connect_instance_storage_config" "recordings" {
  instance_id   = aws_connect_instance.support.id
  resource_type = "CALL_RECORDINGS"

  storage_config {
    storage_type = "S3"

    s3_config {
      bucket_name   = aws_s3_bucket.recordings.id
      bucket_prefix = "call-recordings"

      encryption_config {
        encryption_type = "KMS"
        key_id          = aws_kms_key.workforce.arn
      }
    }
  }
}

resource "aws_lexv2models_bot" "support" {
  name                        = "support-bot"
  role_arn                    = aws_iam_role.lex.arn
  idle_session_ttl_in_seconds = 300

  data_privacy {
    child_directed = false
  }
}

resource "aws_kinesis_video_stream" "screen_share" {
  name                    = "agent-screen-share"
  data_retention_in_hours = 24
  kms_key_id              = aws_kms_key.workforce.arn
  media_type              = "video/h264"
}

resource "aws_chimesdkvoice_sip_media_application" "ivr" {
  name       = "ivr-handler"
  aws_region = var.region

  endpoints {
    lambda_arn = aws_lambda_function.ivr.arn
  }
}

resource "aws_lambda_function" "ivr" {
  function_name = "ivr-handler"
  role          = aws_iam_role.lambda.arn
  handler       = "ivr.handler"
  runtime       = "python3.12"
  timeout       = 15
  memory_size   = 512
  kms_key_arn   = aws_kms_key.workforce.arn

  reserved_concurrent_executions = 20

  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.desktops.id]
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  tracing_config {
    mode = "Active"
  }
}

resource "aws_sqs_queue" "dlq" {
  name                      = "ivr-dlq"
  kms_master_key_id         = aws_kms_key.workforce.arn
  message_retention_seconds = 1209600
  redrive_policy            = "terminal-queue"
}

# ------------------------------------------------------------- Customer comms

resource "aws_ses_domain_identity" "main" {
  domain = "example.com"
}

resource "aws_ses_domain_dkim" "main" {
  domain = aws_ses_domain_identity.main.domain
}

resource "aws_ses_configuration_set" "transactional" {
  name = "transactional"

  delivery_options {
    tls_policy = "REQUIRE"
  }

  reputation_metrics_enabled = true
}

resource "aws_pinpoint_app" "campaigns" {
  name = "customer-campaigns"

  limits {
    daily               = 10000
    maximum_duration    = 3600
    messages_per_second = 50
    total               = 100000
  }

  quiet_time {
    start = "22:00"
    end   = "08:00"
  }
}

# -------------------------------------------------------------------- Storage

resource "aws_s3_bucket" "recordings" {
  bucket = "workforce-call-recordings"
}

resource "aws_s3_bucket_versioning" "recordings" {
  bucket = aws_s3_bucket.recordings.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "recordings" {
  bucket = aws_s3_bucket.recordings.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.workforce.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "recordings" {
  bucket                  = aws_s3_bucket.recordings.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "recordings" {
  bucket        = aws_s3_bucket.recordings.id
  target_bucket = aws_s3_bucket.recordings.id
  target_prefix = "s3-access/self/"
}

# Call recordings are personal data: keep them only as long as the retention
# policy requires.
resource "aws_s3_bucket_lifecycle_configuration" "recordings" {
  bucket = aws_s3_bucket.recordings.id

  rule {
    id     = "retention-policy"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = 400
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
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
        "connect.amazonaws.com",
        "lexv2.amazonaws.com",
        "lambda.amazonaws.com",
        "appstream.amazonaws.com",
      ]
    }
  }
}

resource "aws_iam_role" "lex" {
  name               = "lex-bot-role"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

resource "aws_iam_role" "lambda" {
  name               = "ivr-handler-role"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

data "aws_iam_policy_document" "lambda_access" {
  statement {
    actions   = ["transcribe:StartStreamTranscription", "comprehend:DetectSentiment", "polly:SynthesizeSpeech"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [var.region]
    }
  }

  statement {
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.recordings.arn}/*"]
  }
}

resource "aws_iam_role_policy" "lambda_access" {
  name   = "ivr-language-services"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda_access.json
}

data "aws_iam_policy_document" "flow_logs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "flow_logs" {
  name               = "workforce-flow-logs"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume.json
}

# ------------------------------------------------------------- Observability

resource "aws_cloudwatch_log_group" "fsx" {
  name              = "/aws/fsx/workforce-home"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.workforce.arn
}

resource "aws_cloudwatch_log_group" "flow" {
  name              = "/aws/vpc/workforce/flow-logs"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.workforce.arn
}

resource "aws_cloudwatch_metric_alarm" "queue_wait" {
  alarm_name          = "connect-longest-queue-wait"
  namespace           = "AWS/Connect"
  metric_name         = "LongestQueueWaitTime"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 300
  period              = 300
  evaluation_periods  = 2
  statistic           = "Maximum"
}

resource "aws_budgets_budget" "workforce" {
  name         = "workforce-monthly"
  budget_type  = "COST"
  limit_amount = "6000"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_filter {
    name   = "Service"
    values = ["Amazon WorkSpaces", "Amazon AppStream", "Amazon Connect"]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 85
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = ["it-ops@example.com"]
  }
}
