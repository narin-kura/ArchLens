# ArchLens reference architecture 11 — Live and on-demand video
#
# Two delivery paths that share one CDN. Live: MediaLive encodes the contribution
# feed, MediaPackage packages and DRM-protects it, MediaTailor stitches ads.
# VOD: an upload triggers MediaConvert, output lands in S3, CloudFront serves it.
# IVS covers the low-latency interactive case where a full pipeline is overkill.
#
# Services: MediaLive, MediaPackage, MediaConvert, MediaTailor, MediaConnect,
# IVS, Deadline Cloud, S3, CloudFront, EventBridge, Lambda, SNS, KMS,
# CloudWatch, IAM.
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

variable "region" { default = "us-east-1" }

resource "aws_kms_key" "media" {
  description         = "Media assets at rest"
  enable_key_rotation = true
}

# -------------------------------------------------------------------- Buckets

resource "aws_s3_bucket" "source" {
  bucket = "media-source-uploads"
}

resource "aws_s3_bucket_versioning" "source" {
  bucket = aws_s3_bucket.source.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "source" {
  bucket = aws_s3_bucket.source.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.media.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "source" {
  bucket                  = aws_s3_bucket.source.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "source" {
  bucket        = aws_s3_bucket.source.id
  target_bucket = aws_s3_bucket.source.id
  target_prefix = "s3-access/self/"
}

# Mezzanine files are enormous and read once — archive them aggressively.
resource "aws_s3_bucket_lifecycle_configuration" "source" {
  bucket = aws_s3_bucket.source.id

  rule {
    id     = "archive-mezzanine"
    status = "Enabled"

    transition {
      days          = 7
      storage_class = "GLACIER_IR"
    }

    transition {
      days          = 90
      storage_class = "DEEP_ARCHIVE"
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

resource "aws_s3_bucket_notification" "source" {
  bucket      = aws_s3_bucket.source.id
  eventbridge = true
}

resource "aws_s3_bucket" "output" {
  bucket = "media-vod-output"
}

resource "aws_s3_bucket_versioning" "output" {
  bucket = aws_s3_bucket.output.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "output" {
  bucket = aws_s3_bucket.output.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "output" {
  bucket                  = aws_s3_bucket.output.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "output" {
  bucket        = aws_s3_bucket.output.id
  target_bucket = aws_s3_bucket.output.id
  target_prefix = "s3-access/self/"
}

resource "aws_s3_bucket_lifecycle_configuration" "output" {
  bucket = aws_s3_bucket.output.id

  rule {
    id     = "tier-cold-titles"
    status = "Enabled"

    transition {
      days          = 60
      storage_class = "INTELLIGENT_TIERING"
    }
  }
}

# ------------------------------------------------------------------ Live path

resource "aws_mediaconnect_flow" "contribution" {
  name              = "stadium-feed"
  availability_zone = "${var.region}a"

  source {
    name        = "primary-encoder"
    protocol    = "srt-listener"
    description = "SRT contribution from the venue"
    ingest_port = 5000
  }
}

resource "aws_medialive_input_security_group" "contribution" {
  whitelist_rules {
    cidr = "203.0.113.0/24"
  }
}

resource "aws_medialive_input" "contribution" {
  name                  = "stadium-input"
  type                  = "RTP_PUSH"
  input_security_groups = [aws_medialive_input_security_group.contribution.id]
}

resource "aws_medialive_channel" "live" {
  name          = "main-channel"
  channel_class = "STANDARD"
  role_arn      = aws_iam_role.medialive.arn

  input_specification {
    codec            = "AVC"
    input_resolution = "HD"
    maximum_bitrate  = "MAX_20_MBPS"
  }

  input_attachments {
    input_attachment_name = "stadium"
    input_id              = aws_medialive_input.contribution.id
  }

  destinations {
    id = "mediapackage"

    media_package_settings {
      channel_id = aws_media_package_channel.live.id
    }
  }

  encoder_settings {
    timecode_config {
      source = "EMBEDDED"
    }

    audio_descriptions {
      audio_selector_name = "default"
      name                = "audio-1"
    }

    video_descriptions {
      name   = "video-1080p"
      width  = 1920
      height = 1080
    }

    output_groups {
      output_group_settings {
        media_package_group_settings {
          destination {
            destination_ref_id = "mediapackage"
          }
        }
      }

      outputs {
        output_name             = "1080p"
        audio_description_names = ["audio-1"]
        video_description_name  = "video-1080p"

        output_settings {
          media_package_output_settings {}
        }
      }
    }
  }
}

resource "aws_media_package_channel" "live" {
  channel_id  = "main-channel"
  description = "HLS/DASH packaging for the live channel"

  hls_ingest {
    ingest_endpoints {}
  }
}

resource "aws_ivs_channel" "interactive" {
  name                = "interactive-stage"
  type                = "STANDARD"
  latency_mode        = "LOW"
  authorized          = true
  recording_configuration_arn = aws_ivs_recording_configuration.interactive.arn
}

resource "aws_ivs_recording_configuration" "interactive" {
  name = "interactive-recording"

  destination_configuration {
    s3 {
      bucket_name = aws_s3_bucket.output.id
    }
  }
}

# ------------------------------------------------------------------- VOD path

resource "aws_mediaconvert_queue" "vod" {
  name         = "vod-transcode"
  pricing_plan = "ON_DEMAND"
  status       = "ACTIVE"
}

resource "aws_cloudwatch_event_rule" "new_upload" {
  name        = "media-new-upload"
  description = "Kick off a transcode when a mezzanine file lands"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["Object Created"]
    detail      = { bucket = { name = [aws_s3_bucket.source.id] } }
  })
}

resource "aws_cloudwatch_event_target" "start_transcode" {
  rule      = aws_cloudwatch_event_rule.new_upload.name
  target_id = "start-transcode"
  arn       = aws_lambda_function.submit_job.arn
}

resource "aws_lambda_function" "submit_job" {
  function_name = "media-submit-job"
  role          = aws_iam_role.lambda.arn
  handler       = "submit.handler"
  runtime       = "python3.12"
  timeout       = 60
  memory_size   = 512
  kms_key_arn   = aws_kms_key.media.arn

  reserved_concurrent_executions = 20

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
  cidr_block           = "10.100.0.0/16"
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
  name        = "media-lambda-sg"
  description = "Job submission function"
  vpc_id      = aws_vpc.main.id

  egress {
    description = "HTTPS to AWS endpoints inside the VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.100.0.0/16"]
  }
}

resource "aws_sqs_queue" "dlq" {
  name                      = "media-submit-dlq"
  kms_master_key_id         = aws_kms_key.media.arn
  message_retention_seconds = 1209600
  redrive_policy            = "terminal-queue"
}

# Render farm for the titles that need graphics work before transcode.
resource "aws_deadline_farm" "render" {
  display_name = "post-production"
  kms_key_arn  = aws_kms_key.media.arn
}

resource "aws_deadline_queue" "render" {
  display_name = "render-queue"
  farm_id      = aws_deadline_farm.render.id

  job_run_as_user {
    run_as = "WORKER_AGENT_USER"
  }
}

# ----------------------------------------------------------------- Ad insertion

resource "aws_mediatailor_configuration" "ads" {
  name                         = "vod-ads"
  ad_decision_server_url       = "https://ads.example.com/vast?id=[session.id]"
  video_content_source_url     = "https://${aws_cloudfront_distribution.delivery.domain_name}/vod"
  slate_ad_url                 = "https://${aws_cloudfront_distribution.delivery.domain_name}/slate.mp4"
  personalization_threshold_seconds = 2
}

# -------------------------------------------------------------------- Delivery

resource "aws_cloudfront_origin_access_control" "output" {
  name                              = "media-output-oac"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_wafv2_web_acl" "delivery" {
  name        = "media-delivery-waf"
  description = "Token abuse and hotlinking protection"
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "media-delivery-waf"
    sampled_requests_enabled   = true
  }
}

resource "aws_cloudfront_distribution" "delivery" {
  enabled         = true
  is_ipv6_enabled = true
  price_class     = "PriceClass_All"
  web_acl_id      = aws_wafv2_web_acl.delivery.arn

  origin {
    domain_name              = aws_s3_bucket.output.bucket_regional_domain_name
    origin_id                = "vod"
    origin_access_control_id = aws_cloudfront_origin_access_control.output.id
  }

  default_cache_behavior {
    target_origin_id       = "vod"
    viewer_protocol_policy = "https-only"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    compress               = false

    # Signed URLs are what stop a paid title being shared as a plain link.
    trusted_key_groups = [aws_cloudfront_key_group.subscribers.id]
  }

  viewer_certificate {
    cloudfront_default_certificate = true
    minimum_protocol_version       = "TLSv1.2_2021"
  }

  logging_config {
    bucket          = aws_s3_bucket.output.bucket_domain_name
    prefix          = "cloudfront/"
    include_cookies = false
  }

  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = ["US", "GB", "DE", "IN", "JP"]
    }
  }
}

resource "aws_cloudfront_public_key" "subscribers" {
  name        = "subscriber-signing-key"
  encoded_key = file("public_key.pem")
}

resource "aws_cloudfront_key_group" "subscribers" {
  name  = "subscribers"
  items = [aws_cloudfront_public_key.subscribers.id]
}

# ------------------------------------------------------------------------ IAM

data "aws_iam_policy_document" "service_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type = "Service"
      identifiers = [
        "medialive.amazonaws.com",
        "mediaconvert.amazonaws.com",
        "lambda.amazonaws.com",
      ]
    }
  }
}

resource "aws_iam_role" "medialive" {
  name               = "medialive-role"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

resource "aws_iam_role" "mediaconvert" {
  name               = "mediaconvert-role"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

data "aws_iam_policy_document" "mediaconvert_access" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.source.arn}/*"]
  }

  statement {
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.output.arn}/*"]
  }

  statement {
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.media.arn]
  }
}

resource "aws_iam_role_policy" "mediaconvert_access" {
  name   = "mediaconvert-buckets"
  role   = aws_iam_role.mediaconvert.id
  policy = data.aws_iam_policy_document.mediaconvert_access.json
}

resource "aws_iam_role" "lambda" {
  name               = "media-submit-role"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

# ------------------------------------------------------------- Observability

resource "aws_sns_topic" "media_alerts" {
  name              = "media-alerts"
  kms_master_key_id = aws_kms_key.media.arn
}

resource "aws_cloudwatch_log_group" "medialive" {
  name              = "/aws/medialive/main-channel"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.media.arn
}

resource "aws_cloudwatch_metric_alarm" "input_loss" {
  alarm_name          = "medialive-input-loss"
  namespace           = "AWS/MediaLive"
  metric_name         = "InputVideoFrameRate"
  comparison_operator = "LessThanThreshold"
  threshold           = 1
  period              = 60
  evaluation_periods  = 2
  statistic           = "Average"
  alarm_actions       = [aws_sns_topic.media_alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "transcode_errors" {
  alarm_name          = "mediaconvert-job-errors"
  namespace           = "AWS/MediaConvert"
  metric_name         = "JobsErroredCount"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  period              = 300
  evaluation_periods  = 1
  statistic           = "Sum"
  alarm_actions       = [aws_sns_topic.media_alerts.arn]
}
