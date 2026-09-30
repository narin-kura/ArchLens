# ArchLens reference architecture 16 — Batch compute, HPC and game servers
#
# Three workloads that all care about cost per core. AWS Batch runs the nightly
# risk calculation on Spot; a Parallel Computing Service cluster with FSx for
# Lustre handles the tightly-coupled simulations; GameLift fleets host match
# sessions with a serverless matchmaker in front. Braket is wired in for the one
# team experimenting with quantum solvers.
#
# Services: AWS Batch, EC2 Spot, ParallelCluster / Parallel Computing Service,
# FSx for Lustre, EFS, GameLift, Braket, Lambda, DynamoDB, ElastiCache, API
# Gateway, Cognito, SNS, S3, KMS, CloudWatch, IAM.
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

variable "region" { default = "us-west-2" }

resource "aws_kms_key" "compute" {
  description         = "Batch, HPC and game session data"
  enable_key_rotation = true
}

# ------------------------------------------------------------------- Network

resource "aws_vpc" "main" {
  cidr_block           = "10.140.0.0/16"
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

resource "aws_security_group" "compute" {
  name        = "batch-hpc-sg"
  description = "Batch jobs, HPC nodes and game servers"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "MPI traffic between nodes in the cluster"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["10.140.0.0/16"]
  }

  egress {
    description = "HTTPS to AWS endpoints inside the VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.140.0.0/16"]
  }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
}

# --------------------------------------------------------------- Batch on Spot

resource "aws_launch_template" "batch" {
  name          = "batch-node"
  instance_type = "c7g.4xlarge"
  ebs_optimized = true

  metadata_options {
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size = 100
      volume_type = "gp3"
      encrypted   = true
      kms_key_id  = aws_kms_key.compute.arn
    }
  }

  network_interfaces {
    associate_public_ip_address = false
    security_groups             = [aws_security_group.compute.id]
  }

  monitoring {
    enabled = true
  }
}

resource "aws_batch_compute_environment" "spot" {
  compute_environment_name = "risk-spot"
  type                     = "MANAGED"
  state                    = "ENABLED"
  service_role             = aws_iam_role.batch_service.arn

  compute_resources {
    type                = "SPOT"
    allocation_strategy = "SPOT_CAPACITY_OPTIMIZED"
    # Never pay more than on-demand for interruptible capacity.
    bid_percentage      = 70
    min_vcpus           = 0
    desired_vcpus       = 0
    max_vcpus           = 2048
    instance_type       = ["c7g.4xlarge", "c7g.8xlarge", "c6g.4xlarge"]
    subnets             = aws_subnet.private[*].id
    security_group_ids  = [aws_security_group.compute.id]
    spot_iam_fleet_role = aws_iam_role.spot_fleet.arn
    instance_role       = aws_iam_instance_profile.batch.arn

    launch_template {
      launch_template_id = aws_launch_template.batch.id
      version            = "$Latest"
    }
  }
}

resource "aws_batch_job_queue" "risk" {
  name     = "risk-queue"
  state    = "ENABLED"
  priority = 10

  compute_environment_order {
    order               = 1
    compute_environment = aws_batch_compute_environment.spot.arn
  }
}

resource "aws_batch_job_definition" "risk" {
  name                  = "nightly-risk"
  type                  = "container"
  platform_capabilities = ["EC2"]

  retry_strategy {
    attempts = 3

    evaluate_on_exit {
      action           = "RETRY"
      on_status_reason = "Host EC2*"
    }
  }

  timeout {
    attempt_duration_seconds = 7200
  }

  container_properties = jsonencode({
    image        = "123456789012.dkr.ecr.${var.region}.amazonaws.com/risk:4.2.0"
    vcpus        = 16
    memory       = 32768
    cpu          = 16
    cpu_limit    = 16
    memory_limit = 32768
    user         = "10001"
    run_as_user  = "10001"
    privileged   = false
    readonlyRootFilesystem = true
    jobRoleArn   = aws_iam_role.batch_job.arn
  })
}

# ------------------------------------------------------------------------- HPC

resource "aws_fsx_lustre_file_system" "scratch" {
  storage_capacity            = 4800
  subnet_ids                  = [aws_subnet.private[0].id]
  security_group_ids          = [aws_security_group.compute.id]
  deployment_type             = "PERSISTENT_2"
  per_unit_storage_throughput = 250
  kms_key_id                  = aws_kms_key.compute.arn
  encrypted                   = true

  # Lustre is expensive per TB: keep it as scratch and let S3 hold the truth.
  data_repository_association_count = 1
  automatic_backup_retention_days   = 7
  backup_retention_period           = 7
  daily_automatic_backup_start_time = "01:00"
  copy_tags_to_backups              = true

  log_configuration {
    level       = "WARN_ERROR"
    destination = aws_cloudwatch_log_group.fsx.arn
  }
}

resource "aws_efs_file_system" "home" {
  creation_token   = "hpc-home"
  encrypted        = true
  kms_key_id       = aws_kms_key.compute.arn
  performance_mode = "generalPurpose"
  throughput_mode  = "elastic"

  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS"
  }
}

resource "aws_efs_backup_policy" "home" {
  file_system_id = aws_efs_file_system.home.id

  backup_policy {
    status = "ENABLED"
  }
}

resource "aws_braket_quantum_task" "annealing" {
  device_arn  = "arn:aws:braket:::device/quantum-simulator/amazon/sv1"
  output_s3_bucket = aws_s3_bucket.results.id
  output_s3_key_prefix = "braket/"
  shots       = 1000
  action      = file("braket_program.json")
}

# ---------------------------------------------------------------- Game servers

resource "aws_gamelift_build" "session_server" {
  name             = "match-server"
  operating_system = "AMAZON_LINUX_2023"
  version          = "3.8.1"

  storage_location {
    bucket   = aws_s3_bucket.results.id
    key      = "builds/match-server-3.8.1.zip"
    role_arn = aws_iam_role.gamelift.arn
  }
}

resource "aws_gamelift_fleet" "sessions" {
  name               = "match-sessions"
  build_id           = aws_gamelift_build.session_server.id
  ec2_instance_type  = "c7g.large"
  fleet_type         = "SPOT"
  new_game_session_protection_policy = "FullProtection"

  ec2_inbound_permission {
    from_port = 7777
    to_port   = 7787
    ip_range  = "0.0.0.0/0"
    protocol  = "UDP"
  }

  runtime_configuration {
    server_process {
      concurrent_executions = 4
      launch_path           = "/local/game/match-server"
    }
  }
}

resource "aws_gamelift_alias" "sessions" {
  name        = "match-sessions-live"
  description = "Points matchmaking at the current fleet"

  routing_strategy {
    type     = "SIMPLE"
    fleet_id = aws_gamelift_fleet.sessions.id
  }
}

# --------------------------------------------------------- Matchmaking front end

resource "aws_cognito_user_pool" "players" {
  name                = "players"
  mfa_configuration   = "OPTIONAL"
  deletion_protection = "ACTIVE"

  password_policy {
    minimum_length    = 12
    require_lowercase = true
    require_uppercase = true
    require_numbers   = true
    require_symbols   = false
  }

  software_token_mfa_configuration {
    enabled = true
  }
}

resource "aws_apigatewayv2_api" "matchmaking" {
  name          = "matchmaking"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_authorizer" "players" {
  api_id           = aws_apigatewayv2_api.matchmaking.id
  name             = "cognito-players"
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]

  jwt_configuration {
    audience = [aws_cognito_user_pool.players.id]
    issuer   = "https://cognito-idp.${var.region}.amazonaws.com/${aws_cognito_user_pool.players.id}"
  }
}

resource "aws_apigatewayv2_stage" "prod" {
  api_id      = aws_apigatewayv2_api.matchmaking.id
  name        = "prod"
  auto_deploy = true

  default_route_settings {
    throttling_rate_limit    = 500
    throttling_burst_limit   = 1000
    detailed_metrics_enabled = true
  }

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api.arn
    format          = "$context.requestId $context.status $context.identity.sourceIp"
  }
}

resource "aws_wafv2_web_acl" "matchmaking" {
  name        = "matchmaking-waf"
  description = "Rate limiting for the matchmaking API"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "matchmaking-waf"
    sampled_requests_enabled   = true
  }
}

resource "aws_lambda_function" "matchmaker" {
  function_name = "matchmaker"
  role          = aws_iam_role.lambda.arn
  handler       = "match.handler"
  runtime       = "python3.12"
  timeout       = 10
  memory_size   = 512
  kms_key_arn   = aws_kms_key.compute.arn

  reserved_concurrent_executions = 200

  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.compute.id]
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  tracing_config {
    mode = "Active"
  }
}

resource "aws_sqs_queue" "dlq" {
  name                      = "matchmaker-dlq"
  kms_master_key_id         = aws_kms_key.compute.arn
  message_retention_seconds = 1209600
  redrive_policy            = "terminal-queue"
}

resource "aws_dynamodb_table" "sessions" {
  name                        = "game-sessions"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "session_id"
  deletion_protection_enabled = true

  attribute {
    name = "session_id"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.compute.arn
  }

  point_in_time_recovery {
    enabled = true
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
}

resource "aws_elasticache_serverless_cache" "leaderboard" {
  name               = "leaderboard"
  engine             = "valkey"
  kms_key_id         = aws_kms_key.compute.arn
  security_group_ids = [aws_security_group.compute.id]
  subnet_ids         = slice(aws_subnet.private[*].id, 0, 2)

  cache_usage_limits {
    data_storage {
      maximum = 10
      unit    = "GB"
    }
  }
}

# -------------------------------------------------------------------- Results

resource "aws_s3_bucket" "results" {
  bucket = "batch-hpc-results"
}

resource "aws_s3_bucket_versioning" "results" {
  bucket = aws_s3_bucket.results.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "results" {
  bucket = aws_s3_bucket.results.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.compute.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "results" {
  bucket                  = aws_s3_bucket.results.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "results" {
  bucket        = aws_s3_bucket.results.id
  target_bucket = aws_s3_bucket.results.id
  target_prefix = "s3-access/self/"
}

resource "aws_s3_bucket_lifecycle_configuration" "results" {
  bucket = aws_s3_bucket.results.id

  rule {
    id     = "tier-results"
    status = "Enabled"

    transition {
      days          = 30
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
        "batch.amazonaws.com",
        "spotfleet.amazonaws.com",
        "gamelift.amazonaws.com",
        "lambda.amazonaws.com",
        "ecs-tasks.amazonaws.com",
      ]
    }
  }
}

resource "aws_iam_role" "batch_service" {
  name               = "batch-service-role"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

resource "aws_iam_role" "spot_fleet" {
  name               = "spot-fleet-role"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

resource "aws_iam_role" "batch_job" {
  name               = "batch-job-role"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

data "aws_iam_policy_document" "batch_job" {
  statement {
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${aws_s3_bucket.results.arn}/*"]
  }

  statement {
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.compute.arn]
  }
}

resource "aws_iam_role_policy" "batch_job" {
  name   = "batch-job-access"
  role   = aws_iam_role.batch_job.id
  policy = data.aws_iam_policy_document.batch_job.json
}

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "batch_instance" {
  name               = "batch-instance-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_instance_profile" "batch" {
  name = "batch-instance-profile"
  role = aws_iam_role.batch_instance.name
}

resource "aws_iam_role" "gamelift" {
  name               = "gamelift-role"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

resource "aws_iam_role" "lambda" {
  name               = "matchmaker-role"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

# ------------------------------------------------------------- Observability

resource "aws_cloudwatch_log_group" "api" {
  name              = "/aws/apigateway/matchmaking"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.compute.arn
}

resource "aws_cloudwatch_log_group" "fsx" {
  name              = "/aws/fsx/hpc-scratch"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.compute.arn
}

resource "aws_sns_topic" "compute_alerts" {
  name              = "compute-alerts"
  kms_master_key_id = aws_kms_key.compute.arn
}

resource "aws_cloudwatch_metric_alarm" "job_failures" {
  alarm_name          = "batch-job-failures"
  namespace           = "AWS/Batch"
  metric_name         = "FailedJobs"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 5
  period              = 300
  evaluation_periods  = 1
  statistic           = "Sum"
  alarm_actions       = [aws_sns_topic.compute_alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "spot_interruptions" {
  alarm_name          = "spot-interruption-rate"
  namespace           = "AWS/EC2Spot"
  metric_name         = "TerminatingInstances"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 20
  period              = 300
  evaluation_periods  = 2
  statistic           = "Sum"
  alarm_actions       = [aws_sns_topic.compute_alerts.arn]
}
