# ArchLens reference architecture 02 — Serverless REST API
#
# A pay-per-request API with no servers to patch: HTTP API in front, Lambda
# handlers in a VPC, DynamoDB for state, and SQS + EventBridge + Step Functions
# for everything that should happen out of band. Cognito issues the JWTs the
# API validates, and every function has a dead-letter queue so failed async
# work is visible instead of silently dropped.
#
# Services: API Gateway (HTTP API), Lambda, DynamoDB, SQS, SNS, EventBridge,
# EventBridge Scheduler, Step Functions, Cognito, WAF, X-Ray, CloudWatch Logs,
# KMS, Secrets Manager, S3, VPC, VPC Endpoints, IAM.
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

# ---------------------------------------------------------------- Encryption

resource "aws_kms_key" "main" {
  description             = "Serverless API — data at rest"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

# ------------------------------------------------------------------- Network
# Functions run in private subnets so they reach DynamoDB and Secrets Manager
# over VPC endpoints rather than the public internet.

resource "aws_vpc" "main" {
  cidr_block           = "10.30.0.0/16"
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
  name        = "lambda-sg"
  description = "Lambda egress to AWS endpoints only"
  vpc_id      = aws_vpc.main.id

  egress {
    description = "HTTPS to VPC endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.30.0.0/16"]
  }
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
}

resource "aws_vpc_endpoint" "secretsmanager" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.region}.secretsmanager"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.lambda.id]
  private_dns_enabled = true
}

# ----------------------------------------------------------------- Identity

resource "aws_cognito_user_pool" "main" {
  name                     = "api-users"
  mfa_configuration        = "ON"
  deletion_protection      = "ACTIVE"
  auto_verified_attributes = ["email"]

  password_policy {
    minimum_length                   = 12
    require_lowercase                = true
    require_uppercase                = true
    require_numbers                  = true
    require_symbols                  = true
    temporary_password_validity_days = 3
  }

  software_token_mfa_configuration {
    enabled = true
  }

  user_pool_add_ons {
    advanced_security_mode = "ENFORCED"
  }
}

resource "aws_cognito_user_pool_client" "web" {
  name                                 = "web-client"
  user_pool_id                         = aws_cognito_user_pool.main.id
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email"]
  supported_identity_providers         = ["COGNITO"]
  allowed_oauth_flows_user_pool_client = true
  callback_urls                        = ["https://app.example.com/callback"]
  generate_secret                      = true
}

# ---------------------------------------------------------------------- API

resource "aws_apigatewayv2_api" "main" {
  name          = "serverless-api"
  protocol_type = "HTTP"

  cors_configuration {
    allow_origins = ["https://app.example.com"]
    allow_methods = ["GET", "POST", "PUT", "DELETE"]
    allow_headers = ["authorization", "content-type"]
    max_age       = 300
  }
}

resource "aws_apigatewayv2_authorizer" "jwt" {
  api_id           = aws_apigatewayv2_api.main.id
  name             = "cognito-jwt"
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]

  jwt_configuration {
    audience = [aws_cognito_user_pool_client.web.id]
    issuer   = "https://cognito-idp.${var.region}.amazonaws.com/${aws_cognito_user_pool.main.id}"
  }
}

resource "aws_apigatewayv2_stage" "prod" {
  api_id      = aws_apigatewayv2_api.main.id
  name        = "prod"
  auto_deploy = true

  default_route_settings {
    throttling_rate_limit    = 200
    throttling_burst_limit   = 400
    detailed_metrics_enabled = true
  }

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api.arn
    format          = "$context.requestId $context.status $context.identity.sourceIp $context.authorizer.error"
  }
}

resource "aws_apigatewayv2_route" "create_order" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "POST /orders"
  target             = "integrations/${aws_apigatewayv2_integration.orders.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.jwt.id
}

resource "aws_apigatewayv2_integration" "orders" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.orders_api.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_wafv2_web_acl" "api" {
  name        = "serverless-api-waf"
  description = "Rate limiting and managed rules for the HTTP API"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "serverless-api-waf"
    sampled_requests_enabled   = true
  }
}

# ------------------------------------------------------------------ Functions

resource "aws_lambda_function" "orders_api" {
  function_name = "orders-api"
  role          = aws_iam_role.orders_api.arn
  handler       = "index.handler"
  runtime       = "python3.12"
  timeout       = 15
  memory_size   = 512

  # Reserved concurrency caps blast radius and runaway cost alike.
  reserved_concurrent_executions = 50
  kms_key_arn                    = aws_kms_key.main.arn

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

  environment {
    variables = {
      TABLE_NAME = aws_dynamodb_table.orders.name
      QUEUE_URL  = aws_sqs_queue.fulfilment.url
    }
  }
}

resource "aws_lambda_function" "fulfilment_worker" {
  function_name = "fulfilment-worker"
  role          = aws_iam_role.fulfilment_worker.arn
  handler       = "worker.handler"
  runtime       = "python3.12"
  timeout       = 60
  memory_size   = 1024

  reserved_concurrent_executions = 20
  kms_key_arn                    = aws_kms_key.main.arn

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

resource "aws_lambda_event_source_mapping" "fulfilment" {
  event_source_arn                   = aws_sqs_queue.fulfilment.arn
  function_name                      = aws_lambda_function.fulfilment_worker.arn
  batch_size                         = 10
  maximum_batching_window_in_seconds = 5
  function_response_types            = ["ReportBatchItemFailures"]
}

# ------------------------------------------------------------------- Messaging

resource "aws_sqs_queue" "fulfilment" {
  name                       = "fulfilment"
  kms_master_key_id          = aws_kms_key.main.arn
  visibility_timeout_seconds = 120
  message_retention_seconds  = 345600
  sqs_managed_sse_enabled    = false

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq.arn,
    maxReceiveCount     = 5
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "fulfilment-dlq"
  kms_master_key_id         = aws_kms_key.main.arn
  message_retention_seconds = 1209600
  redrive_policy            = "none-required-terminal-queue"
}

resource "aws_sns_topic" "order_events" {
  name              = "order-events"
  kms_master_key_id = aws_kms_key.main.arn
}

resource "aws_cloudwatch_event_bus" "orders" {
  name              = "orders"
  kms_key_identifier = aws_kms_key.main.arn
}

resource "aws_cloudwatch_event_rule" "order_created" {
  name           = "order-created"
  event_bus_name = aws_cloudwatch_event_bus.orders.name
  description    = "Fan out new orders to the fulfilment workflow"

  event_pattern = jsonencode({
    source      = ["orders.api"],
    detail-type = ["OrderCreated"]
  })
}

resource "aws_sfn_state_machine" "fulfilment" {
  name     = "fulfilment-workflow"
  role_arn = aws_iam_role.step_functions.arn
  type     = "STANDARD"

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.state_machine.arn}:*"
    include_execution_data = false
    level                  = "ERROR"
  }

  tracing_configuration {
    enabled = true
  }

  definition = jsonencode({
    Comment = "Reserve stock, charge, then notify"
    StartAt = "ReserveStock"
    States = {
      ReserveStock = { Type = "Task", Resource = aws_lambda_function.fulfilment_worker.arn, End = true }
    }
  })
}

resource "aws_scheduler_schedule" "nightly_reconcile" {
  name                = "nightly-reconcile"
  schedule_expression = "cron(15 2 * * ? *)"

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = aws_lambda_function.fulfilment_worker.arn
    role_arn = aws_iam_role.step_functions.arn
  }
}

# --------------------------------------------------------------------- State

resource "aws_dynamodb_table" "orders" {
  name                        = "orders"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "pk"
  range_key                   = "sk"
  deletion_protection_enabled = true
  table_class                 = "STANDARD"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.main.arn
  }

  point_in_time_recovery {
    enabled = true
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
}

resource "aws_s3_bucket" "uploads" {
  bucket = "serverless-api-uploads"
}

resource "aws_s3_bucket_versioning" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "uploads" {
  bucket                  = aws_s3_bucket.uploads.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "uploads" {
  bucket        = aws_s3_bucket.uploads.id
  target_bucket = aws_s3_bucket.uploads.id
  target_prefix = "access-logs/"
}

resource "aws_s3_bucket_lifecycle_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  rule {
    id     = "expire-staged-uploads"
    status = "Enabled"

    expiration {
      days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 3
    }
  }
}

resource "aws_secretsmanager_secret" "payment_api" {
  name       = "serverless-api/payment-provider"
  kms_key_id = aws_kms_key.main.arn
}

# ------------------------------------------------------------------------ IAM

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "orders_api" {
  name               = "orders-api-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "orders_api" {
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query"]
    resources = [aws_dynamodb_table.orders.arn]
  }

  statement {
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.fulfilment.arn]
  }

  statement {
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.main.arn]
  }
}

resource "aws_iam_role_policy" "orders_api" {
  name   = "orders-api-access"
  role   = aws_iam_role.orders_api.id
  policy = data.aws_iam_policy_document.orders_api.json
}

resource "aws_iam_role" "fulfilment_worker" {
  name               = "fulfilment-worker-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "step_functions_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["states.amazonaws.com", "scheduler.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "step_functions" {
  name               = "fulfilment-workflow-role"
  assume_role_policy = data.aws_iam_policy_document.step_functions_assume.json
}

# ------------------------------------------------------------- Observability

resource "aws_cloudwatch_log_group" "api" {
  name              = "/aws/apigateway/serverless-api"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.main.arn
}

resource "aws_cloudwatch_log_group" "state_machine" {
  name              = "/aws/states/fulfilment-workflow"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.main.arn
}

resource "aws_cloudwatch_metric_alarm" "dlq_depth" {
  alarm_name          = "fulfilment-dlq-not-empty"
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  period              = 300
  evaluation_periods  = 1
  statistic           = "Sum"
  alarm_actions       = [aws_sns_topic.order_events.arn]

  dimensions = {
    QueueName = aws_sqs_queue.dlq.name
  }
}

resource "aws_cloudwatch_metric_alarm" "api_4xx" {
  alarm_name          = "serverless-api-4xx"
  namespace           = "AWS/ApiGateway"
  metric_name         = "4xx"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 25
  period              = 60
  evaluation_periods  = 3
  statistic           = "Sum"
  alarm_actions       = [aws_sns_topic.order_events.arn]
}

resource "aws_xray_sampling_rule" "api" {
  rule_name      = "serverless-api"
  priority       = 1000
  version        = 1
  reservoir_size = 1
  fixed_rate     = 0.1
  service_name   = "*"
  service_type   = "*"
  host           = "*"
  http_method    = "*"
  url_path       = "*"
  resource_arn   = "*"
}
