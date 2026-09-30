# ArchLens reference architecture 04 — Event-driven microservices on ECS Fargate
#
# Three services behind an internal ALB, talking to each other through
# EventBridge and SQS rather than direct calls, so one slow consumer cannot take
# the writer down with it. Fargate means no hosts to patch; ECR scans every
# image on push; task roles are per-service, not shared.
#
# Services: ECS, Fargate, ECR, ALB, Cloud Map (service discovery), EventBridge,
# SQS, SNS, DynamoDB, ElastiCache Serverless, S3, Secrets Manager, KMS, VPC,
# VPC Endpoints, CloudWatch Container Insights, X-Ray, Application Auto
# Scaling, IAM.
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

resource "aws_kms_key" "main" {
  description         = "Microservices platform"
  enable_key_rotation = true
}

# ------------------------------------------------------------------- Network

resource "aws_vpc" "main" {
  cidr_block           = "10.40.0.0/16"
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

resource "aws_security_group" "alb" {
  name        = "svc-alb-sg"
  description = "Internal ALB — VPC clients only"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from inside the VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.40.0.0/16"]
  }

  egress {
    description = "To service tasks"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["10.40.0.0/16"]
  }
}

resource "aws_security_group" "tasks" {
  name        = "svc-tasks-sg"
  description = "Fargate tasks"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "From internal ALB"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    description = "HTTPS to AWS endpoints inside the VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.40.0.0/16"]
  }
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
}

resource "aws_vpc_endpoint" "ecr_dkr" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.region}.ecr.dkr"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.tasks.id]
  private_dns_enabled = true
}

resource "aws_flow_log" "vpc" {
  vpc_id               = aws_vpc.main.id
  traffic_type         = "REJECT"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.flow.arn
  iam_role_arn         = aws_iam_role.flow_logs.arn
}

# ------------------------------------------------------------------ Registry

resource "aws_ecr_repository" "orders" {
  name                 = "orders"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.main.arn
  }
}

resource "aws_ecr_lifecycle_policy" "orders" {
  repository = aws_ecr_repository.orders.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep the last 30 images"
      selection    = { tagStatus = "any", countType = "imageCountMoreThan", countNumber = 30 }
      action       = { type = "expire" }
    }]
  })
}

# ----------------------------------------------------------------- Discovery

resource "aws_service_discovery_private_dns_namespace" "internal" {
  name = "svc.internal"
  vpc  = aws_vpc.main.id
}

resource "aws_service_discovery_service" "orders" {
  name = "orders"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.internal.id

    dns_records {
      ttl  = 10
      type = "A"
    }
  }

  health_check_custom_config {
    failure_threshold = 1
  }
}

# ------------------------------------------------------------------- Cluster

resource "aws_ecs_cluster" "main" {
  name = "microservices"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  configuration {
    execute_command_configuration {
      kms_key_id = aws_kms_key.main.arn
      logging    = "OVERRIDE"

      log_configuration {
        cloud_watch_encryption_enabled = true
        cloud_watch_log_group_name     = aws_cloudwatch_log_group.exec.name
      }
    }
  }
}

resource "aws_ecs_cluster_capacity_providers" "main" {
  cluster_name       = aws_ecs_cluster.main.name
  capacity_providers = ["FARGATE", "FARGATE_SPOT"]

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
    base              = 2
  }
}

resource "aws_ecs_task_definition" "orders" {
  family                   = "orders"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.task_execution.arn
  task_role_arn            = aws_iam_role.orders_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }

  container_definitions = jsonencode([{
    name             = "orders"
    image            = "${aws_ecr_repository.orders.repository_url}:1.4.2"
    cpu              = 512
    memory           = 1024
    memory_limit     = 1024
    cpu_limit        = 512
    user             = "10001"
    run_as_user      = "10001"
    privileged       = false
    readonlyRootFilesystem = true
    portMappings     = [{ containerPort = 8080 }]
  }])
}

resource "aws_ecs_service" "orders" {
  name                              = "orders"
  cluster                           = aws_ecs_cluster.main.id
  task_definition                   = aws_ecs_task_definition.orders.arn
  desired_count                     = 3
  launch_type                       = "FARGATE"
  health_check_grace_period_seconds = 30
  enable_execute_command            = false
  propagate_tags                    = "SERVICE"

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.tasks.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.orders.arn
    container_name   = "orders"
    container_port   = 8080
  }

  service_registries {
    registry_arn = aws_service_discovery_service.orders.arn
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
}

resource "aws_appautoscaling_target" "orders" {
  service_namespace  = "ecs"
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.orders.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  min_capacity       = 3
  max_capacity       = 30
}

resource "aws_appautoscaling_policy" "orders_cpu" {
  name               = "orders-cpu-target"
  policy_type        = "TargetTrackingScaling"
  service_namespace  = aws_appautoscaling_target.orders.service_namespace
  resource_id        = aws_appautoscaling_target.orders.resource_id
  scalable_dimension = aws_appautoscaling_target.orders.scalable_dimension

  target_tracking_scaling_policy_configuration {
    target_value = 60

    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
  }
}

# --------------------------------------------------------------- Entry point

resource "aws_lb" "internal" {
  name                       = "microservices-alb"
  internal                   = true
  load_balancer_type         = "application"
  subnets                    = aws_subnet.private[*].id
  security_groups            = [aws_security_group.alb.id]
  drop_invalid_header_fields = true
  enable_deletion_protection = true

  access_logs {
    bucket  = aws_s3_bucket.logs.id
    prefix  = "alb"
    enabled = true
  }
}

resource "aws_lb_target_group" "orders" {
  name        = "orders-tg"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.main.id

  health_check {
    path     = "/healthz"
    interval = 15
  }
}

# ------------------------------------------------------------------ Messaging

resource "aws_cloudwatch_event_bus" "domain" {
  name               = "domain-events"
  kms_key_identifier = aws_kms_key.main.arn
}

resource "aws_cloudwatch_event_rule" "order_placed" {
  name           = "order-placed"
  event_bus_name = aws_cloudwatch_event_bus.domain.name

  event_pattern = jsonencode({
    source      = ["orders"]
    detail-type = ["OrderPlaced"]
  })
}

resource "aws_sqs_queue" "shipping" {
  name                       = "shipping-work"
  kms_master_key_id          = aws_kms_key.main.arn
  visibility_timeout_seconds = 300

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.shipping_dlq.arn
    maxReceiveCount     = 5
  })
}

resource "aws_sqs_queue" "shipping_dlq" {
  name                      = "shipping-work-dlq"
  kms_master_key_id         = aws_kms_key.main.arn
  message_retention_seconds = 1209600
  redrive_policy            = "terminal-queue"
}

resource "aws_sns_topic" "alerts" {
  name              = "platform-alerts"
  kms_master_key_id = aws_kms_key.main.arn
}

# ---------------------------------------------------------------------- State

resource "aws_dynamodb_table" "orders" {
  name                        = "svc-orders"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "order_id"
  deletion_protection_enabled = true

  attribute {
    name = "order_id"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.main.arn
  }

  point_in_time_recovery {
    enabled = true
  }
}

resource "aws_elasticache_serverless_cache" "sessions" {
  name                 = "svc-sessions"
  engine               = "valkey"
  kms_key_id           = aws_kms_key.main.arn
  security_group_ids   = [aws_security_group.tasks.id]
  subnet_ids           = slice(aws_subnet.private[*].id, 0, 2)
  daily_snapshot_time  = "04:00"
  snapshot_retention_limit = 7

  cache_usage_limits {
    data_storage {
      maximum = 5
      unit    = "GB"
    }
  }
}

resource "aws_s3_bucket" "logs" {
  bucket = "microservices-platform-logs"
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "logs" {
  bucket        = aws_s3_bucket.logs.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3-access/self/"
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "expire"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = 365
    }
  }
}

resource "aws_secretsmanager_secret" "orders_db" {
  name       = "microservices/orders/credentials"
  kms_key_id = aws_kms_key.main.arn
}

# ------------------------------------------------------------------------ IAM

data "aws_iam_policy_document" "ecs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "task_execution" {
  name               = "ecs-task-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_iam_role_policy_attachment" "task_execution" {
  role       = aws_iam_role.task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role" "orders_task" {
  name               = "orders-task-role"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

data "aws_iam_policy_document" "orders_task" {
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query"]
    resources = [aws_dynamodb_table.orders.arn]
  }

  statement {
    actions   = ["events:PutEvents"]
    resources = [aws_cloudwatch_event_bus.domain.arn]
  }

  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.orders_db.arn]
  }
}

resource "aws_iam_role_policy" "orders_task" {
  name   = "orders-task-access"
  role   = aws_iam_role.orders_task.id
  policy = data.aws_iam_policy_document.orders_task.json
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
  name               = "svc-flow-logs"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume.json
}

# ------------------------------------------------------------- Observability

resource "aws_cloudwatch_log_group" "orders" {
  name              = "/ecs/orders"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.main.arn
}

resource "aws_cloudwatch_log_group" "exec" {
  name              = "/ecs/exec"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.main.arn
}

resource "aws_cloudwatch_log_group" "flow" {
  name              = "/aws/vpc/microservices/flow-logs"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.main.arn
}

resource "aws_cloudwatch_metric_alarm" "queue_backlog" {
  alarm_name          = "shipping-queue-backlog"
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateAgeOfOldestMessage"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 600
  period              = 60
  evaluation_periods  = 5
  statistic           = "Maximum"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_xray_sampling_rule" "services" {
  rule_name      = "microservices"
  priority       = 5000
  version        = 1
  reservoir_size = 2
  fixed_rate     = 0.05
  service_name   = "*"
  service_type   = "*"
  host           = "*"
  http_method    = "*"
  url_path       = "*"
  resource_arn   = "*"
}
