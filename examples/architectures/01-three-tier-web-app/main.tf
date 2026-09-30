# ArchLens reference architecture 01 — Three-tier web application
#
# The classic production web stack: public edge (CloudFront + WAF + ALB),
# private application tier (EC2 Auto Scaling), and an isolated data tier
# (RDS Multi-AZ + ElastiCache). Secure-by-default: every store is encrypted
# with a customer-managed KMS key, nothing in the data tier is reachable from
# the internet, and all three tiers ship logs.
#
# Services: VPC, Subnets, Internet Gateway, NAT Gateway, Route Tables, VPC
# Endpoints, VPC Flow Logs, Security Groups, ALB, ACM, Route 53, CloudFront,
# WAF, EC2, Launch Template, EC2 Auto Scaling, RDS (PostgreSQL), ElastiCache
# (Redis), S3, KMS, Secrets Manager, IAM, CloudWatch, CloudTrail, GuardDuty,
# Systems Manager.
#
# Expected ArchLens findings: the public ALB security group intentionally
# accepts 0.0.0.0/0 on 443 — that is what a public web tier is for. Everything
# else should come back clean.

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
variable "domain_name" { default = "app.example.com" }
variable "app_instance_type" { default = "t3.medium" }
variable "db_instance_class" { default = "db.r6g.large" }

data "aws_availability_zones" "available" {
  state = "available"
}

# ---------------------------------------------------------------- Encryption

resource "aws_kms_key" "main" {
  description             = "Three-tier app — data at rest"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "main" {
  name          = "alias/three-tier-app"
  target_key_id = aws_kms_key.main.key_id
}

# --------------------------------------------------------------------- Network

resource "aws_vpc" "main" {
  cidr_block           = "10.20.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "three-tier-vpc" }
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = false
  tags                    = { Name = "public-${count.index}", Tier = "public" }
}

resource "aws_subnet" "app" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index + 10)
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags              = { Name = "app-${count.index}", Tier = "private" }
}

resource "aws_subnet" "data" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index + 20)
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags              = { Name = "data-${count.index}", Tier = "isolated" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
}

resource "aws_eip" "nat" {
  count  = 2
  domain = "vpc"
}

resource "aws_nat_gateway" "main" {
  count         = 2
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  depends_on    = [aws_internet_gateway.main]
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
}

resource "aws_route" "public_default" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.main.id
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "app" {
  count  = 2
  vpc_id = aws_vpc.main.id
}

resource "aws_route" "app_default" {
  count                  = 2
  route_table_id         = aws_route_table.app[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.main[count.index].id
}

resource "aws_route_table_association" "app" {
  count          = 2
  subnet_id      = aws_subnet.app[count.index].id
  route_table_id = aws_route_table.app[count.index].id
}

# Gateway endpoints keep S3/DynamoDB traffic off the NAT Gateway (no data
# processing charge) and off the public internet.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = aws_route_table.app[*].id
}

resource "aws_vpc_endpoint" "ssm" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.region}.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.app[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
}

resource "aws_flow_log" "vpc" {
  vpc_id                   = aws_vpc.main.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn             = aws_iam_role.flow_logs.arn
  max_aggregation_interval = 60
}

# -------------------------------------------------------------- Security groups

resource "aws_security_group" "alb" {
  name        = "alb-sg"
  description = "Public entry point — HTTPS only"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from the internet (public web tier)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "To application tier only"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["10.20.10.0/23"]
  }
}

resource "aws_security_group" "app" {
  name        = "app-sg"
  description = "Application tier — reachable only from the load balancer"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "From ALB"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    description = "HTTPS to AWS APIs and package mirrors"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.20.0.0/16"]
  }
}

resource "aws_security_group_rule" "app_to_db" {
  type                     = "egress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  security_group_id        = aws_security_group.app.id
  source_security_group_id = aws_security_group.db.id
}

resource "aws_security_group" "db" {
  name        = "db-sg"
  description = "Data tier — application tier only, no internet path"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "PostgreSQL from application tier"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }
}

resource "aws_security_group" "cache" {
  name        = "cache-sg"
  description = "Redis — application tier only"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Redis from application tier"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }
}

resource "aws_security_group" "endpoints" {
  name        = "vpce-sg"
  description = "Interface endpoints"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from inside the VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.20.0.0/16"]
  }
}

# ------------------------------------------------------------------- Edge tier

resource "aws_acm_certificate" "main" {
  domain_name       = var.domain_name
  validation_method = "DNS"
}

resource "aws_wafv2_web_acl" "main" {
  name        = "three-tier-waf"
  description = "Managed rule baseline + rate limiting"
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "three-tier-waf"
    sampled_requests_enabled   = true
  }
}

resource "aws_lb" "main" {
  name                       = "three-tier-alb"
  internal                   = false
  load_balancer_type         = "application"
  subnets                    = aws_subnet.public[*].id
  security_groups            = [aws_security_group.alb.id]
  drop_invalid_header_fields = true
  enable_deletion_protection = true

  access_logs {
    bucket  = aws_s3_bucket.logs.id
    prefix  = "alb"
    enabled = true
  }
}

resource "aws_lb_target_group" "app" {
  name     = "app-tg"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check {
    path                = "/healthz"
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.main.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_cloudfront_distribution" "main" {
  enabled             = true
  aliases             = [var.domain_name]
  web_acl_id          = aws_wafv2_web_acl.main.arn
  default_root_object = "index.html"

  origin {
    domain_name = aws_lb.main.dns_name
    origin_id   = "alb"
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id       = "alb"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate.main.arn
    minimum_protocol_version = "TLSv1.2_2021"
    ssl_support_method       = "sni-only"
  }

  logging_config {
    bucket = aws_s3_bucket.logs.bucket_domain_name
    prefix = "cloudfront"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
}

resource "aws_route53_zone" "main" {
  name = "example.com"
}

resource "aws_route53_record" "app" {
  zone_id = aws_route53_zone.main.zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.main.domain_name
    zone_id                = aws_cloudfront_distribution.main.hosted_zone_id
    evaluate_target_health = false
  }
}

# ------------------------------------------------------------ Application tier

resource "aws_launch_template" "app" {
  name          = "app-lt"
  instance_type = var.app_instance_type
  image_id      = "ami-0c55b159cbfafe1f0"
  ebs_optimized = true

  metadata_options {
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size = 40
      volume_type = "gp3"
      encrypted   = true
      kms_key_id  = aws_kms_key.main.arn
    }
  }

  iam_instance_profile {
    arn = aws_iam_instance_profile.app.arn
  }

  network_interfaces {
    associate_public_ip_address = false
    security_groups             = [aws_security_group.app.id]
  }

  monitoring {
    enabled = true
  }
}

resource "aws_autoscaling_group" "app" {
  name                      = "app-asg"
  min_size                  = 2
  max_size                  = 10
  desired_capacity          = 2
  vpc_zone_identifier       = aws_subnet.app[*].id
  target_group_arns         = [aws_lb_target_group.app.arn]
  health_check_type         = "ELB"
  health_check_grace_period = 120

  launch_template {
    id      = aws_launch_template.app.id
    version = "$Latest"
  }
}

resource "aws_autoscaling_policy" "app_cpu" {
  name                   = "app-target-cpu"
  autoscaling_group_name = aws_autoscaling_group.app.name
  policy_type            = "TargetTrackingScaling"

  target_tracking_configuration {
    target_value = 55
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
  }
}

# ------------------------------------------------------------------- Data tier

resource "aws_secretsmanager_secret" "db" {
  name                    = "three-tier/db/master"
  kms_key_id              = aws_kms_key.main.arn
  recovery_window_in_days = 30
}

resource "aws_db_subnet_group" "main" {
  name       = "three-tier-db"
  subnet_ids = aws_subnet.data[*].id
}

resource "aws_db_instance" "primary" {
  identifier     = "three-tier-postgres"
  engine         = "postgres"
  engine_version = "16.4"
  instance_class = var.db_instance_class

  allocated_storage     = 100
  max_allocated_storage = 500
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.main.arn

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.db.id]
  publicly_accessible    = false
  multi_az               = true

  manage_master_user_password   = true
  master_user_secret_kms_key_id = aws_kms_key.main.arn

  backup_retention_period    = 14
  backup_window              = "03:00-04:00"
  copy_tags_to_snapshot      = true
  deletion_protection        = true
  auto_minor_version_upgrade = true

  parameter_group_name = aws_db_parameter_group.postgres.name

  enabled_cloudwatch_logs_exports      = ["postgresql", "upgrade"]
  performance_insights_enabled         = true
  performance_insights_kms_key_id      = aws_kms_key.main.arn
  monitoring_interval                  = 60
  monitoring_role_arn                  = aws_iam_role.rds_monitoring.arn
  iam_database_authentication_enabled  = true
}

# TLS is enforced at the engine, not on the instance resource: rds.force_ssl
# makes PostgreSQL reject any client that connects without TLS.
resource "aws_db_parameter_group" "postgres" {
  name   = "three-tier-postgres16"
  family = "postgres16"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  parameter {
    name  = "log_statement"
    value = "ddl"
  }

  parameter {
    name  = "pgaudit.log"
    value = "write, ddl"
  }
}

resource "aws_elasticache_subnet_group" "main" {
  name       = "three-tier-cache"
  subnet_ids = aws_subnet.data[*].id
}

resource "aws_elasticache_replication_group" "sessions" {
  replication_group_id = "three-tier-redis"
  description          = "Session and fragment cache"
  engine               = "redis"
  engine_version       = "7.1"
  node_type            = "cache.t4g.small"

  num_cache_clusters         = 2
  automatic_failover_enabled = true
  multi_az_enabled           = true

  subnet_group_name  = aws_elasticache_subnet_group.main.name
  security_group_ids = [aws_security_group.cache.id]

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  kms_key_id                 = aws_kms_key.main.arn
  auth_token                 = aws_secretsmanager_secret_version.redis.secret_string

  snapshot_retention_limit = 7
  auto_minor_version_upgrade = true
}

resource "aws_secretsmanager_secret" "redis" {
  name       = "three-tier/redis/auth-token"
  kms_key_id = aws_kms_key.main.arn
}

resource "aws_secretsmanager_secret_version" "redis" {
  secret_id     = aws_secretsmanager_secret.redis.id
  secret_string = random_password.redis.result
}

resource "random_password" "redis" {
  length  = 48
  special = false
}

# -------------------------------------------------------------------- Storage

resource "aws_s3_bucket" "assets" {
  bucket = "three-tier-app-assets"
}

resource "aws_s3_bucket_versioning" "assets" {
  bucket = aws_s3_bucket.assets.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "assets" {
  bucket = aws_s3_bucket.assets.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "assets" {
  bucket                  = aws_s3_bucket.assets.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "assets" {
  bucket        = aws_s3_bucket.assets.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3-access/assets/"
}

# Tier cold objects down automatically — the single biggest S3 cost lever.
resource "aws_s3_bucket_lifecycle_configuration" "assets" {
  bucket = aws_s3_bucket.assets.id

  rule {
    id     = "tier-and-expire"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 120
      storage_class = "GLACIER_IR"
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

resource "aws_s3_bucket" "logs" {
  bucket = "three-tier-app-logs"
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

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "retain-1y"
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

# ------------------------------------------------------------------------ IAM

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "app" {
  name               = "app-instance-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

data "aws_iam_policy_document" "app_assets" {
  statement {
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${aws_s3_bucket.assets.arn}/*"]
  }

  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.db.arn, aws_secretsmanager_secret.redis.arn]
  }

  statement {
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.main.arn]
  }
}

resource "aws_iam_role_policy" "app_assets" {
  name   = "app-assets-access"
  role   = aws_iam_role.app.id
  policy = data.aws_iam_policy_document.app_assets.json
}

resource "aws_iam_role_policy_attachment" "app_ssm" {
  role       = aws_iam_role.app.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "app" {
  name = "app-instance-profile"
  role = aws_iam_role.app.name
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
  name               = "vpc-flow-logs-role"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume.json
}

data "aws_iam_policy_document" "rds_monitoring_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["monitoring.rds.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "rds_monitoring" {
  name               = "rds-enhanced-monitoring"
  assume_role_policy = data.aws_iam_policy_document.rds_monitoring_assume.json
}

# ----------------------------------------------------------- Observability

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/three-tier/flow-logs"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.main.arn
}

resource "aws_cloudwatch_log_group" "app" {
  name              = "/aws/ec2/three-tier/app"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.main.arn
}

resource "aws_cloudwatch_metric_alarm" "alb_5xx" {
  alarm_name          = "three-tier-alb-5xx"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "HTTPCode_ELB_5XX_Count"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 10
  period              = 60
  evaluation_periods  = 2
  statistic           = "Sum"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "rds_cpu" {
  alarm_name          = "three-tier-rds-cpu"
  namespace           = "AWS/RDS"
  metric_name         = "CPUUtilization"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 80
  period              = 300
  evaluation_periods  = 3
  statistic           = "Average"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_sns_topic" "alerts" {
  name              = "three-tier-alerts"
  kms_master_key_id = aws_kms_key.main.arn
}

resource "aws_cloudtrail" "main" {
  name                          = "three-tier-trail"
  s3_bucket_name                = aws_s3_bucket.logs.id
  s3_key_prefix                 = "cloudtrail"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.main.arn
}

resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}
