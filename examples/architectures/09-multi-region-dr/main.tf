# ArchLens reference architecture 09 — Multi-region active/passive DR
#
# Everything stateful replicates continuously to a second region; everything
# stateless is deployed there but scaled low. Route 53 health checks fail traffic
# over without a human in the loop. The point of the pattern is that failover is
# a DNS change, not a restore-from-backup project.
#
# Services: Aurora Global Database, DynamoDB Global Tables, S3 Cross-Region
# Replication, ECR replication, Route 53 (health checks, failover records),
# Global Accelerator, AWS Backup with cross-region copy, CloudFront, KMS
# (multi-region keys), CloudWatch, IAM.
#
# Expected ArchLens findings: clean.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = "us-east-1"
  alias  = "primary"
}

provider "aws" {
  region = "us-west-2"
  alias  = "secondary"
}

provider "aws" {
  region = "us-east-1"
}

variable "domain_name" { default = "api.example.com" }

# --------------------------------------------------------------- Encryption
# A multi-region key lets the replica decrypt without a cross-region call.

resource "aws_kms_key" "primary" {
  provider            = aws.primary
  description         = "DR primary"
  enable_key_rotation = true
  multi_region        = true
}

resource "aws_kms_replica_key" "secondary" {
  provider        = aws.secondary
  description     = "DR secondary"
  primary_key_arn = aws_kms_key.primary.arn
}

# ------------------------------------------------------------------- Database

resource "aws_rds_global_cluster" "main" {
  global_cluster_identifier = "app-global"
  engine                    = "aurora-postgresql"
  engine_version            = "16.4"
  storage_encrypted         = true
  deletion_protection       = true
}

resource "aws_rds_cluster" "primary" {
  provider                  = aws.primary
  cluster_identifier        = "app-primary"
  global_cluster_identifier = aws_rds_global_cluster.main.id
  engine                    = aws_rds_global_cluster.main.engine
  engine_version            = aws_rds_global_cluster.main.engine_version
  database_name             = "app"

  storage_encrypted               = true
  kms_key_id                      = aws_kms_key.primary.arn
  multi_az                        = true
  publicly_accessible             = false
  deletion_protection             = true
  auto_minor_version_upgrade      = true
  backup_retention_period         = 21
  preferred_backup_window         = "03:00-04:00"
  copy_tags_to_snapshot           = true
  enabled_cloudwatch_logs_exports = ["postgresql"]
  db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.primary.name
  parameter_group_name            = aws_rds_cluster_parameter_group.primary.name
  manage_master_user_password     = true
  master_username                 = "app_admin"
}

resource "aws_rds_cluster_parameter_group" "primary" {
  provider = aws.primary
  name     = "app-aurora-pg16"
  family   = "aurora-postgresql16"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
}

resource "aws_db_parameter_group" "primary" {
  provider = aws.primary
  name     = "app-aurora-instance-pg16"
  family   = "aurora-postgresql16"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
}

# The secondary cluster is read-only until promoted, and costs one instance.
resource "aws_rds_cluster" "secondary" {
  provider                  = aws.secondary
  cluster_identifier        = "app-secondary"
  global_cluster_identifier = aws_rds_global_cluster.main.id
  engine                    = aws_rds_global_cluster.main.engine
  engine_version            = aws_rds_global_cluster.main.engine_version

  storage_encrypted               = true
  kms_key_id                      = aws_kms_replica_key.secondary.arn
  multi_az                        = true
  publicly_accessible             = false
  deletion_protection             = true
  auto_minor_version_upgrade      = true
  backup_retention_period         = 21
  enabled_cloudwatch_logs_exports = ["postgresql"]
  parameter_group_name            = aws_db_parameter_group.primary.name
  depends_on                      = [aws_rds_cluster.primary]
}

resource "aws_dynamodb_table" "sessions" {
  name                        = "app-sessions"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "session_id"
  stream_enabled              = true
  stream_view_type            = "NEW_AND_OLD_IMAGES"
  deletion_protection_enabled = true

  attribute {
    name = "session_id"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.primary.arn
  }

  point_in_time_recovery {
    enabled = true
  }

  # Global tables: writes in either region converge, no failover step needed.
  replica {
    region_name            = "us-west-2"
    kms_key_arn            = aws_kms_replica_key.secondary.arn
    point_in_time_recovery = true
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
}

# ------------------------------------------------------------------- Storage

resource "aws_s3_bucket" "primary" {
  provider = aws.primary
  bucket   = "app-assets-use1"
}

resource "aws_s3_bucket_versioning" "primary" {
  provider = aws.primary
  bucket   = aws_s3_bucket.primary.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "primary" {
  provider = aws.primary
  bucket   = aws_s3_bucket.primary.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.primary.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "primary" {
  provider                = aws.primary
  bucket                  = aws_s3_bucket.primary.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "primary" {
  provider      = aws.primary
  bucket        = aws_s3_bucket.primary.id
  target_bucket = aws_s3_bucket.primary.id
  target_prefix = "s3-access/self/"
}

resource "aws_s3_bucket_replication_configuration" "primary" {
  provider   = aws.primary
  bucket     = aws_s3_bucket.primary.id
  role       = aws_iam_role.replication.arn
  depends_on = [aws_s3_bucket_versioning.primary]

  rule {
    id     = "replicate-all"
    status = "Enabled"

    destination {
      bucket        = aws_s3_bucket.secondary.arn
      storage_class = "STANDARD_IA"

      encryption_configuration {
        replica_kms_key_id = aws_kms_replica_key.secondary.arn
      }

      metrics {
        status = "Enabled"
      }
    }

    delete_marker_replication {
      status = "Enabled"
    }
  }
}

resource "aws_s3_bucket" "secondary" {
  provider = aws.secondary
  bucket   = "app-assets-usw2"
}

resource "aws_s3_bucket_versioning" "secondary" {
  provider = aws.secondary
  bucket   = aws_s3_bucket.secondary.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secondary" {
  provider = aws.secondary
  bucket   = aws_s3_bucket.secondary.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_replica_key.secondary.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "secondary" {
  provider                = aws.secondary
  bucket                  = aws_s3_bucket.secondary.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "secondary" {
  provider      = aws.secondary
  bucket        = aws_s3_bucket.secondary.id
  target_bucket = aws_s3_bucket.secondary.id
  target_prefix = "s3-access/self/"
}

resource "aws_ecr_repository" "app" {
  provider             = aws.primary
  name                 = "app"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.primary.arn
  }
}

resource "aws_ecr_replication_configuration" "app" {
  provider = aws.primary

  replication_configuration {
    rule {
      destination {
        region      = "us-west-2"
        registry_id = "123456789012"
      }
    }
  }
}

# ------------------------------------------------------------------- Backups

resource "aws_backup_vault" "primary" {
  provider    = aws.primary
  name        = "app-primary-vault"
  kms_key_arn = aws_kms_key.primary.arn
}

resource "aws_backup_vault" "secondary" {
  provider    = aws.secondary
  name        = "app-secondary-vault"
  kms_key_arn = aws_kms_replica_key.secondary.arn
}

resource "aws_backup_plan" "app" {
  provider = aws.primary
  name     = "app-daily-with-copy"

  rule {
    rule_name         = "daily"
    target_vault_name = aws_backup_vault.primary.name
    schedule          = "cron(0 4 * * ? *)"

    lifecycle {
      cold_storage_after = 30
      delete_after       = 365
    }

    # A backup that only exists in the failed region is not a backup.
    copy_action {
      destination_vault_arn = aws_backup_vault.secondary.arn

      lifecycle {
        delete_after = 365
      }
    }
  }
}

# --------------------------------------------------------------- Traffic flow

resource "aws_route53_zone" "main" {
  name = "example.com"
}

resource "aws_route53_health_check" "primary" {
  fqdn              = "primary.example.com"
  type              = "HTTPS"
  resource_path     = "/healthz"
  port              = 443
  failure_threshold = 3
  request_interval  = 30
  enable_sni        = true
}

resource "aws_route53_health_check" "secondary" {
  fqdn              = "secondary.example.com"
  type              = "HTTPS"
  resource_path     = "/healthz"
  port              = 443
  failure_threshold = 3
  request_interval  = 30
  enable_sni        = true
}

resource "aws_route53_record" "primary" {
  zone_id         = aws_route53_zone.main.zone_id
  name            = var.domain_name
  type            = "A"
  ttl             = 60
  records         = ["203.0.113.10"]
  set_identifier  = "primary"
  health_check_id = aws_route53_health_check.primary.id

  failover_routing_policy {
    type = "PRIMARY"
  }
}

resource "aws_route53_record" "secondary" {
  zone_id         = aws_route53_zone.main.zone_id
  name            = var.domain_name
  type            = "A"
  ttl             = 60
  records         = ["198.51.100.10"]
  set_identifier  = "secondary"
  health_check_id = aws_route53_health_check.secondary.id

  failover_routing_policy {
    type = "SECONDARY"
  }
}

resource "aws_globalaccelerator_accelerator" "app" {
  name            = "app-accelerator"
  ip_address_type = "IPV4"
  enabled         = true

  attributes {
    flow_logs_enabled   = true
    flow_logs_s3_bucket = aws_s3_bucket.primary.id
    flow_logs_s3_prefix = "global-accelerator/"
  }
}

resource "aws_wafv2_web_acl" "edge" {
  name        = "dr-edge-waf"
  description = "Shared managed-rule baseline for both regions"
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "dr-edge-waf"
    sampled_requests_enabled   = true
  }
}

# ------------------------------------------------------------------------ IAM

data "aws_iam_policy_document" "s3_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com", "backup.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "replication" {
  name               = "s3-crr-role"
  assume_role_policy = data.aws_iam_policy_document.s3_assume.json
}

data "aws_iam_policy_document" "replication" {
  statement {
    actions   = ["s3:GetReplicationConfiguration", "s3:ListBucket"]
    resources = [aws_s3_bucket.primary.arn]
  }

  statement {
    actions   = ["s3:GetObjectVersionForReplication", "s3:GetObjectVersionAcl"]
    resources = ["${aws_s3_bucket.primary.arn}/*"]
  }

  statement {
    actions   = ["s3:ReplicateObject", "s3:ReplicateDelete"]
    resources = ["${aws_s3_bucket.secondary.arn}/*"]
  }
}

resource "aws_iam_role_policy" "replication" {
  name   = "s3-crr-access"
  role   = aws_iam_role.replication.id
  policy = data.aws_iam_policy_document.replication.json
}

# ------------------------------------------------------------- Observability

resource "aws_cloudwatch_metric_alarm" "primary_health" {
  provider            = aws.primary
  alarm_name          = "primary-region-unhealthy"
  namespace           = "AWS/Route53"
  metric_name         = "HealthCheckStatus"
  comparison_operator = "LessThanThreshold"
  threshold           = 1
  period              = 60
  evaluation_periods  = 2
  statistic           = "Minimum"

  dimensions = {
    HealthCheckId = aws_route53_health_check.primary.id
  }
}

resource "aws_cloudwatch_metric_alarm" "replication_lag" {
  provider            = aws.primary
  alarm_name          = "aurora-global-replication-lag"
  namespace           = "AWS/RDS"
  metric_name         = "AuroraGlobalDBReplicationLag"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 5000
  period              = 300
  evaluation_periods  = 3
  statistic           = "Average"
}
