# ArchLens reference architecture 12 — Account security and governance baseline
#
# The controls that should exist before the first workload lands: an
# organisation with service control policies, an org-wide CloudTrail, Config
# recording everything, and the detection services (GuardDuty, Security Hub,
# Inspector, Macie, Detective) enabled and reporting to one place. Findings land
# in Security Lake so they survive the account they came from.
#
# Services: Organizations, Control Tower, CloudTrail, Config, Security Hub,
# GuardDuty, Inspector, Macie, Detective, IAM Access Analyzer, Audit Manager,
# Security Lake, Firewall Manager, Systems Manager (patching), AWS Backup,
# Budgets, KMS, SNS, S3.
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

resource "aws_kms_key" "security" {
  description         = "Security logs and findings"
  enable_key_rotation = true
  # A short window still allows recovery from a mistaken delete, but not from a
  # slow incident response.
  deletion_window_in_days = 30
}

# -------------------------------------------------------------- Org structure

resource "aws_organizations_organization" "main" {
  feature_set = "ALL"

  enabled_policy_types = [
    "SERVICE_CONTROL_POLICY",
    "TAG_POLICY",
    "BACKUP_POLICY",
  ]

  aws_service_access_principals = [
    "cloudtrail.amazonaws.com",
    "config.amazonaws.com",
    "guardduty.amazonaws.com",
    "securityhub.amazonaws.com",
    "sso.amazonaws.com",
  ]
}

resource "aws_organizations_organizational_unit" "workloads" {
  name      = "workloads"
  parent_id = aws_organizations_organization.main.roots[0].id
}

# Deny the actions that would remove the evidence of an incident.
data "aws_iam_policy_document" "deny_log_tampering" {
  statement {
    effect = "Deny"
    actions = [
      "cloudtrail:StopLogging",
      "cloudtrail:DeleteTrail",
      "config:DeleteConfigurationRecorder",
      "guardduty:DeleteDetector",
      "s3:DeleteBucket",
    ]
    resources = ["*"]
  }
}

resource "aws_organizations_policy" "deny_log_tampering" {
  name    = "deny-log-tampering"
  type    = "SERVICE_CONTROL_POLICY"
  content = data.aws_iam_policy_document.deny_log_tampering.json
}

resource "aws_organizations_policy_attachment" "deny_log_tampering" {
  policy_id = aws_organizations_policy.deny_log_tampering.id
  target_id = aws_organizations_organizational_unit.workloads.id
}

resource "aws_controltower_control" "region_deny" {
  control_identifier = "arn:aws:controltower:${var.region}::control/AWS-GR_REGION_DENY"
  target_identifier  = aws_organizations_organizational_unit.workloads.arn
}

resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 16
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
  hard_expiry                    = false
}

# ------------------------------------------------------------------- Log store

resource "aws_s3_bucket" "logs" {
  bucket = "org-security-logs"
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
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.security.arn
    }
    bucket_key_enabled = true
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

# Object Lock in compliance mode means even the root user cannot shorten the
# retention of an audit log.
resource "aws_s3_bucket_object_lock_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 365
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "archive-then-expire"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "GLACIER_IR"
    }

    transition {
      days          = 365
      storage_class = "DEEP_ARCHIVE"
    }

    expiration {
      days = 2555
    }
  }
}

# ------------------------------------------------------------------ Audit trail

resource "aws_cloudtrail" "org" {
  name                          = "org-trail"
  s3_bucket_name                = aws_s3_bucket.logs.id
  s3_key_prefix                 = "cloudtrail"
  is_organization_trail         = true
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.security.arn
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail.arn

  # Data events are off by default and are what show you the object someone read.
  advanced_event_selector {
    name = "s3-data-events"

    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }

    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }
  }
}

resource "aws_config_configuration_recorder" "main" {
  name     = "org-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "org-delivery"
  s3_bucket_name = aws_s3_bucket.logs.id
  s3_key_prefix  = "config"
  s3_kms_key_arn = aws_kms_key.security.arn
  depends_on     = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "s3_public_read" {
  name = "s3-bucket-public-read-prohibited"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "rds_encrypted" {
  name = "rds-storage-encrypted"

  source {
    owner             = "AWS"
    source_identifier = "RDS_STORAGE_ENCRYPTED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "root_mfa" {
  name = "root-account-mfa-enabled"

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# -------------------------------------------------------------------- Detection

resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  datasources {
    s3_logs {
      enable = true
    }

    kubernetes {
      audit_logs {
        enable = true
      }
    }

    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }
}

resource "aws_securityhub_account" "main" {
  enable_default_standards  = true
  control_finding_generator = "SECURITY_CONTROL"
  auto_enable_controls      = true
}

resource "aws_securityhub_standards_subscription" "cis" {
  standards_arn = "arn:aws:securityhub:${var.region}::standards/cis-aws-foundations-benchmark/v/3.0.0"
  depends_on    = [aws_securityhub_account.main]
}

resource "aws_inspector2_enabler" "main" {
  account_ids    = ["123456789012"]
  resource_types = ["EC2", "ECR", "LAMBDA", "LAMBDA_CODE"]
}

resource "aws_macie2_account" "main" {
  status                       = "ENABLED"
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

resource "aws_macie2_classification_job" "quarterly" {
  job_type = "SCHEDULED"
  name     = "quarterly-pii-scan"

  s3_job_definition {
    bucket_definitions {
      account_id = "123456789012"
      buckets    = [aws_s3_bucket.logs.id]
    }
  }

  schedule_frequency {
    weekly_schedule = "MONDAY"
  }
}

resource "aws_detective_graph" "main" {
  enable = true
}

resource "aws_accessanalyzer_analyzer" "org" {
  analyzer_name = "org-external-access"
  type          = "ORGANIZATION"
}

resource "aws_auditmanager_assessment" "soc2" {
  name           = "soc2-readiness"
  framework_id   = "d6b9b0b0-0000-0000-0000-000000000000"
  roles {
    role_arn  = aws_iam_role.audit_manager.arn
    role_type = "PROCESS_OWNER"
  }

  assessment_reports_destination {
    destination      = "s3://${aws_s3_bucket.logs.id}/audit-manager/"
    destination_type = "S3"
  }

  scope {
    aws_accounts {
      id = "123456789012"
    }
  }
}

resource "aws_securitylake_data_lake" "main" {
  meta_store_manager_role_arn = aws_iam_role.security_lake.arn

  configuration {
    region = var.region

    encryption_configuration {
      kms_key_id = aws_kms_key.security.arn
    }

    lifecycle_configuration {
      transition {
        days          = 90
        storage_class = "GLACIER_IR"
      }

      expiration {
        days = 1095
      }
    }
  }
}

resource "aws_fms_policy" "waf_everywhere" {
  name                  = "require-waf-on-albs"
  exclude_resource_tags = false
  remediation_enabled   = true
  resource_type         = "AWS::ElasticLoadBalancingV2::LoadBalancer"

  security_service_policy_data {
    type = "WAFV2"
  }
}

# ------------------------------------------------------------------- Operations

resource "aws_ssm_patch_baseline" "linux" {
  name             = "linux-critical-within-7-days"
  operating_system = "AMAZON_LINUX_2023"

  approval_rule {
    approve_after_days = 7
    compliance_level   = "CRITICAL"

    patch_filter {
      key    = "CLASSIFICATION"
      values = ["Security"]
    }
  }
}

resource "aws_ssm_maintenance_window" "patching" {
  name     = "weekly-patching"
  schedule = "cron(0 3 ? * SUN *)"
  duration = 4
  cutoff   = 1
}

resource "aws_backup_vault" "org" {
  name        = "org-backup-vault"
  kms_key_arn = aws_kms_key.security.arn
}

resource "aws_backup_vault_lock_configuration" "org" {
  backup_vault_name   = aws_backup_vault.org.name
  min_retention_days  = 30
  max_retention_days  = 365
  changeable_for_days = 3
}

resource "aws_backup_plan" "org" {
  name = "org-default"

  rule {
    rule_name         = "daily"
    target_vault_name = aws_backup_vault.org.name
    schedule          = "cron(0 5 * * ? *)"

    lifecycle {
      delete_after = 90
    }
  }
}

# ------------------------------------------------------------------- Reporting

resource "aws_sns_topic" "security_alerts" {
  name              = "security-alerts"
  kms_master_key_id = aws_kms_key.security.arn
}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/org-trail"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.security.arn
}

resource "aws_cloudwatch_log_metric_filter" "root_login" {
  name           = "root-account-usage"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ $.userIdentity.type = \"Root\" }"

  metric_transformation {
    name      = "RootAccountUsage"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "root_login" {
  alarm_name          = "root-account-used"
  namespace           = "Security"
  metric_name         = "RootAccountUsage"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 1
  period              = 300
  evaluation_periods  = 1
  statistic           = "Sum"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}

resource "aws_budgets_budget" "org" {
  name         = "org-monthly"
  budget_type  = "COST"
  limit_amount = "25000"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 90
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = ["finops@example.com"]
  }
}

# ------------------------------------------------------------------------ IAM

data "aws_iam_policy_document" "service_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type = "Service"
      identifiers = [
        "cloudtrail.amazonaws.com",
        "config.amazonaws.com",
        "auditmanager.amazonaws.com",
        "securitylake.amazonaws.com",
      ]
    }
  }
}

resource "aws_iam_role" "cloudtrail" {
  name               = "cloudtrail-to-logs"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

resource "aws_iam_role" "config" {
  name               = "config-recorder"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_iam_role" "audit_manager" {
  name               = "audit-manager"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

resource "aws_iam_role" "security_lake" {
  name               = "security-lake-meta-store"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}
