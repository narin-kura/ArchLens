# ArchLens reference architecture 14 — Migration and hybrid connectivity
#
# The landing zone a data-centre migration lands in. Direct Connect plus a VPN
# backup carry traffic into a Transit Gateway hub; DMS replicates databases with
# change data capture so cutover is minutes rather than a weekend; MGN lifts and
# shifts the servers that cannot be re-platformed yet; DataSync and Transfer
# Family move the file estate.
#
# Services: Migration Hub, Application Discovery Service, Application Migration
# Service, Elastic Disaster Recovery, Database Migration Service, DataSync,
# Transfer Family, Storage Gateway, Snowball, Direct Connect, Site-to-Site VPN,
# Transit Gateway, Cloud WAN, S3, FSx for Windows, KMS, CloudWatch.
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
variable "on_prem_cidr" { default = "192.168.0.0/16" }

resource "aws_kms_key" "migration" {
  description         = "Migration data in flight and at rest"
  enable_key_rotation = true
}

# ------------------------------------------------------------- Hybrid network

resource "aws_vpc" "landing" {
  cidr_block           = "10.120.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.landing.id
  cidr_block        = cidrsubnet(aws_vpc.landing.cidr_block, 8, count.index)
  availability_zone = "${var.region}${count.index == 0 ? "a" : "b"}"
}

resource "aws_security_group" "migration" {
  name        = "migration-sg"
  description = "Replication and transfer endpoints"
  vpc_id      = aws_vpc.landing.id

  ingress {
    description = "Database replication from the data centre"
    from_port   = 1521
    to_port     = 1521
    protocol    = "tcp"
    cidr_blocks = [var.on_prem_cidr]
  }

  ingress {
    description = "SMB for the file estate"
    from_port   = 445
    to_port     = 445
    protocol    = "tcp"
    cidr_blocks = [var.on_prem_cidr]
  }

  egress {
    description = "Back to the data centre and to AWS endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.120.0.0/16", var.on_prem_cidr]
  }
}

resource "aws_ec2_transit_gateway" "hub" {
  description                     = "Migration hub"
  amazon_side_asn                 = 64512
  auto_accept_shared_attachments  = "disable"
  default_route_table_association = "enable"
  dns_support                     = "enable"
  vpn_ecmp_support                = "enable"
}

resource "aws_ec2_transit_gateway_vpc_attachment" "landing" {
  transit_gateway_id = aws_ec2_transit_gateway.hub.id
  vpc_id             = aws_vpc.landing.id
  subnet_ids         = aws_subnet.private[*].id
  dns_support        = "enable"
}

resource "aws_dx_gateway" "main" {
  name            = "migration-dxgw"
  amazon_side_asn = "64513"
}

resource "aws_dx_connection" "primary" {
  name          = "dc-primary-10g"
  bandwidth     = "10Gbps"
  location      = "EqDC2"
  encryption_mode = "must_encrypt"
}

resource "aws_customer_gateway" "datacenter" {
  bgp_asn    = 65000
  ip_address = "203.0.113.20"
  type       = "ipsec.1"
}

# The VPN is the backup path for the Direct Connect, not the primary.
resource "aws_vpn_connection" "backup" {
  customer_gateway_id = aws_customer_gateway.datacenter.id
  transit_gateway_id  = aws_ec2_transit_gateway.hub.id
  type                = "ipsec.1"
  static_routes_only  = false

  tunnel1_ike_versions                 = ["ikev2"]
  tunnel1_phase1_encryption_algorithms = ["AES256-GCM-16"]
  tunnel1_phase2_encryption_algorithms = ["AES256-GCM-16"]
  tunnel1_dpd_timeout_action           = "restart"
}

resource "aws_networkmanager_global_network" "main" {
  description = "Global network for the hybrid estate"
}

resource "aws_networkmanager_core_network" "main" {
  global_network_id = aws_networkmanager_global_network.main.id
  description       = "Cloud WAN core"
}

resource "aws_flow_log" "landing" {
  vpc_id               = aws_vpc.landing.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.flow.arn
  iam_role_arn         = aws_iam_role.flow_logs.arn
}

# ------------------------------------------------------------------ Discovery

resource "aws_migrationhubstrategy_assessment" "estate" {
  s3_bucket           = aws_s3_bucket.migration.id
  data_collection_role = aws_iam_role.migration.arn
}

# ---------------------------------------------------------- Database migration

resource "aws_dms_replication_subnet_group" "main" {
  replication_subnet_group_id          = "migration-subnets"
  replication_subnet_group_description = "DMS replication instances"
  subnet_ids                           = aws_subnet.private[*].id
}

resource "aws_dms_replication_instance" "main" {
  replication_instance_id     = "migration-dms"
  replication_instance_class  = "dms.t3.medium"
  allocated_storage           = 100
  engine_version              = "3.5.3"
  multi_az                    = true
  publicly_accessible         = false
  auto_minor_version_upgrade  = true
  kms_key_arn                 = aws_kms_key.migration.arn
  replication_subnet_group_id = aws_dms_replication_subnet_group.main.id
  vpc_security_group_ids      = [aws_security_group.migration.id]
}

resource "aws_dms_endpoint" "source_oracle" {
  endpoint_id   = "onprem-oracle"
  endpoint_type = "source"
  engine_name   = "oracle"
  server_name   = "oracle.corp.internal"
  port          = 1521
  database_name = "ERP"
  username      = "dms_reader"
  ssl_mode      = "verify-full"
  kms_key_arn   = aws_kms_key.migration.arn

  # The password is read from Secrets Manager, never set in the template.
  secrets_manager_arn             = aws_secretsmanager_secret.source_db.arn
  secrets_manager_access_role_arn = aws_iam_role.migration.arn
}

resource "aws_dms_endpoint" "target_aurora" {
  endpoint_id   = "aurora-target"
  endpoint_type = "target"
  engine_name   = "aurora-postgresql"
  ssl_mode      = "require"
  kms_key_arn   = aws_kms_key.migration.arn

  secrets_manager_arn             = aws_secretsmanager_secret.target_db.arn
  secrets_manager_access_role_arn = aws_iam_role.migration.arn
}

resource "aws_dms_replication_task" "erp" {
  replication_task_id      = "erp-cdc"
  migration_type           = "full-load-and-cdc"
  replication_instance_arn = aws_dms_replication_instance.main.replication_instance_arn
  source_endpoint_arn      = aws_dms_endpoint.source_oracle.endpoint_arn
  target_endpoint_arn      = aws_dms_endpoint.target_aurora.endpoint_arn
  table_mappings           = file("table_mappings.json")
}

resource "aws_secretsmanager_secret" "source_db" {
  name       = "migration/source-oracle"
  kms_key_id = aws_kms_key.migration.arn
}

resource "aws_secretsmanager_secret" "target_db" {
  name       = "migration/target-aurora"
  kms_key_id = aws_kms_key.migration.arn
}

# ------------------------------------------------------------ Server migration

resource "aws_drs_replication_configuration_template" "servers" {
  associate_default_security_group = false
  bandwidth_throttling            = 10000
  create_public_ip                = false
  data_plane_routing              = "PRIVATE_IP"
  default_large_staging_disk_type = "GP3"
  ebs_encryption                  = "CUSTOM"
  ebs_encryption_key_arn          = aws_kms_key.migration.arn
  replication_server_instance_type = "t3.small"
  replication_servers_security_groups_ids = [aws_security_group.migration.id]
  staging_area_subnet_id          = aws_subnet.private[0].id
  use_dedicated_replication_server = false

  staging_area_tags = {
    purpose = "drs-staging"
  }

  pit_policy {
    enabled            = true
    interval           = 10
    retention_duration = 60
    units              = "MINUTE"
    rule_id            = 1
  }
}

# ---------------------------------------------------------------- File estate

resource "aws_datasync_location_s3" "target" {
  s3_bucket_arn = aws_s3_bucket.migration.arn
  subdirectory  = "/fileshares"

  s3_config {
    bucket_access_role_arn = aws_iam_role.migration.arn
  }
}

resource "aws_datasync_task" "fileshares" {
  name                     = "fileshare-sync"
  source_location_arn      = aws_datasync_location_smb.source.arn
  destination_location_arn = aws_datasync_location_s3.target.arn

  options {
    verify_mode            = "POINT_IN_TIME_CONSISTENT"
    posix_permissions      = "NONE"
    preserve_deleted_files = "REMOVE"
    log_level              = "TRANSFER"
  }

  cloudwatch_log_group_arn = aws_cloudwatch_log_group.datasync.arn
}

resource "aws_datasync_location_smb" "source" {
  server_hostname = "files.corp.internal"
  subdirectory    = "/shared"
  user            = "datasync"
  password        = aws_secretsmanager_secret.source_db.arn
  agent_arns      = [aws_datasync_agent.dc.arn]
}

resource "aws_datasync_agent" "dc" {
  name       = "datacenter-agent"
  ip_address = "192.168.10.5"
}

resource "aws_storagegateway_gateway" "files" {
  gateway_name       = "dc-file-gateway"
  gateway_timezone   = "GMT"
  gateway_type       = "FILE_S3"
  gateway_ip_address = "192.168.10.6"
}

resource "aws_transfer_server" "sftp" {
  identity_provider_type = "AWS_LAMBDA"
  endpoint_type          = "VPC"
  protocols              = ["SFTP"]
  security_policy_name   = "TransferSecurityPolicy-2024-01"
  function               = aws_lambda_function.sftp_auth.arn

  endpoint_details {
    vpc_id             = aws_vpc.landing.id
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.migration.id]
  }

  logging_role = aws_iam_role.migration.arn
}

resource "aws_lambda_function" "sftp_auth" {
  function_name = "sftp-authorizer"
  role          = aws_iam_role.migration.arn
  handler        = "auth.handler"
  runtime       = "python3.12"
  timeout       = 10
  memory_size   = 256
  kms_key_arn   = aws_kms_key.migration.arn

  reserved_concurrent_executions = 10

  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.migration.id]
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  tracing_config {
    mode = "Active"
  }
}

resource "aws_sqs_queue" "dlq" {
  name                      = "migration-dlq"
  kms_master_key_id         = aws_kms_key.migration.arn
  message_retention_seconds = 1209600
  redrive_policy            = "terminal-queue"
}

resource "aws_fsx_windows_file_system" "shared" {
  storage_capacity    = 1024
  storage_type        = "SSD"
  throughput_capacity = 32
  subnet_ids          = [aws_subnet.private[0].id]
  security_group_ids  = [aws_security_group.migration.id]
  kms_key_id          = aws_kms_key.migration.arn
  encrypted           = true

  automatic_backup_retention_days   = 30
  backup_retention_period           = 30
  daily_automatic_backup_start_time = "03:00"
  copy_tags_to_backups              = true

  self_managed_active_directory {
    dns_ips     = ["192.168.10.10"]
    domain_name = "corp.internal"
    username    = "fsxadmin"
    password    = aws_secretsmanager_secret.source_db.arn
  }
}

# -------------------------------------------------------------- Bulk transfer

resource "aws_s3_bucket" "migration" {
  bucket = "migration-landing-zone"
}

resource "aws_s3_bucket_versioning" "migration" {
  bucket = aws_s3_bucket.migration.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "migration" {
  bucket = aws_s3_bucket.migration.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.migration.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "migration" {
  bucket                  = aws_s3_bucket.migration.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "migration" {
  bucket        = aws_s3_bucket.migration.id
  target_bucket = aws_s3_bucket.migration.id
  target_prefix = "s3-access/self/"
}

resource "aws_s3_bucket_lifecycle_configuration" "migration" {
  bucket = aws_s3_bucket.migration.id

  rule {
    id     = "archive-migrated-data"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 180
      storage_class = "GLACIER_IR"
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
        "dms.amazonaws.com",
        "datasync.amazonaws.com",
        "transfer.amazonaws.com",
        "lambda.amazonaws.com",
        "migrationhub-strategy.amazonaws.com",
      ]
    }
  }
}

resource "aws_iam_role" "migration" {
  name               = "migration-service-role"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

data "aws_iam_policy_document" "migration" {
  statement {
    actions   = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.migration.arn, "${aws_s3_bucket.migration.arn}/*"]
  }

  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.source_db.arn, aws_secretsmanager_secret.target_db.arn]
  }

  statement {
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.migration.arn]
  }
}

resource "aws_iam_role_policy" "migration" {
  name   = "migration-access"
  role   = aws_iam_role.migration.id
  policy = data.aws_iam_policy_document.migration.json
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
  name               = "migration-flow-logs"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume.json
}

# ------------------------------------------------------------- Observability

resource "aws_cloudwatch_log_group" "datasync" {
  name              = "/aws/datasync/fileshare-sync"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.migration.arn
}

resource "aws_cloudwatch_log_group" "flow" {
  name              = "/aws/vpc/migration/flow-logs"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.migration.arn
}

resource "aws_cloudwatch_metric_alarm" "cdc_latency" {
  alarm_name          = "dms-cdc-latency"
  namespace           = "AWS/DMS"
  metric_name         = "CDCLatencyTarget"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 300
  period              = 300
  evaluation_periods  = 3
  statistic           = "Average"
}
