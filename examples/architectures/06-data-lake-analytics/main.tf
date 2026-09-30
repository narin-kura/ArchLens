# ArchLens reference architecture 06 — Data lake and analytics
#
# Medallion layout (raw → curated → published) on S3, catalogued by Glue,
# governed by Lake Formation, and queried by Athena and Redshift Serverless.
# Orchestration is Step Functions plus MWAA for the DAGs the data team owns.
# Lifecycle rules move cold partitions to cheaper storage classes, which is
# where most of the money in a lake is won or lost.
#
# Services: S3, S3 Glacier (lifecycle), Glue (crawler, catalog, job), Glue
# DataBrew, Lake Formation, Athena, EMR Serverless, Redshift Serverless,
# QuickSight, Data Firehose, MWAA, Step Functions, Lambda, KMS, IAM,
# CloudWatch, DataZone.
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

resource "aws_kms_key" "lake" {
  description         = "Data lake at rest"
  enable_key_rotation = true
}

# ------------------------------------------------------------------- Network

resource "aws_vpc" "main" {
  cidr_block           = "10.60.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index)
  availability_zone = "${var.region}${count.index == 0 ? "a" : "b"}"
}

resource "aws_security_group" "analytics" {
  name        = "analytics-sg"
  description = "Glue, EMR and Redshift Serverless network interfaces"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Self-referencing for distributed jobs"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["10.60.0.0/16"]
  }

  egress {
    description = "HTTPS to AWS APIs inside the VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.60.0.0/16"]
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

# ------------------------------------------------------------- Lake storage

locals {
  layers = ["raw", "curated", "published"]
}

resource "aws_s3_bucket" "layer" {
  count  = 3
  bucket = "example-lake-${local.layers[count.index]}"
}

resource "aws_s3_bucket_versioning" "layer" {
  count  = 3
  bucket = aws_s3_bucket.layer[count.index].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "layer" {
  count  = 3
  bucket = aws_s3_bucket.layer[count.index].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.lake.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "layer" {
  count                   = 3
  bucket                  = aws_s3_bucket.layer[count.index].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "layer" {
  count         = 3
  bucket        = aws_s3_bucket.layer[count.index].id
  target_bucket = aws_s3_bucket.audit.id
  target_prefix = "s3-access/${local.layers[count.index]}/"
}

# Raw data is read once by the ETL job and then rarely touched — tier it fast.
resource "aws_s3_bucket_lifecycle_configuration" "layer" {
  count  = 3
  bucket = aws_s3_bucket.layer[count.index].id

  rule {
    id     = "tier-cold-partitions"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "INTELLIGENT_TIERING"
    }

    transition {
      days          = 180
      storage_class = "GLACIER_IR"
    }

    transition {
      days          = 730
      storage_class = "DEEP_ARCHIVE"
    }

    noncurrent_version_expiration {
      noncurrent_days = 60
    }
  }
}

resource "aws_s3_bucket" "audit" {
  bucket = "example-lake-audit"
}

resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "audit" {
  bucket                  = aws_s3_bucket.audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "audit" {
  bucket        = aws_s3_bucket.audit.id
  target_bucket = aws_s3_bucket.audit.id
  target_prefix = "s3-access/self/"
}

resource "aws_s3_bucket_lifecycle_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id

  rule {
    id     = "retain-2y"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "GLACIER_IR"
    }

    expiration {
      days = 730
    }
  }
}

# --------------------------------------------------------- Catalog & governance

resource "aws_glue_catalog_database" "lake" {
  name        = "lake"
  description = "Curated tables exposed to analysts"
}

resource "aws_glue_security_configuration" "lake" {
  name = "lake-encryption"

  encryption_configuration {
    cloudwatch_encryption {
      cloudwatch_encryption_mode = "SSE-KMS"
      kms_key_arn                = aws_kms_key.lake.arn
    }

    job_bookmarks_encryption {
      job_bookmarks_encryption_mode = "CSE-KMS"
      kms_key_arn                   = aws_kms_key.lake.arn
    }

    s3_encryption {
      s3_encryption_mode = "SSE-KMS"
      kms_key_arn        = aws_kms_key.lake.arn
    }
  }
}

resource "aws_glue_crawler" "raw" {
  name                  = "raw-crawler"
  role                  = aws_iam_role.glue.arn
  database_name         = aws_glue_catalog_database.lake.name
  security_configuration = aws_glue_security_configuration.lake.name
  schedule              = "cron(0 * * * ? *)"

  s3_target {
    path = "s3://${aws_s3_bucket.layer[0].id}/events/"
  }

  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.analytics.id]
  }
}

resource "aws_glue_job" "curate" {
  name                   = "raw-to-curated"
  role_arn               = aws_iam_role.glue.arn
  glue_version           = "4.0"
  worker_type            = "G.1X"
  number_of_workers      = 4
  timeout                = 60
  security_configuration = aws_glue_security_configuration.lake.name

  command {
    script_location = "s3://${aws_s3_bucket.layer[1].id}/scripts/curate.py"
    python_version  = "3"
  }

  execution_property {
    max_concurrent_runs = 2
  }
}

resource "aws_lakeformation_permissions" "analysts" {
  principal   = aws_iam_role.analyst.arn
  permissions = ["SELECT", "DESCRIBE"]

  table {
    database_name = aws_glue_catalog_database.lake.name
    wildcard      = true
  }
}

resource "aws_datazone_domain" "lake" {
  name                  = "example-lake"
  domain_execution_role = aws_iam_role.datazone.arn
  kms_key_identifier    = aws_kms_key.lake.arn
}

# ------------------------------------------------------------------- Ingestion

resource "aws_kinesis_firehose_delivery_stream" "events" {
  name        = "events-to-raw"
  destination = "extended_s3"

  server_side_encryption {
    enabled  = true
    key_type = "CUSTOMER_MANAGED_CMK"
    key_arn  = aws_kms_key.lake.arn
  }

  extended_s3_configuration {
    role_arn            = aws_iam_role.firehose.arn
    bucket_arn          = aws_s3_bucket.layer[0].arn
    prefix              = "events/dt=!{timestamp:yyyy-MM-dd}/"
    error_output_prefix = "errors/"
    compression_format  = "GZIP"
    buffering_size      = 128
    buffering_interval  = 300
    kms_key_arn         = aws_kms_key.lake.arn
  }
}

# --------------------------------------------------------------------- Query

resource "aws_athena_workgroup" "analysts" {
  name = "analysts"

  configuration {
    enforce_workgroup_configuration = true
    # A scan limit is the only hard stop on a runaway query bill.
    bytes_scanned_cutoff_per_query  = 10737418240
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = "s3://${aws_s3_bucket.layer[2].id}/athena-results/"

      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = aws_kms_key.lake.arn
      }
    }
  }
}

resource "aws_emrserverless_application" "spark" {
  name          = "lake-spark"
  release_label = "emr-7.2.0"
  type          = "spark"

  auto_start_configuration {
    enabled = true
  }

  # Idle shutdown is what makes serverless EMR cheaper than a cluster.
  auto_stop_configuration {
    enabled              = true
    idle_timeout_minutes = 5
  }

  maximum_capacity {
    cpu    = "200 vCPU"
    memory = "1000 GB"
  }

  network_configuration {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.analytics.id]
  }
}

resource "aws_redshiftserverless_namespace" "warehouse" {
  namespace_name      = "warehouse"
  admin_username      = "admin"
  kms_key_id          = aws_kms_key.lake.arn
  iam_roles           = [aws_iam_role.redshift.arn]
  log_exports         = ["userlog", "connectionlog", "useractivitylog"]
  manage_admin_password = true
}

resource "aws_redshiftserverless_workgroup" "warehouse" {
  namespace_name       = aws_redshiftserverless_namespace.warehouse.namespace_name
  workgroup_name       = "warehouse"
  base_capacity        = 32
  publicly_accessible  = false
  subnet_ids           = aws_subnet.private[*].id
  security_group_ids   = [aws_security_group.analytics.id]
  enhanced_vpc_routing = true

  config_parameter {
    parameter_key   = "require_ssl"
    parameter_value = "true"
  }
}

resource "aws_quicksight_data_source" "athena" {
  data_source_id = "athena-lake"
  name           = "Lake (Athena)"
  type           = "ATHENA"

  parameters {
    athena {
      work_group = aws_athena_workgroup.analysts.name
    }
  }

  ssl_properties {
    disable_ssl = false
  }
}

# --------------------------------------------------------------- Orchestration

resource "aws_mwaa_environment" "dags" {
  name               = "lake-dags"
  airflow_version    = "2.10.1"
  environment_class  = "mw1.small"
  dag_s3_path        = "dags/"
  source_bucket_arn  = aws_s3_bucket.layer[1].arn
  execution_role_arn = aws_iam_role.mwaa.arn
  kms_key            = aws_kms_key.lake.arn
  webserver_access_mode = "PRIVATE_ONLY"

  min_workers = 1
  max_workers = 5

  network_configuration {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.analytics.id]
  }

  logging_configuration {
    task_logs {
      enabled   = true
      log_level = "INFO"
    }

    scheduler_logs {
      enabled   = true
      log_level = "WARNING"
    }
  }
}

resource "aws_sfn_state_machine" "nightly" {
  name     = "nightly-curation"
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
    StartAt = "Crawl"
    States  = { Crawl = { Type = "Task", Resource = "arn:aws:states:::glue:startCrawler", End = true } }
  })
}

# ------------------------------------------------------------------------ IAM

data "aws_iam_policy_document" "glue_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["glue.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "glue" {
  name               = "lake-glue-role"
  assume_role_policy = data.aws_iam_policy_document.glue_assume.json
}

data "aws_iam_policy_document" "glue_access" {
  statement {
    actions = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
    resources = [
      aws_s3_bucket.layer[0].arn,
      "${aws_s3_bucket.layer[0].arn}/*",
      aws_s3_bucket.layer[1].arn,
      "${aws_s3_bucket.layer[1].arn}/*",
    ]
  }

  statement {
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.lake.arn]
  }
}

resource "aws_iam_role_policy" "glue_access" {
  name   = "glue-lake-access"
  role   = aws_iam_role.glue.id
  policy = data.aws_iam_policy_document.glue_access.json
}

data "aws_iam_policy_document" "firehose_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["firehose.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "firehose" {
  name               = "lake-firehose-role"
  assume_role_policy = data.aws_iam_policy_document.firehose_assume.json
}

data "aws_iam_policy_document" "service_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type = "Service"
      identifiers = [
        "redshift.amazonaws.com",
        "airflow.amazonaws.com",
        "states.amazonaws.com",
        "datazone.amazonaws.com",
      ]
    }
  }
}

resource "aws_iam_role" "redshift" {
  name               = "lake-redshift-role"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

resource "aws_iam_role" "mwaa" {
  name               = "lake-mwaa-role"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

resource "aws_iam_role" "step_functions" {
  name               = "lake-stepfunctions-role"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

resource "aws_iam_role" "datazone" {
  name               = "lake-datazone-role"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

data "aws_iam_policy_document" "analyst_assume" {
  statement {
    actions = ["sts:AssumeRoleWithSAML"]
    principals {
      type        = "Federated"
      identifiers = ["arn:aws:iam::123456789012:saml-provider/IdentityCenter"]
    }
  }
}

resource "aws_iam_role" "analyst" {
  name                 = "lake-analyst"
  assume_role_policy   = data.aws_iam_policy_document.analyst_assume.json
  max_session_duration = 3600
}

# ------------------------------------------------------------- Observability

resource "aws_cloudwatch_log_group" "state_machine" {
  name              = "/aws/states/nightly-curation"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.lake.arn
}

resource "aws_cloudwatch_log_group" "glue" {
  name              = "/aws-glue/jobs/raw-to-curated"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.lake.arn
}

resource "aws_cloudwatch_metric_alarm" "glue_failures" {
  alarm_name          = "glue-job-failures"
  namespace           = "Glue"
  metric_name         = "glue.driver.aggregate.numFailedTasks"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  period              = 300
  evaluation_periods  = 1
  statistic           = "Sum"
}

resource "aws_budgets_budget" "analytics" {
  name         = "analytics-monthly"
  budget_type  = "COST"
  limit_amount = "4000"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_filter {
    name   = "Service"
    values = ["Amazon Athena", "Amazon Redshift", "AWS Glue"]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 85
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = ["data-platform@example.com"]
  }
}
