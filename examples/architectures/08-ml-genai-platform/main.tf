# ArchLens reference architecture 08 — ML training and GenAI (RAG) platform
#
# Two halves that share one data plane. The ML half trains and serves custom
# models on SageMaker; the GenAI half answers questions over the same documents
# using Bedrock with a knowledge base backed by OpenSearch Serverless vectors,
# behind a guardrail. Both run network-isolated with no direct internet path.
#
# Services: SageMaker AI (domain, training, endpoint, Feature Store, Model
# Registry), Bedrock (knowledge base, agent, guardrail), OpenSearch Serverless,
# Textract, Comprehend, Step Functions, Lambda, S3, ECR, KMS, VPC, VPC
# Endpoints, CloudWatch, IAM.
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

resource "aws_kms_key" "ml" {
  description         = "ML and GenAI platform at rest"
  enable_key_rotation = true
}

# ------------------------------------------------------------------- Network

resource "aws_vpc" "main" {
  cidr_block           = "10.80.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index)
  availability_zone = "${var.region}${count.index == 0 ? "a" : "b"}"
}

resource "aws_security_group" "ml" {
  name        = "ml-sg"
  description = "SageMaker training jobs, endpoints and notebooks"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Intra-VPC only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.80.0.0/16"]
  }

  egress {
    description = "HTTPS to AWS endpoints inside the VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.80.0.0/16"]
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

resource "aws_vpc_endpoint" "bedrock" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.region}.bedrock-runtime"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.ml.id]
  private_dns_enabled = true
}

# ------------------------------------------------------------------- Data

resource "aws_s3_bucket" "datasets" {
  bucket = "ml-platform-datasets"
}

resource "aws_s3_bucket_versioning" "datasets" {
  bucket = aws_s3_bucket.datasets.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "datasets" {
  bucket = aws_s3_bucket.datasets.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.ml.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "datasets" {
  bucket                  = aws_s3_bucket.datasets.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "datasets" {
  bucket        = aws_s3_bucket.datasets.id
  target_bucket = aws_s3_bucket.datasets.id
  target_prefix = "s3-access/self/"
}

resource "aws_s3_bucket_lifecycle_configuration" "datasets" {
  bucket = aws_s3_bucket.datasets.id

  rule {
    id     = "archive-old-training-data"
    status = "Enabled"

    transition {
      days          = 60
      storage_class = "INTELLIGENT_TIERING"
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

resource "aws_ecr_repository" "training" {
  name                 = "ml-training"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.ml.arn
  }
}

# --------------------------------------------------------------- SageMaker

resource "aws_sagemaker_domain" "studio" {
  domain_name = "ml-platform"
  auth_mode   = "IAM"
  vpc_id      = aws_vpc.main.id
  subnet_ids  = aws_subnet.private[*].id
  kms_key_id  = aws_kms_key.ml.arn

  # VpcOnly keeps notebook traffic off the public internet.
  app_network_access_type = "VpcOnly"

  default_user_settings {
    execution_role  = aws_iam_role.sagemaker.arn
    security_groups = [aws_security_group.ml.id]

    jupyter_server_app_settings {
      default_resource_spec {
        instance_type = "system"
      }
    }
  }
}

resource "aws_sagemaker_model" "classifier" {
  name                     = "doc-classifier"
  execution_role_arn       = aws_iam_role.sagemaker.arn
  enable_network_isolation = true

  primary_container {
    image = "${aws_ecr_repository.training.repository_url}:2.1.0"
  }

  vpc_config {
    subnets            = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.ml.id]
  }
}

resource "aws_sagemaker_endpoint_configuration" "classifier" {
  name        = "doc-classifier-config"
  kms_key_arn = aws_kms_key.ml.arn

  production_variants {
    variant_name           = "primary"
    model_name             = aws_sagemaker_model.classifier.name
    initial_instance_count = 2
    instance_type          = "ml.m6g.large"
    initial_variant_weight = 1
  }

  data_capture_config {
    enable_capture              = true
    initial_sampling_percentage = 10
    destination_s3_uri          = "s3://${aws_s3_bucket.datasets.id}/capture/"
    kms_key_id                  = aws_kms_key.ml.arn

    capture_options {
      capture_mode = "Input"
    }
  }
}

resource "aws_sagemaker_endpoint" "classifier" {
  name                 = "doc-classifier"
  endpoint_config_name = aws_sagemaker_endpoint_configuration.classifier.name
}

resource "aws_sagemaker_feature_group" "documents" {
  feature_group_name             = "document-features"
  record_identifier_feature_name = "document_id"
  event_time_feature_name        = "ingested_at"
  role_arn                       = aws_iam_role.sagemaker.arn

  feature_definition {
    feature_name = "document_id"
    feature_type = "String"
  }

  feature_definition {
    feature_name = "ingested_at"
    feature_type = "String"
  }

  online_store_config {
    enable_online_store = true

    security_config {
      kms_key_id = aws_kms_key.ml.arn
    }
  }
}

resource "aws_sagemaker_model_package_group" "registry" {
  model_package_group_name        = "doc-classifier-models"
  model_package_group_description = "Approved classifier versions"
}

# ----------------------------------------------------------------- GenAI

resource "aws_opensearchserverless_security_policy" "vectors" {
  name = "vector-encryption"
  type = "encryption"

  policy = jsonencode({
    Rules      = [{ ResourceType = "collection", Resource = ["collection/knowledge"] }]
    AWSOwnedKey = false
    KmsARN     = aws_kms_key.ml.arn
  })
}

resource "aws_opensearchserverless_collection" "knowledge" {
  name             = "knowledge"
  type             = "VECTORSEARCH"
  standby_replicas = "ENABLED"
  depends_on       = [aws_opensearchserverless_security_policy.vectors]
}

resource "aws_bedrockagent_knowledge_base" "docs" {
  name     = "product-docs"
  role_arn = aws_iam_role.bedrock.arn

  knowledge_base_configuration {
    type = "VECTOR"

    vector_knowledge_base_configuration {
      embedding_model_arn = "arn:aws:bedrock:${var.region}::foundation-model/amazon.titan-embed-text-v2:0"
    }
  }

  storage_configuration {
    type = "OPENSEARCH_SERVERLESS"

    opensearch_serverless_configuration {
      collection_arn    = aws_opensearchserverless_collection.knowledge.arn
      vector_index_name = "docs-index"

      field_mapping {
        vector_field   = "embedding"
        text_field     = "chunk"
        metadata_field = "metadata"
      }
    }
  }
}

resource "aws_bedrockagent_data_source" "docs" {
  knowledge_base_id = aws_bedrockagent_knowledge_base.docs.id
  name              = "s3-docs"

  data_source_configuration {
    type = "S3"

    s3_configuration {
      bucket_arn = aws_s3_bucket.datasets.arn
    }
  }
}

# A guardrail is the only server-side control on what the model will discuss or
# repeat back — it applies even if the calling application is compromised.
resource "aws_bedrock_guardrail" "support" {
  name                      = "support-guardrail"
  blocked_input_messaging   = "That request cannot be processed."
  blocked_outputs_messaging = "That response was withheld."
  kms_key_arn               = aws_kms_key.ml.arn

  content_policy_config {
    filters_config {
      type            = "PROMPT_ATTACK"
      input_strength  = "HIGH"
      output_strength = "NONE"
    }

    filters_config {
      type            = "HATE"
      input_strength  = "HIGH"
      output_strength = "HIGH"
    }
  }

  sensitive_information_policy_config {
    pii_entities_config {
      type   = "EMAIL"
      action = "ANONYMIZE"
    }

    pii_entities_config {
      type   = "CREDIT_DEBIT_CARD_NUMBER"
      action = "BLOCK"
    }
  }
}

resource "aws_bedrockagent_agent" "support" {
  agent_name                  = "support-agent"
  agent_resource_role_arn     = aws_iam_role.bedrock.arn
  foundation_model            = "anthropic.claude-sonnet-4-5-20250929-v1:0"
  idle_session_ttl_in_seconds = 600

  guardrail_configuration {
    guardrail_identifier = aws_bedrock_guardrail.support.guardrail_id
    guardrail_version    = "DRAFT"
  }
}

# --------------------------------------------------------------- Ingestion

resource "aws_lambda_function" "extract" {
  function_name = "doc-extract"
  role          = aws_iam_role.lambda.arn
  handler       = "extract.handler"
  runtime       = "python3.12"
  timeout       = 120
  memory_size   = 2048
  kms_key_arn   = aws_kms_key.ml.arn

  reserved_concurrent_executions = 25

  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.ml.id]
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  tracing_config {
    mode = "Active"
  }
}

resource "aws_sqs_queue" "dlq" {
  name                      = "doc-extract-dlq"
  kms_master_key_id         = aws_kms_key.ml.arn
  message_retention_seconds = 1209600
  redrive_policy            = "terminal-queue"
}

resource "aws_sfn_state_machine" "ingest" {
  name     = "doc-ingest"
  role_arn = aws_iam_role.step_functions.arn
  type     = "STANDARD"

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.ingest.arn}:*"
    include_execution_data = false
    level                  = "ERROR"
  }

  tracing_configuration {
    enabled = true
  }

  definition = jsonencode({
    StartAt = "Textract"
    States = {
      Textract = { Type = "Task", Resource = aws_lambda_function.extract.arn, End = true }
    }
  })
}

# ------------------------------------------------------------------------ IAM

data "aws_iam_policy_document" "service_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type = "Service"
      identifiers = [
        "sagemaker.amazonaws.com",
        "bedrock.amazonaws.com",
        "lambda.amazonaws.com",
        "states.amazonaws.com",
      ]
    }
  }
}

resource "aws_iam_role" "sagemaker" {
  name               = "ml-sagemaker-role"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

data "aws_iam_policy_document" "sagemaker_access" {
  statement {
    actions   = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.datasets.arn, "${aws_s3_bucket.datasets.arn}/*"]
  }

  statement {
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.ml.arn]
  }

  statement {
    actions   = ["ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage", "ecr:GetAuthorizationToken"]
    resources = [aws_ecr_repository.training.arn]
  }
}

resource "aws_iam_role_policy" "sagemaker_access" {
  name   = "sagemaker-data-access"
  role   = aws_iam_role.sagemaker.id
  policy = data.aws_iam_policy_document.sagemaker_access.json
}

resource "aws_iam_role" "bedrock" {
  name               = "ml-bedrock-role"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

data "aws_iam_policy_document" "bedrock_access" {
  statement {
    actions   = ["bedrock:InvokeModel"]
    resources = ["arn:aws:bedrock:${var.region}::foundation-model/*"]
  }

  statement {
    actions   = ["aoss:APIAccessAll"]
    resources = [aws_opensearchserverless_collection.knowledge.arn]
  }

  statement {
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.datasets.arn, "${aws_s3_bucket.datasets.arn}/*"]
  }
}

resource "aws_iam_role_policy" "bedrock_access" {
  name   = "bedrock-kb-access"
  role   = aws_iam_role.bedrock.id
  policy = data.aws_iam_policy_document.bedrock_access.json
}

resource "aws_iam_role" "lambda" {
  name               = "ml-extract-role"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

resource "aws_iam_role" "step_functions" {
  name               = "ml-ingest-role"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

# ------------------------------------------------------------- Observability

resource "aws_cloudwatch_log_group" "ingest" {
  name              = "/aws/states/doc-ingest"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.ml.arn
}

resource "aws_cloudwatch_log_group" "endpoint" {
  name              = "/aws/sagemaker/Endpoints/doc-classifier"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.ml.arn
}

resource "aws_cloudwatch_metric_alarm" "endpoint_errors" {
  alarm_name          = "doc-classifier-4xx"
  namespace           = "AWS/SageMaker"
  metric_name         = "Invocation4XXErrors"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 10
  period              = 300
  evaluation_periods  = 2
  statistic           = "Sum"
}

# GenAI spend is dominated by tokens, and token spend has no natural ceiling.
resource "aws_budgets_budget" "bedrock" {
  name         = "bedrock-monthly"
  budget_type  = "COST"
  limit_amount = "2500"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_filter {
    name   = "Service"
    values = ["Amazon Bedrock"]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 75
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = ["ml-platform@example.com"]
  }
}
