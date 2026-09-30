# ArchLens reference architecture 13 — CI/CD and developer platform
#
# Build once, promote the same artefact. CodePipeline moves a commit through
# build, scan, staging and a manual-approval gate to production; CodeBuild runs
# inside the VPC so it can reach private dependencies; images are signed and
# scanned before they are deployable. Fault Injection Service exercises the
# rollback path on a schedule, because an untested rollback is not a rollback.
#
# Services: CodePipeline, CodeBuild, CodeDeploy, CodeArtifact, CodeGuru, ECR,
# Signer, Fault Injection Service, S3, KMS, EventBridge, SNS, CloudWatch, IAM.
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

variable "region" { default = "us-east-2" }
variable "github_connection_arn" {
  description = "CodeStar Connections ARN for the source repository"
  default     = "arn:aws:codeconnections:us-east-2:123456789012:connection/EXAMPLE"
}

resource "aws_kms_key" "cicd" {
  description         = "Pipeline artefacts and build logs"
  enable_key_rotation = true
}

# ------------------------------------------------------------------- Network
# Builds run in private subnets so a compromised build cannot be reached from
# the internet, and can only reach what the security group allows.

resource "aws_vpc" "main" {
  cidr_block           = "10.110.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index)
  availability_zone = "${var.region}${count.index == 0 ? "a" : "b"}"
}

resource "aws_security_group" "build" {
  name        = "codebuild-sg"
  description = "CodeBuild projects"
  vpc_id      = aws_vpc.main.id

  egress {
    description = "HTTPS to AWS endpoints and the artifact repository"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.110.0.0/16"]
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

# ------------------------------------------------------------------- Artefacts

resource "aws_s3_bucket" "artifacts" {
  bucket = "pipeline-artifacts-example"
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.cicd.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "artifacts" {
  bucket        = aws_s3_bucket.artifacts.id
  target_bucket = aws_s3_bucket.artifacts.id
  target_prefix = "s3-access/self/"
}

resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    id     = "expire-old-builds"
    status = "Enabled"

    expiration {
      days = 90
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

resource "aws_codeartifact_domain" "packages" {
  domain         = "example"
  encryption_key = aws_kms_key.cicd.arn
}

resource "aws_codeartifact_repository" "internal" {
  repository = "internal"
  domain     = aws_codeartifact_domain.packages.domain

  # Upstream to a public repo through CodeArtifact so dependencies are cached
  # and auditable rather than pulled from the internet at build time.
  external_connections {
    external_connection_name = "public:pypi"
  }
}

resource "aws_ecr_repository" "app" {
  name                 = "app"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.cicd.arn
  }
}

resource "aws_signer_signing_profile" "lambda" {
  name_prefix = "app"
  platform_id = "AWSLambda-SHA384-ECDSA"

  signature_validity_period {
    value = 12
    type  = "MONTHS"
  }
}

# ---------------------------------------------------------------------- Build

resource "aws_codebuild_project" "build" {
  name           = "app-build"
  service_role   = aws_iam_role.codebuild.arn
  encryption_key = aws_kms_key.cicd.arn
  build_timeout  = 30

  artifacts {
    type = "CODEPIPELINE"
  }

  environment {
    type                        = "ARM_CONTAINER"
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/amazonlinux2-aarch64-standard:3.0"
    image_pull_credentials_type = "CODEBUILD"
    privileged_mode             = false
  }

  source {
    type = "CODEPIPELINE"
  }

  vpc_config {
    vpc_id             = aws_vpc.main.id
    subnets            = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.build.id]
  }

  logs_config {
    cloudwatch_logs {
      group_name = aws_cloudwatch_log_group.build.name
      status     = "ENABLED"
    }

    s3_logs {
      status              = "ENABLED"
      location            = "${aws_s3_bucket.artifacts.id}/build-logs"
      encryption_disabled = false
    }
  }
}

resource "aws_codebuild_project" "scan" {
  name           = "app-scan"
  service_role   = aws_iam_role.codebuild.arn
  encryption_key = aws_kms_key.cicd.arn
  build_timeout  = 20

  artifacts {
    type = "CODEPIPELINE"
  }

  environment {
    type                        = "ARM_CONTAINER"
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/amazonlinux2-aarch64-standard:3.0"
    image_pull_credentials_type = "CODEBUILD"
    privileged_mode             = false
  }

  source {
    type      = "CODEPIPELINE"
    buildspec = "ci/scan.buildspec.yml"
  }

  vpc_config {
    vpc_id             = aws_vpc.main.id
    subnets            = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.build.id]
  }

  logs_config {
    cloudwatch_logs {
      group_name = aws_cloudwatch_log_group.build.name
      status     = "ENABLED"
    }
  }
}

resource "aws_codeguru_reviewer_repository_association" "app" {
  name          = "app"
  provider_type = "GitHubEnterpriseServer"

  kms_key_details {
    encryption_option = "CUSTOMER_MANAGED_CMK"
    kms_key_id        = aws_kms_key.cicd.key_id
  }
}

# --------------------------------------------------------------------- Deploy

resource "aws_codedeploy_app" "app" {
  name             = "app"
  compute_platform = "ECS"
}

resource "aws_codedeploy_deployment_group" "prod" {
  app_name               = aws_codedeploy_app.app.name
  deployment_group_name  = "prod"
  service_role_arn       = aws_iam_role.codedeploy.arn
  deployment_config_name = "CodeDeployDefault.ECSCanary10Percent5Minutes"

  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE", "DEPLOYMENT_STOP_ON_ALARM"]
  }

  alarm_configuration {
    enabled = true
    alarms  = [aws_cloudwatch_metric_alarm.error_rate.alarm_name]
  }

  blue_green_deployment_config {
    terminate_blue_instances_on_deployment_success {
      action                           = "TERMINATE"
      termination_wait_time_in_minutes = 10
    }
  }
}

resource "aws_codepipeline" "app" {
  name          = "app-pipeline"
  role_arn      = aws_iam_role.codepipeline.arn
  pipeline_type = "V2"

  artifact_store {
    type     = "S3"
    location = aws_s3_bucket.artifacts.id

    encryption_key {
      id   = aws_kms_key.cicd.arn
      type = "KMS"
    }
  }

  stage {
    name = "Source"

    action {
      name             = "Source"
      category         = "Source"
      owner            = "AWS"
      provider         = "CodeStarSourceConnection"
      version          = "1"
      output_artifacts = ["source"]

      configuration = {
        ConnectionArn    = var.github_connection_arn
        FullRepositoryId = "example/app"
        BranchName       = "main"
      }
    }
  }

  stage {
    name = "Build"

    action {
      name             = "Build"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      version          = "1"
      input_artifacts  = ["source"]
      output_artifacts = ["build"]

      configuration = {
        ProjectName = aws_codebuild_project.build.name
      }
    }
  }

  stage {
    name = "Scan"

    action {
      name            = "SecurityScan"
      category        = "Test"
      owner           = "AWS"
      provider        = "CodeBuild"
      version         = "1"
      input_artifacts = ["build"]

      configuration = {
        ProjectName = aws_codebuild_project.scan.name
      }
    }
  }

  # Production needs a human. Everything before it does not.
  stage {
    name = "ApproveProd"

    action {
      name     = "Approve"
      category = "Approval"
      owner    = "AWS"
      provider = "Manual"
      version  = "1"

      configuration = {
        NotificationArn = aws_sns_topic.pipeline.arn
        CustomData      = "Review the scan report before approving."
      }
    }
  }

  stage {
    name = "DeployProd"

    action {
      name            = "Deploy"
      category        = "Deploy"
      owner           = "AWS"
      provider        = "CodeDeployToECS"
      version         = "1"
      input_artifacts = ["build"]

      configuration = {
        ApplicationName     = aws_codedeploy_app.app.name
        DeploymentGroupName = aws_codedeploy_deployment_group.prod.deployment_group_name
      }
    }
  }
}

# ------------------------------------------------------------- Resilience test

resource "aws_fis_experiment_template" "task_kill" {
  description = "Terminate a third of the tasks and confirm the canary holds"
  role_arn    = aws_iam_role.fis.arn

  stop_condition {
    source = "aws:cloudwatch:alarm"
    value  = aws_cloudwatch_metric_alarm.error_rate.arn
  }

  action {
    name      = "stop-tasks"
    action_id = "aws:ecs:stop-task"

    target {
      key   = "Tasks"
      value = "app-tasks"
    }
  }

  target {
    name           = "app-tasks"
    resource_type  = "aws:ecs:task"
    selection_mode = "PERCENT(33)"

    resource_tag {
      key   = "app"
      value = "app"
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
        "codebuild.amazonaws.com",
        "codepipeline.amazonaws.com",
        "codedeploy.amazonaws.com",
        "fis.amazonaws.com",
      ]
    }
  }
}

resource "aws_iam_role" "codebuild" {
  name               = "codebuild-role"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

data "aws_iam_policy_document" "codebuild" {
  statement {
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${aws_s3_bucket.artifacts.arn}/*"]
  }

  statement {
    actions   = ["ecr:BatchGetImage", "ecr:PutImage", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload"]
    resources = [aws_ecr_repository.app.arn]
  }

  statement {
    actions   = ["codeartifact:GetAuthorizationToken", "codeartifact:ReadFromRepository"]
    resources = [aws_codeartifact_repository.internal.arn]
  }

  statement {
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.cicd.arn]
  }
}

resource "aws_iam_role_policy" "codebuild" {
  name   = "codebuild-access"
  role   = aws_iam_role.codebuild.id
  policy = data.aws_iam_policy_document.codebuild.json
}

resource "aws_iam_role" "codepipeline" {
  name               = "codepipeline-role"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

resource "aws_iam_role" "codedeploy" {
  name               = "codedeploy-role"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

resource "aws_iam_role" "fis" {
  name               = "fis-role"
  assume_role_policy = data.aws_iam_policy_document.service_assume.json
}

# ------------------------------------------------------------- Observability

resource "aws_cloudwatch_log_group" "build" {
  name              = "/aws/codebuild/app"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.cicd.arn
}

resource "aws_sns_topic" "pipeline" {
  name              = "pipeline-notifications"
  kms_master_key_id = aws_kms_key.cicd.arn
}

resource "aws_cloudwatch_event_rule" "pipeline_failed" {
  name        = "pipeline-failed"
  description = "Notify on any failed pipeline execution"

  event_pattern = jsonencode({
    source      = ["aws.codepipeline"]
    detail-type = ["CodePipeline Pipeline Execution State Change"]
    detail      = { state = ["FAILED"] }
  })
}

resource "aws_cloudwatch_event_target" "pipeline_failed" {
  rule      = aws_cloudwatch_event_rule.pipeline_failed.name
  target_id = "notify"
  arn       = aws_sns_topic.pipeline.arn
}

resource "aws_cloudwatch_metric_alarm" "error_rate" {
  alarm_name          = "app-error-rate"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "HTTPCode_Target_5XX_Count"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 20
  period              = 60
  evaluation_periods  = 2
  statistic           = "Sum"
  alarm_actions       = [aws_sns_topic.pipeline.arn]
}
