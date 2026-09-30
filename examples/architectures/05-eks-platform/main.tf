# ArchLens reference architecture 05 — EKS platform
#
# A Kubernetes platform an internal team can build on: private API endpoint,
# control-plane audit logs on, envelope encryption for Secrets, IRSA instead of
# node instance roles, Bottlerocket managed nodes, and EFS for the workloads
# that insist on a filesystem. Monitoring is Managed Prometheus + Grafana so no
# one has to run the monitoring stack inside the cluster they are monitoring.
#
# Services: EKS, EKS Managed Node Groups, EKS Add-ons, Fargate profiles, ECR,
# EFS, VPC, NAT Gateway, VPC Endpoints, Network Firewall, KMS, IAM (IRSA / OIDC),
# Managed Prometheus, Managed Grafana, CloudWatch, Secrets Manager, S3, Backup.
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
variable "cluster_version" { default = "1.31" }

resource "aws_kms_key" "cluster" {
  description         = "EKS secrets envelope encryption"
  enable_key_rotation = true
}

# ------------------------------------------------------------------- Network

resource "aws_vpc" "main" {
  cidr_block           = "10.50.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}

resource "aws_subnet" "private" {
  count             = 3
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(aws_vpc.main.cidr_block, 4, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    "kubernetes.io/role/internal-elb" = "1"
  }
}

resource "aws_subnet" "public" {
  count                   = 3
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(aws_vpc.main.cidr_block, 4, count.index + 8)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = false

  tags = {
    "kubernetes.io/role/elb" = "1"
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
}

resource "aws_eip" "nat" {
  domain = "vpc"
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id
  depends_on    = [aws_internet_gateway.main]
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
}

resource "aws_route" "private_default" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.main.id
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
}

resource "aws_security_group" "cluster" {
  name        = "eks-cluster-sg"
  description = "EKS control plane"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from the VPC (private API endpoint)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.50.0.0/16"]
  }

  egress {
    description = "To nodes"
    from_port   = 1025
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["10.50.0.0/16"]
  }
}

resource "aws_security_group" "nodes" {
  name        = "eks-nodes-sg"
  description = "Managed node group"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "From the control plane"
    from_port       = 1025
    to_port         = 65535
    protocol        = "tcp"
    security_groups = [aws_security_group.cluster.id]
  }

  egress {
    description = "HTTPS to AWS APIs and image registries"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_networkfirewall_firewall" "egress" {
  name                = "eks-egress-firewall"
  vpc_id              = aws_vpc.main.id
  firewall_policy_arn = aws_networkfirewall_firewall_policy.egress.arn

  subnet_mapping {
    subnet_id = aws_subnet.public[0].id
  }

  delete_protection = true
}

resource "aws_networkfirewall_firewall_policy" "egress" {
  name = "eks-egress-policy"

  firewall_policy {
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:forward_to_sfe"]
  }
}

resource "aws_flow_log" "vpc" {
  vpc_id               = aws_vpc.main.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.flow.arn
  iam_role_arn         = aws_iam_role.flow_logs.arn
}

# ------------------------------------------------------------------- Cluster

resource "aws_eks_cluster" "main" {
  name     = "platform"
  role_arn = aws_iam_role.cluster.arn
  version  = var.cluster_version

  # Every control-plane log type — this is the only audit trail for what
  # happened inside the cluster.
  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  vpc_config {
    subnet_ids              = aws_subnet.private[*].id
    security_group_ids      = [aws_security_group.cluster.id]
    endpoint_private_access = true
    endpoint_public_access  = false
  }

  encryption_config {
    resources = ["secrets"]
    provider {
      key_arn = aws_kms_key.cluster.arn
    }
  }

  access_config {
    authentication_mode                         = "API"
    bootstrap_cluster_creator_admin_permissions = false
  }

  kubernetes_network_config {
    ip_family = "ipv4"
  }
}

resource "aws_eks_node_group" "general" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "general"
  node_role_arn   = aws_iam_role.nodes.arn
  subnet_ids      = aws_subnet.private[*].id
  ami_type        = "BOTTLEROCKET_ARM_64"
  capacity_type   = "ON_DEMAND"
  instance_types  = ["m7g.large"]
  disk_size       = 50

  scaling_config {
    desired_size = 3
    min_size     = 3
    max_size     = 20
  }

  update_config {
    max_unavailable_percentage = 25
  }
}

# Spot capacity for anything interruptible — the cheapest compute on the
# platform, and the node group is labelled so only tolerant workloads land here.
resource "aws_eks_node_group" "spot" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "spot-batch"
  node_role_arn   = aws_iam_role.nodes.arn
  subnet_ids      = aws_subnet.private[*].id
  ami_type        = "BOTTLEROCKET_ARM_64"
  capacity_type   = "SPOT"
  instance_types  = ["m7g.large", "m6g.large", "m7g.xlarge"]

  scaling_config {
    desired_size = 0
    min_size     = 0
    max_size     = 40
  }

  labels = {
    workload = "batch"
  }

  taint {
    key    = "spot"
    value  = "true"
    effect = "NO_SCHEDULE"
  }
}

resource "aws_eks_fargate_profile" "system" {
  cluster_name           = aws_eks_cluster.main.name
  fargate_profile_name   = "system"
  pod_execution_role_arn = aws_iam_role.fargate.arn
  subnet_ids             = aws_subnet.private[*].id

  selector {
    namespace = "kube-system"
    labels = {
      "app.kubernetes.io/managed-by" = "fargate"
    }
  }
}

resource "aws_eks_addon" "ebs_csi" {
  cluster_name             = aws_eks_cluster.main.name
  addon_name               = "aws-ebs-csi-driver"
  service_account_role_arn = aws_iam_role.ebs_csi.arn
  resolve_conflicts_on_update = "OVERWRITE"
}

resource "aws_eks_addon" "pod_identity" {
  cluster_name = aws_eks_cluster.main.name
  addon_name   = "eks-pod-identity-agent"
}

# ------------------------------------------------------------------- Storage

resource "aws_ecr_repository" "platform" {
  name                 = "platform"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.cluster.arn
  }
}

resource "aws_efs_file_system" "shared" {
  creation_token                  = "platform-shared"
  encrypted                       = true
  kms_key_id                      = aws_kms_key.cluster.arn
  performance_mode                = "generalPurpose"
  throughput_mode                 = "elastic"

  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS"
  }
}

resource "aws_efs_backup_policy" "shared" {
  file_system_id = aws_efs_file_system.shared.id

  backup_policy {
    status = "ENABLED"
  }
}

resource "aws_efs_mount_target" "shared" {
  count           = 3
  file_system_id  = aws_efs_file_system.shared.id
  subnet_id       = aws_subnet.private[count.index].id
  security_groups = [aws_security_group.nodes.id]
}

resource "aws_backup_vault" "platform" {
  name        = "platform-backups"
  kms_key_arn = aws_kms_key.cluster.arn
}

resource "aws_backup_plan" "platform" {
  name = "platform-daily"

  rule {
    rule_name         = "daily-35d"
    target_vault_name = aws_backup_vault.platform.name
    schedule          = "cron(0 3 * * ? *)"

    lifecycle {
      delete_after = 35
    }
  }
}

resource "aws_secretsmanager_secret" "platform" {
  name       = "platform/shared"
  kms_key_id = aws_kms_key.cluster.arn
}

# ------------------------------------------------------------------- IRSA/IAM

data "aws_iam_policy_document" "eks_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cluster" {
  name               = "eks-cluster-role"
  assume_role_policy = data.aws_iam_policy_document.eks_assume.json
}

resource "aws_iam_role_policy_attachment" "cluster" {
  role       = aws_iam_role.cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
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

resource "aws_iam_role" "nodes" {
  name               = "eks-node-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy_attachment" "nodes_worker" {
  role       = aws_iam_role.nodes.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

data "aws_iam_policy_document" "fargate_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["eks-fargate-pods.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "fargate" {
  name               = "eks-fargate-role"
  assume_role_policy = data.aws_iam_policy_document.fargate_assume.json
}

# IRSA: pods assume roles through the cluster's OIDC provider, so no workload
# needs the node instance profile.
resource "aws_iam_openid_connect_provider" "cluster" {
  url             = aws_eks_cluster.main.identity[0].oidc[0].issuer
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["9e99a48a9960b14926bb7f3b02e22da2b0ab7280"]
}

data "aws_iam_policy_document" "irsa_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.cluster.arn]
    }
  }
}

resource "aws_iam_role" "ebs_csi" {
  name               = "eks-ebs-csi-irsa"
  assume_role_policy = data.aws_iam_policy_document.irsa_assume.json
}

resource "aws_iam_role" "app_workload" {
  name               = "eks-app-workload-irsa"
  assume_role_policy = data.aws_iam_policy_document.irsa_assume.json
}

data "aws_iam_policy_document" "app_workload" {
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.platform.arn]
  }
}

resource "aws_iam_role_policy" "app_workload" {
  name   = "app-workload-secrets"
  role   = aws_iam_role.app_workload.id
  policy = data.aws_iam_policy_document.app_workload.json
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
  name               = "eks-flow-logs"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume.json
}

# ------------------------------------------------------------- Observability

resource "aws_prometheus_workspace" "platform" {
  alias       = "platform"
  kms_key_arn = aws_kms_key.cluster.arn

  logging_configuration {
    log_group_arn = "${aws_cloudwatch_log_group.prometheus.arn}:*"
  }
}

resource "aws_grafana_workspace" "platform" {
  name                     = "platform"
  account_access_type      = "CURRENT_ACCOUNT"
  authentication_providers = ["AWS_SSO"]
  permission_type          = "SERVICE_MANAGED"
  data_sources             = ["PROMETHEUS", "CLOUDWATCH"]
  role_arn                 = aws_iam_role.grafana.arn
}

data "aws_iam_policy_document" "grafana_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["grafana.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "grafana" {
  name               = "platform-grafana"
  assume_role_policy = data.aws_iam_policy_document.grafana_assume.json
}

resource "aws_cloudwatch_log_group" "prometheus" {
  name              = "/aws/prometheus/platform"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.cluster.arn
}

resource "aws_cloudwatch_log_group" "flow" {
  name              = "/aws/vpc/platform/flow-logs"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.cluster.arn
}

resource "aws_cloudwatch_metric_alarm" "node_not_ready" {
  alarm_name          = "platform-nodes-not-ready"
  namespace           = "ContainerInsights"
  metric_name         = "cluster_node_running_count"
  comparison_operator = "LessThanThreshold"
  threshold           = 3
  period              = 300
  evaluation_periods  = 2
  statistic           = "Minimum"
}
