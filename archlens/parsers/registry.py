"""Auto-detect the right parser from source type."""

from __future__ import annotations
from pathlib import Path

from .base import BaseParser
from .terraform import TerraformParser
from .text import TextParser
from .drawio import DrawioParser
from .cloudformation import CloudFormationParser
from .aws_config import AWSConfigParser
from .gcp_asset import GCPAssetParser
from .kubernetes import KubernetesParser
from .docker_compose import DockerComposeParser
from .dockerfile import DockerfileParser
from .azure_arm import AzureARMParser
from .helm import HelmParser
from .serverless_framework import ServerlessFrameworkParser
from .openapi import OpenAPIParser
from .github_actions import GitHubActionsParser
from .jenkins import JenkinsParser
from .azure_pipelines import AzurePipelinesParser
from .ansible import AnsibleParser


# Order matters: most specific detectors first, text (LLM) last as fallback
_PARSERS: list[BaseParser] = [
    TerraformParser(),
    DockerfileParser(),          # before compose — Dockerfile has no extension
    DockerComposeParser(),
    HelmParser(),                # before k8s — Chart.yaml is more specific
    KubernetesParser(),
    ServerlessFrameworkParser(),
    GitHubActionsParser(),
    JenkinsParser(),
    AzurePipelinesParser(),
    AnsibleParser(),
    DrawioParser(),
    CloudFormationParser(),
    AzureARMParser(),
    AWSConfigParser(),
    GCPAssetParser(),
    OpenAPIParser(),
    TextParser(),
]


def detect_parser(source: str, format_hint: str | None = None) -> BaseParser:
    if format_hint:
        mapping = {
            "terraform":    TerraformParser(),
            "kubernetes":   KubernetesParser(),
            "k8s":          KubernetesParser(),
            "helm":         HelmParser(),
            "compose":      DockerComposeParser(),
            "docker-compose": DockerComposeParser(),
            "dockerfile":   DockerfileParser(),
            "azure-arm":    AzureARMParser(),
            "arm":          AzureARMParser(),
            "serverless":   ServerlessFrameworkParser(),
            "openapi":      OpenAPIParser(),
            "swagger":      OpenAPIParser(),
            "github-actions": GitHubActionsParser(),
            "gha":          GitHubActionsParser(),
            "jenkins":      JenkinsParser(),
            "jenkinsfile":  JenkinsParser(),
            "azure-pipelines": AzurePipelinesParser(),
            "ado":          AzurePipelinesParser(),
            "ansible":      AnsibleParser(),
            "drawio":       DrawioParser(),
            "cloudformation": CloudFormationParser(),
            "cfn":          CloudFormationParser(),
            "aws_config":   AWSConfigParser(),
            "gcp_asset":    GCPAssetParser(),
            "text":         TextParser(),
        }
        if format_hint in mapping:
            return mapping[format_hint]

    for parser in _PARSERS:
        if parser.can_parse(source):
            return parser

    raise ValueError(f"Could not detect input format for: {source}")
