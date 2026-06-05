"""Terraform parser — reads .tf files and builds an ArchitectureModel."""

from __future__ import annotations
import re
from pathlib import Path

from .base import BaseParser
from ..models.architecture import ArchitectureModel, Component, ComponentType


# Maps Terraform resource types → ComponentType
_RESOURCE_TYPE_MAP: dict[str, ComponentType] = {
    "aws_instance":           ComponentType.COMPUTE,
    "aws_lambda_function":    ComponentType.SERVERLESS,
    "aws_ecs_service":        ComponentType.CONTAINER,
    "aws_rds_instance":       ComponentType.DATABASE,
    "aws_db_instance":        ComponentType.DATABASE,
    "aws_s3_bucket":          ComponentType.STORAGE,
    "aws_elasticache_cluster":ComponentType.CACHE,
    "aws_sqs_queue":          ComponentType.QUEUE,
    "aws_sns_topic":          ComponentType.QUEUE,
    "aws_cloudfront_distribution": ComponentType.CDN,
    "aws_api_gateway_rest_api":    ComponentType.GATEWAY,
    "aws_security_group":     ComponentType.NETWORK,
    "aws_vpc":                ComponentType.NETWORK,
    "aws_iam_role":           ComponentType.IAM,
    "aws_iam_policy":         ComponentType.IAM,
    "google_compute_instance":ComponentType.COMPUTE,
    "google_sql_database_instance": ComponentType.DATABASE,
    "google_storage_bucket":  ComponentType.STORAGE,
    "azurerm_virtual_machine":ComponentType.COMPUTE,
    "azurerm_sql_server":     ComponentType.DATABASE,
    "azurerm_storage_account":ComponentType.STORAGE,
}


def _detect_provider(resource_type: str) -> str:
    if resource_type.startswith("aws_"):
        return "aws"
    if resource_type.startswith("google_"):
        return "gcp"
    if resource_type.startswith("azurerm_"):
        return "azure"
    return "generic"


class TerraformParser(BaseParser):
    def can_parse(self, source: str | Path) -> bool:
        p = Path(source)
        if p.is_dir():
            return any(p.glob("*.tf"))
        return p.suffix == ".tf"

    def parse(self, source: str | Path) -> ArchitectureModel:
        p = Path(source)
        tf_files = list(p.glob("*.tf")) if p.is_dir() else [p]

        model = ArchitectureModel(name=p.name, source="terraform")
        for tf_file in tf_files:
            self._parse_file(tf_file, model)
        return model

    def _parse_file(self, path: Path, model: ArchitectureModel) -> None:
        content = path.read_text(encoding="utf-8")

        # Extract resource blocks: resource "type" "name" { ... }
        pattern = re.compile(
            r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}',
            re.DOTALL,
        )
        for match in pattern.finditer(content):
            resource_type, resource_name, block = match.groups()
            component_type = _RESOURCE_TYPE_MAP.get(resource_type, ComponentType.OTHER)
            provider = _detect_provider(resource_type)

            props = self._extract_properties(block)
            model.components.append(
                Component(
                    id=f"{resource_type}.{resource_name}",
                    name=resource_name,
                    type=component_type,
                    provider=provider,
                    service=resource_type,
                    properties=props,
                )
            )

    def _extract_properties(self, block: str) -> dict:
        props: dict = {}
        for line in block.splitlines():
            line = line.strip()
            m = re.match(r'(\w+)\s*=\s*"?([^"#\n]+)"?', line)
            if m:
                key, value = m.group(1), m.group(2).strip().strip('"')
                props[key] = value
        return props
