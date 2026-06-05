"""AWS Config export parser — reads JSON exports from AWS Config recorder."""

from __future__ import annotations
import json
from pathlib import Path

from .base import BaseParser
from ..models.architecture import ArchitectureModel, Component, ComponentType, Connection

_RESOURCE_TYPE_MAP: dict[str, tuple[ComponentType, str]] = {
    "AWS::EC2::Instance":               (ComponentType.COMPUTE,    "ec2"),
    "AWS::Lambda::Function":            (ComponentType.SERVERLESS, "lambda"),
    "AWS::ECS::Cluster":               (ComponentType.CONTAINER,  "ecs"),
    "AWS::EKS::Cluster":               (ComponentType.CONTAINER,  "eks"),
    "AWS::RDS::DBInstance":             (ComponentType.DATABASE,   "rds"),
    "AWS::DynamoDB::Table":             (ComponentType.DATABASE,   "dynamodb"),
    "AWS::S3::Bucket":                  (ComponentType.STORAGE,    "s3"),
    "AWS::ElastiCache::CacheCluster":   (ComponentType.CACHE,      "elasticache"),
    "AWS::SQS::Queue":                  (ComponentType.QUEUE,      "sqs"),
    "AWS::SNS::Topic":                  (ComponentType.QUEUE,      "sns"),
    "AWS::CloudFront::Distribution":    (ComponentType.CDN,        "cloudfront"),
    "AWS::ApiGateway::RestApi":         (ComponentType.GATEWAY,    "apigateway"),
    "AWS::ElasticLoadBalancingV2::LoadBalancer": (ComponentType.GATEWAY, "alb"),
    "AWS::EC2::VPC":                    (ComponentType.NETWORK,    "vpc"),
    "AWS::EC2::SecurityGroup":          (ComponentType.NETWORK,    "security_group"),
    "AWS::IAM::Role":                   (ComponentType.IAM,        "iam_role"),
    "AWS::CloudWatch::Alarm":           (ComponentType.MONITORING, "cloudwatch"),
}


def _is_aws_config(data: object) -> bool:
    if isinstance(data, list):
        return bool(data) and isinstance(data[0], dict) and "resourceType" in data[0]
    if isinstance(data, dict):
        return "configurationItems" in data or "resourceType" in data
    return False


class AWSConfigParser(BaseParser):
    def can_parse(self, source: str | Path) -> bool:
        p = Path(source)
        if not p.is_file() or p.suffix not in {".json"}:
            return False
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            return _is_aws_config(data)
        except Exception:
            return False

    def parse(self, source: str | Path) -> ArchitectureModel:
        p = Path(source)
        data = json.loads(p.read_text(encoding="utf-8"))

        # Normalise: could be a list or {"configurationItems": [...]}
        items = data if isinstance(data, list) else data.get("configurationItems", [])

        model = ArchitectureModel(name=p.stem, source="aws_config")

        for item in items:
            res_type = item.get("resourceType", "")
            res_id   = item.get("resourceId", "")
            res_name = item.get("resourceName") or res_id
            config   = item.get("configuration", {})
            if isinstance(config, str):
                try:
                    config = json.loads(config)
                except Exception:
                    config = {}

            comp_type, service = _RESOURCE_TYPE_MAP.get(res_type, (ComponentType.OTHER, res_type))

            # Flatten useful config properties for analysis
            props = self._extract_props(res_type, config)

            model.components.append(Component(
                id=res_id or res_name,
                name=res_name,
                type=comp_type,
                provider="aws",
                service=service,
                properties=props,
            ))

        return model

    def _extract_props(self, res_type: str, config: dict) -> dict:
        props = {}
        # Storage encryption
        for key in ("storageEncrypted", "encrypted", "encryptionAtRest"):
            if key in config:
                props["storage_encrypted"] = str(config[key]).lower()
        # Instance size
        for key in ("instanceType", "dbInstanceClass", "cacheNodeType"):
            if key in config:
                props["instance_class"] = config[key]
        # Public access
        for key in ("publiclyAccessible", "publicAccess", "acl"):
            if key in config:
                props["acl"] = str(config[key]).lower()
        # Security groups / CIDR
        sgs = config.get("securityGroups", [])
        if sgs:
            props["security_groups"] = str(len(sgs))
        return props
