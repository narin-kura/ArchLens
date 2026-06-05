"""CloudFormation parser — reads AWS CloudFormation YAML/JSON templates."""

from __future__ import annotations
import json
from pathlib import Path

from .base import BaseParser
from ..models.architecture import ArchitectureModel, Component, ComponentType, Connection

_TYPE_MAP: dict[str, tuple[ComponentType, str]] = {
    "AWS::EC2::Instance":               (ComponentType.COMPUTE,    "ec2"),
    "AWS::EC2::AutoScalingGroup":       (ComponentType.COMPUTE,    "asg"),
    "AWS::Lambda::Function":            (ComponentType.SERVERLESS, "lambda"),
    "AWS::ECS::Service":                (ComponentType.CONTAINER,  "ecs"),
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
    "AWS::IAM::Policy":                 (ComponentType.IAM,        "iam_policy"),
    "AWS::CloudWatch::Alarm":           (ComponentType.MONITORING, "cloudwatch"),
}


class CloudFormationParser(BaseParser):
    def can_parse(self, source: str | Path) -> bool:
        p = Path(source)
        if not p.is_file():
            return False
        if p.suffix in {".yaml", ".yml", ".json"}:
            content = p.read_text(encoding="utf-8")
            return "AWSTemplateFormatVersion" in content or "Resources" in content
        return False

    def parse(self, source: str | Path) -> ArchitectureModel:
        p = Path(source)
        content = p.read_text(encoding="utf-8")

        try:
            import yaml
            data = yaml.safe_load(content)
        except Exception:
            data = json.loads(content)

        model = ArchitectureModel(name=p.stem, source="cloudformation")
        resources = data.get("Resources", {})

        for logical_id, resource in resources.items():
            res_type = resource.get("Type", "")
            props    = resource.get("Properties", {})

            comp_type, service = _TYPE_MAP.get(res_type, (ComponentType.OTHER, res_type.lower()))

            model.components.append(Component(
                id=logical_id,
                name=logical_id,
                type=comp_type,
                provider="aws",
                service=service,
                properties=self._flatten(props),
            ))

        return model

    def _flatten(self, props: dict, prefix: str = "") -> dict:
        flat = {}
        for k, v in props.items():
            key = f"{prefix}{k}".lower()
            if isinstance(v, dict):
                flat.update(self._flatten(v, prefix=f"{key}_"))
            elif isinstance(v, (str, int, float, bool)):
                flat[key] = str(v).lower()
        return flat
