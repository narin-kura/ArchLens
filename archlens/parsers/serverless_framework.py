"""Serverless Framework parser — reads serverless.yml configuration files."""

from __future__ import annotations
from pathlib import Path
from typing import Any

from .base import BaseParser
from ..models.architecture import ArchitectureModel, Component, ComponentType

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

_PROVIDER_MAP = {"aws": "aws", "gcp": "gcp", "azure": "azure", "google": "gcp"}


class ServerlessFrameworkParser(BaseParser):
    def can_parse(self, source: str | Path) -> bool:
        if not _YAML_AVAILABLE:
            return False
        p = Path(source)
        if not p.is_file():
            return False
        if p.name.lower() not in {"serverless.yml", "serverless.yaml"}:
            if p.suffix not in {".yml", ".yaml"}:
                return False
            try:
                content = p.read_text(encoding="utf-8")
                return "functions:" in content and "provider:" in content and ("service:" in content or "app:" in content)
            except Exception:
                return False
        return True

    def parse(self, source: str | Path) -> ArchitectureModel:
        if not _YAML_AVAILABLE:
            raise ImportError("Install PyYAML: pip install pyyaml")
        p = Path(source)
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        service_name = data.get("service", data.get("app", p.stem))
        if isinstance(service_name, dict):
            service_name = service_name.get("name", p.stem)

        provider_conf = data.get("provider") or {}
        provider_name = _PROVIDER_MAP.get(str(provider_conf.get("name", "aws")).lower(), "aws")
        runtime = str(provider_conf.get("runtime", ""))

        model = ArchitectureModel(name=str(service_name), source="serverless-framework")

        # Global IAM role
        global_role = str(provider_conf.get("iam", {}).get("role", {}).get("name", "") or provider_conf.get("role", ""))
        global_env = provider_conf.get("environment") or {}

        # Functions
        for fn_name, fn_conf in (data.get("functions") or {}).items():
            fn_conf = fn_conf or {}
            env = {**global_env, **(fn_conf.get("environment") or {})}
            _sensitive = {"password", "secret", "token", "key", "apikey", "api_key", "credentials", "passwd"}
            possible_secrets = [k for k in env if any(s in k.lower() for s in _sensitive) and env.get(k, "")]

            events = fn_conf.get("events") or []
            event_types = [list(e.keys())[0] if isinstance(e, dict) else str(e) for e in events]
            has_http = any(t in ("http", "httpApi", "alb") for t in event_types)
            has_schedule = any(t == "schedule" for t in event_types)

            role = fn_conf.get("role", global_role)

            model.components.append(Component(
                id=f"sls.function.{fn_name}",
                name=fn_name,
                type=ComponentType.SERVERLESS,
                provider=provider_name,
                service="lambda" if provider_name == "aws" else "cloud_function",
                properties={
                    "runtime": fn_conf.get("runtime", runtime),
                    "handler": fn_conf.get("handler", ""),
                    "role": role,
                    "timeout": fn_conf.get("timeout", provider_conf.get("timeout", 30)),
                    "memory_size": fn_conf.get("memorySize", provider_conf.get("memorySize", 1024)),
                    "environment": env,
                    "possible_secret_env": possible_secrets,
                    "event_types": event_types,
                    "has_http_event": has_http,
                    "has_schedule_event": has_schedule,
                    "vpc_config": fn_conf.get("vpc", provider_conf.get("vpc", "")),
                    "dead_letter_config": fn_conf.get("deadLetter", ""),
                    "layers": fn_conf.get("layers") or [],
                },
            ))

        # Resources (CloudFormation-style)
        resources = (data.get("resources") or {}).get("Resources") or {}
        for res_name, res_conf in resources.items():
            res_conf = res_conf or {}
            res_type = res_conf.get("Type", "")
            _rtype_map = {
                "AWS::DynamoDB::Table":   (ComponentType.DATABASE, "dynamodb"),
                "AWS::S3::Bucket":        (ComponentType.STORAGE,  "s3"),
                "AWS::SQS::Queue":        (ComponentType.QUEUE,    "sqs"),
                "AWS::SNS::Topic":        (ComponentType.QUEUE,    "sns"),
                "AWS::RDS::DBInstance":   (ComponentType.DATABASE, "rds"),
                "AWS::ElastiCache::CacheCluster": (ComponentType.CACHE, "elasticache"),
                "AWS::ApiGateway::RestApi": (ComponentType.GATEWAY, "apigateway"),
                "AWS::EC2::VPC":           (ComponentType.NETWORK,  "vpc"),
                "AWS::IAM::Role":          (ComponentType.IAM,      "iam_role"),
                "AWS::CloudWatch::Alarm":  (ComponentType.MONITORING, "cloudwatch"),
            }
            comp_type, service = _rtype_map.get(res_type, (ComponentType.OTHER, res_type.lower()))
            model.components.append(Component(
                id=f"sls.resource.{res_name}",
                name=res_name,
                type=comp_type,
                provider=provider_name,
                service=service,
                properties={"cfn_type": res_type},
            ))

        return model
