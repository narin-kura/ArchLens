"""draw.io XML parser — extracts components from .drawio / .xml diagram files."""

from __future__ import annotations
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from .base import BaseParser
from ..models.architecture import ArchitectureModel, Component, ComponentType, Connection

# Maps draw.io style keywords → ComponentType
_STYLE_MAP = [
    (r"ec2|compute|instance|server|vm",          ComponentType.COMPUTE),
    (r"lambda|serverless|function",              ComponentType.SERVERLESS),
    (r"ecs|fargate|container|docker|k8s|eks",    ComponentType.CONTAINER),
    (r"rds|database|db|aurora|sql|dynamo",       ComponentType.DATABASE),
    (r"s3|storage|bucket|blob|gcs",              ComponentType.STORAGE),
    (r"sqs|sns|queue|topic|pubsub|kafka",        ComponentType.QUEUE),
    (r"elasticache|redis|memcached|cache",       ComponentType.CACHE),
    (r"cloudfront|cdn|akamai",                   ComponentType.CDN),
    (r"apigateway|api.gateway|gateway|alb|elb",  ComponentType.GATEWAY),
    (r"vpc|subnet|securitygroup|firewall|nat",   ComponentType.NETWORK),
    (r"iam|role|policy|identity",                ComponentType.IAM),
    (r"cloudwatch|monitoring|grafana|datadog",   ComponentType.MONITORING),
]


def _infer_type(style: str, label: str) -> ComponentType:
    text = (style + " " + label).lower()
    for pattern, ctype in _STYLE_MAP:
        if re.search(pattern, text):
            return ctype
    return ComponentType.OTHER


def _infer_provider(style: str) -> str:
    s = style.lower()
    if "aws" in s or "amazon" in s:
        return "aws"
    if "gcp" in s or "google" in s:
        return "gcp"
    if "azure" in s or "microsoft" in s:
        return "azure"
    return "generic"


class DrawioParser(BaseParser):
    def can_parse(self, source: str | Path) -> bool:
        p = Path(source)
        return p.is_file() and p.suffix in {".xml", ".drawio"}

    def parse(self, source: str | Path) -> ArchitectureModel:
        p = Path(source)
        tree = ET.parse(str(p))
        root = tree.getroot()

        model = ArchitectureModel(name=p.stem, source="drawio")
        cells: dict[str, Component] = {}

        # draw.io wraps content in <mxGraphModel><root>
        ns_root = root.find(".//root") or root

        for cell in ns_root.findall("mxCell"):
            cid    = cell.get("id", "")
            label  = cell.get("value", "").strip()
            style  = cell.get("style", "")
            vertex = cell.get("vertex", "0")
            edge   = cell.get("edge", "0")
            source_id = cell.get("source", "")
            target_id = cell.get("target", "")

            # Skip blank/structural cells
            if vertex == "1" and label and cid not in ("0", "1"):
                comp = Component(
                    id=cid,
                    name=label,
                    type=_infer_type(style, label),
                    provider=_infer_provider(style),
                    service=label.lower().replace(" ", "_"),
                    properties={"style": style},
                )
                model.components.append(comp)
                cells[cid] = comp

            elif edge == "1" and source_id and target_id:
                model.connections.append(Connection(
                    source_id=source_id,
                    target_id=target_id,
                    label=label,
                ))

        return model
