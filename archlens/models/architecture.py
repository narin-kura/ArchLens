"""Normalized internal model — all parsers output this."""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ComponentType(str, Enum):
    COMPUTE = "compute"
    DATABASE = "database"
    STORAGE = "storage"
    NETWORK = "network"
    IAM = "iam"
    QUEUE = "queue"
    CACHE = "cache"
    CDN = "cdn"
    GATEWAY = "gateway"
    CONTAINER = "container"
    SERVERLESS = "serverless"
    MONITORING = "monitoring"
    OTHER = "other"


@dataclass
class Component:
    id: str
    name: str
    type: ComponentType
    provider: str = ""           # aws, gcp, azure, generic
    service: str = ""            # e.g. ec2, s3, rds, lambda
    properties: dict[str, Any] = field(default_factory=dict)
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class Connection:
    source_id: str
    target_id: str
    label: str = ""
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class ArchitectureModel:
    name: str = "unnamed"
    source: str = ""             # input type: terraform, text, diagram, cloud_export
    components: list[Component] = field(default_factory=list)
    connections: list[Connection] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def get_component(self, id: str) -> Component | None:
        return next((c for c in self.components if c.id == id), None)

    def components_by_type(self, type: ComponentType) -> list[Component]:
        return [c for c in self.components if c.type == type]
