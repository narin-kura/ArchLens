"""Normalized internal model — all parsers output this."""

from __future__ import annotations
import re
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


def grouped_properties(properties: dict[str, Any], block_name: str) -> list[dict[str, Any]]:
    """Reconstruct the individual occurrences of a repeated named block.

    The Terraform parser flattens `block_name { name = "X" ... }` into keys
    like `block_name__X__attr` so two occurrences of the same block (two NSG
    `security_rule`s, two RDS `parameter`s) don't overwrite each other. This
    regroups them back into one dict per occurrence — shared by the parser
    and any analyzer that needs to reason about a single rule's attributes
    together rather than every rule's at once.
    """
    prefix_re = re.compile(rf'^{re.escape(block_name)}__(.+?)__(.+)$')
    groups: dict[str, dict[str, Any]] = {}
    for key, value in properties.items():
        m = prefix_re.match(key)
        if m:
            groups.setdefault(m.group(1), {})[m.group(2)] = value
    return list(groups.values())
