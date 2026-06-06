"""Azure ARM template parser — reads Azure Resource Manager deployment templates."""

from __future__ import annotations
import json
from pathlib import Path
from typing import Any

from .base import BaseParser
from ..models.architecture import ArchitectureModel, Component, ComponentType

_ARM_TYPE_MAP: dict[str, tuple[ComponentType, str]] = {
    "microsoft.compute/virtualmachines":                    (ComponentType.COMPUTE,    "azure_vm"),
    "microsoft.compute/virtualmachinescalesets":            (ComponentType.COMPUTE,    "azure_vmss"),
    "microsoft.web/sites":                                  (ComponentType.SERVERLESS, "azure_functions"),
    "microsoft.web/serverfarms":                            (ComponentType.COMPUTE,    "azure_app_service"),
    "microsoft.containerservice/managedclusters":           (ComponentType.CONTAINER,  "aks"),
    "microsoft.containerinstance/containergroups":          (ComponentType.CONTAINER,  "aci"),
    "microsoft.app/containerapps":                          (ComponentType.CONTAINER,  "azure_container_apps"),
    "microsoft.sql/servers":                                (ComponentType.DATABASE,   "azure_sql_server"),
    "microsoft.sql/servers/databases":                      (ComponentType.DATABASE,   "azure_sql"),
    "microsoft.documentdb/databaseaccounts":                (ComponentType.DATABASE,   "cosmosdb"),
    "microsoft.dbformysql/servers":                         (ComponentType.DATABASE,   "azure_mysql"),
    "microsoft.dbforpostgresql/servers":                    (ComponentType.DATABASE,   "azure_postgres"),
    "microsoft.dbforpostgresql/flexibleservers":            (ComponentType.DATABASE,   "azure_postgres_flex"),
    "microsoft.cache/redis":                                (ComponentType.CACHE,      "azure_redis"),
    "microsoft.storage/storageaccounts":                    (ComponentType.STORAGE,    "azure_storage"),
    "microsoft.network/virtualnetworks":                    (ComponentType.NETWORK,    "azure_vnet"),
    "microsoft.network/networksecuritygroups":              (ComponentType.NETWORK,    "azure_nsg"),
    "microsoft.network/applicationgateways":                (ComponentType.GATEWAY,    "azure_app_gateway"),
    "microsoft.network/frontdoors":                         (ComponentType.CDN,        "azure_frontdoor"),
    "microsoft.cdn/profiles":                               (ComponentType.CDN,        "azure_cdn"),
    "microsoft.servicebus/namespaces":                      (ComponentType.QUEUE,      "azure_servicebus"),
    "microsoft.eventhub/namespaces":                        (ComponentType.QUEUE,      "azure_eventhub"),
    "microsoft.authorization/roleassignments":              (ComponentType.IAM,        "azure_rbac"),
    "microsoft.managedidentity/userassignedidentities":     (ComponentType.IAM,        "azure_identity"),
    "microsoft.insights/components":                        (ComponentType.MONITORING, "app_insights"),
    "microsoft.operationalinsights/workspaces":             (ComponentType.MONITORING, "log_analytics"),
    "microsoft.apimanagement/service":                      (ComponentType.GATEWAY,    "azure_apim"),
    "microsoft.keyvault/vaults":                            (ComponentType.IAM,        "azure_keyvault"),
    "microsoft.network/loadbalancers":                      (ComponentType.GATEWAY,    "azure_lb"),
    "microsoft.network/publicipaddresses":                  (ComponentType.NETWORK,    "azure_public_ip"),
}


def _is_arm_template(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    schema = data.get("$schema", "")
    return "deploymentTemplate" in schema or (
        "resources" in data and isinstance(data.get("resources"), list)
        and any(isinstance(r, dict) and "type" in r for r in data["resources"])
    )


class AzureARMParser(BaseParser):
    def can_parse(self, source: str | Path) -> bool:
        p = Path(source)
        if not p.is_file() or p.suffix not in {".json"}:
            return False
        try:
            content = p.read_text(encoding="utf-8")
            if "deploymentTemplate" not in content and "$schema" not in content:
                return False
            data = json.loads(content)
            return _is_arm_template(data)
        except Exception:
            return False

    def parse(self, source: str | Path) -> ArchitectureModel:
        p = Path(source)
        data = json.loads(p.read_text(encoding="utf-8"))
        model = ArchitectureModel(name=p.stem, source="azure-arm")

        for resource in data.get("resources") or []:
            component = self._parse_resource(resource)
            if component:
                model.components.append(component)
            for nested in resource.get("resources") or []:
                nc = self._parse_resource(nested, parent_type=resource.get("type", ""))
                if nc:
                    model.components.append(nc)

        return model

    def _parse_resource(self, resource: dict, parent_type: str = "") -> Component | None:
        res_type = resource.get("type", "").lower()
        if parent_type:
            res_type = f"{parent_type}/{res_type}".lower()
        name = resource.get("name", "unknown")
        if "[" in name:
            name = name.split("'")[-2] if "'" in name else name.replace("[", "").replace("]", "")

        comp_type, service = _ARM_TYPE_MAP.get(res_type, (ComponentType.OTHER, res_type))
        props = self._flatten_props(resource.get("properties") or {})
        props["arm_type"] = resource.get("type", "")
        props["arm_api_version"] = resource.get("apiVersion", "")
        props["arm_location"] = resource.get("location", "")
        tags = resource.get("tags") or {}

        sku = resource.get("sku") or {}
        if sku:
            props["sku_name"] = sku.get("name", "")
            props["sku_tier"] = sku.get("tier", "")

        return Component(
            id=f"arm.{res_type}.{name}".replace("/", "."),
            name=name,
            type=comp_type,
            provider="azure",
            service=service,
            properties=props,
            tags={k: str(v) for k, v in tags.items()},
        )

    def _flatten_props(self, props: dict, prefix: str = "") -> dict:
        flat: dict = {}
        for k, v in props.items():
            key = f"{prefix}{k}".lower()
            if isinstance(v, dict):
                flat.update(self._flatten_props(v, prefix=f"{key}_"))
            elif isinstance(v, (str, int, float, bool)):
                flat[key] = str(v).lower() if isinstance(v, bool) else v
            elif isinstance(v, list) and all(isinstance(i, str) for i in v):
                flat[key] = v
        return flat
