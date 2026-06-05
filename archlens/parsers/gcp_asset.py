"""GCP Asset Inventory parser — reads JSON exports from GCP Cloud Asset Inventory."""

from __future__ import annotations
import json
from pathlib import Path

from .base import BaseParser
from ..models.architecture import ArchitectureModel, Component, ComponentType

_ASSET_TYPE_MAP: dict[str, tuple[ComponentType, str]] = {
    "compute.googleapis.com/Instance":          (ComponentType.COMPUTE,    "gce_instance"),
    "compute.googleapis.com/Disk":              (ComponentType.STORAGE,    "gce_disk"),
    "run.googleapis.com/Service":               (ComponentType.SERVERLESS, "cloud_run"),
    "cloudfunctions.googleapis.com/CloudFunction": (ComponentType.SERVERLESS, "cloud_function"),
    "container.googleapis.com/Cluster":         (ComponentType.CONTAINER,  "gke"),
    "sqladmin.googleapis.com/Instance":         (ComponentType.DATABASE,   "cloud_sql"),
    "spanner.googleapis.com/Instance":          (ComponentType.DATABASE,   "spanner"),
    "bigtable.googleapis.com/Instance":         (ComponentType.DATABASE,   "bigtable"),
    "storage.googleapis.com/Bucket":            (ComponentType.STORAGE,    "gcs_bucket"),
    "pubsub.googleapis.com/Topic":              (ComponentType.QUEUE,      "pubsub"),
    "redis.googleapis.com/Instance":            (ComponentType.CACHE,      "memorystore"),
    "compute.googleapis.com/Network":           (ComponentType.NETWORK,    "vpc"),
    "compute.googleapis.com/Firewall":          (ComponentType.NETWORK,    "firewall"),
    "iam.googleapis.com/ServiceAccount":        (ComponentType.IAM,        "service_account"),
    "monitoring.googleapis.com/AlertPolicy":    (ComponentType.MONITORING, "cloud_monitoring"),
}


def _resource_name(asset_name: str) -> str:
    return asset_name.split("/")[-1] if "/" in asset_name else asset_name


def _is_gcp_asset(data: object) -> bool:
    if isinstance(data, list):
        return bool(data) and isinstance(data[0], dict) and "assetType" in data[0]
    if isinstance(data, dict):
        return "assetType" in data or "assets" in data
    return False


class GCPAssetParser(BaseParser):
    def can_parse(self, source: str | Path) -> bool:
        p = Path(source)
        if not p.is_file() or p.suffix != ".json":
            return False
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            return _is_gcp_asset(data)
        except Exception:
            return False

    def parse(self, source: str | Path) -> ArchitectureModel:
        p = Path(source)
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Could not parse GCP Asset Inventory export — check it is valid JSON. ({exc})") from exc

        assets = data if isinstance(data, list) else data.get("assets", [])
        model = ArchitectureModel(name=p.stem, source="gcp_asset")

        for asset in assets:
            try:
                asset_type = asset.get("assetType", "")
                asset_name = asset.get("name", "")
                resource   = asset.get("resource", {}) or {}
                res_data   = resource.get("data", {}) or {}

                comp_type, service = _ASSET_TYPE_MAP.get(asset_type, (ComponentType.OTHER, asset_type))
                name = _resource_name(asset_name) or asset_type or "unknown"
                props = self._extract_props(asset_type, res_data)

                model.components.append(Component(
                    id=asset_name or name,
                    name=name,
                    type=comp_type,
                    provider="gcp",
                    service=service,
                    properties=props,
                ))
            except Exception:
                continue

        return model

    def _extract_props(self, asset_type: str, data: dict) -> dict:
        props = {}
        # Encryption
        enc = data.get("diskEncryptionKey") or data.get("encryptionConfig", {})
        if enc:
            props["storage_encrypted"] = "true"
        else:
            props["storage_encrypted"] = "false"
        # Machine type
        machine = data.get("machineType", "")
        if machine:
            props["instance_class"] = machine.split("/")[-1]
        # Public access
        if data.get("iamConfiguration", {}).get("uniformBucketLevelAccess", {}).get("enabled"):
            props["acl"] = "private"
        for member in data.get("bindings", [{}]):
            if "allUsers" in str(member) or "allAuthenticatedUsers" in str(member):
                props["acl"] = "public"
        return props
