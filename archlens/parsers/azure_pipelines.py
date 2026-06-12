"""Azure Pipelines parser — reads azure-pipelines.yml (YAML pipeline definitions).

Extracts the agent pool configuration (Microsoft-hosted `vmImage` vs.
self-hosted `pool: name:`, which may itself be backed by a static pool or a
Scale Set agent pool — indistinguishable from YAML alone), PR trigger
settings, `persistCredentials` usage on checkout, and any task-based cloud
provider usage.
"""

from __future__ import annotations
import re
from pathlib import Path
from typing import Any

from .base import BaseParser
from ..models.architecture import ArchitectureModel, Component, ComponentType

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

_SENSITIVE = {"password", "secret", "token", "key", "apikey", "credentials", "passwd"}


def _iter_jobs(data: dict):
    jobs = data.get("jobs")
    if isinstance(jobs, list):
        for j in jobs:
            if isinstance(j, dict):
                yield j
    stages = data.get("stages")
    if isinstance(stages, list):
        for stage in stages:
            if not isinstance(stage, dict):
                continue
            for j in stage.get("jobs") or []:
                if isinstance(j, dict):
                    yield j


def _all_pools(data: dict) -> list[dict]:
    pools: list[dict] = []
    top_pool = data.get("pool")
    if isinstance(top_pool, dict):
        pools.append(top_pool)
    elif isinstance(top_pool, str):
        pools.append({"name": top_pool})
    for job in _iter_jobs(data):
        jp = job.get("pool")
        if isinstance(jp, dict):
            pools.append(jp)
        elif isinstance(jp, str):
            pools.append({"name": jp})
    return pools


def _classify_pool(pool: dict) -> str:
    if "vmImage" in pool:
        return "microsoft-hosted"
    if "name" in pool:
        return "self-hosted"
    return "unspecified"


def _all_steps(data: dict) -> list[dict]:
    steps: list[dict] = []
    top_steps = data.get("steps")
    if isinstance(top_steps, list):
        steps.extend(s for s in top_steps if isinstance(s, dict))
    for job in _iter_jobs(data):
        job_steps = job.get("steps")
        if isinstance(job_steps, list):
            steps.extend(s for s in job_steps if isinstance(s, dict))
    return steps


def _task_provider(task_name: str) -> str | None:
    base = task_name.split("@")[0].lower()
    if base.startswith("azure"):
        return "azure"
    if base.startswith(("aws", "amazonwebservices", "ecr", "s3")):
        return "aws"
    if base.startswith(("googlecloud", "gcloud", "gke")):
        return "gcp"
    return None


def _find_hardcoded_secret_vars(data: dict) -> list[str]:
    found: list[str] = []
    variables = data.get("variables")
    entries: list[tuple[Any, Any]] = []
    if isinstance(variables, dict):
        entries = list(variables.items())
    elif isinstance(variables, list):
        for entry in variables:
            if isinstance(entry, dict) and "name" in entry and "value" in entry:
                entries.append((entry["name"], entry["value"]))
    for key, value in entries:
        if isinstance(value, str) and value and not value.startswith("$(") \
                and any(s in str(key).lower() for s in _SENSITIVE):
            found.append(str(key))
    return found


class AzurePipelinesParser(BaseParser):
    def can_parse(self, source: str | Path) -> bool:
        if not _YAML_AVAILABLE:
            return False
        p = Path(source)
        if not p.is_file() or p.suffix.lower() not in (".yml", ".yaml"):
            return False
        if "azure-pipelines" in p.name.lower():
            return True
        try:
            content = p.read_text(encoding="utf-8")
            data = yaml.safe_load(content)
        except Exception:
            return False
        if not isinstance(data, dict):
            return False
        # Exclude Kubernetes/Helm/Compose manifests and GitHub Actions workflows
        # (PyYAML parses a bare `on:` key as the boolean True).
        if any(k in data for k in ("apiVersion", "kind", "services")) or True in data:
            return False
        has_struct = any(k in data for k in ("stages", "jobs", "steps"))
        has_marker = any(k in data for k in ("trigger", "pr", "resources")) or "pool" in content
        return has_struct and has_marker

    def parse(self, source: str | Path) -> ArchitectureModel:
        if not _YAML_AVAILABLE:
            raise ImportError("Install PyYAML: pip install pyyaml")
        p = Path(source)
        model = ArchitectureModel(name=p.name, source="azure-pipelines")
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            if isinstance(data, dict):
                model.components.append(self._parse_pipeline(p.stem, data))
        except Exception:
            pass
        return model

    def _parse_pipeline(self, name: str, data: dict) -> Component:
        pools = _all_pools(data)
        pool_types = {_classify_pool(pool) for pool in pools}

        pr_value = data.get("pr", "<unset>")
        pr_trigger = not (
            pr_value in (False, None)
            or (isinstance(pr_value, str) and pr_value.strip().lower() == "none")
        )

        steps = _all_steps(data)
        persist_credentials = any(
            "checkout" in s and s.get("persistCredentials") is True
            for s in steps
        )

        providers = set()
        for s in steps:
            task = s.get("task")
            if isinstance(task, str):
                prov = _task_provider(task)
                if prov:
                    providers.add(prov)

        return Component(
            id=f"azure_pipelines.{name}",
            name=name,
            type=ComponentType.OTHER,
            provider="azure",
            service="azure_pipeline",
            properties={
                "agent_pool_types": sorted(pool_types),
                "pool_names": sorted({p["name"] for p in pools if isinstance(p.get("name"), str)}),
                "vm_images": sorted({p["vmImage"] for p in pools if isinstance(p.get("vmImage"), str)}),
                "pr_trigger": pr_trigger,
                "persist_credentials": persist_credentials,
                "task_providers_used": sorted(providers),
                "hardcoded_secret_vars": _find_hardcoded_secret_vars(data),
                "step_count": len(steps),
                "stage_count": len(data.get("stages") or []),
                "job_count": sum(1 for _ in _iter_jobs(data)),
            },
        )
