"""GitHub Actions parser — reads workflow YAML files from .github/workflows/."""

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

_PRIVILEGED_PERMISSIONS = {"write-all", "id-token: write", "contents: write", "packages: write", "deployments: write"}
_CLOUD_ACTIONS = {
    "aws-actions/configure-aws-credentials": "aws",
    "google-github-actions/auth": "gcp",
    "azure/login": "azure",
}

# GitHub-hosted runner base images: ubuntu-latest, windows-2022, macos-14, ...
_GH_HOSTED_BASE = re.compile(r"^(ubuntu|windows|macos)-(latest|\d+(\.\d+)?)$", re.I)
# "Larger runner" naming convention: ubuntu-latest-4-cores, macos-latest-large, ...
_LARGER_SUFFIX = re.compile(r"(-\d+-cores?$|-large$|-xl$)", re.I)


def _classify_runs_on(value: Any) -> set[str]:
    """Classify a job's `runs-on` value into runner type(s).

    Returns a subset of {"github-hosted", "github-hosted-larger", "self-hosted",
    "dynamic-expression"}. A custom label that doesn't match GitHub's documented
    hosted-runner naming (e.g. an Actions Runner Controller scale-set name) is
    treated as "self-hosted", since that's how GitHub Actions itself routes it.
    """
    if isinstance(value, str):
        labels = [value]
    elif isinstance(value, list):
        labels = [str(v) for v in value]
    else:
        return set()

    types: set[str] = set()
    for label in labels:
        l = label.strip()
        if "${{" in l:
            types.add("dynamic-expression")
        elif l.lower() == "self-hosted":
            types.add("self-hosted")
        elif _LARGER_SUFFIX.search(l) and any(b in l.lower() for b in ("ubuntu", "windows", "macos")):
            types.add("github-hosted-larger")
        elif _GH_HOSTED_BASE.match(l):
            types.add("github-hosted")
        else:
            types.add("self-hosted")
    return types


class GitHubActionsParser(BaseParser):
    def can_parse(self, source: str | Path) -> bool:
        if not _YAML_AVAILABLE:
            return False
        p = Path(source)
        if p.is_dir():
            workflows_dir = p / ".github" / "workflows"
            return workflows_dir.is_dir() and (
                any(workflows_dir.glob("*.yml")) or any(workflows_dir.glob("*.yaml"))
            )
        if p.is_file() and p.suffix in {".yml", ".yaml"}:
            parts = p.parts
            if ".github" in parts and "workflows" in parts:
                return True
            try:
                content = p.read_text(encoding="utf-8")
                return ("jobs:" in content and ("on:" in content or "\"on\":" in content or "'on':" in content))
            except Exception:
                return False
        return False

    def parse(self, source: str | Path) -> ArchitectureModel:
        if not _YAML_AVAILABLE:
            raise ImportError("Install PyYAML: pip install pyyaml")
        p = Path(source)
        model = ArchitectureModel(name=p.name if p.is_file() else p.name, source="github-actions")

        workflow_files: list[Path] = []
        if p.is_dir():
            wf_dir = p / ".github" / "workflows"
            workflow_files = list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml"))
        else:
            workflow_files = [p]

        for wf_file in workflow_files:
            try:
                data = yaml.safe_load(wf_file.read_text(encoding="utf-8")) or {}
                component = self._parse_workflow(wf_file.stem, data)
                model.components.append(component)
            except Exception:
                continue

        return model

    def _parse_workflow(self, name: str, data: dict) -> Component:
        jobs = data.get("jobs") or {}
        on_triggers = data.get("on") or data.get(True) or {}  # PyYAML parses `on:` as True
        if isinstance(on_triggers, str):
            on_triggers = {on_triggers: {}}

        global_perms = data.get("permissions") or {}
        all_steps: list[dict] = []
        for job in jobs.values():
            if isinstance(job, dict):
                all_steps.extend(job.get("steps") or [])

        uses = [s.get("uses", "") for s in all_steps if isinstance(s, dict) and s.get("uses")]
        third_party = [u for u in uses if "/" in u and not u.startswith(("actions/", "github/"))]
        unpinned = [u for u in uses if "@" not in u or u.endswith(("@main", "@master", "@latest"))]
        cloud_providers = list({_CLOUD_ACTIONS[u.split("@")[0]] for u in uses if u.split("@")[0] in _CLOUD_ACTIONS})

        env_vars: dict[str, str] = {}
        for step in all_steps:
            if not isinstance(step, dict):
                continue
            env_vars.update(step.get("env") or {})
        env_vars.update(data.get("env") or {})

        _sensitive = {"password", "secret", "token", "key", "apikey", "credentials", "passwd"}
        hardcoded_secrets = [
            k for k, v in env_vars.items()
            if any(s in k.lower() for s in _sensitive)
            and v and not str(v).startswith("${{")
        ]

        secret_refs = re.findall(r"\$\{\{\s*secrets\.(\w+)\s*\}\}", str(data))

        # Check permissions
        write_perms = []
        if global_perms == "write-all":
            write_perms = ["write-all"]
        elif isinstance(global_perms, dict):
            write_perms = [f"{k}: {v}" for k, v in global_perms.items() if str(v) == "write"]

        has_oidc = "id-token" in str(global_perms) or "id-token" in str(data)
        pr_trigger = "pull_request" in str(on_triggers)
        push_to_main = any(
            "main" in str(v) or "master" in str(v)
            for v in (on_triggers if isinstance(on_triggers, dict) else {}).values()
        )

        job_count = len(jobs)
        runner_types: set[str] = set()
        for job in jobs.values():
            if isinstance(job, dict):
                runner_types |= _classify_runs_on(job.get("runs-on"))
        has_self_hosted = "self-hosted" in runner_types
        has_docker_publish = any(
            re.search(r"docker\s+(push|build)", str(s.get("run", "")), re.I)
            for s in all_steps if isinstance(s, dict)
        )

        return Component(
            id=f"gha.workflow.{name}",
            name=name,
            type=ComponentType.OTHER,
            provider="github",
            service="github_actions_workflow",
            properties={
                "triggers": list(on_triggers.keys()) if isinstance(on_triggers, dict) else [str(on_triggers)],
                "job_count": job_count,
                "step_count": len(all_steps),
                "third_party_actions": third_party,
                "unpinned_actions": unpinned,
                "cloud_providers_used": cloud_providers,
                "write_permissions": write_perms,
                "has_oidc": has_oidc,
                "hardcoded_secrets_in_env": hardcoded_secrets,
                "secret_references": list(set(secret_refs)),
                "pr_trigger": pr_trigger,
                "push_to_main": push_to_main,
                "has_self_hosted_runner": has_self_hosted,
                "runner_types": sorted(runner_types),
                "has_docker_publish": has_docker_publish,
            },
        )
