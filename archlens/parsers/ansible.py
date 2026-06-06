"""Ansible parser — reads playbooks and role structures."""

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

_MODULE_TYPE_MAP: dict[str, tuple[ComponentType, str]] = {
    "amazon.aws.ec2_instance":       (ComponentType.COMPUTE,    "ec2"),
    "ec2":                           (ComponentType.COMPUTE,    "ec2"),
    "amazon.aws.rds_instance":       (ComponentType.DATABASE,   "rds"),
    "amazon.aws.s3_bucket":          (ComponentType.STORAGE,    "s3"),
    "amazon.aws.elb_application_lb": (ComponentType.GATEWAY,    "alb"),
    "amazon.aws.iam_role":           (ComponentType.IAM,        "iam_role"),
    "amazon.aws.security_group":     (ComponentType.NETWORK,    "security_group"),
    "amazon.aws.sqs_queue":          (ComponentType.QUEUE,      "sqs"),
    "amazon.aws.elasticache_cluster":(ComponentType.CACHE,      "elasticache"),
    "amazon.aws.cloudwatch_metric_alarm": (ComponentType.MONITORING, "cloudwatch"),
    "kubernetes.core.k8s":           (ComponentType.CONTAINER,  "kubernetes"),
    "k8s":                           (ComponentType.CONTAINER,  "kubernetes"),
    "community.docker.docker_container": (ComponentType.CONTAINER, "docker"),
    "docker_container":              (ComponentType.CONTAINER,  "docker"),
    "community.docker.docker_image": (ComponentType.CONTAINER,  "docker_image"),
    "mysql_db":                      (ComponentType.DATABASE,   "mysql"),
    "postgresql_db":                 (ComponentType.DATABASE,   "postgresql"),
    "nginx":                         (ComponentType.GATEWAY,    "nginx"),
}

_SENSITIVE_MODULES = {"ansible.builtin.uri", "uri", "get_url", "shell", "command", "raw", "script"}


def _is_playbook(data: Any) -> bool:
    return isinstance(data, list) and all(
        isinstance(play, dict) and ("hosts" in play or "tasks" in play or "roles" in play)
        for play in data if play
    )


class AnsibleParser(BaseParser):
    def can_parse(self, source: str | Path) -> bool:
        if not _YAML_AVAILABLE:
            return False
        p = Path(source)
        if p.is_dir():
            return (p / "site.yml").exists() or (p / "playbook.yml").exists() or (p / "main.yml").exists()
        if not p.is_file() or p.suffix not in {".yml", ".yaml"}:
            return False
        try:
            content = p.read_text(encoding="utf-8")
            if not ("hosts:" in content or "tasks:" in content or "roles:" in content):
                return False
            data = yaml.safe_load(content)
            return _is_playbook(data)
        except Exception:
            return False

    def parse(self, source: str | Path) -> ArchitectureModel:
        if not _YAML_AVAILABLE:
            raise ImportError("Install PyYAML: pip install pyyaml")
        p = Path(source)
        model = ArchitectureModel(name=p.stem, source="ansible")

        playbook_files: list[Path] = []
        if p.is_dir():
            for candidate in ("site.yml", "playbook.yml", "main.yml"):
                f = p / candidate
                if f.exists():
                    playbook_files.append(f)
            playbook_files += [f for f in p.glob("*.yml") if f not in playbook_files]
        else:
            playbook_files = [p]

        for pb_file in playbook_files:
            try:
                plays = yaml.safe_load(pb_file.read_text(encoding="utf-8")) or []
                if not _is_playbook(plays):
                    continue
                self._parse_playbook(pb_file.stem, plays, model)
            except Exception:
                continue

        return model

    def _parse_playbook(self, pb_name: str, plays: list, model: ArchitectureModel) -> None:
        for play_idx, play in enumerate(plays):
            if not isinstance(play, dict):
                continue
            hosts = play.get("hosts", "all")
            play_name = play.get("name", f"{pb_name}-play-{play_idx}")
            tasks = list(play.get("tasks") or []) + list(play.get("pre_tasks") or []) + list(play.get("post_tasks") or [])
            vars_ = play.get("vars") or {}

            _sensitive = {"password", "secret", "token", "key", "apikey", "api_key", "credentials", "passwd"}
            possible_secret_vars = [k for k in vars_ if any(s in k.lower() for s in _sensitive) and vars_.get(k)]

            uses_become = play.get("become", False)
            uses_vault = "vault" in str(vars_).lower()

            discovered: set[str] = set()
            shell_commands: list[str] = []
            for task in tasks:
                if not isinstance(task, dict):
                    continue
                for module, comp_type, service in self._task_modules(task):
                    task_name = task.get("name", module)
                    task_args = task.get(module) or {}
                    if isinstance(task_args, str):
                        task_args = {"_raw_params": task_args}
                    key = f"{module}.{task_name}"
                    if key not in discovered:
                        discovered.add(key)
                        model.components.append(Component(
                            id=f"ansible.{pb_name}.{key}".replace(" ", "_"),
                            name=task_name,
                            type=comp_type,
                            provider=self._detect_provider(module),
                            service=service,
                            properties=self._task_props(task, module, task_args),
                        ))
                if "shell" in task or "command" in task or "raw" in task:
                    cmd = str(task.get("shell") or task.get("command") or task.get("raw") or "")
                    if cmd:
                        shell_commands.append(cmd)

            # Play-level component capturing overall automation context
            model.components.append(Component(
                id=f"ansible.play.{pb_name}.{play_idx}",
                name=play_name,
                type=ComponentType.OTHER,
                provider="ansible",
                service="ansible_play",
                properties={
                    "hosts": str(hosts),
                    "task_count": len(tasks),
                    "uses_become": uses_become,
                    "uses_vault": uses_vault,
                    "possible_secret_vars": possible_secret_vars,
                    "shell_commands": shell_commands[:10],
                    "has_shell_tasks": bool(shell_commands),
                },
            ))

    def _task_modules(self, task: dict) -> list[tuple[str, ComponentType, str]]:
        found = []
        for key in task:
            if key in ("name", "when", "with_items", "loop", "register", "notify", "tags", "ignore_errors", "become", "vars"):
                continue
            if key in _MODULE_TYPE_MAP:
                comp_type, service = _MODULE_TYPE_MAP[key]
                found.append((key, comp_type, service))
        return found or []

    def _detect_provider(self, module: str) -> str:
        if module.startswith("amazon.aws") or module in ("ec2", "s3", "rds"):
            return "aws"
        if module.startswith("google.cloud") or module.startswith("gcp_"):
            return "gcp"
        if module.startswith("azure.azcollection") or module.startswith("azure_rm"):
            return "azure"
        if "docker" in module:
            return "docker"
        if "kubernetes" in module or module == "k8s":
            return "kubernetes"
        return "generic"

    def _task_props(self, task: dict, module: str, args: dict) -> dict:
        props: dict[str, Any] = {
            "module": module,
            "when": str(task.get("when", "")),
            "become": task.get("become", False),
            "ignore_errors": task.get("ignore_errors", False),
        }
        if isinstance(args, dict):
            props.update({k: v for k, v in args.items() if isinstance(v, (str, int, float, bool))})
        return props
