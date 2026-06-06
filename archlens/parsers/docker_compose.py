"""Docker Compose parser — reads docker-compose.yml files."""

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

_COMPOSE_FILENAMES = {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}


class DockerComposeParser(BaseParser):
    def can_parse(self, source: str | Path) -> bool:
        if not _YAML_AVAILABLE:
            return False
        p = Path(source)
        if p.is_file():
            if p.name.lower() in _COMPOSE_FILENAMES:
                return True
            if p.suffix in {".yml", ".yaml"}:
                try:
                    content = p.read_text(encoding="utf-8")
                    return "services:" in content and ("version:" in content or "networks:" in content or "volumes:" in content)
                except Exception:
                    return False
        return False

    def parse(self, source: str | Path) -> ArchitectureModel:
        if not _YAML_AVAILABLE:
            raise ImportError("Install PyYAML: pip install pyyaml")
        p = Path(source)
        content = p.read_text(encoding="utf-8")
        data = yaml.safe_load(content) or {}
        model = ArchitectureModel(name=p.stem, source="docker-compose")

        for svc_name, svc in (data.get("services") or {}).items():
            svc = svc or {}
            props = self._extract_service_props(svc_name, svc)
            model.components.append(Component(
                id=f"compose.service.{svc_name}",
                name=svc_name,
                type=ComponentType.CONTAINER,
                provider="docker",
                service="docker_compose_service",
                properties=props,
            ))

        for vol_name in (data.get("volumes") or {}).keys():
            model.components.append(Component(
                id=f"compose.volume.{vol_name}",
                name=vol_name,
                type=ComponentType.STORAGE,
                provider="docker",
                service="docker_volume",
                properties={"compose_volume": True},
            ))

        for net_name in (data.get("networks") or {}).keys():
            model.components.append(Component(
                id=f"compose.network.{net_name}",
                name=net_name,
                type=ComponentType.NETWORK,
                provider="docker",
                service="docker_network",
                properties={"compose_network": True},
            ))

        return model

    def _extract_service_props(self, name: str, svc: dict) -> dict[str, Any]:
        props: dict[str, Any] = {}
        props["image"] = svc.get("image", "")
        props["build"] = bool(svc.get("build"))
        props["privileged"] = svc.get("privileged", False)
        props["user"] = str(svc.get("user", ""))
        props["network_mode"] = svc.get("network_mode", "")
        props["pid"] = svc.get("pid", "")
        props["ipc"] = svc.get("ipc", "")
        props["read_only"] = svc.get("read_only", False)
        props["restart"] = svc.get("restart", "no")
        props["has_healthcheck"] = bool(svc.get("healthcheck"))

        ports = svc.get("ports") or []
        props["ports"] = [str(p) for p in ports]
        props["exposes_ports"] = bool(ports)

        volumes = svc.get("volumes") or []
        host_mounts = [str(v) for v in volumes if isinstance(v, str) and v.startswith("/")]
        host_mounts += [
            v.get("source", "") for v in volumes
            if isinstance(v, dict) and v.get("type") == "bind"
        ]
        props["host_mounts"] = host_mounts
        props["has_host_mounts"] = bool(host_mounts)

        env = svc.get("environment") or {}
        if isinstance(env, list):
            env_dict = {}
            for item in env:
                if "=" in str(item):
                    k, _, v = str(item).partition("=")
                    env_dict[k.strip()] = v.strip()
            env = env_dict
        props["environment"] = env
        props["env_file"] = bool(svc.get("env_file"))

        _sensitive = {"password", "secret", "token", "key", "apikey", "api_key", "credentials", "passwd"}
        props["possible_secret_env"] = [
            k for k in env if any(s in k.lower() for s in _sensitive) and env.get(k, "")
        ]

        caps = svc.get("cap_add") or []
        props["cap_add"] = caps
        props["security_opt"] = svc.get("security_opt") or []

        return props
