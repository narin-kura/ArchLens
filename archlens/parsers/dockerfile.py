"""Dockerfile parser — reads Dockerfiles and builds an ArchitectureModel."""

from __future__ import annotations
import re
from pathlib import Path

from .base import BaseParser
from ..models.architecture import ArchitectureModel, Component, ComponentType


class DockerfileParser(BaseParser):
    def can_parse(self, source: str | Path) -> bool:
        p = Path(source)
        if not p.is_file():
            return False
        name = p.name.lower()
        return name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile")

    def parse(self, source: str | Path) -> ArchitectureModel:
        p = Path(source)
        content = p.read_text(encoding="utf-8")
        model = ArchitectureModel(name=p.name, source="dockerfile")

        props = self._extract_props(content)
        model.components.append(Component(
            id=f"dockerfile.{p.name}",
            name=p.name,
            type=ComponentType.CONTAINER,
            provider="docker",
            service="dockerfile",
            properties=props,
        ))
        return model

    def _extract_props(self, content: str) -> dict:
        lines = [l.strip() for l in content.splitlines() if l.strip() and not l.strip().startswith("#")]
        props: dict = {}

        # Base images (FROM instructions)
        from_images = [m.group(1).strip() for l in lines if (m := re.match(r"^FROM\s+(.+?)(?:\s+AS\s+\S+)?$", l, re.I))]
        props["base_images"] = from_images
        props["base_image"] = from_images[-1] if from_images else ""
        props["multi_stage"] = len(from_images) > 1

        # Check for :latest or no-tag base images
        unsafe_images = [img for img in from_images if img != "scratch" and (":latest" in img or (":" not in img and "@" not in img))]
        props["latest_base_image"] = bool(unsafe_images)
        props["latest_base_image_names"] = unsafe_images

        # USER instruction
        user_instrs = [re.match(r"^USER\s+(.+)$", l, re.I) for l in lines]
        user_matches = [m.group(1).strip() for m in user_instrs if m]
        final_user = user_matches[-1] if user_matches else ""
        props["user"] = final_user
        props["runs_as_root"] = final_user in ("", "0", "root") or not final_user

        # EXPOSE instructions
        expose_matches = [re.findall(r"\d+", l) for l in lines if re.match(r"^EXPOSE\s+", l, re.I)]
        exposed_ports = [port for ports in expose_matches for port in ports]
        props["exposed_ports"] = exposed_ports
        props["exposes_privileged_port"] = any(int(p) < 1024 for p in exposed_ports if p.isdigit())

        # HEALTHCHECK
        props["has_healthcheck"] = any(re.match(r"^HEALTHCHECK\s+", l, re.I) for l in lines)

        # ADD vs COPY (ADD can fetch URLs and extract archives — security risk)
        props["uses_add"] = any(re.match(r"^ADD\s+", l, re.I) for l in lines)

        # ENV instructions — check for hardcoded secrets
        env_lines = [re.match(r"^ENV\s+(.+)$", l, re.I) for l in lines]
        env_vars: dict[str, str] = {}
        for m in env_lines:
            if not m:
                continue
            pair = m.group(1).strip()
            if "=" in pair:
                k, _, v = pair.partition("=")
                env_vars[k.strip()] = v.strip().strip('"').strip("'")
            else:
                parts = pair.split(None, 1)
                if len(parts) == 2:
                    env_vars[parts[0]] = parts[1]
        _sensitive = {"password", "secret", "token", "key", "apikey", "api_key", "credentials", "passwd"}
        props["env_vars"] = list(env_vars.keys())
        props["possible_secret_env"] = [k for k in env_vars if any(s in k.lower() for s in _sensitive)]

        # Privileged-ish RUN patterns
        run_lines = [l for l in lines if re.match(r"^RUN\s+", l, re.I)]
        props["run_as_sudo"] = any("sudo" in l.lower() or "su " in l.lower() for l in run_lines)
        props["installs_curl_wget"] = any(re.search(r"\b(curl|wget)\b", l) for l in run_lines)
        props["downloads_and_executes"] = any(
            re.search(r"(curl|wget).+\|\s*(bash|sh|python|ruby|perl)", l) for l in run_lines
        )

        # COPY --chown usage (good practice)
        props["uses_copy_chown"] = any("--chown" in l.lower() for l in lines if re.match(r"^COPY\s+", l, re.I))

        # Secrets in build args (ARG instructions)
        arg_lines = [re.match(r"^ARG\s+(\w+)", l, re.I) for l in lines]
        arg_names = [m.group(1) for m in arg_lines if m]
        props["build_args"] = arg_names
        props["possible_secret_build_arg"] = [a for a in arg_names if any(s in a.lower() for s in _sensitive)]

        return props
