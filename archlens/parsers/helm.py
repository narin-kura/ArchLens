"""Helm chart parser — renders a chart's templates with its default values and
reads the result exactly like plain Kubernetes manifests.

Rendering is done in-process by helm_render (no `helm` binary is run). If a
chart cannot be rendered at all, the parser falls back to reading values.yaml
alone, which is what ArchLens did before rendering existed."""

from __future__ import annotations
from pathlib import Path
from typing import Any

from .base import BaseParser
from .helm_render import RenderError, build_context, collect_defines, render_template
from .kubernetes import KubernetesParser
from ..models.architecture import ArchitectureModel, Component, ComponentType

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


class HelmParser(BaseParser):
    def can_parse(self, source: str | Path) -> bool:
        if not _YAML_AVAILABLE:
            return False
        p = Path(source)
        if p.is_dir():
            return (p / "Chart.yaml").exists() or (p / "Chart.yml").exists()
        if p.is_file() and p.name in ("Chart.yaml", "Chart.yml"):
            return True
        return False

    def parse(self, source: str | Path) -> ArchitectureModel:
        if not _YAML_AVAILABLE:
            raise ImportError("Install PyYAML: pip install pyyaml")
        p = Path(source)
        chart_dir = p if p.is_dir() else p.parent

        chart_meta = self._load_yaml(chart_dir / "Chart.yaml") or self._load_yaml(chart_dir / "Chart.yml") or {}
        values = self._load_yaml(chart_dir / "values.yaml") or self._load_yaml(chart_dir / "values.yml") or {}
        chart_name = chart_meta.get("name", chart_dir.name)

        model = ArchitectureModel(name=chart_name, source="helm")
        model.metadata["helm_version"] = chart_meta.get("version", "")
        model.metadata["helm_app_version"] = chart_meta.get("appVersion", "")
        model.metadata["helm_description"] = chart_meta.get("description", "")

        # Render templates/ with the default values, then read the output as
        # ordinary Kubernetes manifests so every Kubernetes check applies.
        rendered = self._render_chart(chart_dir, chart_meta, values, chart_name, model)
        if not rendered:
            # Nothing renderable: fall back to what values.yaml says.
            self._components_from_values(chart_name, values, model)

        if not model.components:
            model.components.append(Component(
                id=f"helm.chart.{chart_name}",
                name=chart_name,
                type=ComponentType.CONTAINER,
                provider="kubernetes",
                service="helm_chart",
                properties=self._chart_props(chart_meta, values),
            ))

        return model

    def _load_yaml(self, path: Path) -> dict | None:
        try:
            if path.exists():
                return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception:
            pass
        return None

    def _components_from_values(self, chart_name: str, values: dict, model: ArchitectureModel) -> None:
        image = values.get("image") or {}
        svc = values.get("service") or {}
        ingress = values.get("ingress") or {}
        resources = values.get("resources") or {}
        sc = values.get("securityContext") or {}
        pod_sc = values.get("podSecurityContext") or {}
        sa = values.get("serviceAccount") or {}
        persistence = values.get("persistence") or {}

        props: dict[str, Any] = {
            "image": f"{image.get('repository', '')}:{image.get('tag', 'latest')}",
            "image_pull_policy": image.get("pullPolicy", "IfNotPresent"),
            "replica_count": values.get("replicaCount", 1),
            "k8s_service_type": svc.get("type", "ClusterIP"),
            "k8s_has_tls": bool((ingress.get("tls") or [])),
            "k8s_has_ingress": ingress.get("enabled", False),
            "k8s_has_resource_limits": bool(resources.get("limits")),
            "k8s_has_resource_requests": bool(resources.get("requests")),
            "k8s_run_as_non_root": pod_sc.get("runAsNonRoot", sc.get("runAsNonRoot", False)),
            "k8s_run_as_user": pod_sc.get("runAsUser", sc.get("runAsUser", None)),
            "k8s_readonly_root_filesystem": sc.get("readOnlyRootFilesystem", False),
            "k8s_allow_privilege_escalation": sc.get("allowPrivilegeEscalation", True),
            "k8s_automount_sa_token": sa.get("automount", True),
            "k8s_service_account": sa.get("name", "default") if sa.get("create") else "default",
            "persistence_enabled": persistence.get("enabled", False),
            "k8s_images": [f"{image.get('repository', '')}:{image.get('tag', 'latest')}"],
        }

        env = values.get("env") or values.get("environment") or {}
        if isinstance(env, list):
            env = {e.get("name", ""): e.get("value", "") for e in env if isinstance(e, dict)}
        _sensitive = {"password", "secret", "token", "key", "apikey", "api_key", "credentials", "passwd"}
        props["possible_secret_env"] = [k for k in env if any(s in k.lower() for s in _sensitive) and env.get(k)]

        model.components.append(Component(
            id=f"helm.workload.{chart_name}",
            name=chart_name,
            type=ComponentType.CONTAINER,
            provider="kubernetes",
            service="helm_workload",
            properties=props,
        ))

        if ingress.get("enabled"):
            model.components.append(Component(
                id=f"helm.ingress.{chart_name}",
                name=f"{chart_name}-ingress",
                type=ComponentType.GATEWAY,
                provider="kubernetes",
                service="ingress",
                properties={
                    "k8s_kind": "Ingress",
                    "k8s_has_tls": bool(ingress.get("tls")),
                    "k8s_ingress_class": ingress.get("className", ""),
                },
            ))

        if persistence.get("enabled"):
            model.components.append(Component(
                id=f"helm.pvc.{chart_name}",
                name=f"{chart_name}-pvc",
                type=ComponentType.STORAGE,
                provider="kubernetes",
                service="persistentvolumeclaim",
                properties={"k8s_kind": "PersistentVolumeClaim"},
            ))

    def _render_chart(self, chart_dir: Path, chart_meta: dict, values: dict,
                      chart_name: str, model: ArchitectureModel) -> bool:
        templates_dir = chart_dir / "templates"
        if not templates_dir.is_dir():
            return False
        files = sorted(p for p in templates_dir.rglob("*") if p.is_file())
        texts: dict[Path, str] = {}
        for f in files:
            try:
                texts[f] = f.read_text(encoding="utf-8")
            except Exception:
                continue
        # Named templates can live in any file, conventionally _helpers.tpl.
        defines = collect_defines(list(texts.values()))
        context = build_context(values, chart_meta, release_name=chart_name)
        k8s = KubernetesParser()
        rendered_any = False
        skipped: list[str] = []
        for f, text in texts.items():
            if f.suffix not in (".yaml", ".yml") or f.name.startswith("_"):
                continue
            rel = f.relative_to(chart_dir).as_posix()
            context["Template"] = {"Name": f"{chart_name}/{rel}", "BasePath": f"{chart_name}/templates"}
            try:
                output = render_template(text, context, defines)
                docs = list(yaml.safe_load_all(output))
            except (RenderError, yaml.YAMLError, RecursionError):
                skipped.append(rel)
                continue
            for doc in docs:
                if not isinstance(doc, dict):
                    continue
                component = k8s._parse_resource(doc)
                if component is None:
                    continue
                component.id = component.id.replace("k8s.", "helm.", 1)
                component.properties["helm_template"] = rel
                model.components.append(component)
                rendered_any = True
        model.metadata["helm_rendered"] = rendered_any
        if skipped:
            model.metadata["helm_unrendered_templates"] = skipped
        return rendered_any

    def _chart_props(self, meta: dict, values: dict) -> dict:
        return {
            "chart_name": meta.get("name", ""),
            "chart_version": meta.get("version", ""),
            "app_version": meta.get("appVersion", ""),
            "dependencies": [d.get("name", "") for d in (meta.get("dependencies") or [])],
        }
