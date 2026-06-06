"""Kubernetes YAML parser — reads K8s manifests and builds an ArchitectureModel."""

from __future__ import annotations
from pathlib import Path
from typing import Any

from .base import BaseParser
from ..models.architecture import ArchitectureModel, Component, ComponentType, Connection

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


_KIND_TO_COMPONENT_TYPE: dict[str, ComponentType] = {
    "Pod":                  ComponentType.CONTAINER,
    "Deployment":           ComponentType.CONTAINER,
    "StatefulSet":          ComponentType.CONTAINER,
    "DaemonSet":            ComponentType.CONTAINER,
    "ReplicaSet":           ComponentType.CONTAINER,
    "Job":                  ComponentType.CONTAINER,
    "CronJob":              ComponentType.CONTAINER,
    "Service":              ComponentType.NETWORK,
    "Ingress":              ComponentType.GATEWAY,
    "NetworkPolicy":        ComponentType.NETWORK,
    "ServiceAccount":       ComponentType.IAM,
    "Role":                 ComponentType.IAM,
    "ClusterRole":          ComponentType.IAM,
    "RoleBinding":          ComponentType.IAM,
    "ClusterRoleBinding":   ComponentType.IAM,
    "PersistentVolume":     ComponentType.STORAGE,
    "PersistentVolumeClaim": ComponentType.STORAGE,
    "ConfigMap":            ComponentType.OTHER,
    "Secret":               ComponentType.OTHER,
    "Namespace":            ComponentType.OTHER,
    "HorizontalPodAutoscaler": ComponentType.COMPUTE,
}

_WORKLOAD_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}


class KubernetesParser(BaseParser):
    def can_parse(self, source: str | Path) -> bool:
        if not _YAML_AVAILABLE:
            return False
        p = Path(source)
        if p.is_dir():
            return any(p.rglob("*.yaml")) or any(p.rglob("*.yml"))
        if p.suffix in {".yaml", ".yml"} and p.exists():
            try:
                content = p.read_text(encoding="utf-8")
                return "apiVersion:" in content and "kind:" in content
            except Exception:
                return False
        return False

    def parse(self, source: str | Path) -> ArchitectureModel:
        if not _YAML_AVAILABLE:
            raise ImportError("Install PyYAML: pip install pyyaml")
        p = Path(source)
        model = ArchitectureModel(name=p.name, source="kubernetes")

        yaml_files = list(p.rglob("*.yaml")) + list(p.rglob("*.yml")) if p.is_dir() else [p]
        for yf in yaml_files:
            try:
                content = yf.read_text(encoding="utf-8")
                for doc in yaml.safe_load_all(content):
                    if doc and isinstance(doc, dict):
                        component = self._parse_resource(doc)
                        if component:
                            model.components.append(component)
            except Exception:
                continue
        return model

    def _parse_resource(self, doc: dict) -> Component | None:
        kind = doc.get("kind", "")
        if not kind:
            return None
        component_type = _KIND_TO_COMPONENT_TYPE.get(kind, ComponentType.OTHER)
        metadata = doc.get("metadata", {}) or {}
        name = metadata.get("name", "unknown")
        namespace = metadata.get("namespace", "default")

        props: dict[str, Any] = {"k8s_kind": kind, "k8s_namespace": namespace}

        if kind in _WORKLOAD_KINDS:
            self._extract_workload_props(doc, kind, props)
        elif kind == "Service":
            self._extract_service_props(doc, props)
        elif kind == "Ingress":
            self._extract_ingress_props(doc, props)
        elif kind in ("Role", "ClusterRole"):
            self._extract_role_props(doc, props)
        elif kind in ("RoleBinding", "ClusterRoleBinding"):
            self._extract_binding_props(doc, props)
        elif kind == "NetworkPolicy":
            self._extract_netpol_props(doc, props)
        elif kind == "ServiceAccount":
            self._extract_sa_props(doc, props)
        elif kind == "ConfigMap":
            self._extract_configmap_props(doc, props)
        elif kind == "Secret":
            self._extract_secret_props(doc, props)
        elif kind == "PersistentVolume":
            self._extract_pv_props(doc, props)

        return Component(
            id=f"k8s.{kind.lower()}.{namespace}.{name}",
            name=name,
            type=component_type,
            provider="kubernetes",
            service=kind.lower(),
            properties=props,
            tags=dict(metadata.get("labels") or {}),
        )

    def _extract_workload_props(self, doc: dict, kind: str, props: dict) -> None:
        if kind == "CronJob":
            spec = (doc.get("spec") or {}).get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {})
        elif kind == "Pod":
            spec = doc.get("spec") or {}
        else:
            spec = (doc.get("spec") or {}).get("template", {}).get("spec", {})

        spec = spec or {}
        props["k8s_host_network"] = spec.get("hostNetwork", False)
        props["k8s_host_pid"] = spec.get("hostPID", False)
        props["k8s_host_ipc"] = spec.get("hostIPC", False)
        props["k8s_automount_sa_token"] = spec.get("automountServiceAccountToken", True)
        props["k8s_service_account"] = spec.get("serviceAccountName", "default")

        volumes = spec.get("volumes") or []
        props["k8s_host_path_volumes"] = any("hostPath" in (v or {}) for v in volumes)

        pod_sc = spec.get("securityContext") or {}
        props["k8s_run_as_non_root"] = pod_sc.get("runAsNonRoot", False)
        props["k8s_run_as_user"] = pod_sc.get("runAsUser", None)
        props["k8s_seccomp_profile"] = (pod_sc.get("seccompProfile") or {}).get("type", "")
        props["k8s_sysctls"] = pod_sc.get("sysctls", [])

        containers = list(spec.get("containers") or []) + list(spec.get("initContainers") or [])

        has_limits = True
        has_requests = True
        has_liveness = True
        has_readiness = True
        images: list[str] = []
        worst_privileged = False
        worst_allow_priv_esc = False
        worst_readonly_rootfs = True
        all_caps_add: list[str] = []
        any_missing_sc = False
        any_drops_all = False

        for container in containers:
            container = container or {}
            images.append(container.get("image", ""))

            resources = container.get("resources") or {}
            if not resources.get("limits"):
                has_limits = False
            if not resources.get("requests"):
                has_requests = False

            if not container.get("livenessProbe"):
                has_liveness = False
            if not container.get("readinessProbe"):
                has_readiness = False

            sc = container.get("securityContext")
            if sc is None:
                any_missing_sc = True
                sc = {}

            if sc.get("privileged", False):
                worst_privileged = True
            if sc.get("allowPrivilegeEscalation", True):
                worst_allow_priv_esc = True
            if not sc.get("readOnlyRootFilesystem", False):
                worst_readonly_rootfs = False

            caps = sc.get("capabilities") or {}
            added = caps.get("add") or []
            dropped = caps.get("drop") or []
            all_caps_add.extend(added)
            if "ALL" in [d.upper() for d in dropped]:
                any_drops_all = True

        props["k8s_has_resource_limits"] = has_limits
        props["k8s_has_resource_requests"] = has_requests
        props["k8s_has_liveness_probe"] = has_liveness
        props["k8s_has_readiness_probe"] = has_readiness
        props["k8s_images"] = images
        props["k8s_privileged"] = worst_privileged
        props["k8s_allow_privilege_escalation"] = worst_allow_priv_esc
        props["k8s_readonly_root_filesystem"] = worst_readonly_rootfs
        props["k8s_capabilities_add"] = all_caps_add
        props["k8s_drops_all_caps"] = any_drops_all
        props["k8s_has_security_context"] = not any_missing_sc
        props["k8s_container_count"] = len(containers)

    def _extract_service_props(self, doc: dict, props: dict) -> None:
        spec = doc.get("spec") or {}
        props["k8s_service_type"] = spec.get("type", "ClusterIP")
        props["k8s_node_port"] = spec.get("nodePort")

    def _extract_ingress_props(self, doc: dict, props: dict) -> None:
        spec = doc.get("spec") or {}
        annotations = (doc.get("metadata") or {}).get("annotations") or {}
        props["k8s_has_tls"] = bool(spec.get("tls"))
        props["k8s_ingress_class"] = (
            annotations.get("kubernetes.io/ingress.class", "")
            or spec.get("ingressClassName", "")
        )
        props["k8s_has_default_backend"] = bool(spec.get("defaultBackend"))

    def _extract_role_props(self, doc: dict, props: dict) -> None:
        rules = doc.get("rules") or []
        props["k8s_wildcard_verbs"] = any("*" in (r.get("verbs") or []) for r in rules)
        props["k8s_wildcard_resources"] = any("*" in (r.get("resources") or []) for r in rules)
        props["k8s_wildcard_api_groups"] = any("*" in (r.get("apiGroups") or []) for r in rules)
        props["k8s_accesses_secrets"] = any("secrets" in (r.get("resources") or []) for r in rules)

    def _extract_binding_props(self, doc: dict, props: dict) -> None:
        role_ref = doc.get("roleRef") or {}
        props["k8s_role_ref"] = role_ref.get("name", "")
        props["k8s_is_cluster_admin"] = role_ref.get("name") == "cluster-admin"
        subjects = doc.get("subjects") or []
        props["k8s_binds_default_sa"] = any(
            (s or {}).get("name") == "default" and (s or {}).get("kind") == "ServiceAccount"
            for s in subjects
        )
        props["k8s_binds_all_sa"] = any((s or {}).get("kind") == "Group" and (s or {}).get("name") == "system:serviceaccounts" for s in subjects)

    def _extract_netpol_props(self, doc: dict, props: dict) -> None:
        spec = doc.get("spec") or {}
        props["k8s_policy_types"] = spec.get("policyTypes", [])
        props["k8s_netpol_allows_all_ingress"] = not bool(spec.get("ingress"))
        props["k8s_netpol_allows_all_egress"] = not bool(spec.get("egress"))
        props["k8s_netpol_empty_pod_selector"] = not bool(spec.get("podSelector"))

    def _extract_sa_props(self, doc: dict, props: dict) -> None:
        props["k8s_automount_sa_token"] = doc.get("automountServiceAccountToken", True)

    def _extract_configmap_props(self, doc: dict, props: dict) -> None:
        data = doc.get("data") or {}
        props["k8s_configmap_keys"] = list(data.keys())
        props["k8s_configmap_data"] = data

    def _extract_secret_props(self, doc: dict, props: dict) -> None:
        props["k8s_secret_type"] = doc.get("type", "Opaque")
        props["k8s_secret_keys"] = list((doc.get("data") or {}).keys())

    def _extract_pv_props(self, doc: dict, props: dict) -> None:
        spec = doc.get("spec") or {}
        props["k8s_pv_access_modes"] = spec.get("accessModes", [])
        props["k8s_pv_host_path"] = "hostPath" in spec
        props["k8s_pv_reclaim_policy"] = spec.get("persistentVolumeReclaimPolicy", "Delete")
