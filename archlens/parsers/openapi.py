"""OpenAPI / Swagger parser — reads API spec files and builds an ArchitectureModel."""

from __future__ import annotations
import json
from pathlib import Path
from typing import Any

from .base import BaseParser
from ..models.architecture import ArchitectureModel, Component, ComponentType

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


def _load(path: Path) -> dict | None:
    content = path.read_text(encoding="utf-8")
    if _YAML_AVAILABLE:
        try:
            return yaml.safe_load(content)
        except Exception:
            pass
    try:
        return json.loads(content)
    except Exception:
        return None


def _is_openapi(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    return bool(data.get("openapi") or data.get("swagger"))


class OpenAPIParser(BaseParser):
    def can_parse(self, source: str | Path) -> bool:
        p = Path(source)
        if not p.is_file() or p.suffix not in {".json", ".yaml", ".yml"}:
            return False
        try:
            content = p.read_text(encoding="utf-8")
            return ("openapi:" in content or '"openapi"' in content
                    or "swagger:" in content or '"swagger"' in content)
        except Exception:
            return False

    def parse(self, source: str | Path) -> ArchitectureModel:
        p = Path(source)
        data = _load(p)
        if not data or not _is_openapi(data):
            raise ValueError(f"Not a valid OpenAPI/Swagger file: {p}")

        spec_version = data.get("openapi") or data.get("swagger", "")
        title = (data.get("info") or {}).get("title", p.stem)
        model = ArchitectureModel(name=title, source="openapi")

        paths = data.get("paths") or {}
        components_sec = data.get("components") or {}
        security_schemes = (
            components_sec.get("securitySchemes")
            or data.get("securityDefinitions")
            or {}
        )
        servers = data.get("servers") or [data.get("host", "")]

        auth_types = [
            (v.get("type") or v.get("in") or "").lower()
            for v in security_schemes.values()
            if isinstance(v, dict)
        ]
        global_security = data.get("security") or []
        has_global_auth = bool(global_security)

        endpoint_count = len(paths)
        methods: list[str] = []
        unauth_endpoints: list[str] = []
        for path_str, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method in ("get", "post", "put", "patch", "delete", "options"):
                op = path_item.get(method)
                if not isinstance(op, dict):
                    continue
                methods.append(method.upper())
                op_security = op.get("security")
                if op_security is not None and op_security == []:
                    unauth_endpoints.append(f"{method.upper()} {path_str}")
                elif not has_global_auth and op_security is None:
                    unauth_endpoints.append(f"{method.upper()} {path_str}")

        model.components.append(Component(
            id=f"openapi.gateway.{title}",
            name=title,
            type=ComponentType.GATEWAY,
            provider="generic",
            service="openapi_gateway",
            properties={
                "spec_version": str(spec_version),
                "servers": [str(s.get("url", s) if isinstance(s, dict) else s) for s in servers],
                "endpoint_count": endpoint_count,
                "http_methods": list(set(methods)),
                "auth_types": auth_types,
                "has_global_auth": has_global_auth,
                "unauth_endpoints": unauth_endpoints,
                "unauth_endpoint_count": len(unauth_endpoints),
                "security_schemes": list(security_schemes.keys()),
                "has_oauth2": any("oauth" in a for a in auth_types),
                "has_api_key": any("apikey" in a or "api_key" in a for a in auth_types),
                "has_http_basic": any(a == "http" for a in auth_types),
            },
        ))

        # Schemas may reveal sensitive data models
        schemas = components_sec.get("schemas") or {}
        _sensitive_fields = {"password", "secret", "token", "ssn", "credit_card", "cvv", "pin"}
        for schema_name, schema in schemas.items():
            if not isinstance(schema, dict):
                continue
            props_keys = set((schema.get("properties") or {}).keys())
            sensitive = [k for k in props_keys if any(s in k.lower() for s in _sensitive_fields)]
            if sensitive:
                model.components.append(Component(
                    id=f"openapi.schema.{schema_name}",
                    name=schema_name,
                    type=ComponentType.OTHER,
                    provider="generic",
                    service="openapi_schema",
                    properties={
                        "sensitive_fields": sensitive,
                        "field_count": len(props_keys),
                    },
                ))

        return model
