"""Kubernetes and Helm analysis: template rendering, checks, and archive uploads."""

from __future__ import annotations

import io
import sys
import tarfile
import textwrap
import zipfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from archlens.archive import ArchiveError, extract_archive  # noqa: E402
from archlens.engine import run_analysis  # noqa: E402
from archlens.models.findings import FindingType  # noqa: E402
from archlens.parsers.helm_render import build_context, collect_defines, render_template  # noqa: E402

CHART = ROOT / "examples" / "helm" / "web-app"
DEMO = ROOT / "examples" / "kubernetes" / "insecure-demo.yaml"


def _titles(source) -> list[str]:
    return [f.title for f in run_analysis(str(source)).findings]


def _render(template: str, values: dict, helpers: str = "") -> str:
    ctx = build_context(values, {"name": "app", "version": "1.0.0", "appVersion": "2.0"}, "app")
    return render_template(textwrap.dedent(template), ctx, collect_defines([helpers]))


# ------------------------------------------------------------------ renderer

def test_render_trims_include_and_nindent():
    helpers = '{{- define "app.labels" -}}\napp: {{ .Chart.Name }}\nver: {{ .Chart.AppVersion | quote }}\n{{- end }}'
    out = _render("""
        metadata:
          labels:
            {{- include "app.labels" . | nindent 4 }}
        """, {}, helpers)
    assert yaml.safe_load(out) == {"metadata": {"labels": {"app": "app", "ver": "2.0"}}}


def test_render_with_range_if_else_and_variables():
    out = _render("""
        {{- $port := .Values.port | default 8080 }}
        {{- with .Values.sc }}
        securityContext:
          {{- toYaml . | nindent 2 }}
        {{- end }}
        hosts:
        {{- range .Values.hosts }}
          - {{ printf "%s:%v" .name $port | quote }}
        {{- end }}
        {{- if .Values.tls }}
        tls: "on"
        {{- else if .Values.plain }}
        tls: "off"
        {{- else }}
        tls: "none"
        {{- end }}
        """, {"sc": {"runAsNonRoot": True}, "hosts": [{"name": "a"}, {"name": "b"}], "plain": True})
    doc = yaml.safe_load(out)
    assert doc["securityContext"] == {"runAsNonRoot": True}
    assert doc["hosts"] == ["a:8080", "b:8080"]
    assert doc["tls"] == "off"


def test_render_fullname_helper_like_helm_create():
    helpers = (CHART / "templates" / "_helpers.tpl").read_text(encoding="utf-8")
    assert _render('{{ include "web-app.fullname" . }}', {}, helpers) == "app"
    assert _render('{{ include "web-app.fullname" . }}', {"fullnameOverride": "custom"}, helpers) == "custom"


def test_render_unknown_function_degrades_to_empty():
    assert _render("x: {{ someSprigFunc .Values.a }}", {"a": 1}).strip() == "x:"


# ------------------------------------------------------------- Helm charts

def test_helm_chart_gets_full_kubernetes_checks():
    titles = _titles(CHART)
    for expected in (
        "Workload 'web-app' runs a privileged container",
        "Workload 'web-app' uses ':latest' image tag: nginx:latest",
        "Workload 'web-app' adds dangerous capabilities: NET_ADMIN",
        "Workload 'web-app' sets credentials as plain env values: DB_PASSWORD",
        "Secret 'web-app-api' has its values written in the manifest",
        "Ingress 'web-app' has no TLS configured",
        "Service 'web-app-admin' is type LoadBalancer (public cloud LB per service)",
        "2 Services each create their own cloud load balancer",
        "'web-app' runs a fixed 4 replicas with no autoscaler",
    ):
        assert expected in titles, expected


def test_helm_chart_without_namespace_is_not_flagged_for_default_namespace():
    assert not any("'default' namespace" in t for t in _titles(CHART))


def test_helm_autoscaler_suppresses_fixed_replica_finding(tmp_path):
    chart = tmp_path / "web-app"
    _copy_tree(CHART, chart)
    values = yaml.safe_load((chart / "values.yaml").read_text())
    values["autoscaling"]["enabled"] = True
    (chart / "values.yaml").write_text(yaml.safe_dump(values))
    assert not any("fixed" in t and "replicas" in t for t in _titles(chart))


# -------------------------------------------------- plain Kubernetes manifests

def test_kubernetes_manifest_gets_no_cloud_only_findings():
    titles = _titles(DEMO)
    for wrong in ("public access block", "versioning", "API Gateway", "no backup configured",
                  "not encrypted at rest", "No monitoring", "No WAF"):
        assert not any(wrong in t for t in titles), wrong


def test_cluster_scoped_objects_are_not_flagged_for_default_namespace():
    titles = _titles(DEMO)
    assert "Resource 'data-pv' is deployed in the 'default' namespace" not in titles
    assert "Resource 'admin-binding' is deployed in the 'default' namespace" not in titles
    assert "Resource 'api-server' is deployed in the 'default' namespace" in titles


def test_secret_key_ref_is_not_a_literal_secret(tmp_path):
    manifest = tmp_path / "app.yaml"
    manifest.write_text(textwrap.dedent("""
        apiVersion: apps/v1
        kind: Deployment
        metadata: {name: api}
        spec:
          replicas: 1
          template:
            spec:
              containers:
                - name: api
                  image: registry.example.com/api:1.2.3
                  env:
                    - name: DB_PASSWORD
                      valueFrom: {secretKeyRef: {name: db, key: password}}
                    - name: API_TOKEN
                      value: "plain-text-token"
        ---
        apiVersion: v1
        kind: Secret
        metadata: {name: empty}
        stringData: {password: ""}
        """))
    titles = _titles(manifest)
    assert "Workload 'api' sets credentials as plain env values: API_TOKEN" in titles
    assert not any("Secret 'empty'" in t for t in titles)


def test_single_loadbalancer_is_not_a_cost_finding(tmp_path):
    manifest = tmp_path / "svc.yaml"
    manifest.write_text("apiVersion: v1\nkind: Service\nmetadata: {name: web}\nspec: {type: LoadBalancer}\n")
    costs = [f for f in run_analysis(str(manifest)).findings if f.type == FindingType.COST]
    assert not any("load balancer" in f.title for f in costs)


# ------------------------------------------------------------------ archives

def _copy_tree(src: Path, dest: Path) -> None:
    for p in src.rglob("*"):
        if p.is_file():
            target = dest / p.relative_to(src)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(p.read_bytes())


def _chart_tgz() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        tf.add(CHART, arcname="web-app")
    return buf.getvalue()


def test_tgz_chart_extracts_to_chart_root(tmp_path):
    root = extract_archive(_chart_tgz(), "web-app-0.1.0.tgz", tmp_path / "x")
    assert (root / "Chart.yaml").exists()
    assert "Workload 'web-app' runs a privileged container" in _titles(root)


def test_zip_with_parent_path_is_rejected(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../evil.yaml", "kind: Pod")
    with pytest.raises(ArchiveError):
        extract_archive(buf.getvalue(), "bad.zip", tmp_path / "x")
    assert not (tmp_path / "evil.yaml").exists()


def test_tar_links_are_skipped(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        link = tarfile.TarInfo("manifests/passwd")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tf.addfile(link)
        data = b"apiVersion: v1\nkind: Service\nmetadata: {name: web}\n"
        info = tarfile.TarInfo("manifests/svc.yaml")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    root = extract_archive(buf.getvalue(), "m.tgz", tmp_path / "x")
    assert not (root / "passwd").exists()
    assert (root / "svc.yaml").exists()


def test_oversized_archive_is_rejected(tmp_path, monkeypatch):
    import archlens.archive as archive
    monkeypatch.setattr(archive, "MAX_TOTAL_BYTES", 1000)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.yaml", "a" * 5000)
    with pytest.raises(ArchiveError):
        extract_archive(buf.getvalue(), "big.zip", tmp_path / "x")


def test_web_upload_of_helm_chart_tgz():
    from fastapi.testclient import TestClient
    from web.app import app

    client = TestClient(app)
    resp = client.post("/analyze", files={"file": ("web-app-0.1.0.tgz", _chart_tgz(), "application/gzip")})
    assert resp.status_code == 200, resp.text
    body = resp.text
    assert "runs a privileged container" in body
    assert "sets credentials as plain env values" in body


def test_web_upload_rejects_hostile_zip():
    from fastapi.testclient import TestClient
    from web.app import app

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../evil.yaml", "kind: Pod")
    resp = TestClient(app).post("/analyze", files={"file": ("bad.zip", buf.getvalue(), "application/zip")})
    assert resp.status_code == 422
    assert "leaves its folder" in resp.json()["detail"]
