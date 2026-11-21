"""Diagram -> Kubernetes export (web/static/js/k8s-export.js).

The exporter runs in the browser; these tests run the same file under Node.js
and check the manifests it writes: valid YAML, wired from the diagram's
arrows, and clean under ArchLens's own analysis.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from archlens.engine import run_analysis  # noqa: E402

NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="Node.js is needed to run the browser exporter")

_RUNNER = """
global.window = {};
require(process.argv[1] + '/web/static/js/k8s-templates.js');
const {buildKubernetesExport} = require(process.argv[1] + '/web/static/js/k8s-export.js');
let input = '';
process.stdin.on('data', d => input += d);
process.stdin.on('end', () => {
  const {nodes, edges} = JSON.parse(input);
  process.stdout.write(buildKubernetesExport(nodes, edges).yaml);
});
"""


def _node(uid, name, service, provider="kubernetes", type_="OTHER"):
    return {"uid": uid, "name": name, "provider": provider, "type": type_, "service": service}


def _edge(a, b):
    return {"uid": f"{a}-{b}", "from": a, "to": b, "label": ""}


def _export(nodes, edges) -> str:
    result = subprocess.run([NODE, "-e", _RUNNER, str(ROOT)], input=json.dumps({"nodes": nodes, "edges": edges}),
                            capture_output=True, text=True, encoding="utf-8", check=True)
    return result.stdout


def _docs(text: str) -> list[dict]:
    return [d for d in yaml.safe_load_all(text) if d]


def _find(docs, kind, name):
    return next(d for d in docs if d["kind"] == kind and d["metadata"]["name"] == name)


def _templates() -> dict:
    return {p.stem.lower() for p in (ROOT / "scripts" / "k8s_templates").glob("*.yaml")}


SHOP = (
    [
        _node("ing", "Web Ingress", "ingress", type_="GATEWAY"),
        _node("svc", "web", "service", type_="NETWORK"),
        _node("web", "web", "deployment", type_="CONTAINER"),
        _node("db", "PostgreSQL", "postgres", provider="generic", type_="DATABASE"),
        _node("cm", "web-config", "configmap"),
        _node("sec", "db-credentials", "secret"),
        _node("hpa", "web-hpa", "horizontalpodautoscaler", type_="COMPUTE"),
        _node("s3", "Uploads", "aws_s3_bucket", provider="aws", type_="STORAGE"),
        _node("ns", "shop", "namespace"),
        _node("kp", "Karpenter NodePool", "karpenter_nodepool"),
    ],
    [_edge("ing", "svc"), _edge("svc", "web"), _edge("web", "db"), _edge("web", "cm"),
     _edge("web", "sec"), _edge("hpa", "web"), _edge("web", "s3")],
)


def test_export_uses_every_template_and_passes_analysis(tmp_path):
    kinds = sorted(_templates() - {"namespace"})
    nodes = [_node(k, f"my-{k}", k, type_="CONTAINER" if k in
                   {"deployment", "statefulset", "daemonset", "job", "cronjob", "pod"} else "OTHER") for k in kinds]
    nodes.append(_node("namespace", "prod", "namespace"))
    edges = [_edge("ingress", "service"), _edge("service", "deployment"), _edge("gateway", "httproute"),
             _edge("httproute", "service"), _edge("horizontalpodautoscaler", "deployment"),
             _edge("poddisruptionbudget", "deployment"), _edge("deployment", "configmap"),
             _edge("deployment", "secret"), _edge("deployment", "persistentvolumeclaim"),
             _edge("deployment", "serviceaccount"), _edge("rolebinding", "role"),
             _edge("rolebinding", "serviceaccount"), _edge("deployment", "statefulset"),
             _edge("cronjob", "statefulset")]
    text = _export(nodes, edges)
    docs = _docs(text)
    assert {d["kind"].lower() for d in docs} == _templates()
    assert all(d["metadata"].get("namespace") == "prod" for d in docs if d["kind"] != "Namespace")

    out = tmp_path / "export.yaml"
    out.write_text(text, encoding="utf-8")
    findings = run_analysis(str(out)).findings
    assert findings == [], [f.title for f in findings]


def test_arrows_wire_the_objects():
    docs = _docs(_export(*SHOP))
    deploy = _find(docs, "Deployment", "web")
    container = deploy["spec"]["template"]["spec"]["containers"][0]
    assert {"configMapRef": {"name": "web-config"}} in container["envFrom"]
    assert {"secretRef": {"name": "db-credentials"}} in container["envFrom"]
    assert "replicas" not in deploy["spec"], "the autoscaler owns the replica count"
    assert deploy["spec"]["template"]["spec"]["serviceAccountName"] == "web"

    assert _find(docs, "Service", "web")["spec"]["selector"] == {"app.kubernetes.io/name": "web"}
    ingress = _find(docs, "Ingress", "web-ingress")
    assert ingress["spec"]["rules"][0]["http"]["paths"][0]["backend"]["service"]["name"] == "web"
    assert _find(docs, "HorizontalPodAutoscaler", "web-hpa")["spec"]["scaleTargetRef"]["name"] == "web"

    db = _find(docs, "StatefulSet", "postgresql")
    assert db["spec"]["serviceName"] == "postgresql"
    assert _find(docs, "Service", "postgresql")["spec"]["clusterIP"] == "None"

    to_db = _find(docs, "NetworkPolicy", "allow-to-postgresql")
    assert to_db["spec"]["ingress"][0]["from"] == [{"podSelector": {"matchLabels": {"app.kubernetes.io/name": "web"}}}]
    to_web = _find(docs, "NetworkPolicy", "allow-to-web")
    assert "namespaceSelector" in to_web["spec"]["ingress"][0]["from"][0]
    assert _find(docs, "NetworkPolicy", "default-deny")["spec"]["podSelector"] == {}


def test_unsupported_and_external_nodes_are_listed_not_invented():
    text = _export(*SHOP)
    assert '"Karpenter NodePool" (karpenter_nodepool)' in text
    assert '"Uploads" (aws aws_s3_bucket)' in text
    kinds = {d["kind"] for d in _docs(text)}
    assert "NodePool" not in kinds and "Bucket" not in kinds


def test_names_are_made_dns_safe_and_unique():
    nodes = [_node("a", "My API (v2)!", "deployment", type_="CONTAINER"),
             _node("b", "My API (v2)!", "deployment", type_="CONTAINER")]
    names = sorted(d["metadata"]["name"] for d in _docs(_export(nodes, [])) if d["kind"] == "Deployment")
    assert names == ["my-api-v2", "my-api-v2-2"]


def test_browser_templates_match_yaml_sources():
    spec = importlib.util.spec_from_file_location("gen", ROOT / "scripts" / "gen_k8s_templates.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    expected = {p.stem.lower(): gen.load(p) for p in sorted(gen.SRC.glob("*.yaml"))}
    js = (ROOT / "web" / "static" / "js" / "k8s-templates.js").read_text(encoding="utf-8")
    actual = json.loads(js.split("window.K8S_TEMPLATES = ", 1)[1].rstrip().rstrip(";"))
    assert actual == expected, "run: python scripts/gen_k8s_templates.py"
