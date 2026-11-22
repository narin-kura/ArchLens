"""The diagram's Export Terraform / Export Kubernetes buttons are enabled only
when the diagram holds something that export can generate.

Runs the browser files under Node.js (same approach as test_k8s_export.py).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="Node.js is needed to run the browser exporters")

_RUNNER = """
global.window = {};
const js = process.argv[1] + '/web/static/js/';
require(js + 'tf-samples.js');
require(js + 'k8s-templates.js');
const {terraformExportableNodes} = require(js + 'terraform-export.js');
const {kubernetesExportableNodes} = require(js + 'k8s-export.js');
let input = '';
process.stdin.on('data', d => input += d);
process.stdin.on('end', () => {
  const nodes = JSON.parse(input);
  process.stdout.write(JSON.stringify({
    terraform: terraformExportableNodes(nodes).map(n => n.uid),
    kubernetes: kubernetesExportableNodes(nodes).map(n => n.uid),
  }));
});
"""


def _exportable(*nodes) -> dict:
    out = subprocess.run([NODE, "-e", _RUNNER, str(ROOT)], input=json.dumps(list(nodes)),
                         capture_output=True, text=True, encoding="utf-8", check=True).stdout
    return json.loads(out)


def _n(uid, provider, type_, service):
    return {"uid": uid, "name": uid, "provider": provider, "type": type_, "service": service}


S3 = _n("s3", "aws", "STORAGE", "aws_s3_bucket")
VM = _n("vm", "azure", "COMPUTE", "azurerm_linux_virtual_machine")
DEPLOY = _n("deploy", "kubernetes", "CONTAINER", "deployment")
SVC = _n("svc", "kubernetes", "NETWORK", "service")
NAMESPACE = _n("ns", "kubernetes", "OTHER", "namespace")
KARPENTER = _n("kp", "kubernetes", "OTHER", "karpenter_nodepool")
DOCKER_CONTAINER = _n("dc", "docker", "CONTAINER", "docker_container")
GENERIC_REDIS = _n("redis", "generic", "CACHE", "redis")
DATADOG = _n("dd", "generic", "MONITORING", "datadog")
RETIRED = _n("batch", "aws", "COMPUTE", "aws_batch")


def test_cloud_only_diagram_exports_terraform_not_kubernetes():
    assert _exportable(S3, VM) == {"terraform": ["s3", "vm"], "kubernetes": []}


def test_kubernetes_only_diagram_exports_kubernetes_not_terraform():
    assert _exportable(DEPLOY, SVC) == {"terraform": [], "kubernetes": ["deploy", "svc"]}


def test_mixed_diagram_exports_each_its_own_part():
    assert _exportable(S3, DEPLOY, DATADOG) == {"terraform": ["s3"], "kubernetes": ["deploy"]}


def test_namespace_alone_or_untemplated_kinds_do_not_enable_kubernetes():
    assert _exportable(NAMESPACE)["kubernetes"] == []
    assert _exportable(KARPENTER)["kubernetes"] == []
    assert _exportable(NAMESPACE, KARPENTER, DEPLOY)["kubernetes"] == ["deploy"]


def test_containers_and_self_hosted_stores_enable_kubernetes():
    # A Docker container is both a kreuzwerker/docker resource and something
    # Kubernetes can run; a generic Redis becomes a StatefulSet.
    assert _exportable(DOCKER_CONTAINER, GENERIC_REDIS) == {"terraform": ["dc"], "kubernetes": ["dc", "redis"]}


def test_tools_and_retired_types_enable_nothing():
    assert _exportable(DATADOG, RETIRED) == {"terraform": [], "kubernetes": []}
