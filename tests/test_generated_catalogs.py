"""The Kubernetes and on-prem palette files are generated from Python modules;
fail if someone edits one side without regenerating the other."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize("script, output", [
    ("scripts/gen_k8s_catalog.py", "web/static/js/catalog_kubernetes.js"),
    ("scripts/gen_onprem_catalog.py", "web/static/js/catalog_onprem.js"),
])
def test_generated_catalog_is_in_sync(script, output):
    target = ROOT / output
    before = target.read_text(encoding="utf-8")
    try:
        subprocess.run([sys.executable, str(ROOT / script)], check=True, cwd=ROOT, capture_output=True)
        assert target.read_text(encoding="utf-8") == before, f"{output} is stale — run {script} and commit it"
    finally:
        target.write_text(before, encoding="utf-8")
