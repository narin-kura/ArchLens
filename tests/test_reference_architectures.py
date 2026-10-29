"""Regression gate: every bundled reference architecture and fixture must
produce exactly the finding counts recorded in tests/baseline.json.

A changed count means an analyzer or parser change moved results. If the
change is intended, regenerate the baseline and review the diff:

    python tests/test_reference_architectures.py --update
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from archlens.engine import run_analysis  # noqa: E402

BASELINE = Path(__file__).with_name("baseline.json")
ARCH_DIRS = ("architectures", "architectures-azure", "architectures-gcp", "architectures-oracle")
FIXTURES = (
    "terraform",
    "kubernetes/insecure-demo.yaml",
    "cloud_exports/aws_config_export.json",
    "cloud_exports/cloudformation_stack.yaml",
    "cloud_exports/gcp_asset_inventory.json",
)


def _targets() -> dict[str, Path]:
    found = {}
    for sub in ARCH_DIRS:
        for d in sorted((ROOT / "examples" / sub).iterdir()):
            if d.is_dir():
                found[f"{sub}/{d.name}"] = d
    for f in FIXTURES:
        found[f] = ROOT / "examples" / f
    return found


def _counts(path: Path) -> dict[str, int]:
    findings = run_analysis(str(path)).findings
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
    return {"total": len(findings), **dict(sorted(by_sev.items()))}


TARGETS = _targets()


def test_every_target_is_in_the_baseline():
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    missing = sorted(set(TARGETS) - set(baseline))
    stale = sorted(set(baseline) - set(TARGETS))
    assert not missing, f"new targets without a baseline entry (run --update): {missing}"
    assert not stale, f"baseline entries with no target: {stale}"


@pytest.mark.parametrize("name", sorted(TARGETS))
def test_finding_counts_unchanged(name):
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    assert _counts(TARGETS[name]) == baseline[name]


if __name__ == "__main__" and "--update" in sys.argv:
    data = {name: _counts(path) for name, path in TARGETS.items()}
    BASELINE.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(data)} entries to {BASELINE.name}")
