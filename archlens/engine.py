"""Central engine — routes input to the right parser then runs all analyzers."""

from __future__ import annotations
from pathlib import Path

from .models.findings import AnalysisReport, Finding
from .parsers.registry import detect_parser
from .analyzers.security import SecurityAnalyzer
from .analyzers.cost import CostAnalyzer
from .analyzers.kubernetes_security import KubernetesSecurityAnalyzer


def run_analysis(source: str, format_hint: str | None = None) -> AnalysisReport:
    parser = detect_parser(source, format_hint)
    model = parser.parse(source)

    findings: list[Finding] = []
    for analyzer in [SecurityAnalyzer(), KubernetesSecurityAnalyzer(), CostAnalyzer()]:
        findings.extend(analyzer.analyze(model))

    return AnalysisReport(architecture_name=model.name, findings=findings)
