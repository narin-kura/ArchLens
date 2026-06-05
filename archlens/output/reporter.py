"""Report renderer — console, JSON, and markdown output."""

from __future__ import annotations
import json
import sys
from pathlib import Path

from ..models.findings import AnalysisReport, FindingType, Severity


_SEVERITY_ICONS = {
    Severity.CRITICAL: "[CRIT]",
    Severity.HIGH:     "[HIGH]",
    Severity.MEDIUM:   "[MED] ",
    Severity.LOW:      "[LOW] ",
    Severity.INFO:     "[INFO]",
}


def print_report(
    report: AnalysisReport,
    output_format: str = "console",
    out_file: str | None = None,
) -> None:
    if output_format == "json":
        content = _to_json(report)
    elif output_format == "markdown":
        content = _to_markdown(report)
    else:
        content = _to_console(report)

    if out_file:
        Path(out_file).write_text(content, encoding="utf-8")
        print(f"Report written to {out_file}")
    else:
        print(content)


def _to_console(report: AnalysisReport) -> str:
    lines = []
    lines.append(f"\n{'=' * 60}")
    lines.append(f"  ArchLens Report -- {report.architecture_name}")
    lines.append(f"{'=' * 60}\n")

    sec = report.security_findings
    cost = report.cost_findings

    if sec:
        lines.append(f"[SECURITY] Findings ({len(sec)})")
        lines.append("-" * 60)
        for f in sorted(sec, key=lambda x: list(Severity).index(x.severity)):
            icon = _SEVERITY_ICONS[f.severity]
            comp = f"[{f.component_name}] " if f.component_name else ""
            lines.append(f"  {icon} {comp}{f.title}")
            lines.append(f"           {f.recommendation}")
            lines.append("")

    if cost:
        total = report.total_estimated_savings
        lines.append(f"[COST] Findings ({len(cost)}" + (f" -- est. ${total:.0f}/mo savings)" if total else ")"))
        lines.append("-" * 60)
        for f in cost:
            icon = _SEVERITY_ICONS[f.severity]
            savings = f"  (-${f.estimated_savings:.0f}/mo)" if f.estimated_savings else ""
            lines.append(f"  {icon} {f.title}{savings}")
            lines.append(f"           {f.recommendation}")
            lines.append("")

    if not sec and not cost:
        lines.append("  [OK] No findings. Architecture looks good!")

    return "\n".join(lines)


def _to_markdown(report: AnalysisReport) -> str:
    lines = [f"# ArchLens Report — {report.architecture_name}\n"]

    sec = report.security_findings
    if sec:
        lines.append(f"## 🔐 Security Findings ({len(sec)})\n")
        for f in sorted(sec, key=lambda x: list(Severity).index(x.severity)):
            lines.append(f"### {f.severity.upper()}: {f.title}")
            if f.component_name:
                lines.append(f"**Component:** {f.component_name}")
            lines.append(f"\n{f.description}\n")
            lines.append(f"**Recommendation:** {f.recommendation}\n")

    cost = report.cost_findings
    if cost:
        total = report.total_estimated_savings
        lines.append(f"## 💰 Cost Findings ({len(cost)})")
        if total:
            lines.append(f"**Estimated monthly savings: ${total:.0f}**\n")
        for f in cost:
            lines.append(f"### {f.title}")
            if f.estimated_savings:
                lines.append(f"**Estimated saving:** ${f.estimated_savings:.0f}/mo")
            lines.append(f"\n{f.description}\n")
            lines.append(f"**Recommendation:** {f.recommendation}\n")

    return "\n".join(lines)


def _to_json(report: AnalysisReport) -> str:
    data = {
        "architecture": report.architecture_name,
        "summary": {
            "security_findings": len(report.security_findings),
            "cost_findings": len(report.cost_findings),
            "estimated_monthly_savings": report.total_estimated_savings,
        },
        "findings": [
            {
                "type": f.type.value,
                "severity": f.severity.value,
                "title": f.title,
                "description": f.description,
                "component": f.component_name,
                "recommendation": f.recommendation,
                "estimated_savings": f.estimated_savings,
            }
            for f in report.findings
        ],
    }
    return json.dumps(data, indent=2)
