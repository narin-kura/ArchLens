"""ArchLens FastAPI web server."""

from __future__ import annotations
import os
import tempfile
from pathlib import Path
from typing import Optional

# Allow HF Spaces / Docker to inject the key via environment variable
if os.getenv("ANTHROPIC_API_KEY"):
    os.environ["ANTHROPIC_API_KEY"] = os.getenv("ANTHROPIC_API_KEY")

from fastapi import FastAPI, File, Form, UploadFile, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from archlens.parsers.registry import detect_parser
from archlens.analyzers.security import SecurityAnalyzer
from archlens.analyzers.cost import CostAnalyzer
from archlens.models.findings import AnalysisReport
from archlens.models.architecture import ArchitectureModel, Component, Connection, ComponentType

app = FastAPI(title="ArchLens", description="Architecture security & cost analyzer")

_STATIC = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")


@app.get("/", response_class=HTMLResponse)
def index():
    return (_STATIC / "index.html").read_text(encoding="utf-8")


@app.post("/analyze")
async def analyze(
    file: Optional[UploadFile] = File(default=None),
    text: Optional[str] = Form(default=None),
    format_hint: Optional[str] = Form(default=None),
):
    if not file and not text:
        raise HTTPException(status_code=400, detail="Provide either a file or a text description.")

    try:
        if file and file.filename:
            model = await _parse_upload(file, format_hint)
        else:
            model = _parse_text(text, format_hint)

        findings = SecurityAnalyzer().analyze(model) + CostAnalyzer().analyze(model)
        report = AnalysisReport(architecture_name=model.name, findings=findings)
        return _report_to_dict(report)

    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/analyze-interactive")
async def analyze_interactive(request: Request):
    try:
        data = await request.json()
        model = ArchitectureModel(
            name=data.get("name", "Interactive Diagram"),
            source="interactive",
        )
        for c in data.get("components", []):
            try:
                ctype = ComponentType[c.get("type", "OTHER")]
            except KeyError:
                ctype = ComponentType.OTHER
            model.components.append(Component(
                id=c["id"],
                name=c["name"],
                type=ctype,
                provider=c.get("provider", "generic"),
                service=c.get("service", ""),
            ))
        for conn in data.get("connections", []):
            model.connections.append(Connection(
                source_id=conn["source_id"],
                target_id=conn["target_id"],
                label=conn.get("label", ""),
            ))
        findings = SecurityAnalyzer().analyze(model) + CostAnalyzer().analyze(model)
        report = AnalysisReport(architecture_name=model.name, findings=findings)
        return _report_to_dict(report)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


async def _parse_upload(file: UploadFile, format_hint: Optional[str]) -> object:
    suffix = Path(file.filename).suffix
    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / file.filename
        dest.write_bytes(await file.read())
        # For .tf files use the tmp dir so TerraformParser can glob
        source = str(tmp) if suffix == ".tf" else str(dest)
        parser = detect_parser(source, format_hint)
        return parser.parse(source)


def _parse_text(text: str, format_hint: Optional[str]) -> object:
    parser = detect_parser(text, format_hint or "text")
    return parser.parse(text)


def _report_to_dict(report: AnalysisReport) -> dict:
    return {
        "architecture": report.architecture_name,
        "summary": {
            "security_count": len(report.security_findings),
            "cost_count": len(report.cost_findings),
            "estimated_savings": report.total_estimated_savings,
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
