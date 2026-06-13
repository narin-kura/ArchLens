# Copyright (c) 2026 K.N.Narin (github.com/narin-kura). All rights reserved.
# Non-commercial use only. Commercial use requires written permission: github.com/narin-kura
# See LICENSE for full terms.
"""ArchLens FastAPI web server."""

from __future__ import annotations
import logging
import os
import tempfile
from pathlib import Path
from typing import Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


from fastapi import FastAPI, File, Form, UploadFile, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from archlens.parsers.registry import detect_parser
from archlens.analyzers.security import SecurityAnalyzer
from archlens.analyzers.cost import CostAnalyzer
from archlens.analyzers.ai import AIAnalyzer
from archlens.analyzers.kubernetes_security import KubernetesSecurityAnalyzer
from archlens.analyzers.cicd_security import CicdSecurityAnalyzer
from archlens.models.findings import AnalysisReport
from archlens.models.architecture import ArchitectureModel, Component, Connection, ComponentType
from archlens.recommender import recommend as build_recommendation

app = FastAPI(title="ArchLens", description="Architecture security & cost analyzer")

_STATIC = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")

MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB


@app.get("/", response_class=HTMLResponse)
def index():
    return (_STATIC / "index.html").read_text(encoding="utf-8")


@app.get("/health")
async def health():
    """Check app liveness and connectivity to each LLM provider."""
    providers: dict[str, dict] = {}

    gemini_key = os.getenv("GEMINI_API_KEY")
    if not gemini_key:
        providers["gemini"] = {"status": "missing_key"}
    else:
        try:
            await run_in_threadpool(_ping_gemini, gemini_key)
            providers["gemini"] = {"status": "ok"}
        except Exception as exc:
            providers["gemini"] = {"status": "error", "detail": str(exc)[:200]}

    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    if not anthropic_key:
        providers["anthropic"] = {"status": "missing_key"}
    else:
        try:
            await run_in_threadpool(_ping_anthropic, anthropic_key)
            providers["anthropic"] = {"status": "ok"}
        except Exception as exc:
            providers["anthropic"] = {"status": "error", "detail": str(exc)[:200]}

    # Degraded = a key is set but the provider can't be reached
    any_error = any(v["status"] == "error" for v in providers.values())
    overall = "degraded" if any_error else "healthy"
    return {"status": overall, "providers": providers}


def _ping_gemini(api_key: str) -> None:
    import google.generativeai as genai
    genai.configure(api_key=api_key, transport="rest")
    # list_models is the lightest authenticated call available
    next(iter(genai.list_models()), None)


def _ping_anthropic(api_key: str) -> None:
    import socket
    import anthropic

    # Step 1: raw TCP check — separates "can't reach host" from "SDK/auth issue"
    try:
        socket.setdefaulttimeout(8)
        socket.getaddrinfo("api.anthropic.com", 443)
    except OSError as exc:
        raise RuntimeError(f"DNS/TCP failed for api.anthropic.com: {exc}") from exc

    # Step 2: authenticated SDK call
    client = anthropic.Anthropic(api_key=api_key, timeout=10.0, max_retries=0)
    client.models.list(limit=1)


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
            if not text or not text.strip():
                raise HTTPException(status_code=400, detail="Text description cannot be empty.")
            # threadpool: LLM-backed parse must not block the event loop
            model = await run_in_threadpool(_parse_text, text, format_hint)

        findings = SecurityAnalyzer().analyze(model) + KubernetesSecurityAnalyzer().analyze(model) + CicdSecurityAnalyzer().analyze(model) + CostAnalyzer().analyze(model) + AIAnalyzer().analyze(model)
        report = AnalysisReport(architecture_name=model.name, findings=findings)
        return _report_to_dict(report, len(model.components))

    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        logger.exception("Unexpected error during analysis")
        raise HTTPException(
            status_code=500,
            detail="Analysis failed. Please check your file format and try again."
        )


@app.post("/analyze-interactive")
async def analyze_interactive(request: Request):
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body.")

    components_raw = data.get("components", [])
    if not components_raw:
        raise HTTPException(
            status_code=400,
            detail="No components selected. Please add at least one service to your stack."
        )

    try:
        model = ArchitectureModel(
            name=data.get("name", "My Stack"),
            source="interactive",
        )
        for c in components_raw:
            try:
                ctype = ComponentType[c.get("type", "OTHER")]
            except KeyError:
                ctype = ComponentType.OTHER
            model.components.append(Component(
                id=c.get("id", "unknown"),
                name=c.get("name", "unknown"),
                type=ctype,
                provider=c.get("provider", "generic"),
                service=c.get("service", ""),
            ))
        for conn in data.get("connections", []):
            try:
                model.connections.append(Connection(
                    source_id=conn["source_id"],
                    target_id=conn["target_id"],
                    label=conn.get("label", ""),
                ))
            except Exception:
                continue

        findings = SecurityAnalyzer().analyze(model) + KubernetesSecurityAnalyzer().analyze(model) + CicdSecurityAnalyzer().analyze(model) + CostAnalyzer().analyze(model) + AIAnalyzer().analyze(model)
        report = AnalysisReport(architecture_name=model.name, findings=findings)
        return _report_to_dict(report, len(model.components))

    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Unexpected error during interactive analysis")
        raise HTTPException(
            status_code=500,
            detail="Analysis failed. Please try again."
        )


@app.post("/recommend")
async def recommend(request: Request):
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body.")

    try:
        # threadpool: the AI-summary step may make a blocking network call
        return await run_in_threadpool(build_recommendation, data)
    except Exception:
        logger.exception("Unexpected error during recommendation")
        raise HTTPException(
            status_code=500,
            detail="Could not generate a recommendation. Please try again."
        )


async def _parse_upload(file: UploadFile, format_hint: Optional[str]) -> ArchitectureModel:
    content = await file.read()
    if len(content) > MAX_FILE_BYTES:
        raise ValueError(
            f"File is too large ({len(content) // 1024} KB). "
            f"Maximum allowed size is {MAX_FILE_BYTES // 1024 // 1024} MB."
        )
    suffix = Path(file.filename).suffix
    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / file.filename
        dest.write_bytes(content)
        source = str(tmp) if suffix == ".tf" else str(dest)
        parser = detect_parser(source, format_hint)
        # threadpool: text/LLM parsers must not block the event loop
        return await run_in_threadpool(parser.parse, source)


def _parse_text(text: str, format_hint: Optional[str]) -> ArchitectureModel:
    parser = detect_parser(text, format_hint or "text")
    return parser.parse(text)


def _report_to_dict(report: AnalysisReport, components_found: int = 0) -> dict:
    return {
        "architecture": report.architecture_name,
        "components_found": components_found,
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
                "references": f.references,
            }
            for f in report.findings
        ],
    }
