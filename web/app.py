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
from archlens.analyzers.topology import TopologyAnalyzer
from archlens.analyzers.cicd_security import CicdSecurityAnalyzer
from archlens.models.findings import AnalysisReport
from archlens.models.architecture import ArchitectureModel, Component, Connection, ComponentType
from archlens.recommender import recommend as build_recommendation

app = FastAPI(title="ArchLens", description="Architecture security & cost analyzer")

_STATIC = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")

MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB


def _page(name: str) -> HTMLResponse:
    return HTMLResponse((_STATIC / name).read_text(encoding="utf-8"))


@app.get("/", response_class=HTMLResponse)
def index():
    return _page("index.html")


@app.get("/analyze", response_class=HTMLResponse)
def analyze_page():
    return _page("analyze.html")


@app.get("/diagram", response_class=HTMLResponse)
def diagram_page():
    return _page("diagram.html")


@app.get("/examples", response_class=HTMLResponse)
def examples_page():
    return _page("examples.html")


# The bundled reference architectures. Keyed by slug so a request can never
# reach a path outside these directories. Both clouds reuse the same
# "01-three-tier-web-app"-style directory names, so the slug is prefixed with
# the provider to stay unique and URL-safe.
_EXAMPLES_ROOT = Path(__file__).resolve().parent.parent / "examples"
_EXAMPLE_DIRS = {
    "aws": _EXAMPLES_ROOT / "architectures",
    "azure": _EXAMPLES_ROOT / "architectures-azure",
}


def _example_slugs() -> dict[str, tuple[str, Path]]:
    slugs: dict[str, tuple[str, Path]] = {}
    for provider, base in _EXAMPLE_DIRS.items():
        if not base.is_dir():
            continue
        for d in sorted(base.iterdir()):
            if d.is_dir() and (d / "main.tf").is_file():
                slugs[f"{provider}-{d.name}"] = (provider, d / "main.tf")
    return slugs


def _example_summary(slug: str, provider: str, path: Path) -> dict:
    """Title, blurb and service list come from the file's header comment."""
    lines = path.read_text(encoding="utf-8").splitlines()
    comment = []
    for line in lines:
        if line.startswith("#"):
            comment.append(line.lstrip("#").strip())
        elif comment:
            break
    title = comment[0].split("—")[-1].strip() if comment else slug
    body = " ".join(comment[1:]).strip()
    services, expected, blurb = "", "", body
    for marker, field in (("Services:", "services"), ("Expected ArchLens findings:", "expected")):
        if marker in body:
            after = body.split(marker, 1)[1]
            for other in ("Services:", "Expected ArchLens findings:"):
                if other != marker and other in after:
                    after = after.split(other, 1)[0]
            value = after.strip()
            if field == "services":
                services = value
            else:
                expected = value
    blurb = body.split("Services:")[0].strip()
    return {
        "slug": slug,
        "provider": provider,
        "number": path.parent.name.split("-", 1)[0],
        "title": title,
        "description": blurb,
        "services": [s.strip(" .") for s in services.split(",") if s.strip(" .")],
        "expected": expected,
        "lines": len(lines),
    }


@app.get("/api/examples")
def list_examples():
    return {
        "examples": [
            _example_summary(slug, provider, path)
            for slug, (provider, path) in _example_slugs().items()
        ]
    }


@app.post("/api/examples/{slug}/analyze")
async def analyze_example(slug: str):
    entry = _example_slugs().get(slug)
    if entry is None:
        raise HTTPException(status_code=404, detail="No such example architecture.")
    _, path = entry
    try:
        parser = detect_parser(str(path.parent), "terraform")
        model = await run_in_threadpool(parser.parse, str(path.parent))
        findings = (SecurityAnalyzer().analyze(model) + KubernetesSecurityAnalyzer().analyze(model)
                    + CicdSecurityAnalyzer().analyze(model) + TopologyAnalyzer().analyze(model)
                    + CostAnalyzer().analyze(model) + AIAnalyzer().analyze(model))
        report = AnalysisReport(architecture_name=slug, findings=findings)
        return _report_to_dict(report, len(model.components))
    except Exception:
        logger.exception("Failed to analyze bundled example %s", slug)
        raise HTTPException(status_code=500, detail="Could not analyze that example.")


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
    # Strip whitespace/newlines a corrupted secret may carry (Windows echo footgun)
    genai.configure(api_key=api_key.strip(), transport="rest")
    # list_models is the lightest authenticated call available
    next(iter(genai.list_models()), None)


def _ping_anthropic(api_key: str) -> None:
    import socket
    import anthropic

    # Strip whitespace/newlines a corrupted secret may carry (Windows echo footgun)
    api_key = api_key.strip()

    # Step 1: raw TCP check — separates "can't reach host" from "SDK/auth issue"
    try:
        socket.setdefaulttimeout(8)
        socket.getaddrinfo("api.anthropic.com", 443)
    except OSError as exc:
        raise RuntimeError(f"DNS/TCP failed for api.anthropic.com: {exc}") from exc

    # Step 2: authenticated SDK call. The SDK masks real causes (e.g. a malformed
    # auth header) behind a generic "Connection error." — unwrap __cause__ so the
    # /health detail is actionable.
    client = anthropic.Anthropic(api_key=api_key, timeout=10.0, max_retries=0)
    try:
        client.models.list(limit=1)
    except Exception as exc:
        cause = exc.__cause__
        if cause is not None:
            raise RuntimeError(f"{exc} (cause: {type(cause).__name__}: {cause})") from exc
        raise


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

        findings = (SecurityAnalyzer().analyze(model) + KubernetesSecurityAnalyzer().analyze(model)
                    + CicdSecurityAnalyzer().analyze(model) + TopologyAnalyzer().analyze(model)
                    + CostAnalyzer().analyze(model) + AIAnalyzer().analyze(model))
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

        findings = (SecurityAnalyzer().analyze(model) + KubernetesSecurityAnalyzer().analyze(model)
                    + CicdSecurityAnalyzer().analyze(model) + TopologyAnalyzer().analyze(model)
                    + CostAnalyzer().analyze(model) + AIAnalyzer().analyze(model))
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
