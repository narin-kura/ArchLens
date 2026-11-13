# Copyright (c) 2026 K.N.Narin (github.com/narin-kura). All rights reserved.
# Non-commercial use only. Commercial use requires written permission: github.com/narin-kura
# See LICENSE for full terms.
"""Search-engine and AI-assistant pages for ArchLens.

The app pages are JavaScript-driven, so this module adds what crawlers need:

    /, /analyze, /diagram, /examples   the app pages with real titles, canonical URL,
                                       social tags and structured data in <head>
    /examples/<slug>                   one server-rendered page per bundled reference
                                       architecture: services, the actual findings
                                       ArchLens reports, and the Terraform source
    /robots.txt, /sitemap.xml          for crawlers
    /llms.txt                          plain-text summary for AI assistants

Wording lives in seo_config.json, HTML in templates/seo/.
"""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Callable

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from jinja2 import Environment, FileSystemLoader, select_autoescape

_DIR = Path(__file__).parent
CONFIG: dict = json.loads((_DIR / "seo_config.json").read_text(encoding="utf-8"))
SITE: dict = CONFIG["site"]
ORIGIN: str = os.environ.get("SITE_ORIGIN", SITE["origin"]).rstrip("/")
CANONICAL_HOST: str = re.sub(r"^https?://", "", ORIGIN)
PAGES: dict = CONFIG["pages"]
PROVIDERS: dict = CONFIG["providers"]

_env = Environment(
    loader=FileSystemLoader(str(_DIR / "templates" / "seo")),
    autoescape=select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def fill(template: str, **values) -> str:
    def sub(m: re.Match) -> str:
        if m.group(1) not in values:
            raise KeyError(f"{template!r}: no value for {{{{{m.group(1)}}}}}")
        return str(values[m.group(1)])
    return re.sub(r"\{\{(\w+)\}\}", sub, template)


def _ld(graph: list[dict]) -> str:
    return json.dumps({"@context": "https://schema.org", "@graph": graph}, ensure_ascii=False).replace("</", "<\\/")


def _site_ld() -> list[dict]:
    return [
        {"@type": "WebSite", "@id": f"{ORIGIN}/#website", "name": SITE["name"], "alternateName": SITE["alternateNames"],
         "url": f"{ORIGIN}/", "publisher": {"@id": f"{SITE['makerUrl']}/#org"}},
        {"@type": "Organization", "@id": f"{SITE['makerUrl']}/#org", "name": SITE["makerName"], "url": SITE["makerUrl"]},
    ]


def _app_ld() -> dict:
    return {
        "@type": "WebApplication", "name": SITE["name"], "url": f"{ORIGIN}/", "description": SITE["summary"],
        "applicationCategory": "DeveloperApplication", "operatingSystem": "Web", "isAccessibleForFree": True,
        "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"},
        "sameAs": [SITE["github"]], "publisher": {"@id": f"{SITE['makerUrl']}/#org"},
    }


def _sentence_cut(text: str, limit: int) -> str:
    """First sentence(s) of text within limit characters, ending on a full stop."""
    text = text.strip()
    if len(text) <= limit:
        return text if text.endswith(".") else text + "."
    cut = text[:limit]
    end = cut.rfind(". ")
    return cut[: end + 1] if end > 40 else cut.rsplit(" ", 1)[0] + "…"


class Examples:
    """The bundled reference architectures, analysed once and cached."""

    def __init__(self, slugs: Callable[[], dict], summary: Callable, analyze: Callable):
        self._slugs, self._summary, self._analyze = slugs, summary, analyze

    @lru_cache(maxsize=None)
    def all(self) -> dict[str, dict]:
        out = {}
        for slug, (provider, path) in self._slugs().items():
            out[slug] = {**self._summary(slug, provider, path), "path": path}
        return out

    @lru_cache(maxsize=None)
    def report(self, slug: str) -> dict:
        ex = self.all()[slug]
        model, findings = self._analyze(ex["path"])
        def key(f):
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            return (SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else 9, f.title)
        rows = []
        for f in sorted(findings, key=key):
            rows.append({
                "type": f.type.value if hasattr(f.type, "value") else str(f.type),
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "title": f.title, "description": f.description, "recommendation": f.recommendation,
                "savings": f.estimated_savings, "references": [r for r in (f.references or []) if r.startswith("http")],
            })
        return {
            "components": len(model.components),
            "security": [r for r in rows if r["type"] == "security"],
            "cost": [r for r in rows if r["type"] == "cost"],
            "source": ex["path"].read_text(encoding="utf-8"),
        }


def head_html(page: str, examples: Examples) -> str:
    cfg = PAGES[page]
    values = {"count": len(examples.all())}
    title, description = fill(cfg["title"], **values), fill(cfg["description"], **values)
    graph = _site_ld() + ([_app_ld()] if page == "index.html" else [])
    return _env.get_template("head.html").render(
        site=SITE, title=title, description=description, canonical=ORIGIN + cfg["path"], jsonld=_ld(graph))


def decorate(page: str, html: str, examples: Examples) -> str:
    """Swap the static page's <title> + description for the full search-engine head,
    and fill the crawlable example list on the examples page."""
    html = re.sub(r"<title>.*?</title>\s*<meta name=\"description\"[^>]*>",
                  lambda _: head_html(page, examples), html, count=1, flags=re.S)
    if "<!-- seo:example-links -->" in html:
        html = html.replace("<!-- seo:example-links -->", example_links_html(examples), 1)
    return html


def _grouped(examples: Examples) -> list[dict]:
    groups = []
    for key, prov in PROVIDERS.items():
        items = [e for e in examples.all().values() if e["provider"] == key]
        if items:
            groups.append({"provider": prov, "key": key,
                           "entries": [{"href": f"/examples/{e['slug']}", "title": e["title"], "number": e["number"]} for e in items]})
    return groups


def example_links_html(examples: Examples) -> str:
    return _env.get_template("example_links.html").render(groups=_grouped(examples))


def render_example(examples: Examples, slug: str) -> str:
    ex = examples.all()[slug]
    rep = examples.report(slug)
    prov = PROVIDERS[ex["provider"]]
    values = {"title": ex["title"], "provider": prov["name"], "slug": slug,
              "blurb": _sentence_cut(ex["description"], 110),
              "security": len(rep["security"]), "cost": len(rep["cost"])}
    path = fill(PAGES["example"]["path"], **values)
    title = fill(PAGES["example"]["title"], **values)
    description = fill(PAGES["example"]["description"], **values)
    same_provider = [e for e in examples.all().values() if e["provider"] == ex["provider"] and e["slug"] != slug]
    other_clouds = [e for e in examples.all().values() if e["number"] == ex["number"] and e["provider"] != ex["provider"]]
    trail = [("Home", "/"), ("Examples", "/examples"), (f"{prov['name']} examples", f"/examples#{ex['provider']}"), (ex["title"], path)]
    refs = sorted({u for r in rep["security"] + rep["cost"] for u in r["references"]})
    graph = _site_ld() + [
        {"@type": "BreadcrumbList", "itemListElement": [
            {"@type": "ListItem", "position": i + 1, "name": n, "item": ORIGIN + h} for i, (n, h) in enumerate(trail)]},
        {"@type": "TechArticle", "headline": f"{ex['title']} on {prov['name']}", "description": description,
         "url": ORIGIN + path, "about": [prov["long"], "Terraform", "cloud security", "cloud cost optimization"],
         "publisher": {"@id": f"{SITE['makerUrl']}/#org"}},
    ]
    return _env.get_template("example.html").render(
        site=SITE, title=title, description=description, canonical=ORIGIN + path, jsonld=_ld(graph), trail=trail,
        ex=ex, provider=prov, rep=rep, same_provider=same_provider, other_clouds=other_clouds,
        provider_names={k: v["name"] for k, v in PROVIDERS.items()}, references=refs,
    )


def llms_txt(examples: Examples) -> str:
    return _env.get_template("llms.txt").render(site=SITE, origin=ORIGIN, pages=PAGES, groups=_grouped(examples),
                                                 keywords=CONFIG["keywords"], fill=fill, count=len(examples.all()))


def build_router(static_dir: Path, examples: Examples) -> APIRouter:
    router = APIRouter()

    def on_canonical_host(request: Request) -> bool:
        return request.headers.get("host", "").split(":")[0] == CANONICAL_HOST

    def html(body: str, request: Request, max_age: int = 300) -> HTMLResponse:
        headers = {"Cache-Control": f"public, max-age={max_age}"}
        if not on_canonical_host(request):   # HF Space / run.app copies must not compete in search
            headers["X-Robots-Tag"] = "noindex"
        return HTMLResponse(body, headers=headers)

    @lru_cache(maxsize=None)
    def page_html(name: str) -> str:
        return decorate(name, (static_dir / name).read_text(encoding="utf-8"), examples)

    for name, cfg in PAGES.items():
        if name.endswith(".html"):
            def handler(request: Request, _name: str = name):
                return html(page_html(_name), request)
            router.add_api_route(cfg["path"], handler, methods=["GET"], include_in_schema=False, response_class=HTMLResponse)

    @router.get("/examples/{slug}", include_in_schema=False)
    def example_page(slug: str, request: Request):
        if slug not in examples.all():
            raise HTTPException(status_code=404, detail="Not Found")
        return html(render_example(examples, slug), request, max_age=3600)

    @router.get("/robots.txt", include_in_schema=False)
    def robots(request: Request):
        if not on_canonical_host(request):
            return PlainTextResponse("User-agent: *\nDisallow: /\n")
        return PlainTextResponse(f"User-agent: *\nAllow: /\nDisallow: /api/\n\nSitemap: {ORIGIN}/sitemap.xml\n")

    @router.get("/sitemap.xml", include_in_schema=False)
    def sitemap():
        paths = [cfg["path"] for name, cfg in PAGES.items() if name.endswith(".html")]
        paths += [f"/examples/{slug}" for slug in examples.all()]
        body = ('<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
                + "\n".join(f"  <url><loc>{ORIGIN}{p}</loc></url>" for p in paths) + "\n</urlset>\n")
        return Response(body, media_type="application/xml")

    @router.get("/llms.txt", include_in_schema=False)
    def llms():
        return PlainTextResponse(llms_txt(examples))

    return router
