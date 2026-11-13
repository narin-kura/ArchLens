"""Search-engine pages (web/seo.py): every example page renders with unique titles and
working links, and robots.txt / sitemap.xml / llms.txt agree with each other."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # noqa: E402

from web import seo  # noqa: E402
from web.app import app  # noqa: E402

HOST = {"host": seo.CANONICAL_HOST}


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(scope="module")
def site(client):
    sitemap = client.get("/sitemap.xml", headers=HOST)
    assert sitemap.status_code == 200
    paths = [u.removeprefix(seo.ORIGIN) for u in re.findall(r"<loc>(.*?)</loc>", sitemap.text)]
    pages = {}
    for p in paths:
        r = client.get(p, headers=HOST)
        assert r.status_code == 200, p
        pages[p] = r.text
    return pages


def test_sitemap_covers_app_pages_and_every_example(site):
    examples = [p for p in site if p.startswith("/examples/")]
    assert {"/", "/analyze", "/diagram", "/examples"} <= set(site)
    assert len(examples) == 64


def test_each_page_has_one_unique_title_description_and_canonical(site):
    titles = set()
    for path, html in site.items():
        assert html.count("<title>") == 1, path
        assert len(re.findall(r'<meta name="description"', html)) == 1, path
        title = re.search(r"<title>(.*?)</title>", html).group(1)
        assert title not in titles, f"duplicate title {title!r}"
        titles.add(title)
        assert re.search(rf'<link rel="canonical" href="{re.escape(seo.ORIGIN + path)}"', html), path
        json.loads(re.search(r'<script type="application/ld\+json">(.*?)</script>', html, re.S).group(1))
        # No unfilled {{placeholders}}; the Terraform source in <pre> may contain "{{" itself.
        assert not re.search(r"\{\{\s*\w", re.sub(r"<pre>.*?</pre>", "", html, flags=re.S)), path


def test_internal_links_resolve(site):
    known = set(site)
    for path, html in site.items():
        for href in re.findall(r'href="(/[^"#?]*)', html):
            if href.startswith("/static/"):
                continue
            assert href in known, f"broken link {href} on {path}"


def test_example_page_shows_real_findings_and_source(client):
    html = client.get("/examples/aws-01-three-tier-web-app", headers=HOST).text
    assert "Security review" in html and "Cost review" in html
    assert "resource &#34;" in html or 'resource "' in html   # the Terraform itself
    assert "/examples/azure-01-" in html                       # same architecture on another cloud


def test_examples_page_lists_every_example_as_a_plain_link(client, site):
    html = client.get("/examples", headers=HOST).text
    for path in site:
        if path.startswith("/examples/"):
            assert f'href="{path}"' in html, path


def test_robots_llms_and_other_hosts(client, site):
    robots = client.get("/robots.txt", headers=HOST).text
    assert f"Sitemap: {seo.ORIGIN}/sitemap.xml" in robots
    assert "Disallow: /\n" in client.get("/robots.txt", headers={"host": "knnarin-archlens.hf.space"}).text
    assert client.get("/", headers={"host": "x.run.app"}).headers.get("x-robots-tag") == "noindex"
    assert client.get("/", headers=HOST).headers.get("x-robots-tag") is None
    llms = client.get("/llms.txt", headers=HOST).text
    assert llms.startswith("# ArchLens")
    for path in site:
        if path.startswith("/examples/"):
            assert f"{seo.ORIGIN}{path})" in llms, path


def test_unknown_example_is_404(client):
    assert client.get("/examples/aws-99-nope", headers=HOST).status_code == 404
