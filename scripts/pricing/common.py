"""Shared helpers for the price-list builders."""
from __future__ import annotations

import json
import shutil
import time
import urllib.error
import urllib.request
from pathlib import Path

USER_AGENT = "ArchLens-price-builder/1.0 (+https://archlens.vigyatri.com)"


def download(url: str, dest: Path, headers: dict | None = None) -> Path:
    """Fetch url into dest once; later runs reuse the cached file."""
    if dest.exists() and dest.stat().st_size > 0:
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    tmp = dest.with_suffix(dest.suffix + ".part")
    with urllib.request.urlopen(req, timeout=600) as resp, open(tmp, "wb") as out:
        shutil.copyfileobj(resp, out, 1 << 20)
    tmp.replace(dest)
    return dest


def get_json(url: str, headers: dict | None = None, retries: int = 6) -> dict:
    """GET JSON, waiting and retrying when the API rate-limits (HTTP 429) or hiccups."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as e:
            if e.code not in (429, 500, 502, 503, 504) or attempt == retries - 1:
                raise
        except urllib.error.URLError:
            if attempt == retries - 1:
                raise
        time.sleep(min(60, 5 * 2 ** attempt))
    raise RuntimeError("unreachable")


class Rates:
    """Collects prices as rates[key][name] (single prices) and tables[key][table][size]."""

    def __init__(self) -> None:
        self.rates: dict[str, dict[str, dict]] = {}
        self.tables: dict[str, dict[str, dict[str, dict]]] = {}

    def set(self, key: str, name: str, usd: float, per: str, label: str) -> None:
        self.rates.setdefault(key, {})[name] = {"usd": float(f"{usd:.6g}"), "per": per, "label": label}

    def table(self, key: str, table: str, size: str, usd_hour: float, **specs) -> None:
        entry = {"usd_hour": float(f"{usd_hour:.6g}")}
        entry.update({k: v for k, v in specs.items() if v is not None})
        self.tables.setdefault(key, {}).setdefault(table, {})[size] = entry

    def has(self, key: str, name: str) -> bool:
        return name in self.rates.get(key, {})
