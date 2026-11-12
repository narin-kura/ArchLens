# Copyright (c) 2026 K.N.Narin (github.com/narin-kura). All rights reserved.
# Non-commercial use only. Commercial use requires written permission: github.com/narin-kura
# See LICENSE for full terms.
"""Cheaper ways to host: one small server on each big cloud, and a directory of
other hosting platforms (app platforms, simple server providers, Indian clouds).

The single-server prices are worked out from the same official price snapshot as
the main estimate. The directory (data/hosting_platforms.json) is not priced by
ArchLens: every entry links to the provider's own pricing or home page.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from .pricing import PROVIDER_NAMES, VM_SIZE, Unpriced, _Book, load_prices

DIRECTORY = Path(__file__).parent / "data" / "hosting_platforms.json"
SINGLE_SERVER_DISK_GB = 50
BUY_LABELS = {"online": "Sign up online", "website": "See website", "sales": "Priced by quote",
              "government": "Government / approved programmes"}


def _single_servers(region: str) -> list[dict]:
    """One 2 vCPU / 4 GB server with a 50 GB disk on each cloud, per month."""
    prices, out = load_prices(), []
    for provider in ("oci", "gcp", "aws", "azure"):
        book = _Book(provider, region)
        size = VM_SIZE[provider][0]
        try:
            usd = book.vm_hour(size) * book.H + book.disk_month(SINGLE_SERVER_DISK_GB)
        except Unpriced:
            continue
        out.append({"provider": PROVIDER_NAMES[provider], "size": size, "usd_month": round(usd, 2),
                    "pricing_page": prices["sources"][provider]["pricing_page"]})
    return sorted(out, key=lambda o: o["usd_month"])


@lru_cache(maxsize=1)
def hosting_options() -> dict:
    with open(DIRECTORY, encoding="utf-8") as f:
        directory = json.load(f)
    prices = load_prices()
    groups = [{"title": g["title"], "blurb": g["blurb"],
               "items": [{**item, "buy_label": BUY_LABELS.get(item["buy"], "See website")} for item in g["items"]]}
              for g in directory["groups"]]
    return {
        "single_server": {
            "what": f"One 2 vCPU / 4 GB server with a {SINGLE_SERVER_DISK_GB} GB disk, running everything "
                    "(app, database, cache) in containers. Lowest cost, but one server means no failover and "
                    "you manage backups and updates yourself.",
            "by_region": {region: _single_servers(region) for region in prices["regions"]},
        },
        "directory": {"checked": directory["checked"], "groups": groups,
                      "count": sum(len(g["items"]) for g in groups)},
    }
