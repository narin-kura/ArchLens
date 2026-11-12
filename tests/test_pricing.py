"""Cost estimate (archlens/pricing.py) and hosting directory (archlens/hosting.py).

These read the committed price snapshot archlens/data/prices.json; no network.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from archlens.hosting import hosting_options  # noqa: E402
from archlens.models.architecture import ArchitectureModel, Component, ComponentType  # noqa: E402
from archlens.parsers.registry import detect_parser  # noqa: E402
from archlens.pricing import TIERS, estimate, load_prices, provider_of, role_of  # noqa: E402

ARCH_DIRS = ("architectures", "architectures-azure", "architectures-gcp", "architectures-oracle")
EXAMPLES = sorted(p for d in ARCH_DIRS for p in (ROOT / "examples" / d).iterdir() if p.is_dir())


def comp(service: str, type_: ComponentType = ComponentType.OTHER, provider: str = "", **props) -> Component:
    return Component(id=service, name=service, type=type_, provider=provider, service=service, properties=props)


def model(*components: Component) -> ArchitectureModel:
    return ArchitectureModel(name="t", source="test", components=list(components))


# --- the price snapshot ---

def test_snapshot_covers_four_clouds_in_both_regions():
    p = load_prices()
    assert set(p["regions"]) == {"us", "in"}
    for provider in ("aws", "azure", "gcp", "oci"):
        assert p["sources"][provider]["published"], provider
        assert p["sources"][provider]["pricing_page"].startswith("https://")
        for region in p["regions"]:
            assert len(p["rates"][f"{provider}:{region}"]) >= 20, (provider, region)


def test_snapshot_prices_are_plausible():
    """Guards against a broken extraction (wrong unit, wrong row), not against real price changes."""
    p = load_prices()
    t = p["tables"]
    assert 0.03 < t["aws:us"]["vm"]["t3.medium"]["usd_hour"] < 0.06
    assert 0.03 < t["azure:us"]["vm"]["B2s"]["usd_hour"] < 0.06
    assert 0.01 < t["gcp:us"]["vm_family"]["e2"]["usd_hour"] < 0.04
    assert 0.02 < t["oci:us"]["vm_family"]["E5"]["usd_hour"] < 0.05
    assert t["aws:in"]["vm"]["t3.medium"]["usd_hour"] >= t["aws:us"]["vm"]["t3.medium"]["usd_hour"]
    for key, rates in p["rates"].items():
        for name, r in rates.items():
            assert r["usd"] >= 0 and r["per"] and r["label"], (key, name)
    assert 0.015 < p["rates"]["aws:us"]["object_gb_month"]["usd"] < 0.04       # S3 Standard, not another class
    assert p["rates"]["aws:us"]["k8s_cluster_hour"]["usd"] == pytest.approx(0.10)


# --- roles ---

@pytest.mark.parametrize("service,role", [
    ("aws_instance", "vm"), ("ec2", "vm"), ("aws_autoscaling_group", "vm"), ("aws_eks_node_group", "vm"),
    ("aws_db_instance", "db"), ("rds", "db"), ("google_sql_database_instance", "db"),
    ("azurerm_postgresql_flexible_server", "db"), ("oci_database_autonomous_database", "db"),
    ("aws_dynamodb_table", "nosql"), ("aws_elasticache_replication_group", "cache"),
    ("aws_lambda_function", "function"), ("lambda", "function"), ("google_cloud_run_v2_service", "container"),
    ("aws_eks_cluster", "k8s"), ("google_container_cluster", "k8s"), ("aws_s3_bucket", "object"),
    ("aws_lb", "lb"), ("alb", "lb"), ("aws_nat_gateway", "nat"), ("aws_cloudfront_distribution", "cdn"),
    ("aws_sqs_queue", "queue"), ("aws_wafv2_web_acl", "waf"), ("aws_kms_key", "kms"),
    ("aws_iam_role", "free"), ("aws_subnet", "free"), ("aws_security_group", "free"),
    ("aws_launch_template", "free"), ("google_sql_database", "free"), ("random_password", "free"),
    ("aws_bedrockagent_agent", None),
])
def test_role_of(service, role):
    assert role_of(comp(service)) == role


def test_provider_comes_from_service_prefix_or_provider_field():
    assert provider_of(comp("azurerm_lb")) == "azure"
    assert provider_of(comp("google_storage_bucket")) == "gcp"
    assert provider_of(comp("oci_core_instance")) == "oci"
    assert provider_of(comp("lambda", provider="aws")) == "aws"
    assert provider_of(comp("cloud_run", provider="gcp")) == "gcp"
    assert provider_of(comp("postgresql", provider="generic")) is None


# --- estimates ---

def test_budget_levels_rise_and_total_matches_lines():
    e = estimate(model(comp("aws_instance"), comp("aws_db_instance"), comp("aws_lb"), comp("aws_s3_bucket")))
    totals = {t["key"]: t["total"] for t in e["tiers"]}
    assert list(totals) == list(TIERS)                      # no "as written" column without stated sizes
    assert 0 < totals["starter"] < totals["balanced"] < totals["production"]
    for tier in TIERS:
        assert totals[tier] == pytest.approx(sum(l["costs"][tier]["usd"] for l in e["lines"]), abs=0.02)
    assert all(l["costs"][tier]["detail"] for l in e["lines"] for tier in TIERS)   # every amount says what it assumes


def test_free_selfhosted_and_unknown_resources_are_not_priced():
    e = estimate(model(comp("aws_iam_role"), comp("aws_subnet", ComponentType.NETWORK),
                       comp("postgresql", ComponentType.DATABASE, "generic"),
                       comp("aws_bedrockagent_agent", ComponentType.SERVERLESS)))
    assert e["available"] is False and e["lines"] == []
    assert e["no_charge_count"] == 2
    assert {u["service"] for u in e["unpriced"]} == {"postgresql", "aws_bedrockagent_agent"}
    assert all(u["reason"] for u in e["unpriced"])


def test_as_written_uses_stated_sizes_and_ignores_references():
    p = load_prices()
    hour = p["tables"]["aws:us"]["vm"]["m5.xlarge"]["usd_hour"]
    e = estimate(model(comp("aws_instance", instance_type="m5.xlarge", count="2"),
                       comp("aws_db_instance", instance_class="var.db_instance_class")))
    assert e["tiers"][0]["key"] == "as_written"
    vm = next(l for l in e["lines"] if l["service"] == "aws_instance")
    db = next(l for l in e["lines"] if l["service"] == "aws_db_instance")
    assert vm["costs"]["as_written"]["usd"] == pytest.approx(2 * hour * 730, abs=0.01)
    assert "as_written" not in db["costs"]                  # a variable reference is not a size
    assert e["tiers"][0]["total"] == pytest.approx(vm["costs"]["as_written"]["usd"] + db["costs"]["balanced"]["usd"], abs=0.02)


def test_india_region_and_unknown_region_fallback():
    m = model(comp("aws_instance"), comp("aws_db_instance"))
    us, india = estimate(m, "us"), estimate(m, "in")
    assert india["region"] == "in" and india["tiers"][1]["total"] > us["tiers"][1]["total"]
    assert estimate(m, "mars")["region"] == "us"


def test_same_setup_is_priced_on_every_cloud():
    e = estimate(model(comp("aws_instance"), comp("aws_db_instance"), comp("aws_s3_bucket")))
    clouds = {c["provider"]: c for c in e["other_clouds"]}
    assert set(clouds) == {"AWS", "Azure", "Google Cloud", "Oracle Cloud"}
    assert clouds["AWS"]["current"] and not clouds["Azure"]["current"]
    assert clouds["AWS"]["totals"]["balanced"] == e["tiers"][1]["total"]
    assert all(c["totals"]["starter"] > 0 for c in clouds.values())


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: f"{p.parent.name}/{p.name}")
@pytest.mark.parametrize("region", ["us", "in"])
def test_every_reference_architecture_gets_an_estimate(path, region):
    m = detect_parser(str(path), "terraform").parse(str(path))
    e = estimate(m, region)
    assert e["available"], "no resource could be priced"
    totals = [t["total"] for t in e["tiers"] if t["key"] in TIERS]
    assert 0 < totals[0] <= totals[1] <= totals[2]
    assert len(e["lines"]) + e["no_charge_count"] + len(e["unpriced"]) == len(m.components)
    assert len(e["sources"]) == 4


# --- hosting directory ---

def test_single_server_prices_per_region():
    h = hosting_options()
    for region in ("us", "in"):
        servers = h["single_server"]["by_region"][region]
        assert {s["provider"] for s in servers} == {"AWS", "Azure", "Google Cloud", "Oracle Cloud"}
        assert all(10 < s["usd_month"] < 100 for s in servers)
        assert servers == sorted(servers, key=lambda s: s["usd_month"])


def test_directory_entries_are_complete_and_link_to_https():
    d = hosting_options()["directory"]
    names = [i["name"] for g in d["groups"] for i in g["items"]]
    assert len(names) == len(set(names)) == d["count"] >= 60
    for g in d["groups"]:
        assert g["title"] and g["blurb"]
        for i in g["items"]:
            assert i["fits"] and i["where"] and i["buy_label"]
            assert i["url"] is None or i["url"].startswith("https://"), i["name"]


def test_directory_includes_requested_platforms():
    """Vercel, Oracle's free tier, and the Indian providers the owner listed on 2026-11-11."""
    names = " | ".join(i["name"] for g in hosting_options()["directory"]["groups"] for i in g["items"])
    for wanted in ("Vercel", "Oracle Cloud Always Free", "Utho", "E2E Networks", "BharathCloud", "CloudPe", "AceCloud",
                   "Civo", "MilesWeb", "Hostinger", "BigRock", "ResellerClub", "ZNetLive", "Net4", "Netmagic", "Yotta",
                   "Neysa", "Sarvam", "Krutrim", "Tata Communications", "Jio", "CtrlS", "Cloud4C", "ESDS", "NxtGen",
                   "Pi Datacenters", "Sify", "TCS", "Wipro", "Infosys", "HCLTech", "Tech Mahindra", "Cyfuture",
                   "Web Werks", "STT GDC", "Nxtra", "AdaniConneX", "L&T-Cloudfinity", "RackBank", "Anant Raj",
                   "CapitaLand", "Equinix", "Digital Connexion", "MeghRaj", "IndiaAI Compute", "Zoho", "C-DAC"):
        assert wanted in names, wanted


def test_as_written_resolves_terraform_variable_defaults(tmp_path):
    (tmp_path / "main.tf").write_text(
        'variable "size" { default = "m5.xlarge" }\n'
        'variable "no_default" { type = string }\n'
        'resource "aws_instance" "app" { instance_type = var.size }\n'
        'resource "aws_instance" "other" { instance_type = var.no_default }\n', encoding="utf-8")
    m = detect_parser(str(tmp_path), "terraform").parse(str(tmp_path))
    assert m.metadata["variable_defaults"] == {"size": "m5.xlarge"}
    lines = {l["name"]: l for l in estimate(m)["lines"]}
    assert "m5.xlarge" in lines["app"]["costs"]["as_written"]["detail"]
    assert "as_written" not in lines["other"]["costs"]
