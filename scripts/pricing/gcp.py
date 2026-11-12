"""Google Cloud prices from the Cloud Billing Catalog API.

https://cloud.google.com/billing/docs/reference/rest/v1/services.skus/list

This is the one source that needs credentials. Either set GCP_PRICING_API_KEY
(an API key with the Cloud Billing API enabled) or be signed in with the
gcloud CLI (`gcloud auth login`); the price list itself is public data.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import time

from .common import Rates, get_json

API = "https://cloudbilling.googleapis.com/v1"
SOURCE = "Google Cloud Billing Catalog API (cloudbilling.googleapis.com)"

SERVICES = {
    "compute": "6F81-5844-456A", "sql": "9662-B51E-5089", "gke": "CCD8-9BF1-090E",
    "run": "152E-C115-5142", "storage": "95FF-2EF5-5EA1", "network": "E505-1604-58F8",
    "redis": "5AF5-2C11-D467", "functions": "29E7-DA93-CA13", "pubsub": "A1E8-BE35-7EBC",
    "logging": "5490-F7B7-8DF6", "secrets": "EE82-7A5E-871C", "kms": "EE2F-D110-890C",
    "dns": "FA26-5236-B8B5", "firestore": "EE2C-7FAC-5E08",
}
VM_FAMILIES = ("E2", "N1 Predefined", "N2", "N2D AMD", "N4", "C3", "C4", "T2D AMD")


def _auth() -> tuple[str, dict]:
    """(query-string suffix, headers) for whichever credential is available."""
    key = os.environ.get("GCP_PRICING_API_KEY")
    if key:
        return f"&key={key}", {}
    gcloud = shutil.which("gcloud") or shutil.which("gcloud.cmd")
    if gcloud:
        token = subprocess.run([gcloud, "auth", "print-access-token"], capture_output=True, text=True).stdout.strip()
        if token:
            return "", {"Authorization": f"Bearer {token}"}
    raise RuntimeError("GCP prices need GCP_PRICING_API_KEY or a signed-in gcloud CLI.")


def _skus(service_id: str, regions: tuple[str, ...]) -> list[dict]:
    suffix, headers = _auth()
    out, page = [], ""
    while True:
        url = f"{API}/services/{service_id}/skus?pageSize=5000&currencyCode=USD{suffix}"
        if page:
            url += f"&pageToken={page}"
        data = get_json(url, headers)
        out += [s for s in data.get("skus", [])
                if s["category"]["usageType"] == "OnDemand" and set(s.get("serviceRegions", [])) & set(regions)]
        page = data.get("nextPageToken")
        if not page:
            return out


def _price(sku: dict, paid: bool = True) -> float:
    """Unit price; with paid=True, the first tier after any free allowance."""
    tiers = sku["pricingInfo"][0]["pricingExpression"]["tieredRates"]
    prices = [int(t["unitPrice"].get("units", 0)) + t["unitPrice"].get("nanos", 0) / 1e9 for t in tiers]
    if paid:
        return next((p for p in prices if p > 0), 0.0)
    return prices[0]


def fetch(region: str, place: str, rates: Rates, key: str) -> str:
    """region e.g. 'us-central1'; place is how SKU names say it ('Americas'/'Iowa' or 'Mumbai')."""
    regions = (region, "global")
    names = (place, "Americas") if region.startswith("us-") else (place,)
    here = "|".join(re.escape(n) for n in names)

    def find(skus: list[dict], pattern: str) -> dict | None:
        rx = re.compile(pattern)
        hits = [s for s in skus if rx.search(s["description"])]
        local = [s for s in hits if region in s["serviceRegions"]]
        return (local or hits or [None])[0]

    def put(name: str, sku: dict | None, per: str, label: str, scale: float = 1.0) -> None:
        if sku:
            rates.set(key, name, _price(sku) * scale, per, label)

    compute = _skus(SERVICES["compute"], regions)
    for fam in VM_FAMILIES:
        core = find(compute, rf"^{fam} Instance Core running in ({here})$")
        ram = find(compute, rf"^{fam} Instance Ram running in ({here})$")
        if core and ram:
            short = fam.split()[0].lower()
            rates.table(key, "vm_family", short, _price(core), ram_gb_hour=float(f"{_price(ram):.6g}"))
    put("block_gb_month", find(compute, r"^Balanced PD Capacity( in .*)?$"), "GB-month", "Balanced persistent disk")
    put("gpu_t4_hour", find(compute, rf"^Nvidia T4 GPU running in ({here})$"), "GPU-hour", "NVIDIA T4 GPU")
    put("gpu_l4_hour", find(compute, rf"^Nvidia L4 GPU running in ({here})$"), "GPU-hour", "NVIDIA L4 GPU")

    sql = _skus(SERVICES["sql"], regions)
    for engine, word in (("postgres", "PostgreSQL"), ("mysql", "MySQL")):
        for dep, dword in (("single", "Zonal"), ("multi", "Regional")):
            pre = rf"^Cloud SQL for {word}: {dword} - "
            put(f"db_{engine}_{dep}_vcpu_hour", find(sql, pre + rf"vCPU in ({here})$"), "vCPU-hour",
                f"Cloud SQL {word} {dword.lower()} vCPU")
            put(f"db_{engine}_{dep}_ram_gb_hour", find(sql, pre + rf"RAM in ({here})$"), "GB-hour",
                f"Cloud SQL {word} {dword.lower()} RAM")
            put(f"db_{engine}_{dep}_storage_gb_month", find(sql, pre + rf"Standard storage in ({here})$"),
                "GB-month", f"Cloud SQL {word} {dword.lower()} SSD storage")
            for size, sword in (("db-f1-micro", "Micro"), ("db-g1-small", "Small")):
                s = find(sql, pre + rf"{sword} instance in ({here})$")
                if s:
                    rates.table(key, f"db_{engine}_{dep}", size, _price(s))

    gke = _skus(SERVICES["gke"], regions)
    put("k8s_cluster_hour", find(gke, r"^Regional Kubernetes Clusters$"), "hour", "GKE cluster management")
    put("k8s_pod_vcpu_hour", find(gke, rf"^Autopilot Pod mCPU Requests \({region}\)$"), "vCPU-hour",
        "GKE Autopilot pod vCPU", 1000)
    put("k8s_pod_gb_hour", find(gke, rf"^Autopilot Pod Memory Requests \({region}\)$"), "GB-hour",
        "GKE Autopilot pod memory")

    run = _skus(SERVICES["run"], regions)
    put("container_vcpu_second", find(run, r"^Services CPU \(Request-based billing\)$"), "vCPU-second", "Cloud Run CPU")
    put("container_gb_second", find(run, r"^Services Memory \(Request-based billing\)$"), "GiB-second",
        "Cloud Run memory")
    put("container_request_million", find(run, r"^Requests$"), "million requests", "Cloud Run requests", 1e6)

    fn = _skus(SERVICES["functions"], regions)
    put("fn_request_million", find(fn, r"^Cloud Run Functions Invocations$"), "million requests",
        "Cloud Run functions invocations", 1e6)
    put("fn_vcpu_second", find(fn, rf"^Cloud Run functions CPU \(Request-based billing\) in {region}$"),
        "vCPU-second", "Cloud Run functions CPU")
    put("fn_gb_second", find(fn, rf"^Cloud Run functions Memory \(Request-based billing\) in {region}$"),
        "GiB-second", "Cloud Run functions memory")

    storage = _skus(SERVICES["storage"], regions)
    put("object_gb_month", find(storage, rf"^Standard Storage ({here}|US Regional)$"), "GB-month",
        "Cloud Storage Standard")

    net = _skus(SERVICES["network"], regions)
    put("lb_hour", find(net, r"^Regional External Application Load Balancer Forwarding Rule Minimum"), "hour",
        "Application Load Balancer forwarding rule")
    put("lb_data_gb", find(net, r"^Regional External Application Load Balancer Inbound Data Processing"), "GB",
        "Load Balancer data processed")
    put("nat_vm_hour", find(net, r"^Networking Cloud Nat Gateway Uptime$"), "VM-hour",
        "Cloud NAT gateway (per VM using it, up to 32)")
    put("nat_gb", find(net, r"^Networking Cloud Nat Data Processing$"), "GB", "Cloud NAT data processed")
    put("waf_policy_month", find(net, r"^Networking Cloud Armor Policy$"), "month", "Cloud Armor policy")
    put("waf_rule_month", find(net, r"^Networking Cloud Armor Rule$"), "month", "Cloud Armor rule")
    put("waf_million", find(net, r"^Networking Cloud Armor Requests$"), "million requests",
        "Cloud Armor requests", 1e6)
    cdn_to = "North America" if region.startswith("us-") else "Asia"
    put("cdn_gb", find(net, rf"^Networking Cloud CDN Traffic Cache Data Transfer to {cdn_to}$"), "GB",
        "Cloud CDN data out")

    redis = _skus(SERVICES["redis"], regions)
    for tier in ("Basic", "Standard"):
        for size in ("M1", "M2"):
            s = find(redis, rf"^Redis Capacity {tier} {size} .*{re.escape(place)}")
            if s:
                rates.table(key, "cache_gb", f"{tier} {size}", _price(s))

    put("queue_tib", find(_skus(SERVICES["pubsub"], regions), r"^Message Delivery Basic$"), "TiB",
        "Pub/Sub message delivery")
    put("logs_gb", find(_skus(SERVICES["logging"], regions), r"^Log Storage cost$"), "GB", "Cloud Logging ingestion")
    put("secret_month", find(_skus(SERVICES["secrets"], regions), r"^Secret version replica storage$"),
        "secret-month", "Secret Manager secret version")
    put("kms_key_month", find(_skus(SERVICES["kms"], regions), r"^Active software symmetric key versions$"),
        "key-month", "Cloud KMS key version")
    dns = find(_skus(SERVICES["dns"], regions), r"^ManagedZone$")
    if dns:
        rates.set(key, "dns_zone_month", _price(dns, paid=False), "zone-month", "Cloud DNS managed zone")
    fs = _skus(SERVICES["firestore"], regions)
    put("nosql_read_million", find(fs, rf"^Cloud Firestore Read Ops {re.escape(place)}$"), "million reads",
        "Firestore reads", 1e6)
    put("nosql_write_million", find(fs, rf"^Cloud Firestore Entity Writes {re.escape(place)}$"), "million writes",
        "Firestore writes", 1e6)
    put("nosql_gb_month", find(fs, rf"^Cloud Firestore Storage {re.escape(place)}$"), "GB-month", "Firestore storage")
    return time.strftime("%Y-%m-%d")
