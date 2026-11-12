"""Oracle Cloud prices from Oracle's public price list API (no account needed).

https://apexapps.oracle.com/pls/apex/cetools/api/v1/products/?currencyCode=USD

OCI charges the same price in every commercial region, so one list serves all.
Products are picked by Oracle part number, which stays stable when names change.
"""
from __future__ import annotations

import time

from .common import Rates, get_json

API = "https://apexapps.oracle.com/pls/apex/cetools/api/v1/products/?currencyCode=USD"
SOURCE = "Oracle Cloud price list API (apexapps.oracle.com/pls/apex/cetools)"

# name -> (part number, unit, label, multiplier)
PARTS = {
    "block_gb_month": ("B91961", "GB-month", "Block Volume storage", 1),
    "block_vpu_gb_month": ("B91962", "VPU per GB-month", "Block Volume performance units", 1),
    "object_gb_month": ("B91628", "GB-month", "Object Storage Standard", 1),
    "lb_hour": ("B93030", "hour", "Flexible Load Balancer base", 1),
    "lb_mbps_hour": ("B93031", "Mbps-hour", "Load Balancer bandwidth", 1),
    "k8s_cluster_hour": ("B96545", "hour", "OKE enhanced cluster", 1),
    "fn_request_million": ("B90618", "million requests", "Functions invocations", 1),
    "fn_gb_second": ("B90617", "GB-second", "Functions execution time", 1 / 10000),
    "apigw_million": ("B92072", "million calls", "API Gateway calls", 1),
    "queue_million": ("B95697", "million requests", "OCI Queue requests", 1),
    "notify_million": ("B90940", "million deliveries", "Notifications HTTPS delivery", 1),
    "logs_gb": ("B92593", "GB", "Logging storage", 1),
    "waf_policy_month": ("B94579", "instance-month", "Web Application Firewall instance", 1),
    "waf_million": ("B94277", "million requests", "Web Application Firewall requests", 1),
    "firewall_hour": ("B95403", "hour", "Network Firewall instance", 1),
    "dns_million": ("B88525", "million queries", "DNS queries", 1),
    "db_autonomous_ecpu_hour": ("B95702", "ECPU-hour", "Autonomous Transaction Processing ECPU", 1),
    "db_autonomous_gb_month": ("B95706", "GB-month", "Autonomous Database storage", 1),
    "db_mysql_ecpu_hour": ("B108030", "ECPU-hour", "MySQL HeatWave ECPU", 1),
    "db_mysql_gb_month": ("B92426", "GB-month", "MySQL storage", 1),
    "db_postgres_ocpu_hour": ("B99060", "OCPU-hour", "OCI Database with PostgreSQL OCPU", 1),
    "cache_gb_hour": ("B98217", "GB-hour", "OCI Cache (Redis), up to 10 GB", 1),
    "nosql_gb_month": ("B89739", "GB-month", "NoSQL Database storage", 1),
    "gpu_a10_hour": ("B95909", "GPU-hour", "NVIDIA A10 GPU", 1),
    "outbound_gb": ("B93455", "GB", "Outbound data transfer (APAC), after 10 TB free", 1),
}
# shape family -> (OCPU part, memory part). 1 OCPU = 2 vCPUs on x86, 1 vCPU on Arm (A1).
SHAPES = {
    "E4": ("B93113", "B93114"), "E5": ("B97384", "B97385"),
    "A1": ("B93297", "B93298"), "Standard3": ("B94176", "B94177"),
}


def _paid(product: dict) -> float:
    prices = (product.get("currencyCodeLocalizations") or [{}])[0].get("prices", [])
    values = [p["value"] for p in prices if p.get("model") == "PAY_AS_YOU_GO"]
    return next((v for v in values if v > 0), 0.0)


def fetch(rates: Rates, key: str) -> str:
    by_part = {p["partNumber"]: p for p in get_json(API)["items"]}
    for name, (part, per, label, mult) in PARTS.items():
        if part in by_part:
            rates.set(key, name, _paid(by_part[part]) * mult, per, label)
    for family, (ocpu, mem) in SHAPES.items():
        if ocpu in by_part and mem in by_part:
            rates.table(key, "vm_family", family, _paid(by_part[ocpu]),
                        ram_gb_hour=float(f"{_paid(by_part[mem]):.6g}"))
    return time.strftime("%Y-%m-%d")
