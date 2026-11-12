"""Azure prices from the public Azure Retail Prices API (no account needed).

https://learn.microsoft.com/rest/api/cost-management/retail-prices/azure-retail-prices
"""
from __future__ import annotations

import collections
import re
import time
import urllib.parse

from .common import Rates, get_json

API = "https://prices.azure.com/api/retail/prices"
SOURCE = "Azure Retail Prices API (prices.azure.com)"

# VM series kept (Linux, pay-as-you-go): burstable, general purpose, compute,
# memory optimised, and the common GPU series.
VM_SERIES = re.compile(r"^Standard_(B\d|D\d|E\d|F\d|NC|NV|ND)", re.I)


def query(flt: str, cap: int = 20000) -> list[dict]:
    url = API + "?" + urllib.parse.urlencode({"$filter": flt})
    items: list[dict] = []
    while url and len(items) < cap:
        page = get_json(url)
        items += page.get("Items", [])
        url = page.get("NextPageLink")
        time.sleep(0.6)   # the API rate-limits bursts
    return items


def _paid(items: list[dict]) -> dict | None:
    """The first tier with a non-zero price (skips free allowances)."""
    paid = [i for i in items if i["retailPrice"] > 0]
    return min(paid, key=lambda i: i.get("tierMinimumUnits") or 0) if paid else None


def _pick(items: list[dict], region: str, **match) -> dict | None:
    """Items whose fields match the given regexes; prefer the exact region,
    else the most common price (some meters are listed under 'Global' or zones)."""
    def ok(i):
        return all(re.search(rx, str(i.get(f, "")), re.I) for f, rx in match.items())
    hits = [i for i in items if ok(i)]
    exact = [i for i in hits if i.get("armRegionName") == region]
    if exact:
        return _paid(exact)
    if not hits:
        return None
    paid = [i for i in hits if i["retailPrice"] > 0]
    if not paid:
        return None
    common = collections.Counter(round(i["retailPrice"], 6) for i in paid).most_common(1)[0][0]
    return next(i for i in paid if round(i["retailPrice"], 6) == common)


def fetch(region: str, rates: Rates, key: str) -> str:
    base = f"armRegionName eq '{region}' and priceType eq 'Consumption'"

    # -- Virtual machines (Linux = product names without "Windows") --
    for i in query(f"{base} and serviceName eq 'Virtual Machines'"):
        sku, name = i.get("armSkuName", ""), i["skuName"]
        if ("Windows" in i["productName"] or "Spot" in name or "Low Priority" in name
                or not VM_SERIES.match(sku) or i["unitOfMeasure"] != "1 Hour"):
            continue
        rates.table(key, "vm", sku.removeprefix("Standard_"), i["retailPrice"])

    def put(name: str, item: dict | None, per: str, label: str, scale: float = 1.0) -> None:
        if item:
            rates.set(key, name, item["retailPrice"] * scale, per, label)

    # -- PostgreSQL / MySQL flexible server --
    for engine, svc in (("postgres", "Azure Database for PostgreSQL"), ("mysql", "Azure Database for MySQL")):
        items = query(f"{base} and serviceName eq '{svc}' and contains(productName,'Flexible')")
        for i in items:
            prod, sku = i["productName"], i["skuName"]
            if "Compute" not in prod and "Burstable" not in prod:
                continue
            if i["unitOfMeasure"] != "1 Hour" or i["retailPrice"] <= 0:
                continue
            if "Burstable" in prod:
                size = sku.removeprefix("Standard_").upper().rstrip("2")    # B1MS, B2S, B2MS ...
                rates.table(key, f"db_{engine}", size, i["retailPrice"])
            elif re.search(r"General Purpose (Ddsv5|Dsv3|Ddsv4)", prod) and sku == "vCore":
                rates.set(key, f"db_{engine}_gp_vcore_hour", i["retailPrice"], "vCore-hour",
                          f"{svc} General Purpose vCore")
            elif re.search(r"Memory Optimized (Edsv5|Esv3|Edsv4)", prod) and sku == "vCore":
                rates.set(key, f"db_{engine}_mo_vcore_hour", i["retailPrice"], "vCore-hour",
                          f"{svc} Memory Optimized vCore")
        store = query(f"{base} and serviceName eq '{svc}' and contains(productName,'Storage')")
        put("db_storage_gb_month", _pick(store, region, meterName=r"^Storage Data Stored$",
                                         productName=r"Flex"), "GB-month", "Flexible Server storage")

    # -- Azure SQL Database (DTU tiers) --
    for i in query(f"{base} and serviceName eq 'SQL Database' and contains(productName,'Single') "
                   "and contains(meterName,'DTU')"):
        if i["unitOfMeasure"] == "1/Day" and re.fullmatch(r"Basic|S\d+|P\d+", i["skuName"]):
            rates.table(key, "db_sqlserver", i["skuName"], i["retailPrice"] / 24)

    # -- Azure Cache for Redis (Basic/Standard/Premium C/P sizes) --
    for i in query(f"{base} and serviceName eq 'Redis Cache'"):
        m = re.fullmatch(r"Azure Redis Cache (Basic|Standard|Premium)", i["productName"])
        if m and re.fullmatch(r"[CP]\d", i["skuName"]) and i["unitOfMeasure"].endswith("Hour"):
            rates.table(key, "cache_node", f"{m.group(1)} {i['skuName']}", i["retailPrice"])

    simple = [
        ("k8s_cluster_hour", f"{base} and serviceName eq 'Azure Kubernetes Service'",
         dict(meterName=r"^Standard Uptime SLA$"), "hour", "AKS Standard tier"),
        ("lb_hour", "priceType eq 'Consumption' and serviceName eq 'Load Balancer'",
         dict(meterName=r"^Standard Included LB Rules"), "hour", "Standard Load Balancer"),
        ("lb_data_gb", "priceType eq 'Consumption' and serviceName eq 'Load Balancer'",
         dict(meterName=r"^Standard Data Processed$"), "GB", "Load Balancer data processed"),
        ("appgw_hour", f"{base} and serviceName eq 'Application Gateway'",
         dict(productName=r"^Application Gateway Standard v2$", meterName=r"Fixed Cost"), "hour",
         "Application Gateway v2"),
        ("lb_capacity_hour", f"{base} and serviceName eq 'Application Gateway'",
         dict(productName=r"^Application Gateway Standard v2$", meterName=r"Capacity Units"), "CU-hour",
         "Application Gateway capacity unit"),
        ("waf_gateway_hour", f"{base} and serviceName eq 'Application Gateway'",
         dict(productName=r"^Application Gateway WAF v2$", meterName=r"Fixed Cost"), "hour",
         "Application Gateway WAF v2"),
        # NAT Gateway is priced globally, not per region.
        ("nat_hour", "priceType eq 'Consumption' and serviceName eq 'NAT Gateway'",
         dict(meterName=r"^Standard Gateway$"), "hour", "NAT Gateway"),
        ("nat_gb", "priceType eq 'Consumption' and serviceName eq 'NAT Gateway'",
         dict(meterName=r"^Standard Data Processed$"), "GB", "NAT Gateway data processed"),
        ("fn_request_million", f"{base} and serviceName eq 'Functions'",
         dict(skuName=r"^Standard$", meterName=r"Total Executions"), "million requests",
         "Functions consumption executions"),
        ("fn_gb_second", f"{base} and serviceName eq 'Functions'",
         dict(skuName=r"^Standard$", meterName=r"Execution Time"), "GB-second", "Functions consumption compute"),
        ("container_vcpu_second", f"{base} and serviceName eq 'Azure Container Apps'",
         dict(meterName=r"^Standard vCPU Active Usage$"), "vCPU-second", "Container Apps vCPU"),
        ("container_gb_second", f"{base} and serviceName eq 'Azure Container Apps'",
         dict(meterName=r"^Standard Memory Active Usage$"), "GiB-second", "Container Apps memory"),
        ("object_gb_month", f"{base} and serviceName eq 'Storage' and productName eq 'General Block Blob v2'",
         dict(meterName=r"^Hot LRS Data Stored$"), "GB-month", "Blob Storage Hot LRS"),
        ("block_disk_e10_month", f"{base} and serviceName eq 'Storage' and productName eq 'Standard SSD Managed Disks'",
         dict(meterName=r"^E10 LRS Disk$"), "disk-month (128 GB)", "Standard SSD E10 disk"),
        ("apigw_10k", f"{base} and serviceName eq 'API Management'",
         dict(meterName=r"^Consumption Calls$"), "10K calls", "API Management Consumption"),
        ("queue_base_hour", f"{base} and serviceName eq 'Service Bus'",
         dict(meterName=r"^Standard Base Unit$", unitOfMeasure=r"Hour"), "hour", "Service Bus Standard"),
        ("queue_million", f"{base} and serviceName eq 'Service Bus'",
         dict(meterName=r"^Standard Messaging Operations$"), "million operations", "Service Bus operations"),
        ("cdn_gb", "priceType eq 'Consumption' and serviceName eq 'Azure Front Door Service'",
         dict(skuName=r"^Standard$", meterName=r"Standard Data Transfer Out", armRegionName=r"Zone 1"), "GB",
         "Front Door (classic) data out"),
        ("cdn_base_month", "priceType eq 'Consumption' and serviceName eq 'Azure Front Door Service'",
         dict(skuName=r"^Standard$", meterName=r"Base Fee"), "month", "Front Door Standard base fee"),
        ("dns_zone_month", "priceType eq 'Consumption' and serviceName eq 'Azure DNS'",
         dict(meterName=r"^Public Zone"), "zone-month", "Azure DNS public zone"),
        ("logs_gb", f"{base} and serviceName eq 'Log Analytics'",
         dict(meterName=r"^Analytics Logs Data Ingestion$"), "GB", "Log Analytics ingestion"),
        ("firewall_hour", f"{base} and serviceName eq 'Azure Firewall'",
         dict(meterName=r"^Standard Deployment$"), "hour", "Azure Firewall Standard"),
        ("secret_10k_ops", f"{base} and serviceName eq 'Key Vault'",
         dict(skuName=r"^Standard$", meterName=r"^Operations$"), "10K operations", "Key Vault operations"),
        ("nosql_100ru_hour", f"{base} and serviceName eq 'Azure Cosmos DB'",
         dict(skuName=r"^RUs$", meterName=r"^100 RU/s$"), "100 RU/s-hour", "Cosmos DB provisioned throughput"),
        ("nosql_gb_month", f"{base} and serviceName eq 'Azure Cosmos DB'",
         dict(meterName=r"^Data Stored$"), "GB-month", "Cosmos DB storage"),
    ]
    cache: dict[str, list[dict]] = {}
    for name, flt, match, per, label in simple:
        if flt not in cache:
            cache[flt] = query(flt, cap=3000)
        item = _pick(cache[flt], region, **match)
        scale = {"fn_request_million": 1e5}.get(name, 1.0)   # meter unit is "10" executions
        put(name, item, per, label, scale)
    return time.strftime("%Y-%m-%d")
