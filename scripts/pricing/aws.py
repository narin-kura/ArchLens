"""AWS prices from the public AWS Price List files (no account needed).

https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/<Service>/current/<region>/index.csv

The EC2 file is ~300 MB per region, so rows are streamed and only the few
we need are kept: Linux, shared tenancy, on-demand, no pre-installed software.
"""
from __future__ import annotations

import csv
import re
from pathlib import Path

from .common import Rates, download

BASE = "https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws"
SOURCE = "AWS Price List (pricing.us-east-1.amazonaws.com)"

# Instance families kept for VMs (current, commonly used generations).
EC2_FAMILIES = re.compile(
    r"^(t2|t3|t3a|t4g|m5|m5a|m6i|m6a|m6g|m7i|m7a|m7g|m8g|c5|c6i|c6a|c6g|c7i|c7a|c7g|c8g|"
    r"r5|r6i|r6a|r6g|r7i|r7a|r7g|r8g|g4dn|g5|g6|g6e|p4d|p5|inf2|trn1)\.")

RDS_ENGINES = {"PostgreSQL": "postgres", "MySQL": "mysql", "MariaDB": "mariadb",
               "Aurora PostgreSQL": "aurora-postgresql", "Aurora MySQL": "aurora-mysql",
               "SQL Server": "sqlserver"}


def _rows(path: Path):
    """On-demand rows of an AWS price CSV (the first 5 lines are metadata)."""
    with open(path, encoding="utf-8", newline="") as fh:
        for _ in range(5):
            next(fh)
        for row in csv.DictReader(fh):
            if row["TermType"] == "OnDemand":
                yield row


def _published(path: Path) -> str:
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.startswith('"Publication Date"'):
                return line.split(",")[1].strip().strip('"')[:10]
    return ""


def _first_tier(rows, pattern: str, field: str = "usageType", desc: str | None = None) -> float | None:
    """Price of the first paid tier for usage types matching pattern."""
    rx = re.compile(pattern)
    drx = re.compile(desc) if desc else None
    best = None
    for r in rows:
        if rx.search(r[field]) and (drx is None or drx.search(r["PriceDescription"])):
            price = float(r["PricePerUnit"] or 0)
            start = float(r["StartingRange"] or 0)
            # skip free tiers: take the cheapest starting range that has a price
            if price > 0 and (best is None or start < best[0]):
                best = (start, price)
    return best[1] if best else None


def fetch(region_code: str, cache: Path, rates: Rates, key: str) -> str:
    def file(svc: str) -> Path:
        return download(f"{BASE}/{svc}/current/{region_code}/index.csv", cache / f"aws_{svc}_{region_code}.csv")

    # -- EC2: instances, EBS gp3, NAT gateway (one pass over the big file) --
    ec2 = file("AmazonEC2")
    published = _published(ec2)
    for r in _rows(ec2):
        fam = r["Product Family"]
        if fam == "Compute Instance":
            it = r["Instance Type"]
            if (EC2_FAMILIES.match(it) and r["Tenancy"] == "Shared" and r["Operating System"] == "Linux"
                    and r["Pre Installed S/W"] == "NA" and r["CapacityStatus"] == "Used"
                    and r["License Model"] == "No License required" and r["Unit"] == "Hrs"):
                rates.table(key, "vm", it, float(r["PricePerUnit"]),
                            vcpu=_num(r["vCPU"]), memory_gb=_num(r["Memory"]))
        elif fam == "Storage" and r["usageType"].endswith("EBS:VolumeUsage.gp3"):
            rates.set(key, "block_gb_month", float(r["PricePerUnit"]), "GB-month", "EBS gp3 storage")
        elif fam == "NAT Gateway":
            if r["usageType"].endswith("NatGateway-Hours"):
                rates.set(key, "nat_hour", float(r["PricePerUnit"]), "hour", "NAT gateway")
            elif r["usageType"].endswith("NatGateway-Bytes"):
                rates.set(key, "nat_gb", float(r["PricePerUnit"]), "GB", "NAT gateway data processed")

    # -- RDS: single-AZ and Multi-AZ instance prices per engine, gp3 storage --
    for r in _rows(file("AmazonRDS")):
        fam = r["Product Family"]
        if fam == "Database Instance":
            engine = RDS_ENGINES.get(r["Database Engine"])
            if not engine or r["Unit"] != "Hrs":
                continue
            if engine == "sqlserver" and r["Database Edition"] != "Express":
                continue
            if r["License Model"] not in ("No license required", "License included"):
                continue
            if "Outpost" in r["Deployment Option"]:
                continue
            dep = {"Single-AZ": "single", "Multi-AZ": "multi"}.get(r["Deployment Option"])
            if dep:
                rates.table(key, f"db_{engine}_{dep}", r["Instance Type"], float(r["PricePerUnit"]),
                            vcpu=_num(r["vCPU"]), memory_gb=_num(r["Memory"]))
        elif fam == "Database Storage" and r["Volume Type"] == "General Purpose-GP3" \
                and r["Deployment Option"] == "Single-AZ" and r["Database Engine"] == "PostgreSQL":
            rates.set(key, "db_storage_gb_month", float(r["PricePerUnit"]), "GB-month", "RDS gp3 storage")

    # -- ElastiCache (Redis/Valkey node hours) --
    for r in _rows(file("AmazonElastiCache")):
        if r["Product Family"] == "Cache Instance" and r["Cache Engine"] == "Redis" \
                and r["Unit"] in ("Hrs", "Hours"):
            rates.table(key, "cache_node", r["Instance Type"], float(r["PricePerUnit"]),
                        memory_gb=_num(r["Memory"]))

    def unit(svc: str, name: str, pattern: str, per: str, label: str, scale: float = 1.0,
             desc: str | None = None, field: str = "usageType") -> None:
        price = _first_tier(list(_rows(file(svc))), pattern, field, desc)
        if price is not None:
            rates.set(key, name, price * scale, per, label)

    unit("AmazonEKS", "k8s_cluster_hour", r"AmazonEKS-Hours:perCluster$", "hour", "EKS cluster")
    unit("AmazonECS", "container_vcpu_hour", r"Fargate-vCPU-Hours:perCPU$", "vCPU-hour", "Fargate vCPU")
    unit("AmazonECS", "container_gb_hour", r"Fargate-GB-Hours$", "GB-hour", "Fargate memory")
    unit("AWSLambda", "fn_request_million", r"^(\w+-)?Request$", "million requests", "Lambda requests", 1e6)
    unit("AWSLambda", "fn_gb_second", r"^(\w+-)?Lambda-GB-Second$", "GB-second", "Lambda compute")
    unit("AmazonS3", "object_gb_month", r"TimedStorage-ByteHrs$", "GB-month", "S3 Standard storage",
         desc=r"per GB - first 50 TB")
    unit("AWSELB", "lb_hour", r"LoadBalancerUsage$", "hour", "Application Load Balancer",
         desc=r"Application LoadBalancer-hour")
    unit("AWSELB", "lb_capacity_hour", r"LCUUsage$", "LCU-hour", "ALB capacity unit",
         desc=r"used Application load balancer")
    unit("AmazonApiGateway", "apigw_million", r"ApiGatewayHttpRequest$", "million requests",
         "API Gateway HTTP API", 1e6)
    unit("AWSQueueService", "queue_million", r"Requests", "million requests", "SQS standard", 1e6,
         desc=r"SQS standard requests in Tier1")
    unit("AmazonSNS", "notify_million", r"Requests-Tier1$", "million requests", "SNS requests", 1e6)
    unit("awswaf", "waf_policy_month", r"-WebACL$", "month", "WAF web ACL",
         desc=r"^(?!.*Shield)")
    unit("awswaf", "waf_rule_month", r"-Rule$", "month", "WAF rule")
    unit("awswaf", "waf_million", r"-RequestV2-Tier0$", "million requests", "WAF requests", 1e6,
         desc=r"^(?!.*Shield)")
    unit("AWSSecretsManager", "secret_month", r"AWSSecretsManager-Secrets$", "secret-month", "Secrets Manager")
    unit("awskms", "kms_key_month", r"KMS-Keys$", "key-month", "KMS key")
    unit("AmazonCloudWatch", "logs_gb", r"^(\w+-)?DataProcessing-Bytes$", "GB", "CloudWatch Logs ingestion",
         desc=r"Standard log class")
    unit("AmazonDynamoDB", "nosql_write_million", r"^(\w+-)?WriteRequestUnits$", "million writes",
         "DynamoDB on-demand writes", 1e6)
    unit("AmazonDynamoDB", "nosql_read_million", r"^(\w+-)?ReadRequestUnits$", "million reads",
         "DynamoDB on-demand reads", 1e6)
    unit("AmazonDynamoDB", "nosql_gb_month", r"TimedStorage-ByteHrs$", "GB-month", "DynamoDB storage",
         desc=r"storage used beyond")
    unit("AWSNetworkFirewall", "firewall_hour", r"-Endpoint-Hour$", "hour", "Network Firewall endpoint",
         desc=r"^(?!.*(Advanced|Secondary))")

    # Global services (one price list, not per region).
    for svc, name, pattern, per, label, scale, desc in (
        ("AmazonCloudFront", "cdn_gb", r"-DataTransfer-Out-Bytes$", "GB", "CloudFront data out", 1.0,
         r"United States|India"),
        ("AmazonRoute53", "dns_zone_month", r"HostedZone", "zone-month", "Route 53 hosted zone", 1.0, None),
    ):
        path = download(f"{BASE}/{svc}/current/index.csv", cache / f"aws_{svc}_global.csv")
        rows = list(_rows(path))
        if svc == "AmazonCloudFront":
            region_word = "United States" if region_code.startswith("us-") else "India"
            prefix = "US-" if region_code.startswith("us-") else "IN-"
            price = _first_tier([r for r in rows if r["usageType"].startswith(prefix)], pattern)
            if price is None:
                price = _first_tier(rows, pattern, desc=region_word)
        else:
            price = _first_tier(rows, pattern, desc=desc)
        if price is not None:
            rates.set(key, name, price * scale, per, label)
    return published


def _num(text: str) -> float | None:
    m = re.search(r"[\d.]+", text or "")
    return float(m.group()) if m else None
