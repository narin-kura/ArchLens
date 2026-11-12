# Copyright (c) 2026 K.N.Narin (github.com/narin-kura). All rights reserved.
# Non-commercial use only. Commercial use requires written permission: github.com/narin-kura
# See LICENSE for full terms.
"""Estimated monthly cost of an architecture, at three budget levels.

Prices come from archlens/data/prices.json, a snapshot of the providers' own
price lists (AWS, Azure, Google Cloud, Oracle Cloud) built by
scripts/update_prices.py. Nothing here calls the network.

Every resource is given a pricing *role* (virtual machine, database, load
balancer, ...) from its service name. Each budget level then assumes a size
and a usage for that role, so three totals can be shown side by side:

    starter      the cheapest setup that works (one small copy of everything)
    balanced     a sensible default for a live product
    production   larger sizes, several copies, standby database

When the input states real sizes (a Terraform `instance_type`, `instance_class`,
`node_type` ...), an extra "as written" column prices exactly those.

This is an estimate of list prices: no data transfer, taxes, free tiers,
support plans or committed-use discounts.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from .models.architecture import ArchitectureModel, Component, ComponentType

DATA = Path(__file__).parent / "data" / "prices.json"
TIERS = ("starter", "balanced", "production")
TIER_INFO = {
    "starter": ("Starter", "Cheapest setup that works: one small copy of each resource."),
    "balanced": ("Balanced", "Sensible default for a live product: medium sizes, two app servers."),
    "production": ("Production", "Built for reliability: larger sizes, three app servers, standby database."),
}
PROVIDER_NAMES = {"aws": "AWS", "azure": "Azure", "gcp": "Google Cloud", "oci": "Oracle Cloud"}

# --- What each budget level assumes -------------------------------------------
# Index 0/1/2 = starter / balanced / production.
VM_COUNT = (1, 2, 3)
VM_DISK_GB = (30, 50, 100)
VM_SIZE = {   # 2 vCPU/4 GB, 2 vCPU/8 GB, 4 vCPU/16 GB
    "aws": ("t3.medium", "t3.large", "m7i.xlarge"),
    "azure": ("B2s", "D2s_v5", "D4s_v5"),
    "gcp": ("e2-medium", "e2-standard-2", "n2-standard-4"),
    "oci": ("VM.Standard.E5.Flex 1 OCPU/4 GB", "VM.Standard.E5.Flex 1 OCPU/8 GB", "VM.Standard.E5.Flex 2 OCPU/16 GB"),
}
DB_SIZE = {
    "aws": ("db.t4g.micro", "db.t4g.medium", "db.m7g.large"),
    "azure": ("B1MS", "B2MS", "GP 2 vCore"),
    "gcp": ("db-f1-micro", "db-custom-2-8192", "db-custom-4-16384"),
    "oci": ("2 ECPU", "4 ECPU", "8 ECPU"),
}
DB_STORAGE_GB = (20, 50, 100)
DB_STANDBY = (False, False, True)
SQLSERVER_SIZE = ("Basic", "S2", "P1")
CACHE_SIZE = {
    "aws": (("cache.t4g.micro", 1), ("cache.t4g.small", 1), ("cache.m7g.large", 2)),
    "azure": (("Basic C0", 1), ("Standard C1", 1), ("Premium P1", 1)),
    "gcp": (("Basic M1", 1), ("Standard M1", 2), ("Standard M2", 5)),      # (tier, GB)
    "oci": ((None, 2), (None, 4), (None, 16)),                              # GB
}
REQUESTS_M = (1, 10, 100)          # million requests a month (functions, API gateway, queues, WAF)
FN_SECONDS, FN_GB = 0.2, 0.5       # each function call: 200 ms at 512 MB
CONTAINER = ((0.25, 0.5, 1), (0.5, 1, 2), (1, 2, 3))   # (vCPU, GB, copies), running all month
K8S_NODES = (2, 3, 3)
OBJECT_GB = (50, 250, 1000)
BLOCK_GB = (50, 100, 500)
DATA_GB = (10, 100, 500)           # data through NAT / load balancer
CDN_GB = (50, 500, 2000)
LOGS_GB = (5, 25, 100)
NOSQL_GB = (1, 10, 50)
COSMOS_RU = (400, 1000, 4000)
LB_CAPACITY_UNITS = (1, 5, 20)

# --- Service name -> pricing role (first match wins) ---------------------------
_FREE = (r"iam_|_iam|identity|role_assignment|policy$|_policy_|_vpc$|^vpc$|virtual_network$|_vcn$|subnet|route|"
         r"security_group|security_rule|security_list|internet_gateway|service_gateway|firewall$(?<!azurerm_firewall)|"
         r"compute_firewall|resource_group|association|attachment|listener|target_group|backend_set|url_map|"
         r"target_https?_proxy|launch_template|instance_template|instance_configuration|autoscal\w*_(policy|setting|"
         r"configuration)|compute_autoscaler|subnet_group|parameter_group|acm_certificate|ssl_certificate|ssl_policy|"
         r"load_balancer_certificate|health_check|^random_|^null_|secret_version|sql_database$|service_account|"
         r"_eip$|public_ip|global_address|kms_alias|key_ring|kms_vault|private_endpoint|vpc_endpoint|flow_log|"
         r"metric_alarm|monitoring_alarm|alert_policy|uptime_check|metric_alert|access_policy|"
         r"disk_encryption_set|frontdoor_(endpoint|origin|route|origin_group|security_policy|firewall_policy)|"
         r"subscription_pricing|guardduty|cloudtrail|web_application_firewall_policy|waf_web_app_firewall$")
ROLE_RULES: list[tuple[str, str]] = [
    ("free", _FREE),
    ("k8s", r"eks_cluster|^eks$|kubernetes_cluster$|container_cluster|containerengine_cluster$|^aks$|^gke$|^oke$"),
    ("vm", r"node_group|node_pool"),
    ("container", r"fargate|ecs_service|^ecs$|app_?runner|cloud_run|container_app|container_group|container_instance"),
    ("function", r"lambda|function"),
    ("nosql", r"dynamodb|cosmosdb|firestore|nosql"),
    ("db", r"db_instance|^rds|aurora|rds_cluster|sql_database_instance|postgresql\w*_server|mysql\w*_server|"
           r"mssql_database|mariadb_server|autonomous_database|mysql_db_system|database_db_system"),
    ("cache", r"elasticache|redis|memcache|memorydb"),
    ("vm", r"^aws_instance$|^ec2|autoscaling_group|virtual_machine|compute_instance$|instance_group_manager|"
           r"core_instance$|instance_pool|lightsail"),
    ("object", r"s3_bucket$|^s3$|storage_account$|storage_bucket$|objectstorage_bucket"),
    ("block", r"ebs_volume|^ebs$|managed_disk|compute_disk|core_volume$"),
    ("apigw", r"api_?gateway|api_management"),
    ("nat", r"nat_gateway|router_nat"),
    ("lb", r"^aws_lb$|^aws_alb$|^[anc]lb$|^aws_elb$|azurerm_lb$|application_gateway|forwarding_rule|"
           r"load_balancer$|backend_service$"),
    ("cdn", r"cloudfront_distribution|^cloudfront$|cdn_endpoint|cloud_cdn|frontdoor_profile"),
    ("queue", r"sqs|sns|servicebus_namespace|pubsub_topic|queue_queue|notification_topic"),
    ("waf", r"waf"),
    ("firewall", r"networkfirewall_firewall$|network_firewall$|azurerm_firewall$"),
    ("logs", r"log_group$|log_analytics_workspace|logging_project_sink|logging_log$"),
    ("secret", r"secretsmanager_secret$|secret_manager_secret$|key_vault_secret|vault_secret$"),
    ("kms", r"kms_key$|kms_crypto_key$|key_vault_key"),
    ("dns", r"route53_zone|dns_zone$|dns_managed_zone"),
]
_ROLE_RX = [(role, re.compile(rx, re.I)) for role, rx in ROLE_RULES]
ROLE_LABELS = {
    "vm": "Virtual machines", "db": "Database", "nosql": "NoSQL database", "cache": "Cache",
    "function": "Functions (serverless)", "container": "Containers (serverless)", "k8s": "Kubernetes cluster",
    "object": "Object storage", "block": "Disk storage", "lb": "Load balancer", "apigw": "API gateway",
    "nat": "NAT gateway", "cdn": "CDN", "queue": "Queue / notifications", "waf": "Web application firewall",
    "firewall": "Network firewall", "logs": "Logs", "secret": "Secret", "kms": "Encryption key", "dns": "DNS zone",
}
# Types that normally have no hourly charge of their own when no rule matched.
_USUALLY_FREE_TYPES = {ComponentType.IAM, ComponentType.NETWORK, ComponentType.MONITORING, ComponentType.OTHER}


class Unpriced(Exception):
    """This resource can't be priced; the message says why."""


@lru_cache(maxsize=1)
def load_prices() -> dict:
    with open(DATA, encoding="utf-8") as f:
        return json.load(f)


def provider_of(c: Component) -> str | None:
    s = c.service.lower()
    for prefix, p in (("aws_", "aws"), ("azurerm_", "azure"), ("google_", "gcp"), ("oci_", "oci")):
        if s.startswith(prefix):
            return p
    return {"aws": "aws", "azure": "azure", "gcp": "gcp", "google": "gcp", "oci": "oci", "oracle": "oci"}.get(
        (c.provider or "").lower())


def role_of(c: Component) -> str | None:
    for role, rx in _ROLE_RX:
        if rx.search(c.service):
            return role
    return None


# --- Pricing helpers -----------------------------------------------------------

class _Book:
    """Prices for one provider in one region."""

    def __init__(self, provider: str, region: str):
        p = load_prices()
        key = f"{provider}:{region}"
        self.provider, self.H = provider, p["hours_per_month"]
        self.rates, self.tables = p["rates"].get(key, {}), p["tables"].get(key, {})

    def rate(self, name: str) -> float:
        if name not in self.rates:
            raise Unpriced(f"no list price for this in the {PROVIDER_NAMES[self.provider]} price snapshot")
        return self.rates[name]["usd"]

    def size(self, table: str, size: str) -> float:
        entry = self.tables.get(table, {}).get(size)
        if entry is None:
            raise Unpriced(f"size '{size}' is not in the price snapshot")
        return entry["usd_hour"]

    # -- virtual machines --
    def vm_hour(self, size: str) -> float:
        if self.provider in ("aws", "azure"):
            return self.size("vm", size.removeprefix("Standard_") if self.provider == "azure" else size)
        if self.provider == "gcp":
            return self._gcp_vm(size)
        return self._oci_vm(size)

    def _gcp_vm(self, machine: str) -> float:
        m = re.fullmatch(r"(e2|n1|n2|n2d|n4|c3|c4|t2d)-(micro|small|medium|standard|highmem|highcpu)(?:-(\d+))?", machine)
        if not m:
            raise Unpriced(f"machine type '{machine}' is not in the price snapshot")
        fam, kind, n = m.group(1), m.group(2), int(m.group(3) or 0)
        shared = {"micro": (0.25, 1), "small": (0.5, 2), "medium": (1, 4)}
        if kind in shared:
            vcpu, gb = shared[kind]
        else:
            per = {"standard": 3.75 if fam == "n1" else 4, "highmem": 6.5 if fam == "n1" else 8,
                   "highcpu": 0.9 if fam == "n1" else (2 if fam in ("c3", "c4") else 1)}[kind]
            vcpu, gb = n, n * per
        f = self.tables.get("vm_family", {}).get(fam)
        if not f or not vcpu:
            raise Unpriced(f"machine type '{machine}' is not in the price snapshot")
        return vcpu * f["usd_hour"] + gb * f["ram_gb_hour"]

    def _oci_vm(self, shape: str, ocpus: float | None = None, gb: float | None = None) -> float:
        fam = next((f for f in ("E5", "E4", "A1", "Standard3") if f in shape), None)
        m = re.search(r"([\d.]+) OCPU/([\d.]+) GB", shape)
        if m:
            ocpus, gb = float(m.group(1)), float(m.group(2))
        f = self.tables.get("vm_family", {}).get(fam or "")
        if not f or not ocpus or not gb:
            raise Unpriced(f"shape '{shape}' needs its OCPU and memory to be priced")
        return ocpus * f["usd_hour"] + gb * f["ram_gb_hour"]

    def disk_month(self, gb: float) -> float:
        if self.provider == "azure":                      # sold as fixed disk sizes; E10 = 128 GB
            return self.rate("block_disk_e10_month") * max(1, round(gb / 128 + 0.49))
        return gb * self.rate("block_gb_month")


def _f(x: float) -> str:
    return f"{x:g}"


def _tier_cost(book: _Book, role: str, c: Component, t: int, model: ArchitectureModel) -> tuple[float, str]:
    """(USD per month, what was assumed) for one resource at budget level t (0/1/2)."""
    p, H, r = book.provider, book.H, book.rate
    svc = c.service.lower()
    M = REQUESTS_M[t]

    if role == "vm":
        n, size, disk = VM_COUNT[t], VM_SIZE[p][t], VM_DISK_GB[t]
        return n * (book.vm_hour(size) * H + book.disk_month(disk)), f"{n} × {size}, {disk} GB disk each"

    if role == "db":
        gb, standby = DB_STORAGE_GB[t], DB_STANDBY[t]
        ha = " + standby copy" if standby else ""
        engine = _engine(c)
        if p == "aws":
            size = DB_SIZE[p][t]
            table = f"db_{engine}_{'multi' if standby else 'single'}"
            if table not in book.tables:
                table = f"db_postgres_{'multi' if standby else 'single'}"
            store = gb * r("db_storage_gb_month") * (2 if standby else 1)
            return book.size(table, size) * H + store, f"{size}{ha}, {gb} GB storage"
        if p == "azure":
            if "mssql" in svc:
                size = SQLSERVER_SIZE[t]
                return book.size("db_sqlserver", size) * H, f"Azure SQL {size} (DTU tier, storage included)"
            eng = "mysql" if engine == "mysql" else "postgres"
            size = DB_SIZE[p][t]
            hour = 2 * r(f"db_{eng}_gp_vcore_hour") if size.startswith("GP") else book.size(f"db_{eng}", size)
            mult = 2 if standby else 1
            return (hour * H + gb * r("db_storage_gb_month")) * mult, f"Flexible Server {size}{ha}, {gb} GB storage"
        if p == "gcp":
            eng = "mysql" if engine == "mysql" else "postgres"
            dep = "multi" if standby else "single"
            size = DB_SIZE[p][t]
            return (_gcp_sql_hour(book, eng, dep, size) * H + gb * r(f"db_{eng}_{dep}_storage_gb_month"),
                    f"Cloud SQL {size}{ha}, {gb} GB storage")
        if "autonomous" in svc:
            ecpu = (2, 4, 8)[t]
            return (ecpu * r("db_autonomous_ecpu_hour") * H + gb * r("db_autonomous_gb_month"),
                    f"Autonomous Database {ecpu} ECPU, {gb} GB storage")
        ecpu = (2, 4, 8)[t]
        return ecpu * r("db_mysql_ecpu_hour") * H + gb * r("db_mysql_gb_month"), f"MySQL {ecpu} ECPU, {gb} GB storage"

    if role == "nosql":
        gb = NOSQL_GB[t]
        if p == "azure":
            ru = COSMOS_RU[t]
            return (ru / 100 * r("nosql_100ru_hour") * H + gb * r("nosql_gb_month"),
                    f"{ru} RU/s provisioned, {gb} GB")
        if p == "oci":
            return gb * r("nosql_gb_month"), f"{gb} GB stored (read/write units not included)"
        return (M * (r("nosql_read_million") + r("nosql_write_million")) + gb * r("nosql_gb_month"),
                f"{M}M reads + {M}M writes, {gb} GB")

    if role == "cache":
        size, n = CACHE_SIZE[p][t]
        if p == "aws":
            return n * book.size("cache_node", size) * H, f"{n} × {size}"
        if p == "azure":
            return book.size("cache_node", size) * H, f"Azure Cache for Redis {size}"
        if p == "gcp":
            return n * book.size("cache_gb", size) * H, f"Memorystore {size}, {n} GB"
        return n * r("cache_gb_hour") * H, f"{n} GB cache"

    if role == "function":
        gb_s = M * 1e6 * FN_SECONDS * FN_GB
        cost = M * r("fn_request_million") + gb_s * r("fn_gb_second")
        if p == "gcp":
            cost += M * 1e6 * FN_SECONDS * r("fn_vcpu_second")
        return cost, f"{M}M calls a month, 200 ms at 512 MB each"

    if role == "container":
        vcpu, gb, n = CONTAINER[t]
        if p == "aws":
            cost = n * (vcpu * r("container_vcpu_hour") + gb * r("container_gb_hour")) * H
        elif p in ("azure", "gcp"):
            cost = n * (vcpu * r("container_vcpu_second") + gb * r("container_gb_second")) * H * 3600
        else:
            cost = n * book._oci_vm("E5", vcpu / 2, gb) * H
        return cost, f"{n} × {_f(vcpu)} vCPU / {_f(gb)} GB, running all month"

    if role == "k8s":
        cost, detail = r("k8s_cluster_hour") * H, "cluster control plane"
        if not any(role_of(o) == "vm" and re.search(r"node_group|node_pool", o.service, re.I) for o in model.components):
            n, size = K8S_NODES[t], VM_SIZE[p][t]
            cost += n * book.vm_hour(size) * H
            detail += f" + {n} × {size} worker nodes"
        return cost, detail

    if role == "object":
        gb = OBJECT_GB[t]
        return gb * r("object_gb_month"), f"{gb} GB stored"

    if role == "block":
        gb = BLOCK_GB[t]
        return book.disk_month(gb), f"{gb} GB"

    if role == "lb":
        cu, gb = LB_CAPACITY_UNITS[t], DATA_GB[t]
        if p == "aws":
            return (r("lb_hour") + cu * r("lb_capacity_hour")) * H, f"1 load balancer, {cu} capacity unit(s)"
        if p == "azure":
            if "application_gateway" in svc:
                return (r("appgw_hour") + cu * r("lb_capacity_hour")) * H, f"Application Gateway v2, {cu} capacity unit(s)"
            return r("lb_hour") * H + gb * r("lb_data_gb"), f"Standard Load Balancer, {gb} GB processed"
        if p == "gcp":
            return r("lb_hour") * H + gb * r("lb_data_gb"), f"1 forwarding rule, {gb} GB processed"
        return (r("lb_hour") + 10 * r("lb_mbps_hour")) * H, "Flexible Load Balancer, 10 Mbps"

    if role == "apigw":
        if p == "azure":
            return M * 100 * r("apigw_10k"), f"{M}M calls a month (Consumption tier)"
        return M * r("apigw_million"), f"{M}M calls a month"

    if role == "nat":
        gb = DATA_GB[t]
        if p == "oci":
            return 0.0, "NAT Gateway has no charge on Oracle Cloud"
        if p == "gcp":
            n = VM_COUNT[t]
            return n * r("nat_vm_hour") * H + gb * r("nat_gb"), f"{n} VM(s) using it, {gb} GB processed"
        return r("nat_hour") * H + gb * r("nat_gb"), f"1 gateway, {gb} GB processed"

    if role == "cdn":
        gb = CDN_GB[t]
        base = book.rates.get("cdn_base_month", {}).get("usd", 0.0)
        return base + gb * r("cdn_gb"), f"{gb} GB delivered"

    if role == "queue":
        if p == "aws":
            return M * r("notify_million" if "sns" in svc else "queue_million"), f"{M}M requests a month"
        if p == "azure":
            return r("queue_base_hour") * H + M * r("queue_million"), f"Service Bus Standard, {M}M operations"
        if p == "gcp":
            return M * 1e6 * 1024 / 2 ** 40 * r("queue_tib"), f"{M}M messages of 1 KB"
        return M * r("notify_million" if "notification" in svc else "queue_million"), f"{M}M requests a month"

    if role == "waf":
        if p == "azure":
            return 0.0, "WAF policy itself is free on Azure; the gateway it sits on is priced separately"
        if p == "oci":
            return r("waf_policy_month") + M * r("waf_million"), f"1 policy, {M}M requests"
        return r("waf_policy_month") + 5 * r("waf_rule_month") + M * r("waf_million"), f"1 policy, 5 rules, {M}M requests"

    if role == "firewall":
        return r("firewall_hour") * H, "1 firewall, running all month"

    if role == "logs":
        gb = LOGS_GB[t]
        return gb * r("logs_gb"), f"{gb} GB of logs a month"

    if role == "secret":
        if p == "oci":
            return 0.0, "Vault secrets have no charge on Oracle Cloud"
        if p == "azure":
            return r("secret_10k_ops"), "10,000 operations a month"
        return r("secret_month"), "1 secret"

    if role == "kms":
        if p == "oci":
            return 0.0, "software-protected keys have no charge on Oracle Cloud"
        if p == "azure":
            return r("secret_10k_ops"), "10,000 key operations a month"
        return r("kms_key_month"), "1 key"

    if role == "dns":
        if p == "oci":
            return r("dns_million"), "1M queries a month"
        return r("dns_zone_month"), "1 hosted zone"

    raise Unpriced("not covered by the estimator yet")


def _engine(c: Component) -> str:
    text = f"{c.service} {c.properties.get('engine', '')}".lower()
    for word, engine in (("aurora-postgres", "aurora-postgresql"), ("aurora-mysql", "aurora-mysql"),
                         ("aurora", "aurora-postgresql"), ("mysql", "mysql"), ("mariadb", "mariadb"),
                         ("sqlserver", "sqlserver"), ("mssql", "sqlserver")):
        if word in text:
            return engine
    return "postgres"


def _gcp_sql_hour(book: _Book, eng: str, dep: str, tier: str) -> float:
    m = re.fullmatch(r"db-custom-(\d+)-(\d+)", tier)
    if m:
        return (int(m.group(1)) * book.rate(f"db_{eng}_{dep}_vcpu_hour")
                + int(m.group(2)) / 1024 * book.rate(f"db_{eng}_{dep}_ram_gb_hour"))
    return book.size(f"db_{eng}_{dep}", tier)


# --- "As written": price the sizes the input actually states --------------------

def _literal(value) -> str | None:
    """A property value that is a real size, not a Terraform reference or placeholder."""
    s = str(value or "").split(",")[0].strip()
    if not s or s == "configured" or re.match(r"^(var|local|data|module|each)\.|[\[\]{}$]", s) or "." in s and "_" in s.split(".")[0]:
        return None
    return s


def _props(c: Component, model: ArchitectureModel) -> dict:
    """Properties with `var.name` replaced by that Terraform variable's default, when the file gives one."""
    defaults = model.metadata.get("variable_defaults", {})
    return {k: defaults.get(v[4:], v) if isinstance(v, str) and v.startswith("var.") else v
            for k, v in c.properties.items()}


def _int(value, default: int) -> int:
    s = _literal(value)
    return int(s) if s and s.isdigit() and int(s) > 0 else default


def _as_written(book: _Book, role: str, c: Component, model: ArchitectureModel) -> tuple[float, str] | None:
    """Price from stated sizes, or None when the input doesn't state any."""
    P, H, p = _props(c, model), book.H, book.provider
    copies = _int(P.get("count"), 1)
    if role == "vm":
        n = next((_int(P.get(k), 0) for k in ("desired_capacity", "desired_size", "target_size", "instances",
                                              "size", "node_count", "min_size") if _int(P.get(k), 0)), 1)
        size = next((_literal(P.get(k)) for k in ("instance_type", "instance_types", "sku", "size", "vm_size",
                                                  "machine_type", "shape") if _literal(P.get(k))
                     and not str(P.get(k)).isdigit()), None)
        if size is None:   # an auto-scaling group / instance pool takes its size from a template
            for o in model.components:
                if re.search(r"launch_template|instance_template|instance_configuration", o.service, re.I):
                    op = _props(o, model)
                    size = next((_literal(op.get(k)) for k in ("instance_type", "machine_type", "shape")
                                 if _literal(op.get(k)) and _literal(op.get(k)) != "compute"), None)
                    if size:
                        break
        if size is None:
            return None
        if p == "oci":
            ocpus = float(_literal(P.get("ocpus")) or 1)
            gb = float(_literal(P.get("memory_in_gbs")) or 16 * ocpus)
            hour = book._oci_vm(size, ocpus, gb)
            size = f"{size} ({_f(ocpus)} OCPU / {_f(gb)} GB assumed)"
        else:
            hour = book.vm_hour(size)
        return copies * n * hour * H, f"{copies * n} × {size} (disks not included)"
    if role == "db":
        gb = _int(P.get("allocated_storage") or P.get("storage_mb") or P.get("disk_size"), 0)
        if p == "aws":
            size = _literal(P.get("instance_class"))
            if not size:
                return None
            multi = str(P.get("multi_az", "")).lower() == "true"
            table = f"db_{_engine(c)}_{'multi' if multi else 'single'}"
            if table not in book.tables:
                table = f"db_postgres_{'multi' if multi else 'single'}"
            store = gb * book.rate("db_storage_gb_month") * (2 if multi else 1)
            return (copies * (book.size(table, size) * H + store),
                    f"{size}{' Multi-AZ' if multi else ''}" + (f", {gb} GB storage" if gb else ""))
        if p == "gcp":
            tier = _literal(P.get("tier"))
            if not tier:
                return None
            multi = str(P.get("availability_type", "")).upper() == "REGIONAL"
            eng = "mysql" if _engine(c) == "mysql" else "postgres"
            return (_gcp_sql_hour(book, eng, "multi" if multi else "single", tier) * H,
                    f"Cloud SQL {tier}{' regional' if multi else ''} (storage not included)")
        if p == "azure" and "mssql_database" in c.service:
            size = _literal(P.get("sku_name"))
            if size and size in book.tables.get("db_sqlserver", {}):
                return book.size("db_sqlserver", size) * H, f"Azure SQL {size}"
        if p == "oci" and "autonomous" in c.service:
            ecpu = _int(P.get("compute_count"), 0)
            if ecpu:
                tb = _int(P.get("data_storage_size_in_tbs"), 0)
                return (ecpu * book.rate("db_autonomous_ecpu_hour") * H + tb * 1024 * book.rate("db_autonomous_gb_month"),
                        f"Autonomous Database {ecpu} ECPU" + (f", {tb} TB storage" if tb else ""))
        return None
    if role == "cache":
        if p == "aws":
            size = _literal(P.get("node_type"))
            if not size:
                return None
            n = _int(P.get("num_cache_clusters") or P.get("num_cache_nodes"), 2 if str(P.get("multi_az_enabled")) == "true" else 1)
            return n * book.size("cache_node", size) * H, f"{n} × {size}"
        if p == "gcp":
            tier, gb = _literal(P.get("tier")), _int(P.get("memory_size_gb"), 0)
            if tier and gb:
                name = f"{'Standard' if 'STANDARD' in tier.upper() else 'Basic'} {'M1' if gb <= 4 else 'M2'}"
                return gb * book.size("cache_gb", name) * H, f"Memorystore {name}, {gb} GB"
        if p == "azure":
            sku, cap = _literal(P.get("sku_name")), _literal(P.get("capacity"))
            if sku and cap:
                name = f"{sku} {'P' if sku == 'Premium' else 'C'}{cap}"
                return book.size("cache_node", name) * H, f"Azure Cache for Redis {name}"
    return None


# --- The estimate ----------------------------------------------------------------

def estimate(model: ArchitectureModel, region: str = "us") -> dict:
    prices = load_prices()
    if region not in prices["regions"]:
        region = "us"
    books: dict[str, _Book] = {}
    lines, unpriced, no_charge = [], [], 0
    priced: list[tuple[str, str, Component, dict]] = []
    used_providers: set[str] = set()
    any_written = False

    for c in model.components:
        provider, role = provider_of(c), role_of(c)
        if role == "free":
            no_charge += 1
            continue
        if provider is None:
            unpriced.append({"name": c.name, "service": c.service,
                             "reason": "self-hosted or not tied to a cloud: the cost depends on where you run it"})
            continue
        if role is None and c.type in _USUALLY_FREE_TYPES:
            no_charge += 1
            continue
        if role is None:
            unpriced.append({"name": c.name, "service": c.service, "reason": "not covered by the estimator yet"})
            continue
        book = books.setdefault(provider, _Book(provider, region))
        costs: dict[str, dict] = {}
        try:
            for t, tier in enumerate(TIERS):
                usd, detail = _tier_cost(book, role, c, t, model)
                costs[tier] = {"usd": round(usd, 2), "detail": detail}
        except Unpriced as e:
            unpriced.append({"name": c.name, "service": c.service, "reason": str(e)})
            continue
        try:
            written = _as_written(book, role, c, model)
        except Unpriced:
            written = None
        if written:
            any_written = True
            costs["as_written"] = {"usd": round(written[0], 2), "detail": written[1]}
        used_providers.add(provider)
        priced.append((provider, role, c, costs))
        lines.append({"component_id": c.id, "name": c.name, "service": c.service,
                      "provider": PROVIDER_NAMES[provider], "role": ROLE_LABELS[role], "costs": costs})

    tiers = []
    if any_written:
        total = sum(l["costs"].get("as_written", l["costs"]["balanced"])["usd"] for l in lines)
        assumed = sum(1 for l in lines if "as_written" not in l["costs"])
        tiers.append({"key": "as_written", "label": "As written",
                      "blurb": "The sizes your file states (variable defaults included)" + (f"; {assumed} resource(s) without a stated size use the "
                                                               "Balanced assumption." if assumed else "."),
                      "total": round(total, 2)})
    for tier in TIERS:
        label, blurb = TIER_INFO[tier]
        tiers.append({"key": tier, "label": label, "blurb": blurb,
                      "total": round(sum(l["costs"][tier]["usd"] for l in lines), 2)})
    lines.sort(key=lambda l: -l["costs"]["balanced"]["usd"])

    # The same resources re-priced on each cloud, role for role (a VM stays a VM, a database a database).
    other_clouds = []
    for other in PROVIDER_NAMES:
        book = books.setdefault(other, _Book(other, region))
        totals, skipped = [0.0, 0.0, 0.0], 0
        for provider, role, c, costs in priced:
            try:
                row = ([costs[tier]["usd"] for tier in TIERS] if provider == other
                       else [_tier_cost(book, role, c, t, model)[0] for t in range(3)])
            except Unpriced:
                skipped += 1
                continue
            totals = [a + b for a, b in zip(totals, row)]
        other_clouds.append({"provider": PROVIDER_NAMES[other], "current": other in used_providers,
                             "totals": {tier: round(totals[t], 2) for t, tier in enumerate(TIERS)},
                             "not_priced": skipped})
    all_sources = [{"provider": PROVIDER_NAMES[p], **prices["sources"][p]} for p in PROVIDER_NAMES]

    return {
        "available": bool(lines),
        "currency": "USD",
        "region": region,
        "region_label": prices["regions"][region]["label"],
        "regions": [{"key": k, "label": v["label"]} for k, v in prices["regions"].items()],
        "tiers": tiers,
        "lines": lines,
        "no_charge_count": no_charge,
        "unpriced": unpriced,
        "other_clouds": other_clouds if lines else [],
        "sources": all_sources,
        "notes": [
            "List prices for on-demand / pay-as-you-go use, 730 hours a month.",
            "Not included: data transfer out, taxes, support plans, free-tier allowances and committed-use discounts.",
            "Usage-based services (functions, queues, storage, logs) are priced from the usage each level assumes, "
            "shown next to each amount. Your real usage will differ.",
        ],
    }
