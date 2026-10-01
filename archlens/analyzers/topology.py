# Copyright (c) 2026 K.N.Narin (github.com/narin-kura). All rights reserved.
# Non-commercial use only. Commercial use requires written permission: github.com/narin-kura
# See LICENSE for full terms.
"""Topology analyzer — checks that read the edges, not just the nodes.

Every other analyzer judges components in isolation: is this bucket encrypted,
is that database Multi-AZ. This one asks what reaches what. A database can be
perfectly configured and still be a problem if the only thing between it and
the internet is nothing at all.

It stays silent when the model has no connections, which is the case for
Terraform and most cloud exports — absence of edges there means "not described",
not "not connected".
"""

from __future__ import annotations

from .base import BaseAnalyzer
from ..models.architecture import ArchitectureModel, Component, ComponentType
from ..models.findings import Finding, FindingType, Severity

# Anything a request from the public internet can land on first.
_INTERNET_FACING_TYPES = {ComponentType.CDN, ComponentType.GATEWAY}

# Services that terminate internet traffic but are not HTTP front doors, so
# "no WAF in front" is not a meaningful statement about them.
_NON_HTTP_ENTRY = {
    "aws_transfer_server", "aws_connect_instance", "aws_db_proxy",
    "aws_storagegateway_gateway", "aws_lexv2models_bot",
}

_DATA_TYPES = {ComponentType.DATABASE, ComponentType.CACHE, ComponentType.STORAGE}

_FILTER_MARKERS = ("waf", "shield", "firewall", "cloud_armor", "front_door", "cloudflare")


def _is_internet_facing(component: Component) -> bool:
    if component.service in _NON_HTTP_ENTRY:
        return False
    if str(component.properties.get("internal", "false")).lower() in ("true", "yes", "1"):
        return False
    if component.type in _INTERNET_FACING_TYPES:
        return True
    # A VM with a public address is an entry point whether or not it was
    # designed as one.
    public_ip = str(
        component.properties.get("public_ip",
        component.properties.get("associate_public_ip_address",
        component.properties.get("map_public_ip_on_launch", "false")))
    ).lower()
    return public_ip in ("true", "yes", "1")


def _is_traffic_filter(component: Component) -> bool:
    haystack = f"{component.service} {component.name}".lower()
    return any(marker in haystack for marker in _FILTER_MARKERS)


class TopologyAnalyzer(BaseAnalyzer):
    def analyze(self, model: ArchitectureModel) -> list[Finding]:
        if not model.connections:
            return []

        findings: list[Finding] = []
        for check in [
            self._check_internet_reaches_data_tier,
            self._check_entry_point_without_filter,
            self._check_serverless_to_data_outside_vpc,
            self._check_cdn_origin_exposed,
            self._check_unreferenced_data_store,
            self._check_third_party_egress,
        ]:
            findings.extend(check(model))
        return findings

    # ---------------------------------------------------------------- helpers

    @staticmethod
    def _edges(model: ArchitectureModel) -> list[tuple[Component, Component, str]]:
        by_id = {c.id: c for c in model.components}
        resolved = []
        for conn in model.connections:
            source = by_id.get(conn.source_id)
            target = by_id.get(conn.target_id)
            if source is not None and target is not None and source is not target:
                resolved.append((source, target, conn.label or ""))
        return resolved

    # ----------------------------------------------------------------- checks

    def _check_internet_reaches_data_tier(self, model: ArchitectureModel) -> list[Finding]:
        """An internet entry point wired straight into a data store."""
        findings = []
        for source, target, _ in self._edges(model):
            if not _is_internet_facing(source) or target.type not in _DATA_TYPES:
                continue
            # A CDN serving objects out of a bucket is a normal pattern; it has
            # its own check below. This one is about databases and caches.
            if source.type == ComponentType.CDN and target.type == ComponentType.STORAGE:
                continue
            findings.append(Finding(
                type=FindingType.SECURITY,
                severity=Severity.HIGH,
                title=f"'{target.name}' is reachable directly from the internet-facing '{source.name}'",
                description=(
                    f"The diagram connects {source.name} straight to {target.name}, with no application "
                    "tier in between. A flaw at the edge then reaches the data directly."
                ),
                component_id=target.id,
                component_name=target.name,
                recommendation=(
                    "Put an application tier between the edge and the data store, and keep the data "
                    "tier in private subnets reachable only from that tier's security group."
                ),
                references=["https://docs.aws.amazon.com/vpc/latest/userguide/vpc-example-private-subnets-nat.html"],
            ))
        return findings

    def _check_entry_point_without_filter(self, model: ArchitectureModel) -> list[Finding]:
        """An internet-facing HTTP endpoint with no WAF anywhere on its path."""
        edges = self._edges(model)
        if any(_is_traffic_filter(c) for c in model.components):
            # A filter exists; confirm each entry point is actually behind one.
            filtered = {
                target.id for source, target, _ in edges if _is_traffic_filter(source)
            } | {
                source.id for source, target, _ in edges if _is_traffic_filter(target)
            }
        else:
            filtered = set()

        # An entry point forwards traffic inward. A third-party API that only
        # receives our calls is a destination, and no web ACL of ours can sit
        # in front of it.
        forwards_inward = {source.id for source, _, _ in edges}
        receives_only = {target.id for _, target, _ in edges} - forwards_inward

        findings = []
        for c in model.components:
            if not _is_internet_facing(c) or c.type not in _INTERNET_FACING_TYPES:
                continue
            if c.id in filtered or c.id in receives_only:
                continue
            findings.append(Finding(
                type=FindingType.SECURITY,
                severity=Severity.MEDIUM,
                title=f"Internet-facing '{c.name}' has no WAF on its path",
                description=(
                    "Nothing in the diagram filters requests before they reach this endpoint, so "
                    "SQL injection, cross-site scripting and volumetric floods arrive at the application."
                ),
                component_id=c.id,
                component_name=c.name,
                recommendation="Attach AWS WAF (or Cloud Armor / Front Door) to this distribution or API stage.",
                references=["https://docs.aws.amazon.com/waf/latest/developerguide/what-is-aws-waf.html"],
            ))
        return findings

    def _check_serverless_to_data_outside_vpc(self, model: ArchitectureModel) -> list[Finding]:
        """A function that talks to a database from outside the VPC."""
        findings = []
        seen: set[str] = set()
        for source, target, _ in self._edges(model):
            if source.type != ComponentType.SERVERLESS or target.type not in _DATA_TYPES:
                continue
            if source.id in seen:
                continue
            vpc = str(source.properties.get("vpc_config", source.properties.get("vpc_id", ""))).strip()
            if vpc not in ("", "none", "{}", "null"):
                continue
            seen.add(source.id)
            findings.append(Finding(
                type=FindingType.SECURITY,
                severity=Severity.MEDIUM,
                title=f"Function '{source.name}' reaches '{target.name}' from outside a VPC",
                description=(
                    "A function with no VPC configuration reaches its data store over public "
                    "endpoints, which means the store must accept traffic from outside your network."
                ),
                component_id=source.id,
                component_name=source.name,
                recommendation=(
                    "Attach the function to private subnets and reach the data store over a "
                    "VPC endpoint or its private address."
                ),
                references=["https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html"],
            ))
        return findings

    def _check_cdn_origin_exposed(self, model: ArchitectureModel) -> list[Finding]:
        """A CDN origin bucket that the public can also read directly."""
        findings = []
        for source, target, _ in self._edges(model):
            if source.type != ComponentType.CDN or target.type != ComponentType.STORAGE:
                continue
            acl = str(target.properties.get("acl", target.properties.get("public_acl", ""))).lower()
            blocked = str(
                target.properties.get("block_public_acls", target.properties.get("public_access_block", ""))
            ).lower()
            if "public" in acl or blocked not in ("true", "yes", "1", "enabled"):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.HIGH,
                    title=f"CDN origin '{target.name}' can be read without going through '{source.name}'",
                    description=(
                        "The origin bucket is not locked to the distribution, so callers can fetch "
                        "objects directly and bypass the CDN's WAF, logging and signed URLs."
                    ),
                    component_id=target.id,
                    component_name=target.name,
                    recommendation=(
                        "Enable all four Block Public Access settings and grant read access only to "
                        "the distribution through an Origin Access Control policy."
                    ),
                    references=["https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html"],
                ))
        return findings

    def _check_unreferenced_data_store(self, model: ArchitectureModel) -> list[Finding]:
        """A data store nothing in the diagram talks to."""
        connected = set()
        for source, target, _ in self._edges(model):
            connected.add(source.id)
            connected.add(target.id)
        if not connected:
            return []

        findings = []
        for c in model.components:
            if c.type not in _DATA_TYPES or c.id in connected:
                continue
            findings.append(Finding(
                type=FindingType.SECURITY,
                severity=Severity.LOW,
                title=f"Nothing in the diagram reaches '{c.name}'",
                description=(
                    "This data store has no connections. Either the diagram is incomplete, or the "
                    "resource is unused — in which case it is cost and attack surface for nothing."
                ),
                component_id=c.id,
                component_name=c.name,
                recommendation=(
                    "Connect it to whatever reads and writes it, or delete it after confirming "
                    "with CloudTrail data events that nothing is using it."
                ),
                references=["https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/cost-opt-delete-unused.html"],
            ))
        return findings

    def _check_third_party_egress(self, model: ArchitectureModel) -> list[Finding]:
        """Data leaving the account for a third-party endpoint."""
        findings = []
        seen: set[tuple[str, str]] = set()
        for source, target, _ in self._edges(model):
            if source.provider in ("", "generic") or target.provider not in ("", "generic"):
                continue
            if target.type in (ComponentType.OTHER,) and not target.service:
                continue
            key = (source.id, target.id)
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                type=FindingType.SECURITY,
                severity=Severity.INFO,
                title=f"'{source.name}' sends data to the third-party '{target.name}'",
                description=(
                    "This edge leaves your cloud account. Whatever crosses it is governed by the "
                    "provider's terms and retention, not yours."
                ),
                component_id=source.id,
                component_name=source.name,
                recommendation=(
                    "Confirm the data classification allows it, pin TLS, keep the credential in a "
                    "secrets manager, and record the dependency in your vendor review."
                ),
                references=["https://docs.aws.amazon.com/whitepapers/latest/data-classification/data-classification-models-and-schemes.html"],
            ))
        return findings
