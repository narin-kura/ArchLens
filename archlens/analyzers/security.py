"""Security analyzer — rule-based checks against the normalized architecture model."""

from __future__ import annotations

from .base import BaseAnalyzer
from ..models.architecture import ArchitectureModel, ComponentType
from ..models.findings import Finding, FindingType, Severity


class SecurityAnalyzer(BaseAnalyzer):
    def analyze(self, model: ArchitectureModel) -> list[Finding]:
        findings: list[Finding] = []
        for check in [
            self._check_public_storage,
            self._check_unencrypted_databases,
            self._check_overpermissive_iam,
            self._check_open_security_groups,
            self._check_no_monitoring,
        ]:
            findings.extend(check(model))
        return findings

    def _check_public_storage(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.STORAGE):
            acl = c.properties.get("acl", "")
            public_acl = c.properties.get("public_acl", "")
            if "public" in acl.lower() or "public" in public_acl.lower():
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.CRITICAL,
                    title=f"Storage bucket '{c.name}' is publicly accessible",
                    description=f"ACL is set to '{acl or public_acl}'. Public buckets expose data to the internet.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Set bucket ACL to private. Use pre-signed URLs or CloudFront for public content.",
                    references=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-overview.html"],
                ))
        return findings

    def _check_unencrypted_databases(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.DATABASE):
            encrypted = c.properties.get("storage_encrypted", "").lower()
            encryption = c.properties.get("encryption", "").lower()
            if encrypted in ("false", "no", "") and encryption in ("false", "no", "none", ""):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.HIGH,
                    title=f"Database '{c.name}' has no encryption at rest",
                    description="Unencrypted databases risk data exposure if storage media is compromised.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Enable storage_encrypted = true. Use KMS customer-managed keys for regulated data.",
                    references=["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html"],
                ))
        return findings

    def _check_overpermissive_iam(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.IAM):
            policy = str(c.properties.get("policy", ""))
            if '"*"' in policy or "'*'" in policy or "Action: '*'" in policy:
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.HIGH,
                    title=f"IAM '{c.name}' uses wildcard permissions",
                    description="Wildcard Action (*) violates least-privilege principle and broadens attack surface.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Scope IAM policies to specific actions and resources required.",
                    references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"],
                ))
        return findings

    def _check_open_security_groups(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.NETWORK):
            cidr = str(c.properties.get("cidr_blocks", ""))
            if "0.0.0.0/0" in cidr:
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"Network '{c.name}' allows unrestricted inbound traffic",
                    description="0.0.0.0/0 CIDR allows traffic from any IP address.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Restrict inbound rules to known IP ranges. Use VPN or bastion host for admin access.",
                ))
        return findings

    def _check_no_monitoring(self, model: ArchitectureModel) -> list[Finding]:
        has_monitoring = bool(model.components_by_type(ComponentType.MONITORING))
        if not has_monitoring and model.components:
            return [Finding(
                type=FindingType.SECURITY,
                severity=Severity.MEDIUM,
                title="No monitoring or observability components detected",
                description="Without monitoring, security incidents and anomalies go undetected.",
                recommendation="Add CloudWatch, Datadog, or equivalent. Enable VPC Flow Logs and CloudTrail.",
            )]
        return []
