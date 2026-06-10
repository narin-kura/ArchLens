"""Security analyzer — rule-based checks against the normalized architecture model."""

from __future__ import annotations

from .base import BaseAnalyzer
from ..models.architecture import ArchitectureModel, ComponentType
from ..models.findings import Finding, FindingType, Severity


class SecurityAnalyzer(BaseAnalyzer):
    def analyze(self, model: ArchitectureModel) -> list[Finding]:
        findings: list[Finding] = []
        for check in [
            # Storage
            self._check_public_storage,
            self._check_unencrypted_storage,
            self._check_no_access_logging,
            self._check_s3_versioning_disabled,
            self._check_public_access_block_missing,
            # Database
            self._check_unencrypted_databases,
            self._check_database_publicly_accessible,
            self._check_no_deletion_protection,
            self._check_no_backup,
            self._check_database_no_multi_az,
            self._check_database_no_audit_log,
            self._check_database_auto_minor_version_disabled,
            # Network
            self._check_open_security_groups,
            self._check_ssh_rdp_open_to_world,
            self._check_unrestricted_egress,
            self._check_ipv6_unrestricted_ingress,
            # IAM
            self._check_overpermissive_iam,
            self._check_iam_wildcard_resource,
            self._check_iam_no_mfa_required,
            self._check_iam_direct_user_attach,
            # Compute
            self._check_compute_imdsv2,
            self._check_compute_public_ip,
            self._check_compute_no_ebs_encryption,
            # Container
            self._check_container_privileged,
            self._check_container_root_user,
            self._check_container_no_resource_limits,
            self._check_container_no_image_scanning,
            # Serverless
            self._check_serverless_overpermissive_role,
            self._check_serverless_no_dead_letter,
            self._check_serverless_no_vpc,
            # Cache
            self._check_cache_no_auth,
            self._check_cache_not_encrypted,
            # Queue
            self._check_queue_no_encryption,
            self._check_queue_no_dlq,
            # CDN
            self._check_cdn_no_https_only,
            self._check_cdn_outdated_tls,
            # Gateway
            self._check_gateway_no_auth,
            self._check_gateway_no_throttling,
            self._check_gateway_no_logging,
            self._check_no_waf,
            # Cross-cutting
            self._check_hardcoded_credentials,
            self._check_encryption_in_transit,
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
                    references=["https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html"],
                ))
        return findings

    def _check_unencrypted_storage(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.STORAGE):
            sse = str(c.properties.get("server_side_encryption", c.properties.get("encryption", ""))).lower()
            if sse in ("false", "no", "none", "disabled", ""):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.HIGH,
                    title=f"Storage '{c.name}' is not encrypted at rest",
                    description="Unencrypted storage exposes data if the underlying media is accessed or stolen.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Enable server-side encryption (SSE-S3 minimum, SSE-KMS for sensitive data).",
                    references=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/serv-side-encryption.html"],
                ))
        return findings

    def _check_no_access_logging(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.STORAGE):
            logging_val = str(c.properties.get("logging", c.properties.get("access_log", ""))).lower()
            if logging_val in ("false", "no", "none", "disabled", ""):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"Storage '{c.name}' has no access logging enabled",
                    description="Without access logs, unauthorized data access or exfiltration cannot be detected or investigated.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Enable S3 server access logging or equivalent. Ship logs to a SIEM.",
                    references=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html"],
                ))
        return findings

    def _check_database_publicly_accessible(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.DATABASE):
            publicly_accessible = str(c.properties.get("publicly_accessible", "false")).lower()
            if publicly_accessible in ("true", "yes", "1"):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.CRITICAL,
                    title=f"Database '{c.name}' is publicly accessible from the internet",
                    description="A publicly accessible database is directly reachable without going through the application tier, bypassing network controls.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Set publicly_accessible = false. Place databases in private subnets and access via the application tier.",
                    references=["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.DBInstance.Modifying.html"],
                ))
        return findings

    def _check_no_deletion_protection(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.DATABASE):
            deletion_protection = str(c.properties.get("deletion_protection", "false")).lower()
            if deletion_protection in ("false", "no", "0", ""):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"Database '{c.name}' has no deletion protection",
                    description="Without deletion protection, a misconfigured deployment or human error can permanently destroy the database.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Set deletion_protection = true on all production databases.",
                    references=["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteInstance.html"],
                ))
        return findings

    def _check_no_backup(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        backup_types = {ComponentType.DATABASE, ComponentType.STORAGE}
        for c in model.components:
            if c.type not in backup_types:
                continue
            retention = str(c.properties.get("backup_retention_period", "0"))
            backup_enabled = str(c.properties.get("backup_enabled", "")).lower()
            if retention in ("0", "") and backup_enabled not in ("true", "yes", "1"):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.HIGH,
                    title=f"'{c.name}' has no backup configured",
                    description="Without backups, data is irrecoverable after corruption, accidental deletion, or ransomware.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Set backup_retention_period >= 7 days. Validate restores periodically.",
                    references=["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html"],
                ))
        return findings

    def _check_ssh_rdp_open_to_world(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.NETWORK):
            ingress = c.properties.get("ingress", [])
            if not isinstance(ingress, list):
                ingress = [ingress]
            for rule in ingress:
                rule_str = str(rule)
                if "0.0.0.0/0" not in rule_str and "::/0" not in rule_str:
                    continue
                ports_exposed = False
                if isinstance(rule, dict):
                    try:
                        fp = int(rule.get("from_port", rule.get("FromPort", -1)))
                        tp = int(rule.get("to_port", rule.get("ToPort", fp)))
                        ports_exposed = (fp <= 22 <= tp) or (fp <= 3389 <= tp)
                    except (ValueError, TypeError):
                        ports_exposed = "22" in rule_str or "3389" in rule_str
                else:
                    ports_exposed = "22" in rule_str or "3389" in rule_str
                if ports_exposed:
                    findings.append(Finding(
                        type=FindingType.SECURITY,
                        severity=Severity.HIGH,
                        title=f"Network '{c.name}' exposes SSH/RDP to the internet",
                        description="Open SSH (22) or RDP (3389) to 0.0.0.0/0 allows brute-force and credential-stuffing attacks from any IP.",
                        component_id=c.id,
                        component_name=c.name,
                        recommendation="Restrict SSH/RDP ingress to known IP ranges, or use a bastion host / VPN.",
                        references=["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules.html"],
                    ))
                    break
        return findings

    def _check_gateway_no_auth(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.GATEWAY):
            auth = str(c.properties.get("authorization", c.properties.get("authentication", ""))).lower()
            if auth in ("none", ""):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.HIGH,
                    title=f"API Gateway '{c.name}' has no authentication configured",
                    description="An unauthenticated API endpoint is reachable by any caller on the internet with no identity verification.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Add an authorizer (IAM SigV4, JWT/Cognito, or Lambda) to all API Gateway stages.",
                    references=["https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-to-api.html"],
                ))
        return findings

    def _check_no_waf(self, model: ArchitectureModel) -> list[Finding]:
        gateways = model.components_by_type(ComponentType.GATEWAY)
        cdns = model.components_by_type(ComponentType.CDN)
        if not gateways and not cdns:
            return []
        has_waf = any(
            "waf" in c.service.lower() or "waf" in c.name.lower()
            for c in model.components
        )
        if not has_waf:
            return [Finding(
                type=FindingType.SECURITY,
                severity=Severity.MEDIUM,
                title="No WAF detected for public-facing endpoints",
                description="Without a Web Application Firewall, internet-facing APIs and CDNs are unprotected against SQLi, XSS, and volumetric attacks.",
                recommendation="Attach AWS WAF (or equivalent) to API Gateway stages and CloudFront distributions.",
                references=["https://docs.aws.amazon.com/waf/latest/developerguide/what-is-aws-waf.html"],
            )]
        return []

    def _check_serverless_overpermissive_role(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.SERVERLESS):
            role = str(c.properties.get("role", "")).lower()
            if "admin" in role or "administrator" in role or role.endswith(":*"):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.HIGH,
                    title=f"Serverless function '{c.name}' uses an overpermissive IAM role",
                    description="An admin or wildcard role attached to a function violates least-privilege and widens the blast radius of a compromise.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Create a dedicated execution role scoped to only the permissions the function requires.",
                    references=["https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html"],
                ))
        return findings

    def _check_compute_imdsv2(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.COMPUTE):
            metadata_opts = c.properties.get("metadata_options", {})
            http_tokens = str(
                metadata_opts.get("http_tokens", "") if isinstance(metadata_opts, dict)
                else c.properties.get("http_tokens", "optional")
            ).lower()
            if http_tokens not in ("required", "v2"):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"Compute '{c.name}' may allow IMDSv1 (instance metadata service v1)",
                    description="IMDSv1 is vulnerable to SSRF attacks that can expose instance credentials and role tokens.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Set metadata_options.http_tokens = 'required' to enforce IMDSv2 on all EC2 instances.",
                    references=["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html"],
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
                references=["https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/working_with_metrics.html"],
            )]
        return []

    # ------------------------------------------------------------------ Storage

    def _check_s3_versioning_disabled(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.STORAGE):
            versioning = str(c.properties.get("versioning", c.properties.get("versioning_enabled", ""))).lower()
            if versioning not in ("enabled", "true", "yes", "1"):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"Storage '{c.name}' has versioning disabled",
                    description="Without versioning, accidental deletions and ransomware overwrites are unrecoverable.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Enable S3 versioning and pair it with lifecycle rules to expire old versions cost-effectively.",
                    references=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html"],
                ))
        return findings

    def _check_public_access_block_missing(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.STORAGE):
            block = str(c.properties.get("block_public_acls", c.properties.get("public_access_block", "false"))).lower()
            if block not in ("true", "yes", "1", "enabled"):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.HIGH,
                    title=f"Storage '{c.name}' is missing the public access block",
                    description="Without block_public_acls/block_public_policy, future ACL or policy changes can silently expose the bucket.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Enable all four S3 Block Public Access settings at the bucket and account level.",
                    references=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"],
                ))
        return findings

    # ----------------------------------------------------------------- Database

    def _check_database_no_multi_az(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.DATABASE):
            multi_az = str(c.properties.get("multi_az", c.properties.get("availability", "false"))).lower()
            if multi_az not in ("true", "yes", "1", "enabled"):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"Database '{c.name}' is not Multi-AZ",
                    description="A single-AZ database is a single point of failure; an AZ outage causes downtime and potential data loss.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Enable Multi-AZ for automatic failover in production environments.",
                    references=["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.html"],
                ))
        return findings

    def _check_database_no_audit_log(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.DATABASE):
            audit = str(c.properties.get("audit_log", c.properties.get("enable_audit_log", ""))).lower()
            if audit not in ("true", "yes", "1", "enabled"):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"Database '{c.name}' has no audit logging enabled",
                    description="Without audit logs, unauthorized queries, privilege escalations, and data exfiltration go undetected.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Enable database audit logging and ship logs to CloudWatch Logs or a SIEM.",
                    references=["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_LogAccess.html"],
                ))
        return findings

    def _check_database_auto_minor_version_disabled(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.DATABASE):
            auto_upgrade = str(c.properties.get("auto_minor_version_upgrade", "true")).lower()
            if auto_upgrade in ("false", "no", "0"):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.LOW,
                    title=f"Database '{c.name}' will not auto-apply minor version patches",
                    description="Disabling automatic minor version upgrades leaves known CVEs unpatched until manually applied.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Enable auto_minor_version_upgrade = true, or establish a documented patching schedule.",
                    references=["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_UpgradeDBInstance.Upgrading.html"],
                ))
        return findings

    # ------------------------------------------------------------------ Network

    def _check_unrestricted_egress(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.NETWORK):
            egress = c.properties.get("egress", [])
            if not isinstance(egress, list):
                egress = [egress]
            for rule in egress:
                rule_str = str(rule)
                if "0.0.0.0/0" in rule_str or "::/0" in rule_str:
                    findings.append(Finding(
                        type=FindingType.SECURITY,
                        severity=Severity.MEDIUM,
                        title=f"Network '{c.name}' has unrestricted outbound (egress) traffic",
                        description="Unrestricted egress enables data exfiltration and C2 communication if a workload is compromised.",
                        component_id=c.id,
                        component_name=c.name,
                        recommendation="Restrict egress to specific ports and destinations required by the application.",
                        references=["https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html"],
                    ))
                    break
        return findings

    def _check_ipv6_unrestricted_ingress(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.NETWORK):
            ingress = c.properties.get("ingress", [])
            if not isinstance(ingress, list):
                ingress = [ingress]
            for rule in ingress:
                if "::/0" in str(rule):
                    findings.append(Finding(
                        type=FindingType.SECURITY,
                        severity=Severity.MEDIUM,
                        title=f"Network '{c.name}' allows unrestricted IPv6 inbound traffic",
                        description="::/0 grants access from any IPv6 address. IPv6 rules are often overlooked while IPv4 is tightly controlled.",
                        component_id=c.id,
                        component_name=c.name,
                        recommendation="Apply the same least-privilege CIDR restrictions to IPv6 rules as to IPv4.",
                        references=["https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html"],
                    ))
                    break
        return findings

    # --------------------------------------------------------------------- IAM

    def _check_iam_wildcard_resource(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.IAM):
            policy = str(c.properties.get("policy", ""))
            if '"Resource": "*"' in policy or "'Resource': '*'" in policy or "Resource: '*'" in policy:
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.HIGH,
                    title=f"IAM '{c.name}' grants permissions on all resources (*)",
                    description="Wildcard Resource (*) allows the policy to act on any AWS resource, not just the intended targets.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Scope Resource to specific ARNs. Use conditions to add additional guardrails.",
                    references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html"],
                ))
        return findings

    def _check_iam_no_mfa_required(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.IAM):
            mfa = str(c.properties.get("mfa_required", c.properties.get("mfa", ""))).lower()
            if mfa not in ("true", "yes", "1", "required", "enabled"):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.HIGH,
                    title=f"IAM '{c.name}' does not require MFA",
                    description="Without MFA enforcement, a stolen password alone is sufficient to access sensitive operations.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Add a Condition with aws:MultiFactorAuthPresent: true to policies that control sensitive actions.",
                    references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"],
                ))
        return findings

    def _check_iam_direct_user_attach(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.IAM):
            attached_to = str(c.properties.get("attached_to", c.properties.get("principal_type", ""))).lower()
            if "user" in attached_to:
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.LOW,
                    title=f"IAM policy '{c.name}' is attached directly to a user",
                    description="Attaching policies directly to users instead of roles/groups makes access reviews and revocation harder.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Attach policies to IAM groups or roles, then assign users to groups.",
                    references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#use-groups-for-permissions"],
                ))
        return findings

    # ----------------------------------------------------------------- Compute

    def _check_compute_public_ip(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.COMPUTE):
            public_ip = str(c.properties.get("associate_public_ip_address", c.properties.get("public_ip", "false"))).lower()
            if public_ip in ("true", "yes", "1"):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"Compute '{c.name}' has a public IP address directly assigned",
                    description="A directly attached public IP exposes the instance to the internet without the protection of a load balancer or NAT.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Place instances in private subnets. Use a load balancer for inbound and a NAT gateway for outbound traffic.",
                    references=["https://docs.aws.amazon.com/vpc/latest/userguide/vpc-ip-addressing.html"],
                ))
        return findings

    def _check_compute_no_ebs_encryption(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.COMPUTE):
            ebs_opts = c.properties.get("ebs_block_device", c.properties.get("root_block_device", {}))
            if isinstance(ebs_opts, dict):
                encrypted = str(ebs_opts.get("encrypted", "false")).lower()
            else:
                encrypted = str(c.properties.get("ebs_encrypted", "false")).lower()
            if encrypted not in ("true", "yes", "1"):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.HIGH,
                    title=f"Compute '{c.name}' has unencrypted EBS volumes",
                    description="Unencrypted EBS volumes expose data if a snapshot is shared, exported, or the volume is detached and moved.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Enable EBS encryption by default in the account, or set encrypted = true on each block device.",
                    references=["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html"],
                ))
        return findings

    # --------------------------------------------------------------- Container

    def _check_container_privileged(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.CONTAINER):
            privileged = str(c.properties.get("privileged", "false")).lower()
            if privileged in ("true", "yes", "1"):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.CRITICAL,
                    title=f"Container '{c.name}' runs in privileged mode",
                    description="Privileged containers have full access to the host kernel — a container escape becomes a full host compromise.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Remove privileged: true. Use specific Linux capabilities (cap_add) instead of full privilege.",
                    references=["https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities"],
                ))
        return findings

    def _check_container_root_user(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.CONTAINER):
            user = str(c.properties.get("user", c.properties.get("run_as_user", "0"))).strip()
            if user in ("0", "root", ""):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.HIGH,
                    title=f"Container '{c.name}' runs as root",
                    description="Running as root inside a container increases the impact of a container breakout or process exploit.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Set a non-root USER in the Dockerfile, or use run_as_user / run_as_non_root in the pod spec.",
                    references=["https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user"],
                ))
        return findings

    def _check_container_no_resource_limits(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.CONTAINER):
            cpu = c.properties.get("cpu_limit", c.properties.get("cpu", ""))
            memory = c.properties.get("memory_limit", c.properties.get("memory", ""))
            if not cpu or not memory:
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"Container '{c.name}' has no CPU/memory limits",
                    description="Without resource limits, a compromised or buggy container can exhaust host resources and cause a denial-of-service.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Set explicit cpu_limit and memory_limit on all containers.",
                    references=["https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/"],
                ))
        return findings

    def _check_container_no_image_scanning(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.CONTAINER):
            scan = str(c.properties.get("image_scanning_enabled", c.properties.get("scan_on_push", "false"))).lower()
            if scan not in ("true", "yes", "1", "enabled"):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"Container '{c.name}' has no image vulnerability scanning",
                    description="Images without scanning may ship known CVEs into production undetected.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Enable scan_on_push in ECR (or equivalent registry). Fail CI pipelines on critical CVEs.",
                    references=["https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html"],
                ))
        return findings

    # --------------------------------------------------------------- Serverless

    def _check_serverless_no_dead_letter(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.SERVERLESS):
            dlq = str(c.properties.get("dead_letter_config", c.properties.get("dlq", ""))).lower()
            if dlq in ("", "none", "false", "{}"):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"Serverless function '{c.name}' has no dead-letter queue",
                    description="Failed async invocations are silently dropped without a DLQ, hiding processing errors and potential data loss.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Configure a dead_letter_config pointing to an SQS queue or SNS topic, and alert on DLQ depth.",
                    references=["https://docs.aws.amazon.com/lambda/latest/dg/invocation-async.html#invocation-dlq"],
                ))
        return findings

    def _check_serverless_no_vpc(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.SERVERLESS):
            vpc = str(c.properties.get("vpc_config", c.properties.get("vpc_id", ""))).strip()
            if vpc in ("", "none", "{}", "null"):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.LOW,
                    title=f"Serverless function '{c.name}' runs outside a VPC",
                    description="Functions outside a VPC access downstream services over the public internet, bypassing private network controls.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Attach the function to a VPC with private subnets if it needs to reach databases or internal services.",
                    references=["https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html"],
                ))
        return findings

    # ------------------------------------------------------------------- Cache

    def _check_cache_no_auth(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.CACHE):
            auth = str(c.properties.get("auth_token", c.properties.get("authentication", ""))).strip()
            if auth in ("", "none", "false"):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.HIGH,
                    title=f"Cache '{c.name}' has no authentication configured",
                    description="An unauthenticated cache (Redis/Memcached) can be read and written by any process that can reach it on the network.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Enable AUTH tokens for Redis, or use VPC security groups and IAM auth as a minimum control.",
                    references=["https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/auth.html"],
                ))
        return findings

    def _check_cache_not_encrypted(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.CACHE):
            at_rest = str(c.properties.get("at_rest_encryption_enabled", "false")).lower()
            in_transit = str(c.properties.get("transit_encryption_enabled", "false")).lower()
            if at_rest not in ("true", "yes", "1") or in_transit not in ("true", "yes", "1"):
                which = []
                if at_rest not in ("true", "yes", "1"):
                    which.append("at rest")
                if in_transit not in ("true", "yes", "1"):
                    which.append("in transit")
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.HIGH,
                    title=f"Cache '{c.name}' is not encrypted ({' and '.join(which)})",
                    description=f"Unencrypted cache data ({', '.join(which)}) is readable by anyone with network access to the node.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Enable at_rest_encryption_enabled and transit_encryption_enabled on all ElastiCache clusters.",
                    references=["https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/encryption.html"],
                ))
        return findings

    # ------------------------------------------------------------------- Queue

    def _check_queue_no_encryption(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.QUEUE):
            kms = str(c.properties.get("kms_master_key_id", c.properties.get("encryption", ""))).strip()
            if kms in ("", "none", "false"):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"Queue '{c.name}' messages are not encrypted at rest",
                    description="Unencrypted SQS/SNS messages can be read by anyone with access to the underlying storage.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Set kms_master_key_id to a KMS key (or use alias/aws/sqs for the AWS-managed key).",
                    references=["https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html"],
                ))
        return findings

    def _check_queue_no_dlq(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.QUEUE):
            dlq = str(c.properties.get("redrive_policy", c.properties.get("dlq", ""))).strip()
            if dlq in ("", "none", "false", "{}"):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"Queue '{c.name}' has no dead-letter queue (redrive policy)",
                    description="Messages that fail processing repeatedly are deleted without a DLQ, causing silent data loss.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Configure a redrive_policy with a DLQ and set maxReceiveCount to a low value (e.g. 3–5).",
                    references=["https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html"],
                ))
        return findings

    # --------------------------------------------------------------------- CDN

    def _check_cdn_no_https_only(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.CDN):
            protocol = str(c.properties.get("viewer_protocol_policy", c.properties.get("https_only", ""))).lower()
            if protocol not in ("redirect-to-https", "https-only", "true", "yes", "1"):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.HIGH,
                    title=f"CDN '{c.name}' allows plain HTTP traffic",
                    description="Allowing HTTP exposes users to MITM attacks and cookie/credential theft over unencrypted connections.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Set viewer_protocol_policy = 'redirect-to-https' or 'https-only' on all CloudFront behaviors.",
                    references=["https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https.html"],
                ))
        return findings

    def _check_cdn_outdated_tls(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.CDN):
            tls_policy = str(c.properties.get("minimum_protocol_version", c.properties.get("ssl_policy", ""))).lower()
            outdated = {"tlsv1", "tlsv1_2016", "tlsv1.1_2016", "tlsv1_2018", "tls 1.0", "tls 1.1"}
            if tls_policy and tls_policy in outdated:
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"CDN '{c.name}' allows outdated TLS versions",
                    description=f"TLS policy '{tls_policy}' permits TLS 1.0/1.1, which have known vulnerabilities (BEAST, POODLE).",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Set minimum_protocol_version to TLSv1.2_2021 or newer on all CloudFront distributions.",
                    references=["https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html"],
                ))
        return findings

    # ----------------------------------------------------------------- Gateway

    def _check_gateway_no_throttling(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.GATEWAY):
            throttle = str(c.properties.get("throttling_rate_limit", c.properties.get("rate_limit", ""))).strip()
            if throttle in ("", "0", "none", "-1"):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"API Gateway '{c.name}' has no throttling / rate limits",
                    description="Without throttling, the API is vulnerable to abuse, credential stuffing, and volumetric DoS attacks.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Set throttling_rate_limit and throttling_burst_limit on the stage, and use a usage plan for API key clients.",
                    references=["https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-request-throttling.html"],
                ))
        return findings

    def _check_gateway_no_logging(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.GATEWAY):
            logging_val = str(c.properties.get("access_log_settings", c.properties.get("logging", ""))).lower()
            if logging_val in ("", "none", "false", "disabled", "{}"):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"API Gateway '{c.name}' has no access logging configured",
                    description="Without access logs, malicious API calls, error spikes, and data exfiltration attempts go undetected.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Enable access_log_settings with a CloudWatch log group ARN, and enable execution logging at the stage level.",
                    references=["https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html"],
                ))
        return findings

    # ----------------------------------------------------------- Cross-cutting

    def _check_hardcoded_credentials(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        sensitive_keys = {
            "password", "secret", "token", "api_key", "apikey",
            "access_key", "secret_key", "private_key", "credentials",
            "db_password", "database_password",
        }
        for c in model.components:
            for key, value in c.properties.items():
                if key.lower() in sensitive_keys and isinstance(value, str) and value and value.lower() not in (
                    "true", "false", "", "null", "none", "var.", "${", "arn:", "ssm:", "secretsmanager:"
                ) and not value.startswith(("${", "var.", "data.", "arn:", "ssm:", "/aws/")):
                    findings.append(Finding(
                        type=FindingType.SECURITY,
                        severity=Severity.CRITICAL,
                        title=f"Possible hardcoded credential in '{c.name}' (key: {key})",
                        description=f"The property '{key}' appears to contain a literal secret rather than a reference to a secrets manager.",
                        component_id=c.id,
                        component_name=c.name,
                        recommendation="Replace hardcoded values with references to AWS Secrets Manager, SSM Parameter Store, or Vault.",
                        references=["https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html"],
                    ))
                    break
        return findings

    def _check_encryption_in_transit(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        check_types = {ComponentType.DATABASE, ComponentType.CACHE, ComponentType.QUEUE}
        for c in model.components:
            if c.type not in check_types:
                continue
            tls = str(c.properties.get("transit_encryption_enabled",
                      c.properties.get("ssl_enabled",
                      c.properties.get("require_ssl", "false")))).lower()
            if tls not in ("true", "yes", "1", "enabled", "required"):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.HIGH,
                    title=f"'{c.name}' does not enforce encryption in transit",
                    description="Data flowing to/from this service without TLS can be intercepted in a VPC by a compromised workload.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Enable transit_encryption_enabled / require_ssl on all data-tier services.",
                    references=["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html"],
                ))
        return findings
