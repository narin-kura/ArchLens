"""Security analyzer — rule-based checks against the normalized architecture model."""

from __future__ import annotations

import re

from .base import BaseAnalyzer
from ..models.architecture import ArchitectureModel, Component, ComponentType, grouped_properties
from ..models.findings import Finding, FindingType, Severity

# MFA applies to identities a person signs in as. A service role assumed by
# Lambda or EC2 has no password and no MFA device, so demanding MFA of it is
# noise, not a finding.
_HUMAN_IDENTITY_SERVICES = {
    "aws_iam_user", "aws_iam_group", "aws_iam_user_policy", "aws_iam_group_policy",
    "iam_user", "iam_group",
    "azuread_user", "google_project_iam_member",
}


# Authorizers, usage plans and stage access logs are API-gateway concepts. A
# load balancer is also a GATEWAY component but has none of them, so the
# API-specific checks skip it.
_API_GATEWAY_MARKERS = ("apigateway", "api_gateway", "appsync", "http_api", "graphql")


def _is_api_gateway(component: Component) -> bool:
    service = component.service.lower()
    if any(marker in service for marker in _API_GATEWAY_MARKERS):
        return True
    # A Kubernetes Ingress, or a gateway from prose or a diagram, carries no
    # cloud resource type but is still an HTTP front door.
    return not service.startswith(("aws_", "google_", "azurerm_"))


# These engines have no deletion-protection flag at all; you guard them with
# final snapshots and IAM instead.
_NO_DELETION_PROTECTION = {
    "aws_opensearch_domain", "aws_elasticsearch_domain", "aws_memorydb_cluster",
    "aws_redshift_cluster", "aws_docdb_cluster",
    # Azure SQL protects via RBAC/locks, not a resource-level flag — neither
    # the server nor the database has a deletion-protection attribute at all.
    "azurerm_mssql_server", "azurerm_sql_server",
    "azurerm_mssql_database", "azurerm_sql_database",
    # No resource-level flag exists — Cosmos DB is protected by RBAC and
    # resource locks, the same as the SQL resources above.
    "azurerm_cosmosdb_account", "azurerm_synapse_sql_pool",
    "azurerm_digital_twins_instance",
}

# Encryption at rest is Microsoft-managed and unconditional for these — TDE
# for SQL, platform encryption for Cosmos DB and the flexible-server engines.
# An optional customer-managed key changes who holds the key, not whether the
# data is encrypted, so there is no meaningful "is it encrypted" to assert.
_ALWAYS_ENCRYPTED_DATABASES = {
    "azurerm_mssql_database", "azurerm_sql_database", "azurerm_cosmosdb_account",
    "azurerm_postgresql_flexible_server", "azurerm_mysql_flexible_server",
    "azurerm_synapse_sql_pool", "azurerm_digital_twins_instance",
}

# The logical server resource (connection endpoint, TLS policy, firewall
# rules) holds no data of its own — encryption, backup retention and zone
# redundancy belong to the database resource it hosts, not the server.
_LOGICAL_DB_SERVERS = {"azurerm_mssql_server", "azurerm_sql_server"}

# TLS enforcement and audit logging are configured once, at the server, and
# apply to every database on it — checking the database too would double
# the same missing-setting finding without adding information.
_DELEGATES_TO_SERVER = {"azurerm_mssql_database", "azurerm_sql_database"}

# Snapshots, failover and deletion windows on a serverless data service are
# AWS's job — there is no retention or deletion-protection setting to assert.
_MANAGED_DATA_SERVICES = {
    "aws_redshiftserverless_namespace", "aws_redshiftserverless_workgroup",
    "aws_opensearchserverless_collection", "aws_aurora_dsql", "aws_keyspaces_table",
    "aws_timestreamwrite_table", "aws_timestreamwrite_database",
    "aws_healthlake_fhir_datastore", "aws_bedrockagent_knowledge_base",
    "aws_iotsitewise_asset_model", "aws_neptune_analytics", "aws_finspace",
    # A global cluster is a container: retention and encryption are set on the
    # regional clusters that belong to it.
    "aws_rds_global_cluster", "aws_dynamodb_global_table",
}

# Multi-AZ, audit logs, TLS enforcement and minor-version patching are settings
# of an instance-based engine. DynamoDB, Keyspaces, Timestream and the
# serverless engines expose none of them — AWS operates them across AZs, over
# TLS only, and patches them. Applying RDS controls to them invents findings.
_INSTANCE_DATABASES = {
    "aws_db_instance", "aws_rds_instance", "aws_rds_cluster", "aws_rds_cluster_instance",
    "aws_docdb_cluster", "aws_neptune_cluster", "aws_memorydb_cluster",
    "aws_redshift_cluster", "aws_opensearch_domain", "aws_elasticsearch_domain",
    "azurerm_mssql_server", "azurerm_mssql_database", "azurerm_postgresql_flexible_server",
    "azurerm_mysql_flexible_server", "google_sql_database_instance",
}


def _is_instance_database(component: Component) -> bool:
    # A model built from prose or a diagram carries no resource type, so fall
    # back to checking it anyway rather than skipping silently.
    return component.service in _INSTANCE_DATABASES or not component.service.startswith(("aws_", "google_", "azurerm_"))


# A dead-letter queue and a VPC attachment belong to a function. Step Functions
# state machines, event-source mappings and schedulers are SERVERLESS too but
# have neither.
_FUNCTION_SERVICES = {
    "aws_lambda_function", "azurerm_function_app", "azurerm_linux_function_app",
    "google_cloudfunctions_function", "google_cloudfunctions2_function", "lambda",
}

# Dead-lettering is configured per-trigger in the function's code/bindings,
# not as an attribute on the function resource itself the way AWS Lambda's
# dead_letter_config is — there is nothing on these resources to check.
_AZURE_FUNCTION_SERVICES = {
    "azurerm_function_app", "azurerm_linux_function_app", "azurerm_windows_function_app",
}

# MSK Serverless encrypts at rest with no attribute to set or unset.
_ALWAYS_ENCRYPTED_QUEUES = {
    "aws_msk_serverless_cluster", "azurerm_servicebus_namespace",
    "azurerm_servicebus_topic", "azurerm_servicebus_subscription",
    "azurerm_servicebus_queue", "azurerm_eventgrid_topic",
    "azurerm_eventgrid_system_topic", "azurerm_eventhub_namespace",
    # Encryption is set once at the namespace; the hub itself is a partitioned
    # topic within it with no encryption attribute of its own.
    "azurerm_eventhub",
}

# Rules, subscriptions and event-source mappings route messages; they do not
# store them, so they have no encryption or redrive settings of their own.
_MESSAGE_ROUTERS = {
    "aws_cloudwatch_event_rule", "aws_sns_topic_subscription",
    "aws_lambda_event_source_mapping", "aws_pipes_pipe", "aws_iot_topic_rule",
    # These send or schedule messages; none of them stores a payload of its own.
    "aws_ses_domain_identity", "aws_pinpoint_app", "aws_batch_job_queue",
    # A consumer group is a read cursor, not a message store; a Stream
    # Analytics input is a job's binding to an existing Event Hub.
    "azurerm_eventhub_consumer_group", "azurerm_stream_analytics_stream_input_eventhub",
    "azurerm_eventgrid_event_subscription",
}

# These origins only ever serve over HTTPS — there is no plaintext option to
# turn off, and no viewer protocol policy on the resource.
_HTTPS_ONLY_ORIGINS = {
    "aws_mediapackage_channel", "aws_media_package_channel", "aws_ivs_channel",
    "aws_mediapackagev2_channel",
}

# Front Door splits one logical CDN across four resources — profile, endpoint,
# origin and origin group carry no protocol-policy attribute at all; only the
# route does.
_CDN_NO_PROTOCOL_CONCEPT = {
    "azurerm_cdn_frontdoor_profile", "azurerm_cdn_frontdoor_endpoint",
    "azurerm_cdn_frontdoor_origin", "azurerm_cdn_frontdoor_origin_group",
}

# A WAF sits in front of HTTP. An SFTP server, a contact-center instance or a
# database proxy is a GATEWAY component that no web ACL can protect.
_NON_HTTP_GATEWAYS = {
    "aws_transfer_server", "aws_connect_instance", "aws_db_proxy",
    "aws_storagegateway_gateway",
    "aws_lexv2models_bot", "aws_workspaces_secure_browser",
    # Device/control-plane endpoints (AMQP/MQTT/provisioning), not a browsable
    # web surface a WAF protects.
    "azurerm_iothub", "azurerm_iothub_dps",
}

# Only a real queue has a redrive policy.
_REDRIVE_CAPABLE = {
    "aws_sqs_queue", "sqs", "azurerm_servicebus_queue", "google_pubsub_subscription",
}


# Cluster, service and registry resources orchestrate containers but do not
# declare them — the user, CPU and memory of a container live in a task
# definition or a pod spec, so that is where those checks belong.
_CONTAINER_PLATFORMS = {
    "aws_ecs_cluster", "aws_ecs_cluster_capacity_providers", "aws_ecs_service",
    "aws_ecs_anywhere", "aws_eks_cluster", "aws_eks_node_group",
    "aws_eks_fargate_profile", "aws_eks_addon", "aws_eks_anywhere", "aws_eks_distro",
    "aws_ecr_repository", "aws_ecrpublic_repository", "aws_rosa", "aws_bottlerocket",
    "azurerm_kubernetes_cluster", "azurerm_kubernetes_cluster_node_pool",
    "azurerm_container_registry", "azurerm_container_app_environment",
    "google_container_cluster", "google_container_node_pool",
    "google_artifact_registry_repository",
}

# Container Apps exposes no security-context attribute via Terraform at all —
# there is no "user"/"run_as_user" field on the container block to assert
# either way, unlike an ECS task definition or a Kubernetes pod spec.
_NO_CONTAINER_USER_CONCEPT = {"azurerm_container_app"}

_REGISTRY_MARKERS = ("ecr", "container_registry", "artifact_registry", "acr")


# A security group holds rules in both directions, and a standalone rule
# resource states its direction in `type`. Reading "the CIDRs" without asking
# which direction they belong to turns normal outbound access into a reported
# open inbound port.
def _rule_direction(component: Component) -> str:
    declared = str(component.properties.get("type", "")).lower()
    if declared in ("ingress", "egress"):
        return declared
    service = component.service
    if service.endswith("_ingress_rule"):
        return "ingress"
    if service.endswith("_egress_rule"):
        return "egress"
    return "both"


# Azure NSGs describe rules on entirely different axes than an AWS security
# group — direction is "Inbound"/"Outbound" (not a block name), a rule only
# applies if access is "Allow" (a "Deny" rule exposes nothing), and "any
# source" is spelled "*"/"Internet"/"Any", not "0.0.0.0/0". Normalizing a rule
# down to the same (cidr, from_port, to_port) shape the AWS checks already
# understand means one check — not a parallel Azure-only copy — covers both.
_NSG_SERVICES = {"azurerm_network_security_group", "azurerm_network_security_rule"}
_OPEN_SOURCE_TOKENS = {"*", "0.0.0.0/0", "internet", "any"}


def _azure_nsg_rules(component: Component) -> list[dict]:
    if component.service not in _NSG_SERVICES:
        return []
    grouped = grouped_properties(component.properties, "security_rule")
    if grouped:
        return grouped
    if component.service == "azurerm_network_security_rule":
        return [component.properties]
    return []


def _azure_port_bounds(port_range: str) -> tuple[int, int]:
    port_range = str(port_range).strip()
    if port_range in ("*", ""):
        return 0, 65535
    if "-" in port_range:
        lo, hi = port_range.split("-", 1)
        try:
            return int(lo), int(hi)
        except ValueError:
            return 0, 65535
    try:
        value = int(port_range)
        return value, value
    except ValueError:
        return 0, 65535


def _azure_normalized_rules(component: Component, direction: str) -> list[dict]:
    """NSG rules matching `direction` ("inbound"/"outbound"), reshaped into
    the {cidr_blocks, from_port, to_port} dict the AWS-oriented checks read."""
    out = []
    for rule in _azure_nsg_rules(component):
        if str(rule.get("direction", "")).lower() != direction:
            continue
        if str(rule.get("access", "")).lower() != "allow":
            continue
        prefix_key = "source_address_prefix" if direction == "inbound" else "destination_address_prefix"
        prefix = str(rule.get(prefix_key, rule.get(f"{prefix_key}es", ""))).strip()
        if prefix.lower() in _OPEN_SOURCE_TOKENS:
            cidr = "0.0.0.0/0"
        elif "::/0" in prefix:
            cidr = "::/0"
        else:
            continue  # a real, scoped CIDR — not what these checks flag
        lo, hi = _azure_port_bounds(rule.get("destination_port_range", "*"))
        out.append({"cidr_blocks": cidr, "from_port": lo, "to_port": hi})
    return out


def _inbound_cidrs(component: Component) -> str:
    props = component.properties
    if _rule_direction(component) == "egress":
        return ""
    azure_open = _azure_normalized_rules(component, "inbound")
    if azure_open:
        return " ".join(r["cidr_blocks"] for r in azure_open)
    return str(props.get("ingress_cidr_blocks", props.get("cidr_blocks", props.get("cidr_ipv4", ""))))


def _inbound_rules(component: Component) -> list:
    """Every inbound rule as a searchable string, one entry per rule set."""
    azure_open = _azure_normalized_rules(component, "inbound")
    if azure_open:
        return azure_open
    props = component.properties
    if _rule_direction(component) == "egress":
        return []
    parts = [
        props.get("ingress", ""),
        props.get("ingress_cidr_blocks", ""),
        props.get("ingress_cidr_ipv6_blocks", ""),
    ]
    if not any(parts):
        parts = [props.get("cidr_blocks", ""), props.get("cidr_ipv4", ""), props.get("cidr_ipv6", "")]
    ports = " ".join(str(props.get(k, "")) for k in
                     ("ingress_from_port", "ingress_to_port", "from_port", "to_port"))
    return [f"{part} {ports}" for part in parts if part]


def _outbound_rules(component: Component) -> list:
    azure_open = _azure_normalized_rules(component, "outbound")
    if azure_open:
        return [str(r) for r in azure_open]
    props = component.properties
    if _rule_direction(component) == "ingress":
        return []
    values = [props.get("egress_cidr_blocks", ""), props.get("egress_cidr_ipv6_blocks", ""), props.get("egress", "")]
    if not any(values) and _rule_direction(component) == "egress":
        values = [props.get("cidr_blocks", ""), props.get("cidr_ipv4", ""), props.get("cidr_ipv6", "")]
    return [str(v) for v in values if v]


# A vault exists to hold backups, and AWS encrypts these stores unconditionally,
# so asking them for their own backup or encryption setting makes no sense.
_ARCHIVE_STORAGE = {
    "aws_backup_vault", "aws_glacier_vault", "aws_securitylake_data_lake",
    "aws_codeartifact_repository", "azurerm_recovery_services_vault",
}

# Versioning, bucket ACLs, Block Public Access and server access logging are
# object-store features. A file system or block volume has none of them, so the
# bucket checks must not be pointed at EFS, FSx or EBS.
_OBJECT_STORES = {
    "aws_s3_bucket", "aws_s3_directory_bucket", "aws_s3_access_point",
    "aws_s3tables_table_bucket", "s3", "google_storage_bucket", "gcs_bucket",
    "azurerm_storage_account", "blob_storage",
}


def _is_object_store(component: Component) -> bool:
    if component.service in _OBJECT_STORES:
        return True
    # Prose- and diagram-derived models carry no resource type; keep checking them.
    return not component.service.startswith(("aws_", "google_", "azurerm_"))


# Serverless cache engines are encrypted in both directions and authenticated
# through IAM with no opt-out, so they expose no encryption or auth_token
# attribute to check.
_ALWAYS_ENCRYPTED_CACHES = {
    "aws_elasticache_serverless_cache", "aws_file_cache", "aws_memorydb_cluster",
}

# These require an access key or Entra ID to connect (there is no "no auth"
# mode) and encrypt at rest unconditionally. enable_non_ssl_port is the one
# real toggle Azure exposes — whether a client may skip TLS entirely.
_ALWAYS_AUTHENTICATED_CACHES = {"azurerm_redis_cache", "azurerm_redis_enterprise_cluster"}


def _defines_containers(component: Component) -> bool:
    return component.service not in _CONTAINER_PLATFORMS


def _scans_images(component: Component) -> bool:
    """Only a registry (or a generic manifest-derived component) can scan."""
    service = component.service.lower()
    if any(marker in service for marker in _REGISTRY_MARKERS):
        return True
    return not service.startswith(("aws_", "google_", "azurerm_"))


def _is_function(component: Component) -> bool:
    return (component.service in _FUNCTION_SERVICES
            or not component.service.startswith(("aws_", "google_", "azurerm_")))


# Disk encryption and IMDS are properties of a virtual machine you own. An
# Auto Scaling group delegates both to its launch template, and a managed
# service (MediaLive, WorkSpaces, Batch, GameLift…) has no host to configure.
_HOST_RESOURCES = {
    "aws_instance", "aws_launch_template", "aws_launch_configuration",
    "aws_spot_instance_request", "aws_emr_cluster", "aws_lightsail_instance",
}


# `password = aws_secretsmanager_secret.db.arn` or `random_password.x.result`
# is a reference, not a literal — flagging it as a hardcoded secret trains
# people to ignore the finding that matters.
_REFERENCE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z0-9_\[\]\*-]+)+$')


def _is_expression(value: str) -> bool:
    value = value.strip()
    return bool(_REFERENCE.match(value)) or "(" in value or value.startswith(("local.", "module.", "each.", "count."))


def _owns_host_disks(component: Component) -> bool:
    if component.service in _HOST_RESOURCES:
        return True
    # Prose- and diagram-derived components have no resource type; still check.
    return not component.service.startswith(("aws_", "google_", "azurerm_"))


def _is_human_principal(component: Component) -> bool:
    if component.service in _HUMAN_IDENTITY_SERVICES:
        return True
    if "assume_role_policy" in component.properties:
        return False
    principal = str(
        component.properties.get("principal_type", component.properties.get("attached_to", ""))
    ).lower()
    return "user" in principal or "group" in principal


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
            if not _is_object_store(c):
                continue
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
            if c.service in _MANAGED_DATA_SERVICES or c.service in _ALWAYS_ENCRYPTED_DATABASES:
                continue
            if c.service in _LOGICAL_DB_SERVERS:
                continue
            encrypted = str(c.properties.get("storage_encrypted", "")).lower()
            # DynamoDB, OpenSearch and Redshift each name this differently.
            encryption = str(
                c.properties.get("encryption",
                c.properties.get("server_side_encryption",
                c.properties.get("at_rest_encryption_enabled",
                c.properties.get("encrypted",
                c.properties.get("kms_key_id",
                c.properties.get("kms_key_arn", ""))))))
            ).lower()
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
            # A wildcard trust policy is as dangerous as a wildcard permission:
            # it lets any principal assume the role. Each parser names the
            # document differently (policy, assumeRolePolicyDocument,
            # assumerolepolicydocument_statement…), so match on the key.
            policy = " ".join(
                str(value) for key, value in c.properties.items()
                if "policy" in key.lower() or "statement" in key.lower()
            ).strip()
            if policy in ("*", "Allow *") or '"*"' in policy or "'*'" in policy or "Action: '*'" in policy:
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.HIGH,
                    title=f"IAM '{c.name}' uses wildcard permissions",
                    description="A wildcard (*) in an IAM permission or trust policy violates least-privilege and broadens the attack surface.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Scope IAM policies to specific actions and resources required.",
                    references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"],
                ))
        return findings

    def _check_open_security_groups(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.NETWORK):
            cidr = _inbound_cidrs(c)
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
            if c.service in _ARCHIVE_STORAGE or c.service == "azurerm_storage_account":
                continue
            sse = str(
                c.properties.get("server_side_encryption",
                c.properties.get("encryption",
                c.properties.get("encrypted",
                c.properties.get("sse_algorithm",
                c.properties.get("kms_key_arn",
                c.properties.get("kms_key_id", ""))))))
            ).lower()
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
            if not _is_object_store(c):
                continue
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
            publicly_accessible = str(
                c.properties.get("publicly_accessible",
                c.properties.get("public_network_access_enabled", "false"))
            ).lower()
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
            if c.service in _MANAGED_DATA_SERVICES or c.service in _NO_DELETION_PROTECTION:
                continue
            deletion_protection = str(
                c.properties.get("deletion_protection",
                c.properties.get("deletion_protection_enabled", "false"))
            ).lower()
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
            if c.type not in backup_types or c.service in _ARCHIVE_STORAGE:
                continue
            if (c.service in _MANAGED_DATA_SERVICES or c.service in _LOGICAL_DB_SERVERS
                    or c.service == "azurerm_digital_twins_instance"):
                continue
            retention = str(c.properties.get("backup_retention_period",
                            c.properties.get("snapshot_retention_limit",
                            c.properties.get("automated_snapshot_start_hour",
                            c.properties.get("retention_days", "0")))))
            backup_enabled = str(
                c.properties.get("backup_enabled",
                c.properties.get("point_in_time_recovery",
                c.properties.get("backup_policy",
                c.properties.get("snapshot_options",
                c.properties.get("backup",
                c.properties.get("geo_backup_policy_enabled", ""))))))
            ).lower()
            # Object stores have no retention window — versioning plus lifecycle
            # rules are how a bucket survives deletion and corruption.
            if c.type == ComponentType.STORAGE:
                versioning = str(c.properties.get("versioning", c.properties.get("versioning_enabled", ""))).lower()
                if versioning in ("enabled", "true", "yes", "1"):
                    continue
            enabled_marker = any(
                token in backup_enabled for token in ("true", "yes", "enabled", "configured")
            )
            if retention in ("0", "") and not enabled_marker:
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
            for rule in _inbound_rules(c):
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
            if not _is_api_gateway(c):
                continue
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
        # With edges in the model, TopologyAnalyzer says which entry point is
        # unprotected instead of whether a WAF exists somewhere.
        if model.connections:
            return []
        gateways = [
            c for c in model.components_by_type(ComponentType.GATEWAY)
            # An internal load balancer has no internet exposure to filter;
            # neither does an Azure resource with public access turned off.
            if str(c.properties.get("internal", "false")).lower() not in ("true", "yes", "1")
            and str(c.properties.get("public_network_access_enabled", "true")).lower() not in ("false", "no", "0")
            and c.service not in _NON_HTTP_GATEWAYS
        ]
        cdns = model.components_by_type(ComponentType.CDN)
        if not gateways and not cdns:
            return []
        waf_markers = ("waf", "application_firewall", "frontdoor_firewall")
        has_waf = any(
            any(marker in c.service.lower() for marker in waf_markers)
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
            if not _owns_host_disks(c):
                continue
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
            if not _is_object_store(c):
                continue
            if c.properties.get("account_kind", "").lower() == "filestorage":
                continue
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
            if not _is_object_store(c):
                continue
            if c.service == "azurerm_storage_account":
                # Azure has no single "block public access" switch — the
                # equivalent posture comes from three independent settings.
                allow_public = str(c.properties.get("allow_nested_items_to_be_public", "true")).lower()
                public_network = str(c.properties.get("public_network_access_enabled", "true")).lower()
                default_deny = str(c.properties.get("default_action", "")).lower() == "deny"
                blocked = allow_public in ("false", "no", "0") or public_network in ("false", "no", "0") or default_deny
                description = "Without allow_nested_items_to_be_public = false (or a network_rules default_action of Deny), a container or blob can be made public by a future ACL or policy change."
                recommendation = "Set allow_nested_items_to_be_public = false and add a network_rules block with default_action = \"Deny\"."
                reference = "https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent"
            else:
                block = str(c.properties.get("block_public_acls", c.properties.get("public_access_block", "false"))).lower()
                blocked = block in ("true", "yes", "1", "enabled")
                description = "Without block_public_acls/block_public_policy, future ACL or policy changes can silently expose the bucket."
                recommendation = "Enable all four S3 Block Public Access settings at the bucket and account level."
                reference = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
            if blocked:
                continue
            findings.append(Finding(
                type=FindingType.SECURITY,
                severity=Severity.HIGH,
                title=f"Storage '{c.name}' is missing the public access block",
                description=description,
                component_id=c.id,
                component_name=c.name,
                recommendation=recommendation,
                references=[reference],
            ))
        return findings

    # ----------------------------------------------------------------- Database

    def _check_database_no_multi_az(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.DATABASE):
            if not _is_instance_database(c) or c.service in _LOGICAL_DB_SERVERS:
                continue
            multi_az = str(
                c.properties.get("multi_az",
                c.properties.get("availability",
                # OpenSearch and Redshift call it zone awareness; Azure SQL
                # and Postgres/MySQL Flexible Server call it zone redundancy.
                c.properties.get("zone_awareness_enabled",
                c.properties.get("multi_az_enabled",
                c.properties.get("zone_redundant", "false")))))
            ).lower()
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
            if not _is_instance_database(c) or c.service in _DELEGATES_TO_SERVER:
                continue
            audit = str(
                c.properties.get("audit_log",
                c.properties.get("enable_audit_log",
                c.properties.get("extended_auditing_policy", "")))
            ).lower()
            # Terraform's real knob is a log-export list, e.g.
            # enabled_cloudwatch_logs_exports = ["postgresql", "audit"]
            exports = str(
                c.properties.get("enabled_cloudwatch_logs_exports",
                c.properties.get("log_type",
                c.properties.get("log_exports",
                c.properties.get("enabled_cluster_log_types", ""))))
            ).lower()
            if any(kind in exports for kind in ("audit", "postgresql", "pgaudit", "general", "slowquery", "error")):
                continue
            if audit not in ("true", "yes", "1", "enabled", "configured"):
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
            if not _is_instance_database(c):
                continue
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
            for rule in _outbound_rules(c):
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
            for rule in _inbound_rules(c):
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
            if not _is_human_principal(c):
                continue
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
            if not _owns_host_disks(c):
                continue
            ebs_opts = c.properties.get("ebs_block_device", c.properties.get("root_block_device", {}))
            if isinstance(ebs_opts, dict) and ebs_opts:
                encrypted = str(ebs_opts.get("encrypted", "false")).lower()
            else:
                # Flattened HCL: `encrypted = true` inside a block_device_mappings
                # / ebs / root_block_device block lands as a top-level key.
                encrypted = str(c.properties.get("ebs_encrypted", c.properties.get("encrypted", "false"))).lower()
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
            if not _defines_containers(c):
                continue
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
            if not _defines_containers(c) or c.service in _NO_CONTAINER_USER_CONCEPT:
                continue
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
            if not _defines_containers(c):
                continue
            containers = grouped_properties(c.properties, "container")
            if containers:
                cpu = containers[0].get("cpu_limit", containers[0].get("cpu", ""))
                memory = containers[0].get("memory_limit", containers[0].get("memory", ""))
            else:
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
        # ACR's scanning is enabled account-wide through Defender for Cloud,
        # not a per-registry attribute — a resource_type naming the registry
        # or containers covers every ACR instance in the subscription.
        defender_covers_registries = any(
            c.service == "azurerm_security_center_subscription_pricing"
            and any(t in str(c.properties.get("resource_type", "")) for t in ("Registry", "Containers", "ContainerRegistry"))
            for c in model.components
        )
        for c in model.components_by_type(ComponentType.CONTAINER):
            if not _scans_images(c):
                continue
            if c.service == "azurerm_container_registry" and defender_covers_registries:
                continue
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
            if not _is_function(c) or c.service in _AZURE_FUNCTION_SERVICES:
                continue
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
            if not _is_function(c):
                continue
            vpc = str(
                c.properties.get("vpc_config",
                c.properties.get("vpc_id",
                c.properties.get("virtual_network_subnet_id", "")))
            ).strip()
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
            if c.service in _ALWAYS_ENCRYPTED_CACHES or c.service in _ALWAYS_AUTHENTICATED_CACHES:
                continue
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
            if c.service in _ALWAYS_ENCRYPTED_CACHES:
                continue
            if c.service in _ALWAYS_AUTHENTICATED_CACHES:
                non_ssl = str(c.properties.get("enable_non_ssl_port", "false")).lower()
                if non_ssl in ("true", "yes", "1"):
                    findings.append(Finding(
                        type=FindingType.SECURITY,
                        severity=Severity.HIGH,
                        title=f"Cache '{c.name}' is not encrypted (in transit)",
                        description="enable_non_ssl_port = true accepts connections on the plaintext Redis port, bypassing TLS.",
                        component_id=c.id,
                        component_name=c.name,
                        recommendation="Set enable_non_ssl_port = false so only the TLS port (6380) accepts connections.",
                        references=["https://learn.microsoft.com/azure/azure-cache-for-redis/cache-configure#access-ports"],
                    ))
                continue
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
            if c.service in _MESSAGE_ROUTERS or c.service in _ALWAYS_ENCRYPTED_QUEUES:
                continue
            kms = str(
                c.properties.get("kms_master_key_id",
                c.properties.get("kms_key_identifier",
                c.properties.get("kms_key_arn",
                c.properties.get("kms_key_id",
                c.properties.get("encryption_type",
                c.properties.get("encryption", ""))))))
            ).strip()
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
            # Redrive is a queue setting. An SNS topic, EventBridge bus or
            # Kafka/Kinesis stream has no DLQ of its own — its targets do.
            if (c.service not in _REDRIVE_CAPABLE
                    and c.service.startswith(("aws_", "google_", "azurerm_"))):
                continue
            # Service Bus dead-letters automatically once a message exceeds
            # max_delivery_count — there is no separate DLQ resource to wire up.
            dlq = str(
                c.properties.get("redrive_policy",
                c.properties.get("dlq",
                c.properties.get("max_delivery_count", "")))
            ).strip()
            if dlq in ("", "none", "false", "{}", "0"):
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
            if c.service in _HTTPS_ONLY_ORIGINS or c.service in _CDN_NO_PROTOCOL_CONCEPT:
                continue
            # Front Door's redirect policy lives on the route (https_redirect_
            # enabled), not on the profile/endpoint CloudFront-style attributes.
            protocol = str(
                c.properties.get("viewer_protocol_policy",
                c.properties.get("https_only",
                c.properties.get("https_redirect_enabled", "")))
            ).lower()
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
            if not _is_api_gateway(c):
                continue
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
            if not _is_api_gateway(c):
                continue
            logging_val = str(
                c.properties.get("access_log_settings",
                c.properties.get("access_logs",
                c.properties.get("logging", "")))
            ).lower()
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
                    "true", "false", "", "null", "none", "var.", "${", "arn:", "ssm:", "secretsmanager:", "configured"
                ) and not value.startswith(("${", "var.", "data.", "arn:", "ssm:", "/aws/"))                         and not _is_expression(value):
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
        # A managed queue endpoint (SQS, SNS, Pub/Sub) is HTTPS-only and cannot
        # be reached in the clear. A self-managed broker on a VM can be.
        check_types = {ComponentType.DATABASE, ComponentType.CACHE, ComponentType.QUEUE}
        for c in model.components:
            if c.type not in check_types:
                continue
            if c.type == ComponentType.QUEUE and c.service.startswith(("aws_", "google_", "azurerm_")):
                continue
            if c.type == ComponentType.DATABASE and not _is_instance_database(c):
                continue
            if c.type == ComponentType.DATABASE and c.service in _DELEGATES_TO_SERVER:
                continue
            if c.service in _ALWAYS_ENCRYPTED_CACHES or c.service in _ALWAYS_AUTHENTICATED_CACHES:
                continue
            # Azure spells TLS enforcement as a minimum version string
            # ("1.2"/"TLS1_2"), not a boolean — any version at or above 1.2
            # satisfies the same intent as the AWS/GCP require_ssl toggles.
            tls_version = str(c.properties.get("minimum_tls_version", c.properties.get("min_tls_version", ""))).strip().lower()
            if tls_version and tls_version not in ("1.0", "1.1", "tls1_0", "tls1_1"):
                continue
            tls = str(c.properties.get("transit_encryption_enabled",
                      c.properties.get("ssl_enabled",
                      c.properties.get("require_ssl",
                      c.properties.get("node_to_node_encryption",
                      c.properties.get("enforce_https", "false")))))).lower()
            if tls not in ("true", "yes", "1", "enabled", "required", "configured"):
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
