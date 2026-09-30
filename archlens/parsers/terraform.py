"""Terraform parser — reads .tf files and builds an ArchitectureModel."""

from __future__ import annotations
import re
from pathlib import Path

from .base import BaseParser
from ..models.architecture import ArchitectureModel, Component, ComponentType

C = ComponentType

# Maps Terraform resource types → ComponentType.
# Anything not listed falls back to ComponentType.OTHER, which still shows up in
# the component count but skips the type-specific checks.
_RESOURCE_TYPE_MAP: dict[str, ComponentType] = {
    # ---- AWS compute
    "aws_instance":                       C.COMPUTE,
    "aws_launch_template":                C.COMPUTE,
    "aws_launch_configuration":           C.COMPUTE,
    "aws_autoscaling_group":              C.COMPUTE,
    "aws_spot_instance_request":           C.COMPUTE,
    "aws_lightsail_instance":             C.COMPUTE,
    "aws_batch_compute_environment":      C.COMPUTE,
    "aws_batch_job_queue":                C.QUEUE,
    "aws_batch_job_definition":           C.COMPUTE,
    "aws_elastic_beanstalk_environment":  C.COMPUTE,
    "aws_emr_cluster":                    C.COMPUTE,
    "aws_emrserverless_application":      C.SERVERLESS,
    "aws_workspaces_workspace":           C.COMPUTE,
    "aws_appstream_fleet":                C.COMPUTE,
    "aws_gamelift_fleet":                 C.COMPUTE,
    "aws_mainframe_modernization_environment": C.COMPUTE,
    "aws_mediaconvert_queue":             C.SERVERLESS,
    "aws_medialive_channel":              C.SERVERLESS,
    "aws_braket_quantum_task":            C.COMPUTE,
    # ---- AWS serverless
    "aws_lambda_function":                C.SERVERLESS,
    "aws_lambda_event_source_mapping":    C.SERVERLESS,
    "aws_lambda_permission":              C.IAM,
    "aws_apprunner_service":              C.SERVERLESS,
    "aws_sfn_state_machine":              C.SERVERLESS,
    "aws_glue_job":                       C.SERVERLESS,
    "aws_glue_crawler":                   C.SERVERLESS,
    "aws_athena_workgroup":               C.SERVERLESS,
    "aws_amplify_app":                    C.SERVERLESS,
    "aws_cloudfront_function":            C.SERVERLESS,
    "aws_bedrockagent_agent":             C.SERVERLESS,
    # ---- AWS containers
    "aws_ecs_cluster":                    C.CONTAINER,
    "aws_ecs_service":                    C.CONTAINER,
    "aws_ecs_task_definition":            C.CONTAINER,
    "aws_eks_cluster":                    C.CONTAINER,
    "aws_eks_node_group":                 C.CONTAINER,
    "aws_eks_fargate_profile":            C.CONTAINER,
    "aws_eks_addon":                      C.CONTAINER,
    "aws_ecr_repository":                 C.CONTAINER,
    "aws_ecrpublic_repository":           C.CONTAINER,
    # ---- AWS database
    "aws_db_instance":                    C.DATABASE,
    "aws_rds_instance":                   C.DATABASE,
    "aws_rds_cluster":                    C.DATABASE,
    "aws_rds_cluster_instance":           C.DATABASE,
    "aws_rds_global_cluster":             C.DATABASE,
    "aws_db_proxy":                       C.GATEWAY,
    "aws_dynamodb_table":                 C.DATABASE,
    "aws_dynamodb_global_table":          C.DATABASE,
    "aws_redshift_cluster":               C.DATABASE,
    "aws_redshiftserverless_namespace":   C.DATABASE,
    "aws_redshiftserverless_workgroup":   C.OTHER,
    "aws_neptune_cluster":                C.DATABASE,
    "aws_docdb_cluster":                  C.DATABASE,
    "aws_memorydb_cluster":               C.DATABASE,
    "aws_keyspaces_table":                C.DATABASE,
    "aws_timestreamwrite_table":          C.DATABASE,
    "aws_timestreamwrite_database":       C.DATABASE,
    "aws_opensearch_domain":              C.DATABASE,
    "aws_opensearchserverless_collection": C.DATABASE,
    "aws_elasticsearch_domain":           C.DATABASE,
    "aws_qldb_ledger":                    C.DATABASE,
    "aws_healthlake_fhir_datastore":      C.DATABASE,
    "aws_iotsitewise_asset_model":        C.DATABASE,
    # ---- AWS cache
    "aws_elasticache_cluster":            C.CACHE,
    "aws_elasticache_replication_group":  C.CACHE,
    "aws_elasticache_serverless_cache":   C.CACHE,
    "aws_dax_cluster":                    C.CACHE,
    "aws_file_cache":                     C.CACHE,
    # ---- AWS storage
    "aws_s3_bucket":                      C.STORAGE,
    "aws_s3_access_point":                C.STORAGE,
    "aws_s3_directory_bucket":            C.STORAGE,
    "aws_s3tables_table_bucket":          C.STORAGE,
    "aws_ebs_volume":                     C.STORAGE,
    "aws_efs_file_system":                C.STORAGE,
    "aws_fsx_windows_file_system":        C.STORAGE,
    "aws_fsx_lustre_file_system":         C.STORAGE,
    "aws_fsx_ontap_file_system":          C.STORAGE,
    "aws_fsx_openzfs_file_system":        C.STORAGE,
    "aws_storagegateway_gateway":         C.GATEWAY,
    "aws_backup_vault":                   C.STORAGE,
    "aws_backup_plan":                    C.OTHER,
    "aws_glacier_vault":                  C.STORAGE,
    "aws_codeartifact_repository":        C.STORAGE,
    "aws_securitylake_data_lake":         C.STORAGE,
    # ---- AWS network
    "aws_vpc":                            C.NETWORK,
    "aws_subnet":                         C.NETWORK,
    "aws_security_group":                 C.NETWORK,
    "aws_security_group_rule":            C.NETWORK,
    "aws_vpc_security_group_ingress_rule": C.NETWORK,
    "aws_vpc_security_group_egress_rule": C.NETWORK,
    "aws_network_acl":                    C.NETWORK,
    "aws_network_acl_rule":               C.NETWORK,
    "aws_internet_gateway":               C.NETWORK,
    "aws_nat_gateway":                    C.NETWORK,
    "aws_egress_only_internet_gateway":   C.NETWORK,
    "aws_route_table":                    C.NETWORK,
    "aws_route":                          C.NETWORK,
    "aws_vpc_endpoint":                   C.NETWORK,
    "aws_vpc_endpoint_service":           C.NETWORK,
    "aws_vpclattice_service":             C.NETWORK,
    "aws_vpclattice_service_network":     C.NETWORK,
    "aws_ec2_transit_gateway":            C.NETWORK,
    "aws_ec2_transit_gateway_vpc_attachment": C.NETWORK,
    "aws_networkmanager_core_network":    C.NETWORK,
    "aws_dx_gateway":                     C.NETWORK,
    "aws_dx_connection":                  C.NETWORK,
    "aws_vpn_gateway":                    C.NETWORK,
    "aws_vpn_connection":                 C.NETWORK,
    "aws_ec2_client_vpn_endpoint":        C.NETWORK,
    "aws_route53_zone":                   C.NETWORK,
    "aws_route53_record":                 C.NETWORK,
    "aws_route53_health_check":           C.NETWORK,
    "aws_route53_resolver_endpoint":      C.NETWORK,
    "aws_globalaccelerator_accelerator":  C.NETWORK,
    "aws_service_discovery_service":      C.NETWORK,
    "aws_service_discovery_private_dns_namespace": C.NETWORK,
    "aws_networkfirewall_firewall":       C.NETWORK,
    "aws_wafv2_web_acl":                  C.NETWORK,
    "aws_waf_web_acl":                    C.NETWORK,
    "aws_wafregional_web_acl":            C.NETWORK,
    "aws_shield_protection":              C.NETWORK,
    "aws_fms_policy":                     C.NETWORK,
    "aws_flow_log":                       C.MONITORING,
    "aws_mediaconnect_flow":              C.NETWORK,
    "aws_appmesh_mesh":                   C.NETWORK,
    "aws_eip":                            C.NETWORK,
    # ---- AWS CDN
    "aws_cloudfront_distribution":        C.CDN,
    "aws_media_package_channel":          C.CDN,
    "aws_mediapackage_channel":           C.CDN,
    "aws_ivs_channel":                    C.CDN,
    # ---- AWS gateway / edge
    "aws_api_gateway_rest_api":           C.GATEWAY,
    "aws_api_gateway_stage":              C.GATEWAY,
    "aws_apigatewayv2_api":               C.GATEWAY,
    "aws_apigatewayv2_stage":             C.GATEWAY,
    "aws_lb":                             C.GATEWAY,
    "aws_alb":                            C.GATEWAY,
    "aws_elb":                            C.GATEWAY,
    "aws_lb_listener":                    C.GATEWAY,
    "aws_appsync_graphql_api":            C.GATEWAY,
    "aws_iot_topic_rule":                 C.QUEUE,
    "aws_transfer_server":                C.GATEWAY,
    "aws_connect_instance":               C.GATEWAY,
    "aws_lexv2models_bot":                C.GATEWAY,
    "aws_bedrockagent_knowledge_base":    C.DATABASE,
    # ---- AWS messaging / streaming
    "aws_sqs_queue":                      C.QUEUE,
    "aws_sns_topic":                       C.QUEUE,
    "aws_sns_topic_subscription":          C.QUEUE,
    "aws_cloudwatch_event_rule":          C.QUEUE,
    "aws_cloudwatch_event_bus":           C.QUEUE,
    "aws_pipes_pipe":                     C.QUEUE,
    "aws_kinesis_stream":                 C.QUEUE,
    "aws_kinesis_firehose_delivery_stream": C.QUEUE,
    "aws_kinesis_video_stream":           C.QUEUE,
    "aws_kinesisanalyticsv2_application": C.SERVERLESS,
    "aws_msk_cluster":                    C.QUEUE,
    "aws_msk_serverless_cluster":         C.QUEUE,
    "aws_mq_broker":                      C.QUEUE,
    "aws_ses_domain_identity":            C.QUEUE,
    "aws_pinpoint_app":                   C.QUEUE,
    # ---- AWS identity / security
    "aws_iam_role":                       C.IAM,
    "aws_iam_policy":                     C.IAM,
    "aws_iam_role_policy":                C.IAM,
    "aws_iam_user":                       C.IAM,
    "aws_iam_user_policy":                C.IAM,
    "aws_iam_group":                      C.IAM,
    "aws_iam_group_policy":               C.IAM,
    "aws_iam_instance_profile":           C.IAM,
    "aws_iam_openid_connect_provider":    C.IAM,
    "aws_iam_account_password_policy":    C.IAM,
    "aws_kms_key":                        C.IAM,
    "aws_cloudhsm_v2_cluster":            C.IAM,
    "aws_secretsmanager_secret":          C.IAM,
    "aws_ssm_parameter":                  C.IAM,
    "aws_acm_certificate":                C.IAM,
    "aws_acmpca_certificate_authority":   C.IAM,
    "aws_cognito_user_pool":              C.IAM,
    "aws_cognito_identity_pool":          C.IAM,
    "aws_verifiedpermissions_policy_store": C.IAM,
    "aws_verifiedaccess_instance":        C.IAM,
    "aws_directory_service_directory":    C.IAM,
    "aws_ram_resource_share":             C.IAM,
    "aws_organizations_organization":     C.IAM,
    "aws_organizations_policy":           C.IAM,
    "aws_controltower_control":           C.IAM,
    "aws_lakeformation_permissions":      C.IAM,
    "aws_iot_policy":                     C.IAM,
    # ---- AWS observability / governance
    "aws_cloudwatch_log_group":           C.MONITORING,
    "aws_cloudwatch_metric_alarm":        C.MONITORING,
    "aws_cloudwatch_dashboard":           C.MONITORING,
    "aws_cloudtrail":                     C.MONITORING,
    "aws_config_configuration_recorder":  C.MONITORING,
    "aws_config_config_rule":             C.MONITORING,
    "aws_guardduty_detector":             C.MONITORING,
    "aws_inspector2_enabler":             C.MONITORING,
    "aws_securityhub_account":            C.MONITORING,
    "aws_macie2_account":                 C.MONITORING,
    "aws_detective_graph":                C.MONITORING,
    "aws_accessanalyzer_analyzer":        C.MONITORING,
    "aws_auditmanager_assessment":        C.MONITORING,
    "aws_xray_sampling_rule":             C.MONITORING,
    "aws_prometheus_workspace":           C.MONITORING,
    "aws_grafana_workspace":              C.MONITORING,
    "aws_budgets_budget":                 C.MONITORING,
    "aws_devicefarm_project":             C.MONITORING,
    "aws_iot_thing_type":                 C.OTHER,
    # ---- GCP
    "google_compute_instance":            C.COMPUTE,
    "google_compute_instance_template":   C.COMPUTE,
    "google_cloud_run_service":           C.SERVERLESS,
    "google_cloudfunctions_function":     C.SERVERLESS,
    "google_container_cluster":           C.CONTAINER,
    "google_container_node_pool":         C.CONTAINER,
    "google_artifact_registry_repository": C.CONTAINER,
    "google_sql_database_instance":       C.DATABASE,
    "google_spanner_instance":            C.DATABASE,
    "google_firestore_database":          C.DATABASE,
    "google_bigtable_instance":           C.DATABASE,
    "google_bigquery_dataset":            C.DATABASE,
    "google_redis_instance":              C.CACHE,
    "google_storage_bucket":              C.STORAGE,
    "google_filestore_instance":          C.STORAGE,
    "google_compute_network":             C.NETWORK,
    "google_compute_subnetwork":          C.NETWORK,
    "google_compute_firewall":            C.NETWORK,
    "google_compute_router_nat":          C.NETWORK,
    "google_dns_managed_zone":            C.NETWORK,
    "google_compute_global_forwarding_rule": C.GATEWAY,
    "google_compute_backend_service":     C.GATEWAY,
    "google_pubsub_topic":                C.QUEUE,
    "google_pubsub_subscription":         C.QUEUE,
    "google_cloud_tasks_queue":           C.QUEUE,
    "google_service_account":             C.IAM,
    "google_kms_crypto_key":              C.IAM,
    "google_secret_manager_secret":       C.IAM,
    "google_logging_project_sink":        C.MONITORING,
    "google_monitoring_alert_policy":     C.MONITORING,
    # ---- Azure
    "azurerm_virtual_machine":            C.COMPUTE,
    "azurerm_linux_virtual_machine":      C.COMPUTE,
    "azurerm_windows_virtual_machine":    C.COMPUTE,
    "azurerm_virtual_machine_scale_set":  C.COMPUTE,
    "azurerm_linux_function_app":         C.SERVERLESS,
    "azurerm_function_app":               C.SERVERLESS,
    "azurerm_logic_app_workflow":         C.SERVERLESS,
    "azurerm_app_service":                C.COMPUTE,
    "azurerm_linux_web_app":              C.COMPUTE,
    "azurerm_kubernetes_cluster":         C.CONTAINER,
    "azurerm_container_group":            C.CONTAINER,
    "azurerm_container_app":              C.CONTAINER,
    "azurerm_container_registry":         C.CONTAINER,
    "azurerm_sql_server":                 C.DATABASE,
    "azurerm_mssql_server":               C.DATABASE,
    "azurerm_mssql_database":             C.DATABASE,
    "azurerm_cosmosdb_account":           C.DATABASE,
    "azurerm_postgresql_flexible_server": C.DATABASE,
    "azurerm_mysql_flexible_server":      C.DATABASE,
    "azurerm_synapse_workspace":          C.DATABASE,
    "azurerm_redis_cache":                C.CACHE,
    "azurerm_storage_account":            C.STORAGE,
    "azurerm_storage_container":          C.STORAGE,
    "azurerm_virtual_network":            C.NETWORK,
    "azurerm_subnet":                     C.NETWORK,
    "azurerm_network_security_group":     C.NETWORK,
    "azurerm_bastion_host":               C.NETWORK,
    "azurerm_dns_zone":                   C.NETWORK,
    "azurerm_firewall":                   C.NETWORK,
    "azurerm_application_gateway":        C.GATEWAY,
    "azurerm_lb":                         C.GATEWAY,
    "azurerm_api_management":             C.GATEWAY,
    "azurerm_cdn_frontdoor_profile":      C.CDN,
    "azurerm_servicebus_queue":           C.QUEUE,
    "azurerm_servicebus_topic":           C.QUEUE,
    "azurerm_eventhub":                   C.QUEUE,
    "azurerm_key_vault":                  C.IAM,
    "azurerm_user_assigned_identity":     C.IAM,
    "azurerm_role_assignment":            C.IAM,
    "azurerm_monitor_diagnostic_setting": C.MONITORING,
    "azurerm_log_analytics_workspace":    C.MONITORING,
}

# Modern Terraform splits one logical resource across several blocks — an S3
# bucket's encryption, versioning and logging each live in their own resource,
# and an API's authorizer and stage settings live outside the API. Folding them
# back into the parent is what lets the analyzers see real posture instead of
# reporting every well-configured bucket and API as insecure.
#
# service: (reference property, parent resource type, [(target key, fixed value, source key)])
_FOLD_RULES: dict[str, tuple[str, str, list]] = {
    "aws_s3_bucket_versioning":
        ("bucket", "aws_s3_bucket", [("versioning", "", "status")]),
    "aws_s3_bucket_server_side_encryption_configuration":
        ("bucket", "aws_s3_bucket", [("server_side_encryption", "", "sse_algorithm")]),
    "aws_s3_bucket_logging":
        ("bucket", "aws_s3_bucket", [("logging", "enabled", "target_bucket")]),
    "aws_s3_bucket_public_access_block":
        ("bucket", "aws_s3_bucket", [("public_access_block", "enabled", "block_public_acls")]),
    "aws_s3_bucket_acl":
        ("bucket", "aws_s3_bucket", [("acl", "", "acl")]),
    "aws_s3_bucket_lifecycle_configuration":
        ("bucket", "aws_s3_bucket", [("lifecycle_rules", "configured", "")]),
    "aws_s3_bucket_replication_configuration":
        ("bucket", "aws_s3_bucket", [("replication", "enabled", "")]),
    "aws_s3_bucket_notification":
        ("bucket", "aws_s3_bucket", [("notifications", "enabled", "")]),
    "aws_s3_bucket_policy":
        ("bucket", "aws_s3_bucket", [("bucket_policy", "configured", "")]),
    "aws_api_gateway_authorizer":
        ("rest_api_id", "aws_api_gateway_rest_api", [("authorization", "", "type")]),
    "aws_api_gateway_stage":
        ("rest_api_id", "aws_api_gateway_rest_api", [("logging", "enabled", "access_log_settings")]),
    "aws_api_gateway_method_settings":
        ("rest_api_id", "aws_api_gateway_rest_api", [("rate_limit", "", "throttling_rate_limit")]),
    "aws_apigatewayv2_authorizer":
        ("api_id", "aws_apigatewayv2_api", [("authorization", "", "authorizer_type")]),
    "aws_apigatewayv2_stage":
        ("api_id", "aws_apigatewayv2_api", [("logging", "enabled", "access_log_settings")]),
    "aws_efs_backup_policy":
        ("file_system_id", "aws_efs_file_system", [("backup_policy", "", "status")]),
}

# Child keys that describe the child block itself, not the parent's posture.
_FOLD_SKIP_KEYS = {"bucket", "id", "name", "tags", "api_id", "rest_api_id", "file_system_id", "depends_on"}

# Parameters that mean "reject unencrypted client connections". RDS enforces
# TLS through a parameter group, not an attribute on the instance.
_TLS_PARAMETERS = {"rds.force_ssl", "require_secure_transport"}


_RESOURCE_HEADER = re.compile(r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{')


def _iter_resource_blocks(content: str):
    """Yield (type, name, body) for each resource, tracking nested braces.

    Regex alone cannot match a resource body: CloudFront and launch templates
    nest blocks several levels deep, and a pattern that stops at the first
    unbalanced brace silently truncates everything after it — which reads as
    "attribute absent" to every downstream check.
    """
    for header in _RESOURCE_HEADER.finditer(content):
        depth = 1
        i = header.end()
        in_string = False
        while i < len(content) and depth > 0:
            ch = content[i]
            if in_string:
                if ch == "\\":
                    i += 2
                    continue
                if ch == '"':
                    in_string = False
            elif ch == '"':
                in_string = True
            elif ch == "#":
                nl = content.find("\n", i)
                i = len(content) if nl == -1 else nl
                continue
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        yield header.group(1), header.group(2), content[header.end():i]


def _detect_provider(resource_type: str) -> str:
    if resource_type.startswith("aws_"):
        return "aws"
    if resource_type.startswith("google_"):
        return "gcp"
    if resource_type.startswith("azurerm_") or resource_type.startswith("azuread_"):
        return "azure"
    return "generic"


class TerraformParser(BaseParser):
    def can_parse(self, source: str | Path) -> bool:
        p = Path(source)
        if p.is_dir():
            return any(p.glob("*.tf"))
        return p.suffix == ".tf"

    def parse(self, source: str | Path) -> ArchitectureModel:
        p = Path(source)
        tf_files = list(p.glob("*.tf")) if p.is_dir() else [p]

        model = ArchitectureModel(name=p.name, source="terraform")
        for tf_file in tf_files:
            self._parse_file(tf_file, model)
        self._fold_configuration_resources(model)
        return model

    def _parse_file(self, path: Path, model: ArchitectureModel) -> None:
        content = path.read_text(encoding="utf-8")

        for resource_type, resource_name, block in _iter_resource_blocks(content):
            component_type = _RESOURCE_TYPE_MAP.get(resource_type, ComponentType.OTHER)
            provider = _detect_provider(resource_type)

            props = self._extract_properties(block)
            model.components.append(
                Component(
                    id=f"{resource_type}.{resource_name}",
                    name=resource_name,
                    type=component_type,
                    provider=provider,
                    service=resource_type,
                    properties=props,
                )
            )

    def _extract_properties(self, block: str) -> dict:
        props: dict = {}
        # Which nested block the current line sits in. Flattening alone would
        # merge an `egress { cidr_blocks = ["0.0.0.0/0"] }` rule into the same
        # key as the ingress rules and read as an open inbound port.
        scope: list = []
        for raw in block.splitlines():
            line = raw.strip()
            if line in ("}", "},") and scope:
                scope.pop()
            m = re.match(r'(\w+)\s*=\s*(.+)$', line)
            if m:
                key = m.group(1)
                if scope and scope[-1] in ("ingress", "egress"):
                    key = f"{scope[-1]}_{key}"
                # Keep the whole right-hand side: lists like
                # ["0.0.0.0/0"] and ["postgresql", "audit"] are exactly what
                # the CIDR and audit-log checks need to read.
                value = re.sub(r'\s+#.*$', '', m.group(2)).strip().rstrip(',').strip()
                if len(value) > 1 and value[0] == '"' and value[-1] == '"':
                    value = value[1:-1]
                # Repeated blocks reuse keys — a parameter group has one `name`
                # per parameter, a security group one `cidr_blocks` per rule.
                # Overwriting would hide every value but the last.
                # Joined rather than listed: every consumer treats property
                # values as strings, and a substring search over the joined
                # value still finds each one.
                if key in props and value not in str(props[key]).split(", "):
                    props[key] = f"{props[key]}, {value}"
                else:
                    props[key] = value
                continue
            # Nested block header, e.g. `access_logs {` or `ebs {`. Record the
            # block's presence — several checks only need to know it is there.
            nested = re.match(r'(\w+)\s*\{\s*$', line)
            if nested:
                scope.append(nested.group(1))
                props.setdefault(nested.group(1), "configured")
        return props

    def _fold_configuration_resources(self, model: ArchitectureModel) -> None:
        by_id = {c.id: c for c in model.components}
        folded: set[str] = set()

        for comp in model.components:
            rule = _FOLD_RULES.get(comp.service)
            if rule:
                ref_prop, parent_service, targets = rule
                parent = self._resolve_parent(comp, ref_prop, parent_service, by_id)
                if parent is None:
                    continue
                for key, fixed_value, source_key in targets:
                    value = fixed_value or str(comp.properties.get(source_key, "enabled"))
                    parent.properties.setdefault(key, value)
                # The child's own settings are the parent's real posture.
                for key, value in comp.properties.items():
                    if key not in _FOLD_SKIP_KEYS:
                        parent.properties.setdefault(key, value)
                folded.add(comp.id)
                continue

            if comp.service in ("aws_db_parameter_group", "aws_rds_cluster_parameter_group"):
                self._fold_db_parameters(comp, model)
                folded.add(comp.id)

        model.components = [c for c in model.components if c.id not in folded]

    @staticmethod
    def _resolve_parent(comp: Component, ref_prop: str, parent_service: str,
                        by_id: dict[str, Component]) -> Component | None:
        """Follow a `bucket = aws_s3_bucket.x.id`-style reference to its parent."""
        ref = str(comp.properties.get(ref_prop, ""))
        m = re.search(re.escape(parent_service) + r'\.([A-Za-z0-9_-]+)', ref)
        if not m:
            return None
        return by_id.get(f"{parent_service}.{m.group(1)}")

    @staticmethod
    def _fold_db_parameters(group: Component, model: ArchitectureModel) -> None:
        """Apply a parameter group's TLS enforcement to the databases using it."""
        enforces_tls = any(
            param in str(value) for value in group.properties.values() for param in _TLS_PARAMETERS
        )
        if not enforces_tls:
            return
        for db in model.components_by_type(ComponentType.DATABASE):
            ref = " ".join(str(db.properties.get(key, "")) for key in
                           ("parameter_group_name", "db_cluster_parameter_group_name",
                            "db_parameter_group_name"))
            if f"{group.service}.{group.name}" in ref:
                db.properties.setdefault("require_ssl", "true")
