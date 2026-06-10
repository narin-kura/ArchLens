"""AI/ML architecture analyzer — cost and security checks for AI-heavy stacks."""

from __future__ import annotations

from .base import BaseAnalyzer
from ..models.architecture import ArchitectureModel, ComponentType
from ..models.findings import Finding, FindingType, Severity

# Services that call external LLM APIs (per-token billing = runaway cost risk)
_LLM_API_SERVICES = {
    "openai_api", "anthropic_api", "gemini_api", "bedrock",
    "azure_openai", "huggingface",
}

# Services that run training or fine-tuning workloads (GPU-heavy)
_TRAINING_SERVICES = {
    "sagemaker", "vertex_ai", "azure_ml", "ray", "bigquery_ml",
}

# Self-hosted or managed inference servers
_INFERENCE_SERVICES = {
    "sagemaker", "triton", "vertex_ai", "azure_ml", "ollama",
}

# Vector databases (often deployed without auth in dev → left open in prod)
_VECTOR_DB_SERVICES = {
    "pinecone", "weaviate", "chroma", "qdrant", "pgvector",
}

# Secrets/key management services — presence means team is managing secrets properly
_SECRETS_SERVICES = {
    "secrets_manager", "vault", "key_vault", "secret_manager", "kms", "cloud_kms",
}

# Approximate on-demand monthly cost (USD) for GPU instances used in AI
_GPU_INSTANCE_COSTS: dict[str, float] = {
    # AWS — p-series (training)
    "p3.2xlarge": 2200, "p3.8xlarge": 8800, "p3.16xlarge": 17600,
    "p4d.24xlarge": 29000, "p4de.24xlarge": 34000,
    # AWS — g-series (inference)
    "g4dn.xlarge": 380, "g4dn.2xlarge": 760, "g4dn.12xlarge": 2800,
    "g5.xlarge": 580, "g5.2xlarge": 1160, "g5.12xlarge": 4200,
    # AWS — inf-series (inference chips)
    "inf1.xlarge": 225, "inf2.xlarge": 758,
    # GCP (rough equivalents)
    "a2-highgpu-1g": 2900, "a2-highgpu-4g": 11600,
    "n1-standard-8-k80": 1200, "n1-standard-16-v100": 3200,
}


def _has_type(model: ArchitectureModel, *types: ComponentType) -> bool:
    return any(model.components_by_type(t) for t in types)


def _services_in_model(model: ArchitectureModel) -> set[str]:
    return {c.service.lower() for c in model.components}


def _is_ai_stack(model: ArchitectureModel) -> bool:
    """True if the model has at least one recognisable AI/ML component."""
    known = (
        _LLM_API_SERVICES | _TRAINING_SERVICES |
        _INFERENCE_SERVICES | _VECTOR_DB_SERVICES |
        {"langchain", "llamaindex", "mlflow", "wandb", "feast", "triton",
         "rekognition", "textract", "comprehend", "kendra",
         "vision_api", "cloud_nlp", "cognitive_services"}
    )
    return bool(_services_in_model(model) & known)


class AIAnalyzer(BaseAnalyzer):
    def analyze(self, model: ArchitectureModel) -> list[Finding]:
        if not _is_ai_stack(model):
            return []
        findings: list[Finding] = []
        for check in [
            # Security
            self._check_llm_keys_without_secrets_manager,
            self._check_vector_db_without_auth,
            self._check_training_data_encryption,
            self._check_model_endpoint_no_gateway,
            self._check_no_llm_cost_monitoring,
            # Cost
            self._check_gpu_no_spot,
            self._check_llm_without_cache,
            self._check_always_on_inference_endpoint,
            self._check_multiple_vector_dbs,
        ]:
            findings.extend(check(model))
        return findings

    # ── Security ──────────────────────────────────────────────────────────────

    def _check_llm_keys_without_secrets_manager(self, model: ArchitectureModel) -> list[Finding]:
        services = _services_in_model(model)
        llm_components = [c for c in model.components if c.service in _LLM_API_SERVICES]
        if not llm_components:
            return []
        has_secrets = bool(services & _SECRETS_SERVICES)
        if has_secrets:
            return []
        names = ", ".join(c.name for c in llm_components)
        return [Finding(
            type=FindingType.SECURITY,
            severity=Severity.HIGH,
            title="LLM API keys may not be managed securely",
            description=(
                f"Found LLM API integrations ({names}) but no secrets management service "
                "(Secrets Manager, Vault, Key Vault). API keys hardcoded in env vars or "
                "config files are a common credential-leak vector."
            ),
            recommendation=(
                "Store API keys in AWS Secrets Manager, HashiCorp Vault, or equivalent. "
                "Rotate keys on a schedule and use least-privilege IAM roles to access them."
            ),
            references=["https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html"],
        )]

    def _check_vector_db_without_auth(self, model: ArchitectureModel) -> list[Finding]:
        services = _services_in_model(model)
        vector_dbs = [c for c in model.components if c.service in _VECTOR_DB_SERVICES]
        if not vector_dbs:
            return []
        has_iam = _has_type(model, ComponentType.IAM)
        if has_iam:
            return []
        findings = []
        for c in vector_dbs:
            # Self-hosted ones (chroma, qdrant, weaviate) default to no auth
            if c.service in {"chroma", "qdrant", "weaviate", "pgvector"}:
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.HIGH,
                    title=f"Vector DB '{c.name}' may be running without authentication",
                    description=(
                        f"{c.name} ({c.service}) defaults to no authentication in its "
                        "out-of-box configuration. Exposed vector stores leak embeddings "
                        "and the private data used to generate them."
                    ),
                    component_id=c.id,
                    component_name=c.name,
                    recommendation=(
                        "Enable API key auth or mTLS. Place the vector DB inside a private "
                        "VPC subnet with no public endpoint. Add an IAM role or API gateway in front."
                    ),
                    references=["https://docs.aws.amazon.com/vpc/latest/userguide/configure-subnets.html"],
                ))
        return findings

    def _check_training_data_encryption(self, model: ArchitectureModel) -> list[Finding]:
        services = _services_in_model(model)
        has_training = bool(services & _TRAINING_SERVICES)
        if not has_training:
            return []
        unencrypted_storage = [
            c for c in model.components_by_type(ComponentType.STORAGE)
            if c.properties.get("storage_encrypted", "true").lower() in ("false", "no", "")
        ]
        if not unencrypted_storage:
            return []
        names = ", ".join(c.name for c in unencrypted_storage)
        return [Finding(
            type=FindingType.SECURITY,
            severity=Severity.HIGH,
            title="Training data storage may be unencrypted",
            description=(
                f"ML training workloads detected alongside unencrypted storage ({names}). "
                "Training datasets often contain PII or proprietary data — unencrypted "
                "storage violates GDPR, HIPAA, and most data-handling policies."
            ),
            recommendation=(
                "Enable server-side encryption with KMS customer-managed keys on all "
                "storage buckets used for training data, model artifacts, and feature stores."
            ),
            estimated_savings=0,
            references=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html"],
        )]

    def _check_model_endpoint_no_gateway(self, model: ArchitectureModel) -> list[Finding]:
        services = _services_in_model(model)
        inference = [c for c in model.components if c.service in _INFERENCE_SERVICES]
        if not inference:
            return []
        has_gateway = _has_type(model, ComponentType.GATEWAY)
        has_iam = _has_type(model, ComponentType.IAM)
        if has_gateway or has_iam:
            return []
        names = ", ".join(c.name for c in inference)
        return [Finding(
            type=FindingType.SECURITY,
            severity=Severity.MEDIUM,
            title="Model serving endpoints have no auth gateway detected",
            description=(
                f"Inference endpoints ({names}) found with no API gateway or IAM auth layer. "
                "Unauthenticated endpoints can be abused to run inference at your cost or "
                "extract model weights via repeated queries."
            ),
            recommendation=(
                "Put an API Gateway or ALB with Cognito/IAM auth in front of inference "
                "endpoints. Apply rate limiting to prevent abuse and cost blowout."
            ),
            references=["https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-to-api.html"],
        )]

    def _check_no_llm_cost_monitoring(self, model: ArchitectureModel) -> list[Finding]:
        services = _services_in_model(model)
        llm = [c for c in model.components if c.service in _LLM_API_SERVICES]
        if not llm:
            return []
        has_monitoring = _has_type(model, ComponentType.MONITORING)
        if has_monitoring:
            return []
        return [Finding(
            type=FindingType.SECURITY,
            severity=Severity.MEDIUM,
            title="No monitoring detected for LLM API usage",
            description=(
                "LLM API costs can spike by 100× overnight due to prompt injection, "
                "traffic spikes, or misconfigured token limits — with no monitoring "
                "you won't know until the invoice arrives."
            ),
            recommendation=(
                "Add CloudWatch / Datadog / Grafana with alerts on token usage and API "
                "spend. Set hard budget limits in the LLM provider console. "
                "Consider MLflow or W&B for experiment cost tracking."
            ),
            references=["https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/working_with_metrics.html"],
        )]

    # ── Cost ──────────────────────────────────────────────────────────────────

    def _check_gpu_no_spot(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.COMPUTE):
            instance = c.properties.get("instance_class", "")
            cost = _GPU_INSTANCE_COSTS.get(instance)
            if not cost:
                # Detect GPU instances by service name even without instance_class
                if c.service not in _TRAINING_SERVICES and c.service not in _INFERENCE_SERVICES:
                    continue
                cost = 1500  # conservative estimate for unknown GPU instance
            spot_cost = cost * 0.3  # spot is typically 60-70% cheaper
            savings = cost - spot_cost
            findings.append(Finding(
                type=FindingType.COST,
                severity=Severity.HIGH,
                title=f"'{c.name}' GPU/ML compute — use Spot/Preemptible for training",
                description=(
                    f"GPU and ML training instances are among the most expensive compute "
                    f"types (~${cost:,.0f}/mo on-demand). Training jobs are fault-tolerant "
                    "by nature — interruptions just resume from the last checkpoint."
                ),
                component_id=c.id,
                component_name=c.name,
                recommendation=(
                    "Use AWS Spot Instances (up to 90% off) or GCP Preemptible/Spot VMs "
                    "for training. Save checkpoints every epoch to S3/GCS. "
                    "Reserve on-demand capacity only for production inference endpoints."
                ),
                estimated_savings=savings,
                references=["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-spot-instances.html"],
            ))
        return findings

    def _check_llm_without_cache(self, model: ArchitectureModel) -> list[Finding]:
        services = _services_in_model(model)
        llm = [c for c in model.components if c.service in _LLM_API_SERVICES]
        if not llm:
            return []
        has_cache = _has_type(model, ComponentType.CACHE)
        vector_dbs = [c for c in model.components if c.service in _VECTOR_DB_SERVICES]
        if has_cache:
            return []
        names = ", ".join(c.name for c in llm)
        return [Finding(
            type=FindingType.COST,
            severity=Severity.MEDIUM,
            title="LLM API calls have no caching layer",
            description=(
                f"Detected LLM API usage ({names}) without a cache. "
                "In most apps 30-60% of queries are near-duplicates — "
                "each one billed separately at per-token rates."
            ),
            recommendation=(
                "Add Redis or ElastiCache for exact-match caching of common queries. "
                "For semantic similarity use a vector DB with threshold matching "
                "(semantic cache pattern). GPTCache and LangChain both support this natively."
            ),
            estimated_savings=200,
            references=["https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/WhatIs.html"],
        )]

    def _check_always_on_inference_endpoint(self, model: ArchitectureModel) -> list[Finding]:
        services = _services_in_model(model)
        sagemaker_comps = [c for c in model.components if c.service == "sagemaker"]
        if not sagemaker_comps:
            return []
        findings = []
        for c in sagemaker_comps:
            endpoint_type = c.properties.get("endpoint_type", "").lower()
            if endpoint_type in ("serverless", "async"):
                continue
            findings.append(Finding(
                type=FindingType.COST,
                severity=Severity.LOW,
                title=f"SageMaker '{c.name}' — consider Serverless Inference for variable traffic",
                description=(
                    "Always-on SageMaker real-time endpoints charge by the hour even at "
                    "zero requests. For spiky or low-volume traffic, serverless endpoints "
                    "charge per invocation and scale to zero."
                ),
                component_id=c.id,
                component_name=c.name,
                recommendation=(
                    "Switch to SageMaker Serverless Inference or Asynchronous Inference "
                    "for workloads with < 1 req/s average. Keep real-time endpoints only "
                    "for latency-sensitive production traffic."
                ),
                estimated_savings=300,
                references=["https://docs.aws.amazon.com/sagemaker/latest/dg/serverless-endpoints.html"],
            ))
        return findings

    def _check_multiple_vector_dbs(self, model: ArchitectureModel) -> list[Finding]:
        vector_dbs = [c for c in model.components if c.service in _VECTOR_DB_SERVICES]
        if len(vector_dbs) < 2:
            return []
        names = ", ".join(c.name for c in vector_dbs)
        return [Finding(
            type=FindingType.COST,
            severity=Severity.LOW,
            title=f"Multiple vector databases detected ({len(vector_dbs)})",
            description=(
                f"Found {len(vector_dbs)} vector stores ({names}). Each adds operational "
                "overhead, separate index costs, and data sync complexity."
            ),
            recommendation=(
                "Consolidate to a single vector DB unless you have distinct latency/scale "
                "requirements per collection. Namespaces or collections within one instance "
                "can separate concerns without running separate services."
            ),
            estimated_savings=150,
        )]
