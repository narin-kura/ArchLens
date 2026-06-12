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


_MLOPS_SERVICES = {"mlflow", "wandb", "feast", "ray"}
_ORCHESTRATOR_SERVICES = {"langchain", "llamaindex", "airflow", "prefect", "kubeflow"}
_QUEUE_SERVICES = {"sqs", "sns", "pubsub", "kafka", "rabbitmq"}


def _is_ai_stack(model: ArchitectureModel) -> bool:
    """True if the model has at least one recognisable AI/ML component."""
    known = (
        _LLM_API_SERVICES | _TRAINING_SERVICES |
        _INFERENCE_SERVICES | _VECTOR_DB_SERVICES |
        _MLOPS_SERVICES | _ORCHESTRATOR_SERVICES |
        {"rekognition", "textract", "comprehend", "kendra",
         "vision_api", "cloud_nlp", "cognitive_services"}
    )
    return bool(_services_in_model(model) & known)


def _detect_workloads(model: ArchitectureModel) -> set[str]:
    """
    Identify which AI workload patterns are present.
    Returns a set of labels: rag, fine_tuning, realtime_inference,
    batch_inference, mlops_pipeline, managed_ai.
    """
    services = _services_in_model(model)
    workloads: set[str] = set()

    # RAG: LLM + vector DB (+ optional orchestrator)
    if (services & _LLM_API_SERVICES) and (services & _VECTOR_DB_SERVICES):
        workloads.add("rag")

    # Fine-tuning / training: dedicated training service + large storage
    if services & _TRAINING_SERVICES:
        has_storage = bool(model.components_by_type(ComponentType.STORAGE))
        if has_storage:
            workloads.add("fine_tuning")
        else:
            workloads.add("realtime_inference")

    # Real-time inference: inference service + gateway (latency-critical)
    if (services & _INFERENCE_SERVICES) and _has_type(model, ComponentType.GATEWAY):
        workloads.add("realtime_inference")

    # Batch inference: queue + compute or storage + compute (no gateway)
    if (services & _INFERENCE_SERVICES) and not _has_type(model, ComponentType.GATEWAY):
        has_queue = bool(services & _QUEUE_SERVICES)
        has_storage = bool(model.components_by_type(ComponentType.STORAGE))
        if has_queue or has_storage:
            workloads.add("batch_inference")

    # MLOps pipeline: experiment tracking / feature store present
    if services & _MLOPS_SERVICES:
        workloads.add("mlops_pipeline")

    # Managed AI: only managed API gateways, no self-hosted training/inference
    only_managed = (services & _LLM_API_SERVICES) and not (
        services & (_TRAINING_SERVICES | {"triton", "ollama"})
    )
    if only_managed:
        workloads.add("managed_ai")

    return workloads


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
            # Workload-specific
            self._check_workload_patterns,
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

    # ── Workload patterns ─────────────────────────────────────────────────────

    def _check_workload_patterns(self, model: ArchitectureModel) -> list[Finding]:
        workloads = _detect_workloads(model)
        if not workloads:
            return []
        findings: list[Finding] = []

        if "rag" in workloads:
            findings.extend(self._workload_rag(model))
        if "fine_tuning" in workloads:
            findings.extend(self._workload_fine_tuning(model))
        if "realtime_inference" in workloads:
            findings.extend(self._workload_realtime_inference(model))
        if "batch_inference" in workloads:
            findings.extend(self._workload_batch_inference(model))
        if "mlops_pipeline" in workloads:
            findings.extend(self._workload_mlops(model))
        if "managed_ai" in workloads:
            findings.extend(self._workload_managed_ai(model))

        return findings

    def _workload_rag(self, model: ArchitectureModel) -> list[Finding]:
        services = _services_in_model(model)
        findings = []
        # RAG without a reranker or cache = poor quality + high cost
        has_cache = _has_type(model, ComponentType.CACHE)
        if not has_cache:
            findings.append(Finding(
                type=FindingType.COST,
                severity=Severity.MEDIUM,
                title="RAG pipeline detected — no semantic cache layer",
                description=(
                    "Your RAG stack (LLM + vector DB) sends every query to the LLM even "
                    "when semantically identical questions were already answered. "
                    "In production RAG apps, 40-60% of queries are near-duplicates."
                ),
                recommendation=(
                    "Add a semantic cache (Redis + GPTCache, or LangChain CacheBackedEmbeddings). "
                    "Cache at the embedding level — queries within cosine similarity >0.95 "
                    "return the cached answer without hitting the LLM."
                ),
                estimated_savings=250,
            ))
        # RAG without monitoring = no visibility into retrieval quality
        has_monitoring = _has_type(model, ComponentType.MONITORING)
        if not has_monitoring:
            findings.append(Finding(
                type=FindingType.SECURITY,
                severity=Severity.MEDIUM,
                title="RAG pipeline has no observability for retrieval quality",
                description=(
                    "Without tracing, you cannot tell if your vector retrieval is returning "
                    "relevant chunks, if context windows are overflowing, or if prompt injection "
                    "is occurring through retrieved documents."
                ),
                recommendation=(
                    "Add LangSmith, W&B Weave, or Arize Phoenix to trace retrieval steps. "
                    "Log chunk relevance scores and flag queries where top-k similarity < 0.7. "
                    "Monitor for unusually long retrieved contexts that may indicate injection."
                ),
            ))
        return findings

    def _workload_fine_tuning(self, model: ArchitectureModel) -> list[Finding]:
        services = _services_in_model(model)
        findings = []
        # Fine-tuning without experiment tracking = waste
        has_mlops = bool(services & _MLOPS_SERVICES)
        if not has_mlops:
            findings.append(Finding(
                type=FindingType.COST,
                severity=Severity.MEDIUM,
                title="Fine-tuning workload without experiment tracking",
                description=(
                    "Fine-tuning GPU runs cost hundreds to thousands of dollars each. "
                    "Without MLflow or W&B you have no record of hyperparameters, loss curves, "
                    "or which run produced which model — making it easy to repeat expensive "
                    "failed experiments."
                ),
                recommendation=(
                    "Add MLflow or Weights & Biases before starting fine-tuning runs. "
                    "Log every hyperparameter, step loss, and checkpoint path. "
                    "Use W&B Sweeps or Optuna for hyperparameter search to avoid manual tuning."
                ),
                estimated_savings=500,
            ))
        # Fine-tuning without versioned model storage
        has_storage = bool(model.components_by_type(ComponentType.STORAGE))
        if not has_storage:
            findings.append(Finding(
                type=FindingType.SECURITY,
                severity=Severity.MEDIUM,
                title="Fine-tuning detected but no model artifact storage",
                description=(
                    "Trained model weights not stored in versioned object storage "
                    "risk being lost on instance termination. GPU spot instances can be "
                    "interrupted without warning."
                ),
                recommendation=(
                    "Save checkpoints every N steps to S3/GCS. Use SageMaker Model Registry "
                    "or MLflow Model Registry to version artifacts alongside their metadata."
                ),
            ))
        return findings

    def _workload_realtime_inference(self, model: ArchitectureModel) -> list[Finding]:
        services = _services_in_model(model)
        findings = []
        # Real-time inference without autoscaling = either over- or under-provisioned
        has_cache = _has_type(model, ComponentType.CACHE)
        if not has_cache:
            findings.append(Finding(
                type=FindingType.COST,
                severity=Severity.LOW,
                title="Real-time inference without response caching",
                description=(
                    "Inference endpoints serving identical or near-identical requests "
                    "waste GPU cycles and add latency on every call. "
                    "Repeated API calls for the same input are common in chatbots and copilots."
                ),
                recommendation=(
                    "Cache deterministic inference results (temperature=0) in Redis with a "
                    "hash of the prompt as the key. For non-deterministic outputs, use "
                    "semantic similarity cache with a tight threshold (>0.98)."
                ),
                estimated_savings=150,
            ))
        # Real-time inference without a CDN or gateway for global users
        has_cdn = bool(model.components_by_type(ComponentType.CDN))
        has_gateway = _has_type(model, ComponentType.GATEWAY)
        if not has_cdn and not has_gateway:
            findings.append(Finding(
                type=FindingType.SECURITY,
                severity=Severity.MEDIUM,
                title="Real-time inference endpoint exposed without gateway protection",
                description=(
                    "Direct exposure of inference endpoints bypasses rate limiting, "
                    "auth, and DDoS protection. A single unauthenticated client can "
                    "exhaust GPU capacity or generate runaway API costs."
                ),
                recommendation=(
                    "Place an API Gateway or ALB in front of inference endpoints with "
                    "rate limiting (requests/minute per API key), auth (Cognito or IAM), "
                    "and WAF rules to block prompt-injection patterns."
                ),
            ))
        return findings

    def _workload_batch_inference(self, model: ArchitectureModel) -> list[Finding]:
        services = _services_in_model(model)
        findings = []
        # Batch inference should always use spot
        has_training_compute = bool(services & _TRAINING_SERVICES)
        if has_training_compute:
            findings.append(Finding(
                type=FindingType.COST,
                severity=Severity.HIGH,
                title="Batch inference workload — use Spot/Preemptible instances",
                description=(
                    "Batch inference (offline scoring, bulk embeddings, nightly re-ranking) "
                    "is inherently fault-tolerant. On-demand GPU instances for batch jobs "
                    "are the most common source of avoidable AI infrastructure cost."
                ),
                recommendation=(
                    "Use AWS Spot or GCP Preemptible VMs for all batch jobs. "
                    "Implement checkpointing at the batch level — restart from the last "
                    "completed chunk on interruption. SageMaker Processing Jobs have "
                    "built-in spot support with automatic retry."
                ),
                estimated_savings=800,
            ))
        # Batch without a queue = polling anti-pattern
        has_queue = bool(services & _QUEUE_SERVICES)
        if not has_queue:
            findings.append(Finding(
                type=FindingType.COST,
                severity=Severity.LOW,
                title="Batch inference without a job queue",
                description=(
                    "Without a queue (SQS, Pub/Sub), batch jobs typically run on a fixed "
                    "schedule or via polling — wasting compute during idle periods and "
                    "struggling to handle burst workloads."
                ),
                recommendation=(
                    "Use SQS + Lambda or Pub/Sub + Cloud Run to trigger inference workers "
                    "only when jobs are queued. Scale workers to zero between batches."
                ),
                estimated_savings=100,
            ))
        return findings

    def _workload_mlops(self, model: ArchitectureModel) -> list[Finding]:
        services = _services_in_model(model)
        findings = []
        # MLOps without CI/CD = manual model deployment
        has_cicd = any(
            c.service in {"github_actions", "gitlab_ci", "jenkins", "terraform"}
            for c in model.components
        )
        if not has_cicd:
            findings.append(Finding(
                type=FindingType.SECURITY,
                severity=Severity.MEDIUM,
                title="MLOps pipeline without CI/CD for model deployment",
                description=(
                    "Manually deploying model updates bypasses validation gates — "
                    "a degraded model can reach production without accuracy checks, "
                    "bias evaluation, or canary testing."
                ),
                recommendation=(
                    "Automate model deployment via GitHub Actions or GitLab CI. "
                    "Gate promotion on: evaluation metrics above baseline, bias/fairness "
                    "checks, and a canary deployment at 5% traffic before full rollout."
                ),
            ))
        # MLOps without feature store = training/serving skew risk
        has_feast = "feast" in services
        has_storage = bool(model.components_by_type(ComponentType.STORAGE))
        if not has_feast and has_storage:
            findings.append(Finding(
                type=FindingType.COST,
                severity=Severity.LOW,
                title="MLOps pipeline without a feature store — training/serving skew risk",
                description=(
                    "Without a feature store, training features are computed differently "
                    "from serving features — a leading cause of model accuracy degradation "
                    "in production that is hard to debug."
                ),
                recommendation=(
                    "Add Feast or use SageMaker Feature Store to share feature definitions "
                    "between training and serving pipelines. This also eliminates duplicate "
                    "feature computation that inflates infrastructure costs."
                ),
                estimated_savings=100,
            ))
        return findings

    def _workload_managed_ai(self, model: ArchitectureModel) -> list[Finding]:
        services = _services_in_model(model)
        findings = []
        # Managed API only — suggest multi-provider fallback
        llm_providers = [c for c in model.components if c.service in _LLM_API_SERVICES]
        if len(llm_providers) == 1:
            provider = llm_providers[0].name
            findings.append(Finding(
                type=FindingType.SECURITY,
                severity=Severity.LOW,
                title=f"Single LLM provider ({provider}) — no fallback strategy",
                description=(
                    f"Relying on a single LLM API ({provider}) means any provider outage, "
                    "rate limit, or price change directly impacts your service. "
                    "LLM provider incidents have caused multi-hour outages for dependent apps."
                ),
                recommendation=(
                    "Implement a provider abstraction layer (LiteLLM, LangChain) that "
                    "can fall back to a secondary provider (e.g. OpenAI → Anthropic → Gemini). "
                    "Route by latency and cost using a smart proxy, not hardcoded fallback."
                ),
            ))
        # Managed AI without rate limiting
        has_gateway = _has_type(model, ComponentType.GATEWAY)
        if not has_gateway:
            findings.append(Finding(
                type=FindingType.COST,
                severity=Severity.MEDIUM,
                title="Managed LLM API without rate limiting",
                description=(
                    "Without a gateway enforcing per-user token limits, a single runaway "
                    "client, prompt injection loop, or misconfigured retry can exhaust "
                    "your monthly token budget in minutes."
                ),
                recommendation=(
                    "Add an API Gateway with per-key rate limits before your LLM calls. "
                    "Set max_tokens on every request. Implement exponential backoff with "
                    "jitter on retries — never retry immediately on 429s."
                ),
                estimated_savings=300,
            ))
        return findings
