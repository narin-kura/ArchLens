// Live client-side suggestions, including topology rules.
// Copyright (c) 2026 K.N.Narin (github.com/narin-kura). All rights reserved.
// Non-commercial use only. See LICENSE. 

// --- Live suggestion rules (pure client-side) ---
const _LLM_SERVICES    = new Set(['openai_api','anthropic_api','gemini_api','bedrock','vertex_ai','azure_openai','huggingface','ollama','kendra','triton','vllm','tgi','nvidia_nim','together_ai','runpod','cohere_api','mistral_api','groq_api','replicate']);
const _VECTOR_SERVICES = new Set(['pinecone','weaviate','chroma','qdrant','pgvector','milvus']);
const _MLOPS_SERVICES  = new Set(['mlflow','wandb']);
const _FRAMEWORK_SVCS  = new Set(['langchain','llamaindex']);
const _ML_TRAIN_SVCS   = new Set(['sagemaker','vertex_ai','azure_ml','ray','nvidia_dgx','rapids','nvidia_nemo','ec2_gpu','gcp_gpu_vm','azure_gpu_vm','kubeflow']);

function computeSuggestions(types, edges, nodes, services) {
  services = services || new Set();
  const has  = t => types.has(t);
  const hasSvc = s => services.has(s);
  const hasAnyLLM    = [..._LLM_SERVICES].some(s => hasSvc(s));
  const hasVectorDb  = [..._VECTOR_SERVICES].some(s => hasSvc(s));
  const hasMLOps     = [..._MLOPS_SERVICES].some(s => hasSvc(s));
  const hasFramework = [..._FRAMEWORK_SVCS].some(s => hasSvc(s));
  const hasMLTrain   = [..._ML_TRAIN_SVCS].some(s => hasSvc(s));
  const suggs = [];

  // --- Topology rules: these only have something to say once the diagram
  // has connections. The server repeats them with access to properties.
  const links = Array.isArray(edges) ? edges.filter(e => e && e.fromType) : [];
  const EDGE_INTO = new Set(['DATABASE', 'CACHE']);
  links.forEach(e => {
    if ((e.fromType === 'CDN' || e.fromType === 'GATEWAY') && EDGE_INTO.has(e.toType))
      suggs.push({l:'crit', t:`${e.fromName} reaches ${e.toName} directly — put an application tier between the edge and your data`});
    if (e.fromType === 'SERVERLESS' && e.toType === 'DATABASE')
      suggs.push({l:'info', t:`${e.fromName} → ${e.toName}: attach the function to a VPC so the database need not accept public traffic`});
  });
  if (links.length) {
    const filtersTraffic = [...services].some(s => /waf|shield|firewall|armor|cloudflare|front_door/.test(s));
    const entryPoints = links.filter(e => e.fromType === 'CDN' || e.fromType === 'GATEWAY');
    if (entryPoints.length && !filtersTraffic)
      suggs.push({l:'warn', t:'Internet-facing entry point with no WAF on the path — add AWS WAF, Cloud Armor or Cloudflare'});
  } else if (types.size > 1) {
    suggs.push({l:'info', t:'Draw connections between your services — ArchLens analyses what reaches what, not just the inventory'});
  }

  // --- General architecture rules ---
  if ((has('COMPUTE') || has('SERVERLESS') || has('CONTAINER')) && !has('MONITORING'))
    suggs.push({l:'crit', t:'No monitoring — critical gap. Add CloudWatch, Datadog, or Grafana'});
  if (has('DATABASE') && !has('MONITORING'))
    suggs.push({l:'warn', t:'Database with no monitoring — query anomalies will go undetected'});
  if (has('COMPUTE') && !has('GATEWAY') && !has('CDN') && !hasAnyLLM)
    suggs.push({l:'warn', t:'Compute exposed without a Gateway or CDN — add API Gateway or ALB'});
  if (has('STORAGE') && !has('IAM'))
    suggs.push({l:'warn', t:'Storage without IAM — public access risk. Add access control'});
  if ((has('COMPUTE') || has('DATABASE')) && !has('NETWORK') && !hasAnyLLM)
    suggs.push({l:'warn', t:'No VPC/Network isolation — resources may be publicly reachable'});
  if (has('CONTAINER') && !has('IAM'))
    suggs.push({l:'warn', t:'Containers need service accounts/RBAC — add IAM'});
  if (has('QUEUE') && !has('MONITORING'))
    suggs.push({l:'warn', t:'Queues should have dead-letter queue monitoring configured'});
  if (has('IAM'))
    suggs.push({l:'info', t:'IAM present — verify least-privilege; avoid wildcard (*) actions'});
  if (has('MONITORING') && (has('COMPUTE') || has('SERVERLESS')))
    suggs.push({l:'good', t:'Monitoring + compute — solid observability foundation'});
  if (has('GATEWAY') || has('CDN'))
    suggs.push({l:'good', t:'Gateway/CDN layer adds traffic control and DDoS protection'});
  if (has('NETWORK'))
    suggs.push({l:'good', t:'Network isolation (VPC/Subnet) is a strong security boundary'});

  // --- AI / ML specific rules ---
  if (hasAnyLLM && !has('MONITORING') && !hasMLOps)
    suggs.push({l:'crit', t:'LLM API with no monitoring — token costs can spike without warning. Add CloudWatch, Datadog, or W&B'});
  if (hasAnyLLM && !has('CACHE'))
    suggs.push({l:'warn', t:'No cache layer — semantic caching (Redis) can cut LLM API costs by 40-60% on repeated queries'});
  if (hasAnyLLM && !has('GATEWAY'))
    suggs.push({l:'warn', t:'LLM API without a Gateway — add API Gateway or rate limiting to control costs and prevent abuse'});
  if (hasVectorDb && !has('IAM'))
    suggs.push({l:'warn', t:'Vector DB stores embeddings that may contain sensitive data — add access control (IAM)'});
  if (hasVectorDb && !hasAnyLLM)
    suggs.push({l:'info', t:'Vector DB without an LLM — is this intentional? Usually paired with an LLM for RAG pipelines'});
  if (hasAnyLLM && hasVectorDb)
    suggs.push({l:'good', t:'LLM + Vector DB — classic RAG setup. Consider adding a cache layer for performance'});
  if (hasFramework && !has('IAM'))
    suggs.push({l:'warn', t:'LangChain/LlamaIndex detected — store API keys in Secrets Manager, never in code'});
  if (hasMLTrain && !has('STORAGE'))
    suggs.push({l:'warn', t:'ML training without artifact storage — add S3 or GCS to save model checkpoints and datasets'});
  if (hasMLTrain && !hasMLOps)
    suggs.push({l:'info', t:'ML training without experiment tracking — consider MLflow or W&B to track runs and compare models'});
  if (hasMLOps)
    suggs.push({l:'good', t:'Experiment tracking configured — great for reproducibility and model comparison'});
  if (hasAnyLLM && hasVectorDb && has('CACHE') && has('MONITORING'))
    suggs.push({l:'good', t:'Well-structured AI stack — LLM + Vector DB + caching + monitoring covers the essentials'});

  if (suggs.length === 0)
    suggs.push({l:'info', t:'Architecture looks reasonable — run full analysis for detailed findings'});
  return suggs;
}

function renderSuggestions(types, _unused, containerId, services) {
  const list = document.getElementById(containerId);
  if (!list) return;
  const items = computeSuggestions(types, [], [], services);
  list.innerHTML = items.map(s =>
    `<div class="sugg-item ${s.l}"><div class="sugg-dot ${s.l}"></div><span>${s.t}</span></div>`
  ).join('');
}
