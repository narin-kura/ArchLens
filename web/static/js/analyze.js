// File upload and plain-text analysis.
// Copyright (c) 2026 K.N.Narin (github.com/narin-kura). All rights reserved.
// Non-commercial use only. See LICENSE. 

const ARCH_KEYWORDS = [
  'aws','gcp','azure','amazon','ec2','lambda','rds','s3','ecs','eks','fargate',
  'docker','kubernetes','k8s','container','server','instance','database','db',
  'mysql','postgres','mongodb','dynamodb','redis','elasticsearch','aurora',
  'storage','bucket','blob','vpc','subnet','load balancer','alb','elb','nginx',
  'api gateway','cdn','cloudfront','firewall','nat','queue','kafka','rabbitmq',
  'sqs','sns','pubsub','terraform','ansible','jenkins','ci/cd','pipeline','deploy',
  'cloudwatch','datadog','grafana','prometheus','monitoring','microservice','api',
  'backend','frontend','infrastructure','service','endpoint','application','iam',
  'security group','cache','serverless','cloud run','cloud sql','spanner','gke',
  'compute engine','github actions','gitlab','helm',
  'llm','openai','anthropic','gemini','gpt','claude','bedrock','vertex ai','sagemaker',
  'machine learning','embedding','vector database','vector db','pinecone','weaviate',
  'chroma','qdrant','langchain','llamaindex','rag','inference','training','hugging face',
  'ollama','mlflow','wandb','triton','ai model','language model','generative ai','chatbot',
];

function looksLikeArchitecture(text) {
  const lower = text.toLowerCase();
  const words = lower.trim().split(/\s+/);
  if (words.length < 5) return false;
  return ARCH_KEYWORDS.some(kw => lower.includes(kw));
}

function validateTextInput(el) {
  const hint = document.getElementById('textHint');
  const val = el.value.trim();
  if (!val) { hint.textContent = ''; hint.className = 'text-hint'; return; }
  if (looksLikeArchitecture(val)) {
    hint.textContent = 'Looks good — ready to analyze.';
    hint.className = 'text-hint good';
  } else {
    hint.textContent = 'Please describe your infrastructure (services, databases, tools). General questions are not supported.';
    hint.className = 'text-hint bad';
  }
}

let selectedFile = null;
let activeTab = 'file';

function switchTab(tab) {
  activeTab = tab;
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
  // Only the tabs this page actually has.
  document.querySelectorAll('.tab-content').forEach(el => {
    el.classList.toggle('active', el.id === 'tab-' + tab);
  });
  const analyzeBtn = document.getElementById('analyzeBtn');
  if (analyzeBtn) analyzeBtn.style.display = (tab === 'recommend') ? 'none' : 'block';
  if (tab === 'recommend') populateMustHaves();
}

function onFileSelect(input) {
  selectedFile = input.files[0];
  document.getElementById('fileName').textContent = selectedFile ? selectedFile.name : '';
}

const dz = document.getElementById('dropZone');
if (dz) {

// Stop the browser from hijacking a dropped file (its default is to open/
// navigate to the file). Without this, a drop that lands even slightly off
// the zone — or before the zone handler runs — makes the file just open.
['dragenter', 'dragover', 'drop'].forEach(evt =>
  document.addEventListener(evt, e => e.preventDefault())
);

['dragenter', 'dragover'].forEach(evt =>
  dz.addEventListener(evt, e => { e.preventDefault(); dz.classList.add('drag-over'); })
);
// Only clear the highlight when the cursor actually leaves the zone, not when
// it crosses between the zone's child elements (which fire dragleave too).
dz.addEventListener('dragleave', e => {
  if (!dz.contains(e.relatedTarget)) dz.classList.remove('drag-over');
});
dz.addEventListener('drop', e => {
  e.preventDefault();
  e.stopPropagation();
  dz.classList.remove('drag-over');
  const f = e.dataTransfer.files[0];
  if (f) {
    selectedFile = f;
    document.getElementById('fileName').textContent = f.name;
    // mirror into the file input so any input-based code path sees it too
    try { document.getElementById('fileInput').files = e.dataTransfer.files; } catch (_) {}
  }
});

}

async function runAnalysis() {
  const btn = document.getElementById('analyzeBtn');
  const loader = document.getElementById('loader');
  const results = document.getElementById('results');
  const errorBox = document.getElementById('errorBox');

  errorBox.style.display = 'none';
  results.style.display = 'none';
  loader.style.display = 'block';
  btn.disabled = true;

  try {
    const form = new FormData();
    if (activeTab === 'file' && selectedFile) {
      form.append('file', selectedFile);
    } else {
      const text = document.getElementById('textInput').value.trim();
      if (!text) throw new Error('Please enter an architecture description.');
      if (!looksLikeArchitecture(text)) throw new Error('Please describe your cloud infrastructure — include services, databases, or tools. General questions are not supported.');
      form.append('text', text);
      form.append('format_hint', 'text');
    }

    const res = await fetch('/analyze', { method: 'POST', body: form });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Analysis failed');
    renderResults(data);
  } catch (err) {
    errorBox.textContent = err.message;
    errorBox.style.display = 'block';
  } finally {
    loader.style.display = 'none';
    btn.disabled = false;
  }
}
