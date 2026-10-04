// The reference architecture gallery: lists the bundled examples and analyses
// one on demand. The files live in the repo, so there is nothing to upload.
// Copyright (c) 2026 K.N.Narin (github.com/narin-kura). All rights reserved.
// Non-commercial use only. See LICENSE.

const GITHUB_EXAMPLES = 'https://github.com/narin-kura/ArchLens/blob/main/examples';
const GITHUB_DIR = { aws: 'architectures', azure: 'architectures-azure' };
const PROVIDER_LABEL = { aws: 'AWS', azure: 'Azure' };

let ALL_EXAMPLES = [];
let ACTIVE_FILTER = 'all';

async function loadExamples() {
  const grid = document.getElementById('examplesGrid');
  try {
    const res = await fetch('/api/examples');
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Could not load the examples.');
    ALL_EXAMPLES = data.examples;
    if (!ALL_EXAMPLES.length) {
      grid.innerHTML = '<div class="examples-loading">No bundled architectures found in this deployment.</div>';
      return;
    }
    renderExamples();
  } catch (err) {
    grid.innerHTML = `<div class="examples-loading">${escapeText(err.message)}</div>`;
  }
}

function filterExamples(provider, btn) {
  ACTIVE_FILTER = provider;
  document.querySelectorAll('.ex-filter-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  renderExamples();
}

function renderExamples() {
  const grid = document.getElementById('examplesGrid');
  const examples = ACTIVE_FILTER === 'all'
    ? ALL_EXAMPLES
    : ALL_EXAMPLES.filter(ex => ex.provider === ACTIVE_FILTER);
  if (!examples.length) {
    grid.innerHTML = '<div class="examples-loading">No architectures match that filter.</div>';
    return;
  }
  grid.innerHTML = examples.map(ex => `
    <div class="ex-card">
      <div class="ex-num">
        <span class="ex-provider ex-provider-${ex.provider}">${PROVIDER_LABEL[ex.provider] || ex.provider}</span>
        ${ex.number} · ${ex.lines} lines of Terraform
      </div>
      <div class="ex-title">${escapeText(ex.title)}</div>
      <div class="ex-desc">${escapeText(ex.description)}</div>
      <div class="ex-meta">${ex.services.slice(0, 7).map(s => `<span class="ex-tag">${escapeText(s)}</span>`).join('')}${
        ex.services.length > 7 ? `<span class="ex-tag">+${ex.services.length - 7} more</span>` : ''}</div>
      <div class="ex-foot">
        <button class="ex-btn" onclick="analyzeExample('${ex.slug}', this)">Analyze</button>
        <a class="ex-link" href="${GITHUB_EXAMPLES}/${GITHUB_DIR[ex.provider] || ex.provider}/${ex.slug.replace(/^(aws|azure)-/, '')}/main.tf" target="_blank" rel="noopener">View Terraform &#8599;</a>
      </div>
      ${ex.expected ? `<div class="ex-expect">${escapeText(ex.expected)}</div>` : ''}
    </div>`).join('');
}

function escapeText(s) {
  const d = document.createElement('div');
  d.textContent = s == null ? '' : String(s);
  return d.innerHTML;
}

async function analyzeExample(slug, btn) {
  const loader = document.getElementById('loader');
  const errorBox = document.getElementById('errorBox');
  errorBox.style.display = 'none';
  document.getElementById('results').style.display = 'none';
  loader.style.display = 'block';
  document.querySelectorAll('.ex-btn').forEach(b => b.disabled = true);
  if (btn) btn.textContent = 'Analyzing…';
  try {
    const res = await fetch(`/api/examples/${encodeURIComponent(slug)}/analyze`, {method: 'POST'});
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Analysis failed');
    renderResults(data);
    document.getElementById('results').scrollIntoView({behavior: 'smooth', block: 'start'});
  } catch (err) {
    errorBox.textContent = err.message;
    errorBox.style.display = 'block';
  } finally {
    loader.style.display = 'none';
    document.querySelectorAll('.ex-btn').forEach(b => b.disabled = false);
    if (btn) btn.textContent = 'Analyze';
  }
}

loadExamples();
