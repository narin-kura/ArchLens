// Shared report rendering: findings, savings, JSON/Markdown export.
// Copyright (c) 2026 K.N.Narin (github.com/narin-kura). All rights reserved.
// Non-commercial use only. See LICENSE. 

function renderResults(data) {
  lastReport = data;
  document.getElementById('archName').textContent = data.architecture;

  // Security card
  document.getElementById('secCount').textContent = data.summary.security_count;
  document.getElementById('secCountBadge').textContent = data.summary.security_count;

  // Severity breakdown pills
  const sec = data.findings.filter(f => f.type === 'security');
  const sevOrder = ['critical','high','medium','low','info'];
  const sevCounts = {};
  for (const f of sec) sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1;
  document.getElementById('sevPills').innerHTML = sevOrder
    .filter(s => sevCounts[s])
    .map(s => `<span class="sev-pill ${s}">${sevCounts[s]} ${s}</span>`)
    .join('');

  // Cost card — count + savings
  document.getElementById('costCount').textContent = data.summary.cost_count;
  document.getElementById('costCountBadge').textContent = data.summary.cost_count;
  const savings = data.summary.estimated_savings;
  document.getElementById('costSavings').textContent =
    savings > 0 ? '$' + Math.round(savings) + '/mo potential savings' : 'No savings estimated';

  // Architecture card — components + workload tags
  const n = data.components_found || 0;
  document.getElementById('compCount').textContent = n + ' component' + (n === 1 ? '' : 's') + ' detected';
  const allText = data.findings.map(f => f.title + ' ' + (f.description || '')).join(' ');
  const workloadMap = [
    ['RAG',        /rag pipeline|retrieval/i],
    ['Fine-tuning',/fine.tuning|training workload/i],
    ['Inference',  /inference endpoint|model serving/i],
    ['Batch AI',   /batch inference/i],
    ['MLOps',      /mlops|experiment tracking|feature store/i],
    ['Managed AI', /single llm provider|managed.*llm/i],
  ];
  const tags = workloadMap.filter(([,re]) => re.test(allText)).map(([label]) => label);
  document.getElementById('workloadTags').innerHTML =
    tags.map(t => `<span class="card-tag">\u{1F916} ${t}</span>`).join('');

  const warn = document.getElementById('warnBanner');
  warn.style.display = n === 0 ? 'block' : 'none';

  const secEl = document.getElementById('secFindings');
  const costEl = document.getElementById('costFindings');
  secEl.innerHTML = ''; costEl.innerHTML = '';

  const cost = data.findings.filter(f => f.type === 'cost');
  const order = ['critical','high','medium','low','info'];
  sec.sort((a,b) => order.indexOf(a.severity) - order.indexOf(b.severity));

  sec.forEach(f => secEl.appendChild(findingCard(f)));
  cost.forEach(f => costEl.appendChild(findingCard(f)));

  if (!sec.length) secEl.innerHTML = '<div style="text-align:center;padding:28px;color:#94a3b8;font-size:14px;font-weight:500;">No security issues found</div>';
  if (!cost.length) costEl.innerHTML = '<div style="text-align:center;padding:28px;color:#94a3b8;font-size:14px;font-weight:500;">No cost issues found</div>';

  document.getElementById('results').style.display = 'block';
  document.getElementById('results').scrollIntoView({ behavior: 'smooth' });
}

let lastReport = null;

function downloadReport(format) {
  if (!lastReport) return;
  let content, filename, mime;

  if (format === 'json') {
    content = JSON.stringify(lastReport, null, 2);
    filename = `archlens-report-${lastReport.architecture}.json`;
    mime = 'application/json';
  } else {
    content = toMarkdown(lastReport);
    filename = `archlens-report-${lastReport.architecture}.md`;
    mime = 'text/markdown';
  }

  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function toMarkdown(data) {
  const lines = [];
  lines.push(`# ArchLens Report — ${data.architecture}\n`);
  lines.push(`**Security findings:** ${data.summary.security_count}  `);
  lines.push(`**Cost findings:** ${data.summary.cost_count}  `);
  if (data.summary.estimated_savings > 0)
    lines.push(`**Estimated savings:** $${Math.round(data.summary.estimated_savings)}/mo\n`);

  const sec = data.findings.filter(f => f.type === 'security');
  const cost = data.findings.filter(f => f.type === 'cost');

  if (sec.length) {
    lines.push(`\n## Security Findings\n`);
    sec.forEach(f => {
      lines.push(`### [${f.severity.toUpperCase()}] ${f.title}`);
      if (f.component) lines.push(`**Component:** ${f.component}  `);
      lines.push(`\n${f.description}\n`);
      if (f.recommendation) lines.push(`**Fix:** ${f.recommendation}\n`);
      if (f.references && f.references.length) {
        lines.push(`**References:**`);
        f.references.forEach(ref => lines.push(`- ${ref}`));
        lines.push('');
      }
    });
  }

  if (cost.length) {
    lines.push(`\n## Cost Optimizations\n`);
    cost.forEach(f => {
      lines.push(`### ${f.title}${f.estimated_savings > 0 ? ` (-$${Math.round(f.estimated_savings)}/mo)` : ''}`);
      lines.push(`\n${f.description}\n`);
      if (f.recommendation) lines.push(`**Fix:** ${f.recommendation}\n`);
      if (f.references && f.references.length) {
        lines.push(`**References:**`);
        f.references.forEach(ref => lines.push(`- ${ref}`));
        lines.push('');
      }
    });
  }

  lines.push(`\n---\n_Generated by [ArchLens](https://knnarin-archlens.hf.space)_`);
  return lines.join('\n');
}

function findingCard(f) {
  const card = document.createElement('div');
  card.className = 'finding-card ' + f.severity;

  const top = document.createElement('div');
  top.className = 'finding-top';

  const pill = document.createElement('span');
  pill.className = 'severity-pill ' + f.severity;
  pill.textContent = f.severity;

  const title = document.createElement('div');
  title.className = 'finding-title';
  title.textContent = f.title;

  top.appendChild(pill); top.appendChild(title);

  if (f.estimated_savings > 0) {
    const badge = document.createElement('span');
    badge.className = 'savings-badge';
    badge.textContent = '-$' + Math.round(f.estimated_savings) + '/mo';
    top.appendChild(badge);
  }

  card.appendChild(top);

  if (f.component) {
    const comp = document.createElement('div');
    comp.className = 'finding-component';
    comp.textContent = 'Component: ' + f.component;
    card.appendChild(comp);
  }

  const desc = document.createElement('div');
  desc.className = 'finding-desc';
  desc.textContent = f.description;
  card.appendChild(desc);

  if (f.recommendation) {
    const rec = document.createElement('div');
    rec.className = 'finding-rec';
    rec.textContent = f.recommendation;
    card.appendChild(rec);
  }

  if (f.references && f.references.length) {
    const refs = document.createElement('div');
    refs.className = 'finding-refs';
    f.references.forEach((ref, i) => {
      const link = document.createElement('a');
      link.className = 'finding-ref-link';
      link.href = ref;
      link.target = '_blank';
      link.rel = 'noopener';
      link.textContent = 'Reference' + (f.references.length > 1 ? ` ${i + 1}` : '');
      refs.appendChild(link);
    });
    card.appendChild(refs);
  }

  return card;
}
