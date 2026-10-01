// "Recommend my stack" questionnaire.
// Copyright (c) 2026 K.N.Narin (github.com/narin-kura). All rights reserved.
// Non-commercial use only. See LICENSE. 

function populateMustHaves() {
  const sel = document.getElementById('recMustHaves');
  if (sel.options.length) return;
  const byCat = {};
  SERVICES.forEach(s => {
    const label = s.group ? `${CAT_LABELS[s.cat] || s.cat} — ${s.group}` : (CAT_LABELS[s.cat] || s.cat);
    (byCat[label] = byCat[label] || []).push(s);
  });
  sel.innerHTML = Object.keys(byCat).filter(c => c !== 'all').map(cat =>
    `<optgroup label="${cat}">${byCat[cat].map(s => `<option value="${s.id}">${s.name} (${s.provider})</option>`).join('')}</optgroup>`
  ).join('');
}

let lastRecommendation = null;

async function getRecommendation() {
  const btn = document.getElementById('recSubmitBtn');
  const errorBox = document.getElementById('errorBox');
  errorBox.style.display = 'none';
  btn.disabled = true;
  btn.textContent = 'Thinking...';
  try {
    const mustHaves = [...document.getElementById('recMustHaves').selectedOptions]
      .map(o => findService(o.value))
      .filter(Boolean)
      .map(s => ({id:s.id, name:s.name, type:s.type, provider:s.provider, service:s.service}));

    const req = {
      project_type: document.getElementById('recProjectType').value,
      scale: document.getElementById('recScale').value,
      cloud: document.getElementById('recCloud').value,
      priority: document.getElementById('recPriority').value,
      database: document.getElementById('recDatabase').value,
      ai_needs: document.getElementById('recAiNeeds').value,
      security_level: document.getElementById('recSecurityLevel').value,
      realtime: document.getElementById('recRealtime').checked,
      must_haves: mustHaves,
    };

    const res = await fetch('/recommend', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(req)
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Could not generate a recommendation.');
    lastRecommendation = data;
    renderRecommendation(data);
  } catch (err) {
    errorBox.textContent = err.message;
    errorBox.style.display = 'block';
  } finally {
    btn.disabled = false;
    btn.textContent = 'Get My Recommendation →';
  }
}

function renderRecommendation(data) {
  const result = document.getElementById('recResult');
  document.getElementById('recSummary').textContent = data.ai_summary ||
    'Here is a starter stack based on your answers. Review the reasoning below, then use it to pre-fill the builder for a full security & cost analysis.';

  document.getElementById('recList').innerHTML = data.recommended.map(r => `
    <div class="rec-item">
      <div class="rec-item-name">
        <span class="svc-prov prov-${r.provider}">${r.provider.toUpperCase()}</span>
        ${r.name}
        <span class="rec-role">${r.role.replace(/_/g, ' ')}</span>
      </div>
      <div class="rec-item-why">${r.why}</div>
    </div>
  `).join('');

  document.getElementById('recCostTips').innerHTML = data.cost_tips.map(t => `<li>${t}</li>`).join('');
  document.getElementById('recSecurityTips').innerHTML = data.security_tips.map(t => `<li>${t}</li>`).join('');

  result.style.display = 'block';
  result.scrollIntoView({behavior:'smooth', block:'nearest'});
}

function useRecommendation() {
  if (!lastRecommendation) return;
  const ids = lastRecommendation.recommended.map(r => r.id);
  try {
    localStorage.setItem('archlens.handoff.v1', JSON.stringify(ids));
  } catch (e) {
    // Storage blocked — fall back to the ids in the URL.
    window.location.href = '/diagram?services=' + encodeURIComponent(ids.join(','));
    return;
  }
  window.location.href = '/diagram';
}
