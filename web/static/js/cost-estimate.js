// Estimated monthly cost section of a report (data from archlens/pricing.py and
// archlens/hosting.py). Builds its own markup so every page that shows a report gets it.
// Copyright (c) 2026 K.N.Narin (github.com/narin-kura). All rights reserved.
// Non-commercial use only. See LICENSE.

let costRegion = 'us';
try { costRegion = localStorage.getItem('archlens.costRegion') || 'us'; } catch {}

function ceEsc(s) {
  return String(s ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
}
function ceMoney(n) {
  if (n >= 100) return '$' + Math.round(n).toLocaleString('en-US');
  return '$' + n.toLocaleString('en-US', {minimumFractionDigits: 2, maximumFractionDigits: 2});
}
function ceUrl(u) { return /^https:\/\//i.test(u || '') ? u : '#'; }

function setCostRegion(region) {
  costRegion = region;
  try { localStorage.setItem('archlens.costRegion', region); } catch {}
  if (lastReport) renderCostEstimate(lastReport);
}

function renderCostEstimate(data) {
  const results = document.getElementById('results');
  if (!results) return;
  let box = document.getElementById('costEstimate');
  if (!box) {
    box = document.createElement('div');
    box.id = 'costEstimate';
    box.className = 'findings-section cost-estimate';
    results.insertBefore(box, results.querySelector('.findings-section'));
  }
  const all = data.cost_estimates || {};
  const est = all[costRegion] || all.us || Object.values(all)[0];
  if (!est) { box.innerHTML = ''; return; }
  const region = est.region;
  const tiers = est.tiers || [], lines = est.lines || [];

  const regionSwitch = (est.regions || []).length > 1 ? `<div class="ce-regions" role="group" aria-label="Price region">${
    est.regions.map(r => `<button type="button" class="${r.key === region ? 'on' : ''}" onclick="setCostRegion('${ceEsc(r.key)}')">${ceEsc(r.label)}</button>`).join('')}</div>` : '';

  let body;
  if (!est.available) {
    body = `<p class="ce-note">No resources here could be priced. ArchLens prices AWS, Azure, Google Cloud and Oracle Cloud resources from their official price lists; self-hosted pieces (your own servers, Kubernetes or Docker) depend on where you run them.</p>`;
  } else {
    const cards = tiers.map(t => `<div class="ce-tier ${ceEsc(t.key)}">
        <div class="ce-tier-name">${ceEsc(t.label)}</div>
        <div class="ce-tier-total">${ceMoney(t.total)}<span>/month</span></div>
        <div class="ce-tier-blurb">${ceEsc(t.blurb)}</div>
      </div>`).join('');

    const rows = lines.map(l => `<tr>
        <td><div class="ce-res">${ceEsc(l.name)}</div><div class="ce-sub">${ceEsc(l.role)} · ${ceEsc(l.provider)}</div></td>
        ${tiers.map(t => { const c = l.costs[t.key];
          return c ? `<td><div class="ce-amt">${ceMoney(c.usd)}</div><div class="ce-sub">${ceEsc(c.detail)}</div></td>`
                   : `<td><div class="ce-sub">uses Balanced</div></td>`; }).join('')}
      </tr>`).join('');
    const table = `<details class="ce-details"${lines.length <= 8 ? ' open' : ''}>
        <summary>What each total is made of (${lines.length} priced resource${lines.length === 1 ? '' : 's'})</summary>
        <div class="ce-scroll"><table class="ce-table">
          <thead><tr><th>Resource</th>${tiers.map(t => `<th>${ceEsc(t.label)}</th>`).join('')}</tr></thead>
          <tbody>${rows}</tbody>
        </table></div>
      </details>`;

    const unpriced = est.unpriced || [];
    const left = [];
    if (est.no_charge_count) left.push(`${est.no_charge_count} resource${est.no_charge_count === 1 ? ' has' : 's have'} no charge of their own (networks, permissions, rules and similar)`);
    if (unpriced.length) left.push(`${unpriced.length} could not be priced and ${unpriced.length === 1 ? 'is' : 'are'} left out of the totals`);
    const leftOut = left.length ? `<details class="ce-details">
        <summary>Left out: ${ceEsc(left.join('; '))}</summary>
        ${unpriced.length ? `<ul class="ce-list">${unpriced.map(u => `<li><b>${ceEsc(u.name)}</b> <span class="ce-sub">${ceEsc(u.service)}</span> — ${ceEsc(u.reason)}</li>`).join('')}</ul>` : ''}
      </details>` : '';

    const clouds = est.other_clouds || [];
    const main3 = tiers.filter(t => t.key !== 'as_written');
    const cloudTable = clouds.length ? `<details class="ce-details" open>
        <summary>The same setup on each cloud</summary>
        <p class="ce-note">Each resource is re-priced as its closest match on the other clouds (a virtual machine stays a virtual machine, a database a database). A like-for-like guide, not a migration quote.</p>
        <div class="ce-scroll"><table class="ce-table">
          <thead><tr><th>Cloud</th>${main3.map(t => `<th>${ceEsc(t.label)}</th>`).join('')}</tr></thead>
          <tbody>${clouds.map(c => `<tr class="${c.current ? 'ce-current' : ''}">
            <td><div class="ce-res">${ceEsc(c.provider)}${c.current ? ' <span class="ce-pill">yours</span>' : ''}</div>${c.not_priced ? `<div class="ce-sub">${c.not_priced} resource${c.not_priced === 1 ? '' : 's'} with no match left out</div>` : ''}</td>
            ${main3.map(t => `<td><div class="ce-amt">${ceMoney(c.totals[t.key])}</div></td>`).join('')}
          </tr>`).join('')}</tbody>
        </table></div>
      </details>` : '';

    body = `<div class="ce-tiers">${cards}</div>${table}${leftOut}${cloudTable}`;
  }

  // Cheaper ways to host: one server per cloud + directory of other platforms
  const host = data.hosting_options || {};
  const single = ((host.single_server || {}).by_region || {})[region] || [];
  const dir = host.directory || {groups: []};
  const hosting = (single.length || dir.groups.length) ? `<details class="ce-details">
      <summary>Cheaper ways to host: one server, app platforms, Indian clouds (${dir.count || 0} platforms)</summary>
      ${single.length ? `<h4 class="ce-h4">Everything on one server</h4>
        <p class="ce-note">${ceEsc(host.single_server.what)}</p>
        <div class="ce-chips">${single.map(s => `<a class="ce-chip" href="${ceEsc(ceUrl(s.pricing_page))}" target="_blank" rel="noopener noreferrer"><b>${ceEsc(s.provider)}</b> ${ceMoney(s.usd_month)}/mo <span>${ceEsc(s.size)}</span></a>`).join('')}</div>` : ''}
      <p class="ce-note">ArchLens does not price the platforms below. Each links to the provider's own pricing or home page${dir.checked ? ` (links checked ${ceEsc(dir.checked)})` : ''}.</p>
      ${dir.groups.map(g => `<h4 class="ce-h4">${ceEsc(g.title)}</h4>
        <p class="ce-note">${ceEsc(g.blurb)}</p>
        <div class="ce-platforms">${g.items.map(p => {
          const inner = `<b>${ceEsc(p.name)}</b><span>${ceEsc(p.fits)}</span><span class="ce-meta">${ceEsc(p.where)} · ${ceEsc(p.buy_label)}</span>${p.note ? `<span class="ce-meta">${ceEsc(p.note)}</span>` : ''}`;
          return p.url ? `<a class="ce-platform" href="${ceEsc(ceUrl(p.url))}" target="_blank" rel="noopener noreferrer">${inner}</a>`
                       : `<div class="ce-platform">${inner}</div>`; }).join('')}</div>`).join('')}
    </details>` : '';

  const sources = (est.sources || []).map(s => `<a href="${ceEsc(ceUrl(s.pricing_page))}" target="_blank" rel="noopener noreferrer">${ceEsc(s.provider)}</a> (${ceEsc(s.name)}, ${ceEsc(s.published)})`).join('; ');
  const foot = `<div class="ce-foot">
      <p><b>How to read this:</b> ${(est.notes || []).map(ceEsc).join(' ')}</p>
      ${sources ? `<p><b>Price sources:</b> ${sources}.</p>` : ''}
    </div>`;

  box.innerHTML = `<div class="section-hdr ce-hdr"><span>Estimated monthly cost <span class="ce-usd">USD</span></span>${regionSwitch}</div>${body}${hosting}${foot}`;
}

// Cost section for the Markdown export.
function costEstimateMarkdown(data) {
  const all = data.cost_estimates || {};
  const est = all[costRegion] || all.us;
  if (!est || !est.available) return [];
  const out = [`\n## Estimated monthly cost (USD, ${est.region_label})\n`];
  est.tiers.forEach(t => out.push(`- **${t.label}:** ${ceMoney(t.total)}/month — ${t.blurb}`));
  out.push('', `| Resource | ${est.tiers.map(t => t.label).join(' | ')} |`, `|---|${est.tiers.map(() => '---').join('|')}|`);
  est.lines.forEach(l => out.push(`| ${l.name} (${l.role}, ${l.provider}) | ${est.tiers.map(t => l.costs[t.key] ? `${ceMoney(l.costs[t.key].usd)} (${l.costs[t.key].detail})` : 'uses Balanced').join(' | ')} |`));
  if ((est.other_clouds || []).length) {
    out.push('', '**The same setup on each cloud (Starter / Balanced / Production):**');
    est.other_clouds.forEach(c => out.push(`- ${c.provider}: ${ceMoney(c.totals.starter)} / ${ceMoney(c.totals.balanced)} / ${ceMoney(c.totals.production)}${c.not_priced ? ` (${c.not_priced} left out)` : ''}`));
  }
  if (est.unpriced.length) out.push('', `Not priced (${est.unpriced.length}): ${est.unpriced.map(u => u.name).join(', ')}`);
  out.push('', (est.notes || []).join(' '), '', '**Price sources:**');
  est.sources.forEach(s => out.push(`- ${s.provider}: ${s.name}, ${s.published} — ${s.pricing_page}`));
  return out;
}
