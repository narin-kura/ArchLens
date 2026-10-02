// Diagram canvas: nodes, edges, drag, connect, auto-arrange, draft.
// Copyright (c) 2026 K.N.Narin (github.com/narin-kura). All rights reserved.
// Non-commercial use only. See LICENSE. 

// ---------------- canvas state ----------------
// nodes carry their own uid so the same service can appear twice (two
// buckets are two buckets), and edges reference those uids.
let nodes = [];          // {uid, svcId, name, type, provider, service, icon, x, y}
let edges = [];          // {uid, from, to, label}
let selection = null;    // {kind:'node'|'edge', uid}
let seq = 0;
let currentCat = 'aws';
let currentGroup = 'all';

const NODE_W = 132, NODE_H = 72, GRID = 22;
const DRAFT_KEY = 'archlens.diagram.v1';
const HANDOFF_KEY = 'archlens.handoff.v1';

function nodeById(uid) { return nodes.find(n => n.uid === uid); }

// ---------------- palette ----------------

function renderPalette() {
  const list = document.getElementById('paletteList');
  if (!list) return;
  const q = (document.getElementById('serviceSearch').value || '').toLowerCase();
  const inCat = SERVICES.filter(s => matchesCat(s, currentCat));
  const filtered = inCat.filter(s => {
    const matchGroup = currentGroup === 'all' || s.group === currentGroup;
    const matchQ = !q || s.name.toLowerCase().includes(q) || s.provider.includes(q)
      || s.service.includes(q) || (s.group || '').toLowerCase().includes(q);
    return matchGroup && matchQ;
  });

  renderGroupTabs(inCat);

  const label = s => s.group || CAT_LABELS[s.cat] || 'Other';
  const showHeads = currentGroup === 'all' && new Set(filtered.map(label)).size > 1;
  let last = null;
  list.innerHTML = filtered.map(s => {
    const head = showHeads && label(s) !== last ? `<div class="palette-group-head">${label(s)}</div>` : '';
    last = label(s);
    return head + `
      <div class="palette-item${s.legacy ? ' legacy' : ''}" draggable="true"
           data-svc="${s.id}" onclick="addNode('${s.id}')"
           title="${s.name} (${s.provider})${s.group ? ' — ' + s.group : ''}${s.legacy ? ' — retired' : ''}">
        <span class="palette-icon">${s.icon}</span>
        <span class="palette-name">${s.name}</span>
        ${s.legacy ? '<span class="palette-legacy">LEGACY</span>' : ''}
      </div>`;
  }).join('') || '<div class="palette-hint" style="padding:14px 0;">Nothing matches that search.</div>';

  list.querySelectorAll('.palette-item').forEach(el => {
    el.addEventListener('dragstart', e => {
      e.dataTransfer.setData('text/plain', el.dataset.svc);
      e.dataTransfer.effectAllowed = 'copy';
    });
  });
}

function renderGroupTabs(inCat) {
  const el = document.getElementById('groupTabs');
  if (!el) return;
  const counts = new Map();
  inCat.forEach(s => { if (s.group) counts.set(s.group, (counts.get(s.group) || 0) + 1); });
  if (counts.size < 2) { el.innerHTML = ''; return; }
  const chip = (g, text, n) =>
    `<button class="group-tab ${currentGroup === g ? 'active' : ''}" onclick="setGroup('${g.replace(/'/g, "\\'")}')">${text}<span class="group-count">${n}</span></button>`;
  el.innerHTML = chip('all', 'All', inCat.length)
    + [...counts.entries()].map(([g, n]) => chip(g, g, n)).join('');
}

function setCat(el) {
  currentCat = el.value !== undefined ? el.value : el.dataset.cat;
  currentGroup = 'all';
  renderPalette();
}

function setGroup(group) {
  currentGroup = group;
  renderPalette();
}

// ---------------- nodes & edges ----------------

function addNode(svcId, x, y) {
  const svc = findService(svcId);
  if (!svc) return;
  if (x === undefined) {
    // Drop into the first free slot so clicking repeatedly never stacks.
    const cols = 6;
    for (let i = 0; i < 400; i++) {
      const cx = 40 + (i % cols) * (NODE_W + 40);
      const cy = 40 + Math.floor(i / cols) * (NODE_H + 46);
      if (!nodes.some(n => Math.abs(n.x - cx) < 8 && Math.abs(n.y - cy) < 8)) { x = cx; y = cy; break; }
    }
  }
  nodes.push({
    uid: `n${++seq}`, svcId: svc.id, name: svc.name, type: svc.type,
    provider: svc.provider, service: svc.service, icon: svc.icon,
    x: Math.max(0, x), y: Math.max(0, y),
  });
  select('node', `n${seq}`);
  renderCanvas();
}

function removeNode(uid) {
  nodes = nodes.filter(n => n.uid !== uid);
  edges = edges.filter(e => e.from !== uid && e.to !== uid);
  if (selection && selection.uid === uid) selection = null;
  renderCanvas();
}

function addEdge(from, to) {
  if (from === to) return;
  if (edges.some(e => e.from === from && e.to === to)) return;
  edges.push({uid: `e${++seq}`, from, to, label: ''});
  renderCanvas();
}

function select(kind, uid) {
  selection = kind ? {kind, uid} : null;
  const btn = document.getElementById('canvasDeleteBtn');
  if (btn) btn.disabled = !selection;
}

function deleteSelection() {
  if (!selection) return;
  if (selection.kind === 'node') removeNode(selection.uid);
  else { edges = edges.filter(e => e.uid !== selection.uid); selection = null; renderCanvas(); }
}

function clearCanvas() {
  if (nodes.length && !confirm('Remove every service and connection from the canvas?')) return;
  nodes = []; edges = []; select(null);
  renderCanvas();
}

// Tiers run left to right in the direction traffic travels.
const TIER_ORDER = ['NETWORK','CDN','GATEWAY','COMPUTE','CONTAINER','SERVERLESS','QUEUE','CACHE','DATABASE','STORAGE','IAM','MONITORING','OTHER'];

function autoArrange() {
  const byTier = new Map();
  nodes.forEach(n => {
    const found = TIER_ORDER.indexOf(n.type);
    const tier = found === -1 ? TIER_ORDER.length - 1 : found;
    if (!byTier.has(tier)) byTier.set(tier, []);
    byTier.get(tier).push(n);
  });
  let col = 0;
  [...byTier.keys()].sort((a, b) => a - b).forEach(tier => {
    byTier.get(tier).forEach((n, row) => {
      n.x = 40 + col * (NODE_W + 72);
      n.y = 40 + row * (NODE_H + 40);
    });
    col++;
  });
  renderCanvas();
}

// ---------------- rendering ----------------

function edgePath(a, b) {
  const x1 = a.x + NODE_W, y1 = a.y + NODE_H / 2;
  const x2 = b.x, y2 = b.y + NODE_H / 2;
  // Route backwards edges around rather than through the source node.
  const dx = Math.max(40, Math.abs(x2 - x1) * 0.45);
  return `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;
}

function renderCanvas() {
  const inner = document.getElementById('canvasInner');
  const svg = document.getElementById('canvasEdges');
  if (!inner || !svg) return;

  // Edges first so they sit behind the nodes.
  const defs = svg.querySelector('defs');
  svg.innerHTML = '';
  if (defs) svg.appendChild(defs);
  edges.forEach(e => {
    const a = nodeById(e.from), b = nodeById(e.to);
    if (!a || !b) return;
    const d = edgePath(a, b);
    const sel = selection && selection.kind === 'edge' && selection.uid === e.uid;
    const hit = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    hit.setAttribute('d', d);
    hit.setAttribute('class', 'edge-hit');
    hit.addEventListener('click', ev => { ev.stopPropagation(); select('edge', e.uid); renderCanvas(); });
    hit.addEventListener('dblclick', ev => { ev.stopPropagation(); labelEdge(e.uid); });
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', d);
    path.setAttribute('class', 'edge' + (sel ? ' selected' : ''));
    path.setAttribute('marker-end', sel ? 'url(#arrowEndSel)' : 'url(#arrowEnd)');
    svg.appendChild(path);
    svg.appendChild(hit);
    if (e.label) {
      const t = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      t.setAttribute('x', (a.x + NODE_W + b.x) / 2);
      t.setAttribute('y', (a.y + b.y) / 2 + NODE_H / 2 - 7);
      t.setAttribute('text-anchor', 'middle');
      t.setAttribute('class', 'edge-label');
      t.textContent = e.label;
      svg.appendChild(t);
    }
  });

  inner.querySelectorAll('.node').forEach(el => el.remove());
  nodes.forEach(n => {
    const el = document.createElement('div');
    el.className = 'node' + (selection && selection.kind === 'node' && selection.uid === n.uid ? ' selected' : '');
    el.style.left = n.x + 'px';
    el.style.top = n.y + 'px';
    el.dataset.uid = n.uid;
    el.title = `${n.name} — drag to move, drag the right dot to connect`;
    el.innerHTML = `
      <div><span class="node-prov prov-${n.provider}">${n.provider.toUpperCase()}</span></div>
      <div class="node-icon">${n.icon}</div>
      <div class="node-name">${n.name}</div>
      <div class="node-handle" title="Drag to another service to connect"></div>
      <div class="node-del" title="Remove">&#10005;</div>`;
    inner.appendChild(el);
  });

  document.getElementById('canvasEmpty').style.display = nodes.length ? 'none' : 'block';
  document.getElementById('canvasCounts').textContent =
    `${nodes.length} service${nodes.length === 1 ? '' : 's'} · ${edges.length} connection${edges.length === 1 ? '' : 's'}`;
  const btn = document.getElementById('builderAnalyzeBtn');
  if (btn) btn.disabled = nodes.length === 0;

  updateSuggestions();
  saveDraft();
}

function labelEdge(uid) {
  const e = edges.find(x => x.uid === uid);
  if (!e) return;
  const text = prompt('Label this connection (e.g. "reads", "writes", "TLS 1.3"):', e.label || '');
  if (text === null) return;
  e.label = text.trim().slice(0, 40);
  renderCanvas();
}

function updateSuggestions() {
  const types = new Set(nodes.map(n => n.type));
  const services = new Set(nodes.map(n => n.service));
  const resolved = edges.map(e => {
    const a = nodeById(e.from), b = nodeById(e.to);
    return a && b ? {fromType: a.type, toType: b.type, fromName: a.name, toName: b.name} : null;
  }).filter(Boolean);
  renderSuggestions(types, resolved, 'suggList', services);
}

// ---------------- interaction ----------------

function initCanvas() {
  const canvas = document.getElementById('canvas');
  const inner = document.getElementById('canvasInner');
  if (!canvas || canvas.dataset.ready) return;
  canvas.dataset.ready = '1';

  let drag = null;   // {uid, el, offsetX, offsetY}
  let link = null;   // {fromUid, path}

  const localPoint = ev => {
    const r = inner.getBoundingClientRect();
    return {x: ev.clientX - r.left, y: ev.clientY - r.top};
  };

  inner.addEventListener('pointerdown', ev => {
    const nodeEl = ev.target.closest('.node');
    if (!nodeEl) return;
    const uid = nodeEl.dataset.uid;

    if (ev.target.classList.contains('node-del')) { removeNode(uid); return; }

    if (ev.target.classList.contains('node-handle')) {
      const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      path.setAttribute('class', 'rubber');
      document.getElementById('canvasEdges').appendChild(path);
      link = {fromUid: uid, path};
      inner.setPointerCapture(ev.pointerId);
      ev.preventDefault();
      return;
    }

    select('node', uid);
    const p = localPoint(ev);
    const n = nodeById(uid);
    drag = {uid, el: nodeEl, offsetX: p.x - n.x, offsetY: p.y - n.y, moved: false};
    nodeEl.classList.add('dragging');
    inner.setPointerCapture(ev.pointerId);
    renderCanvas();
    ev.preventDefault();
  });

  // setPointerCapture retargets every move/up event's `ev.target` to the
  // capturing element itself (`inner`), not whatever the cursor is actually
  // over — ev.target.closest('.node') would look for a .node *ancestor* of
  // inner, which can never exist since inner is the nodes' parent. Real
  // screen-coordinate hit-testing sidesteps the capture retargeting.
  const nodeUnderPointer = ev => {
    const hit = document.elementFromPoint(ev.clientX, ev.clientY);
    return hit && hit.closest ? hit.closest('.node') : null;
  };

  inner.addEventListener('pointermove', ev => {
    if (link) {
      const a = nodeById(link.fromUid);
      const p = localPoint(ev);
      link.path.setAttribute('d', `M ${a.x + NODE_W} ${a.y + NODE_H / 2} L ${p.x} ${p.y}`);
      const over = nodeUnderPointer(ev);
      inner.querySelectorAll('.node.link-target').forEach(el => el.classList.remove('link-target'));
      if (over && over.dataset.uid !== link.fromUid) over.classList.add('link-target');
      return;
    }
    if (!drag) return;
    const p = localPoint(ev);
    const n = nodeById(drag.uid);
    if (!n) return;
    n.x = Math.max(0, Math.round((p.x - drag.offsetX) / 2) * 2);
    n.y = Math.max(0, Math.round((p.y - drag.offsetY) / 2) * 2);
    drag.el.style.left = n.x + 'px';
    drag.el.style.top = n.y + 'px';
    drag.moved = true;
    redrawEdgesOnly();
  });

  inner.addEventListener('pointerup', ev => {
    if (link) {
      const over = nodeUnderPointer(ev);
      if (over && over.dataset.uid !== link.fromUid) addEdge(link.fromUid, over.dataset.uid);
      link.path.remove();
      inner.querySelectorAll('.node.link-target').forEach(el => el.classList.remove('link-target'));
      link = null;
      renderCanvas();
      return;
    }
    if (drag) {
      drag.el.classList.remove('dragging');
      // Snap to the dot grid so diagrams stay tidy without a layout pass.
      const n = nodeById(drag.uid);
      if (n && drag.moved) {
        n.x = Math.round(n.x / GRID) * GRID;
        n.y = Math.round(n.y / GRID) * GRID;
      }
      drag = null;
      renderCanvas();
    }
  });

  canvas.addEventListener('click', ev => {
    if (!ev.target.closest('.node') && !ev.target.closest('path')) { select(null); renderCanvas(); }
  });

  canvas.addEventListener('keydown', ev => {
    if ((ev.key === 'Delete' || ev.key === 'Backspace') && selection) { ev.preventDefault(); deleteSelection(); }
    if (ev.key === 'Escape') { select(null); renderCanvas(); }
  });

  // Palette drag-and-drop
  canvas.addEventListener('dragover', ev => { ev.preventDefault(); canvas.classList.add('drop-active'); });
  canvas.addEventListener('dragleave', () => canvas.classList.remove('drop-active'));
  canvas.addEventListener('drop', ev => {
    ev.preventDefault();
    canvas.classList.remove('drop-active');
    const svcId = ev.dataTransfer.getData('text/plain');
    if (!svcId) return;
    const r = inner.getBoundingClientRect();
    addNode(svcId, Math.round((ev.clientX - r.left - NODE_W / 2) / GRID) * GRID,
                   Math.round((ev.clientY - r.top - NODE_H / 2) / GRID) * GRID);
  });
}

// Dragging a node only moves lines; skipping the full re-render keeps it smooth.
function redrawEdgesOnly() {
  const svg = document.getElementById('canvasEdges');
  const paths = svg.querySelectorAll('path.edge, path.edge-hit');
  let i = 0;
  edges.forEach(e => {
    const a = nodeById(e.from), b = nodeById(e.to);
    if (!a || !b) return;
    const d = edgePath(a, b);
    if (paths[i]) paths[i].setAttribute('d', d);
    if (paths[i + 1]) paths[i + 1].setAttribute('d', d);
    i += 2;
  });
}

// ---------------- draft persistence (this browser only) ----------------

function saveDraft() {
  try {
    localStorage.setItem(DRAFT_KEY, JSON.stringify({nodes, edges, seq}));
  } catch (e) { /* private mode or blocked storage — the canvas still works */ }
}

function restoreDraft() {
  try {
    const raw = localStorage.getItem(DRAFT_KEY);
    if (!raw) return false;
    const data = JSON.parse(raw);
    if (!Array.isArray(data.nodes) || !data.nodes.length) return false;
    nodes = data.nodes;
    edges = Array.isArray(data.edges) ? data.edges : [];
    seq = data.seq || nodes.length + edges.length;
    return true;
  } catch (e) { return false; }
}

async function runBuilderAnalysis() {
  if (!nodes.length) return;
  if (typeof openReport === 'function') openReport();
  const btn = document.getElementById('builderAnalyzeBtn');
  const loader = document.getElementById('loader');
  const errorBox = document.getElementById('errorBox');
  errorBox.style.display = 'none';
  document.getElementById('results').style.display = 'none';
  loader.style.display = 'block';
  btn.disabled = true;
  try {
    const res = await fetch('/analyze-interactive', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        name: 'My Diagram',
        // The node uid is the component id, so the edges below resolve and
        // the same service can appear more than once.
        components: nodes.map(n => ({id:n.uid, name:n.name, type:n.type, provider:n.provider, service:n.service})),
        connections: edges.map(e => ({source_id:e.from, target_id:e.to, label:e.label || ''}))
      })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Analysis failed');
    renderResults(data);
  } catch (err) {
    errorBox.textContent = err.message; errorBox.style.display = 'block';
  } finally {
    loader.style.display = 'none'; btn.disabled = false;
  }
}

// The recommender lives on another page now, so it leaves its picks here and
// sends the visitor over. Consumed once, then cleared.
function applyHandoff() {
  let ids;
  const fromUrl = new URLSearchParams(window.location.search).get('services');
  if (fromUrl) ids = fromUrl.split(',').filter(Boolean);
  try {
    if (ids) throw 'from-url';
    const raw = localStorage.getItem(HANDOFF_KEY);
    if (!raw) return false;
    localStorage.removeItem(HANDOFF_KEY);
    ids = JSON.parse(raw);
  } catch (e) { if (!ids) return false; }
  if (!Array.isArray(ids) || !ids.length) return false;
  nodes = []; edges = []; select(null);
  ids.forEach(id => addNode(id));
  autoArrange();
  select(null);
  return true;
}
