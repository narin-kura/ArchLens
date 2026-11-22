// Diagram -> Kubernetes: turns the canvas's nodes/edges into a sample manifest.
//
// Every Kubernetes node on the canvas whose kind has a template in
// window.K8S_TEMPLATES (generated from scripts/k8s_templates/*.yaml by
// scripts/gen_k8s_templates.py) becomes that object, with secure defaults
// that pass ArchLens's own checks. The diagram's arrows wire the objects:
//
//   Service <-> workload        Service selects the workload's pods
//   Ingress / HTTPRoute -> ...  backend is the connected Service (one is
//                               created for a workload that has none)
//   Gateway <-> HTTPRoute       the route attaches to the gateway
//   ConfigMap / Secret <-> W    envFrom on the workload's container
//   PVC <-> W                   mounted at /mnt/<claim>
//   ServiceAccount <-> W        the workload runs as it
//   HPA / PDB <-> W             scale target / selector
//   RoleBinding <-> Role, SA    roleRef / subject
//   A -> B (traffic)            a NetworkPolicy lets A's pods reach B's
//
// Every workload gets its own ServiceAccount unless one is drawn, and the
// namespace gets a default-deny NetworkPolicy unless one is drawn. Generic
// container nodes (Docker, a self-hosted model server...) become
// Deployments; generic databases, caches and queues become StatefulSets.
// Managed cloud services and kinds without a template are listed as TODOs
// at the end, never as made-up objects.
// Copyright (c) 2026 K.N.Narin (github.com/narin-kura). All rights reserved.
// Non-commercial use only. See LICENSE.

const K8S_WORKLOAD_KINDS = new Set(['deployment', 'statefulset', 'daemonset', 'job', 'cronjob', 'pod']);
const K8S_SCALABLE_KINDS = new Set(['deployment', 'statefulset']);
const K8S_ENTRY_KINDS = new Set(['ingress', 'httproute', 'gateway']);
// Namespace the ingress controller runs in, for NetworkPolicy rules that let
// it reach the pods behind an Ingress or Gateway.
const K8S_INGRESS_CONTROLLER_NS = 'ingress-nginx';
// Kubernetes object order in the file: things others refer to come first.
const K8S_ORDER = ['namespace', 'resourcequota', 'limitrange', 'serviceaccount', 'role', 'rolebinding',
  'configmap', 'secret', 'persistentvolumeclaim', 'deployment', 'statefulset', 'daemonset', 'job',
  'cronjob', 'pod', 'service', 'ingress', 'gateway', 'httproute', 'horizontalpodautoscaler',
  'poddisruptionbudget', 'networkpolicy'];

// ------------------------------------------------------------------ YAML

function k8sYamlScalar(v, isKey) {
  if (v === null || v === undefined) return 'null';
  if (typeof v === 'boolean' || typeof v === 'number') return String(v);
  const s = String(v);
  const risky = s === ''
    || /^\s|\s$/.test(s)
    || /[:#\[\]{},&*!|>'"%@`]/.test(s.replace(/^[A-Za-z0-9_.\/-]+$/, ''))
    || /^(true|false|yes|no|on|off|null|y|n|~)$/i.test(s)
    || (!isKey && /^[-+]?(\d|\.\d)/.test(s))
    || /^[-?]/.test(s)
    || /: |\s#/.test(s);
  return risky ? JSON.stringify(s) : s;
}

function k8sIsEmpty(v) {
  return (Array.isArray(v) && v.length === 0)
    || (v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === 0);
}

function k8sToYaml(value, indent) {
  indent = indent || 0;
  const pad = ' '.repeat(indent);
  const lines = [];
  if (Array.isArray(value)) {
    value.forEach(item => {
      if (item && typeof item === 'object' && !k8sIsEmpty(item)) {
        const inner = k8sToYaml(item, indent + 2).split('\n');
        inner[0] = pad + '- ' + inner[0].slice(indent + 2);
        lines.push(...inner);
      } else {
        lines.push(pad + '- ' + (k8sIsEmpty(item) ? (Array.isArray(item) ? '[]' : '{}') : k8sYamlScalar(item)));
      }
    });
    return lines.join('\n');
  }
  Object.keys(value).forEach(key => {
    const v = value[key];
    const k = k8sYamlScalar(key, true);
    if (v && typeof v === 'object' && !k8sIsEmpty(v)) {
      lines.push(`${pad}${k}:`);
      lines.push(k8sToYaml(v, Array.isArray(v) ? indent + 2 : indent + 2));
    } else if (k8sIsEmpty(v)) {
      lines.push(`${pad}${k}: ${Array.isArray(v) ? '[]' : '{}'}`);
    } else {
      lines.push(`${pad}${k}: ${k8sYamlScalar(v)}`);
    }
  });
  return lines.join('\n');
}

// ----------------------------------------------------------------- naming

function k8sDnsName(name, fallback) {
  let s = String(name || fallback || 'app').toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-').replace(/-+/g, '-').replace(/^-+|-+$/g, '');
  if (!s) s = fallback || 'app';
  if (!/^[a-z0-9]/.test(s)) s = 'x-' + s;
  return s.slice(0, 50).replace(/-+$/, '');
}

function k8sDeepReplace(value, map) {
  if (typeof value === 'string') {
    return value.replace(/__NAME__|__NAMESPACE__/g, m => map[m]);
  }
  if (Array.isArray(value)) return value.map(v => k8sDeepReplace(v, map));
  if (value && typeof value === 'object') {
    const out = {};
    Object.keys(value).forEach(k => { out[k] = k8sDeepReplace(value[k], map); });
    return out;
  }
  return value;
}

// The pod spec inside any workload kind.
function k8sPodSpec(obj) {
  if (obj.kind === 'Pod') return obj.spec;
  if (obj.kind === 'CronJob') return obj.spec.jobTemplate.spec.template.spec;
  return obj.spec.template.spec;
}

// ------------------------------------------------------------------ export

// What a diagram node becomes: a Kubernetes kind (catalog service id), or
// null for things that are not Kubernetes objects (managed cloud services).
function k8sKindOf(n) {
  if (n.provider === 'kubernetes') return n.service;
  if (n.provider === 'generic' || n.provider === 'docker') {
    if (n.type === 'CONTAINER' || n.type === 'COMPUTE') return 'deployment';
    if (n.type === 'DATABASE' || n.type === 'CACHE' || n.type === 'QUEUE') return 'statefulset';
  }
  return null;
}

function k8sTemplates(templatesArg) {
  return templatesArg || (typeof window !== 'undefined' && window.K8S_TEMPLATES) || {};
}

// Diagram nodes the Kubernetes export can turn into objects: Kubernetes kinds
// that have a template, and generic containers / data stores. A Namespace on
// its own is not enough. The canvas enables "Export Kubernetes" only when
// there is at least one.
function kubernetesExportableNodes(diagramNodes, templatesArg) {
  const templates = k8sTemplates(templatesArg);
  return diagramNodes.filter(n => {
    const kind = k8sKindOf(n);
    return kind && kind !== 'namespace' && templates[kind];
  });
}

function buildKubernetesExport(diagramNodes, diagramEdges, templatesArg) {
  const templates = k8sTemplates(templatesArg);
  const kindOf = k8sKindOf;

  const nsNode = diagramNodes.find(n => kindOf(n) === 'namespace');
  const namespace = nsNode ? k8sDnsName(nsNode.name, 'app') : 'app';

  const usedNames = new Set();
  const uniqueName = (kind, base) => {
    let name = base, i = 1;
    while (usedNames.has(kind + '/' + name)) { i++; name = `${base}-${i}`; }
    usedNames.add(kind + '/' + name);
    return name;
  };

  const items = [];            // {uid, kind, name, obj, notes[], node}
  const byUid = new Map();
  const todoKinds = [];        // Kubernetes kinds with no template
  const external = [];         // managed cloud services, SaaS, CI tools...

  diagramNodes.forEach(n => {
    const kind = kindOf(n);
    if (kind === 'namespace') return;
    if (!kind) { external.push(n); return; }
    const tpl = templates[kind];
    if (!tpl) { todoKinds.push(n); return; }
    const name = uniqueName(kind, k8sDnsName(n.name, kind));
    const obj = k8sDeepReplace(JSON.parse(JSON.stringify(tpl.object)),
                               {__NAME__: name, __NAMESPACE__: namespace});
    const notes = tpl.note ? [tpl.note] : [];
    if (n.provider !== 'kubernetes') notes.push(`Drawn as "${n.name}" (${n.service}); set the image to the one you run.`);
    const item = {uid: n.uid, kind, name, obj, notes, node: n, auto: false};
    items.push(item);
    byUid.set(n.uid, item);
  });

  const neighbours = uid => diagramEdges
    .filter(e => e.from === uid || e.to === uid)
    .map(e => byUid.get(e.from === uid ? e.to : e.from))
    .filter(Boolean);
  const neighboursOfKind = (uid, kinds) => neighbours(uid).filter(i => kinds.has(i.kind));
  const workloads = items.filter(i => K8S_WORKLOAD_KINDS.has(i.kind));

  const addItem = (kind, name, notes) => {
    const tpl = templates[kind];
    if (!tpl) return null;
    const unique = uniqueName(kind, name);
    const obj = k8sDeepReplace(JSON.parse(JSON.stringify(tpl.object)),
                               {__NAME__: unique, __NAMESPACE__: namespace});
    const item = {uid: null, kind, name: unique, obj, node: null, auto: true,
                  notes: notes && notes.length ? notes : (tpl.note ? [tpl.note] : [])};
    items.push(item);
    return item;
  };

  // --- ServiceAccounts: one per workload unless one is drawn next to it.
  workloads.forEach(w => {
    const drawn = neighboursOfKind(w.uid, new Set(['serviceaccount']))[0];
    let sa = drawn;
    if (!sa) sa = addItem('serviceaccount', w.name, [`Identity for ${w.kind} "${w.name}".`]);
    w.serviceAccount = sa;
    k8sPodSpec(w.obj).serviceAccountName = sa.name;
  });

  // --- Services select the workload they are connected to.
  const serviceFor = new Map();    // workload name -> Service item
  items.filter(i => i.kind === 'service').forEach(s => {
    const targets = neighboursOfKind(s.uid, K8S_WORKLOAD_KINDS);
    if (targets.length) {
      s.target = targets[0];
      s.obj.spec.selector = {'app.kubernetes.io/name': targets[0].name};
      if (!serviceFor.has(targets[0].name)) serviceFor.set(targets[0].name, s);
      if (targets.length > 1) s.notes.push(`TODO: connected to ${targets.length} workloads; it selects "${targets[0].name}" only.`);
    } else {
      s.notes.push('TODO: no workload connected on the diagram; set spec.selector to your pods\' labels.');
    }
  });

  // A workload that receives traffic (from an Ingress, a route, or another
  // workload) or is a StatefulSet needs a Service; create one if none is drawn.
  const receivesTraffic = w => diagramEdges.some(e => {
    if (e.to !== w.uid) return false;
    const src = byUid.get(e.from);
    return src && (K8S_WORKLOAD_KINDS.has(src.kind) || K8S_ENTRY_KINDS.has(src.kind));
  }) || items.some(i => K8S_ENTRY_KINDS.has(i.kind) && neighbours(i.uid).includes(w));
  workloads.forEach(w => {
    if (serviceFor.has(w.name)) return;
    if (!(receivesTraffic(w) || w.kind === 'statefulset')) return;
    const s = addItem('service', w.name, [`Created for ${w.kind} "${w.name}", which receives traffic on the diagram.`]);
    if (!s) return;
    s.target = w;
    s.obj.spec.selector = {'app.kubernetes.io/name': w.name};
    if (w.kind === 'statefulset') s.obj.spec.clusterIP = 'None';
    serviceFor.set(w.name, s);
  });
  workloads.filter(w => w.kind === 'statefulset' && serviceFor.has(w.name))
    .forEach(w => { w.obj.spec.serviceName = serviceFor.get(w.name).name; });

  const serviceNear = uid => {
    const svc = neighboursOfKind(uid, new Set(['service']))[0];
    if (svc) return svc;
    const w = neighboursOfKind(uid, K8S_WORKLOAD_KINDS)[0];
    return w ? serviceFor.get(w.name) : null;
  };

  // --- Ingress and HTTPRoute backends; routes attach to gateways.
  items.filter(i => i.kind === 'ingress').forEach(ing => {
    const svc = serviceNear(ing.uid);
    const backend = ing.obj.spec.rules[0].http.paths[0].backend.service;
    if (svc) backend.name = svc.name;
    else ing.notes.push('TODO: no Service or workload connected; set the backend Service name.');
  });
  items.filter(i => i.kind === 'httproute').forEach(route => {
    const svc = serviceNear(route.uid);
    if (svc) route.obj.spec.rules[0].backendRefs[0].name = svc.name;
    else route.notes.push('TODO: no Service or workload connected; set backendRefs.');
    const gw = neighboursOfKind(route.uid, new Set(['gateway']))[0]
      || (items.filter(i => i.kind === 'gateway').length === 1 ? items.find(i => i.kind === 'gateway') : null);
    if (gw) route.obj.spec.parentRefs[0].name = gw.name;
    else route.notes.push('TODO: no Gateway connected; set parentRefs to your Gateway.');
  });

  // --- ConfigMaps, Secrets and volume claims used by workloads.
  workloads.forEach(w => {
    const pod = k8sPodSpec(w.obj);
    const container = pod.containers[0];
    neighbours(w.uid).forEach(other => {
      if (other.kind === 'configmap' || other.kind === 'secret') {
        container.envFrom = container.envFrom || [];
        const ref = other.kind === 'configmap' ? 'configMapRef' : 'secretRef';
        container.envFrom.push({[ref]: {name: other.name}});
      } else if (other.kind === 'persistentvolumeclaim') {
        pod.volumes.push({name: other.name, persistentVolumeClaim: {claimName: other.name}});
        container.volumeMounts.push({name: other.name, mountPath: `/mnt/${other.name}`});
      }
    });
  });

  // --- Autoscalers and disruption budgets target the connected workload.
  items.filter(i => i.kind === 'horizontalpodautoscaler').forEach(hpa => {
    const near = neighboursOfKind(hpa.uid, K8S_SCALABLE_KINDS)[0];
    const only = workloads.filter(w => K8S_SCALABLE_KINDS.has(w.kind));
    const target = near || (only.length === 1 ? only[0] : null);
    if (target) {
      hpa.obj.spec.scaleTargetRef = {apiVersion: 'apps/v1', kind: target.obj.kind, name: target.name};
      // The autoscaler owns the replica count from here on.
      delete target.obj.spec.replicas;
    } else {
      hpa.notes.push('TODO: connect it to a Deployment or StatefulSet; scaleTargetRef is a placeholder.');
    }
  });
  items.filter(i => i.kind === 'poddisruptionbudget').forEach(pdb => {
    const target = neighboursOfKind(pdb.uid, K8S_WORKLOAD_KINDS)[0];
    if (target) pdb.obj.spec.selector.matchLabels = {'app.kubernetes.io/name': target.name};
    else pdb.notes.push('TODO: connect it to a workload; the selector is a placeholder.');
  });

  // --- RoleBindings: role and subject from the diagram.
  items.filter(i => i.kind === 'rolebinding').forEach(rb => {
    const role = neighboursOfKind(rb.uid, new Set(['role']))[0];
    if (role) rb.obj.roleRef.name = role.name;
    else rb.notes.push('TODO: connect it to a Role; roleRef is a placeholder.');
    const sa = neighboursOfKind(rb.uid, new Set(['serviceaccount']))[0]
      || (neighboursOfKind(rb.uid, K8S_WORKLOAD_KINDS)[0] || {}).serviceAccount;
    if (sa) rb.obj.subjects[0].name = sa.name;
    else rb.notes.push('TODO: connect it to a ServiceAccount or workload; the subject is a placeholder.');
  });

  // --- NetworkPolicies: default deny, then allow what the arrows show.
  if (!items.some(i => i.kind === 'networkpolicy')) {
    addItem('networkpolicy', 'default-deny', []);
  }
  const workloadBehind = item => (K8S_WORKLOAD_KINDS.has(item.kind) ? item
    : item.kind === 'service' ? item.target : null);
  const allowFrom = new Map();    // target workload name -> {target, peers: Map}
  diagramEdges.forEach(e => {
    const src = byUid.get(e.from), dst = byUid.get(e.to);
    if (!src || !dst) return;
    const target = workloadBehind(dst);
    if (!target) return;
    let peer = null;
    if (K8S_WORKLOAD_KINDS.has(src.kind)) {
      if (src === target) return;
      peer = {key: 'pod:' + src.name, rule: {podSelector: {matchLabels: {'app.kubernetes.io/name': src.name}}}};
    } else if (K8S_ENTRY_KINDS.has(src.kind)) {
      peer = {key: 'ingress', rule: {namespaceSelector: {matchLabels:
        {'kubernetes.io/metadata.name': K8S_INGRESS_CONTROLLER_NS}}}};
    } else return;
    if (!allowFrom.has(target.name)) allowFrom.set(target.name, {target, peers: new Map()});
    allowFrom.get(target.name).peers.set(peer.key, peer);
  });
  // Entry objects drawn next to a workload/Service also send it traffic.
  items.filter(i => K8S_ENTRY_KINDS.has(i.kind)).forEach(entry => {
    const svc = serviceNear(entry.uid);
    const target = svc && workloadBehind(svc);
    if (!target) return;
    if (!allowFrom.has(target.name)) allowFrom.set(target.name, {target, peers: new Map()});
    allowFrom.get(target.name).peers.set('ingress', {rule: {namespaceSelector: {matchLabels:
      {'kubernetes.io/metadata.name': K8S_INGRESS_CONTROLLER_NS}}}});
  });
  allowFrom.forEach(({target, peers}) => {
    const np = addItem('networkpolicy', `allow-to-${target.name}`, [
      `Lets the traffic the diagram shows reach "${target.name}" on its http port.`]);
    if (!np) return;
    np.obj.spec.podSelector = {matchLabels: {'app.kubernetes.io/name': target.name}};
    np.obj.spec.ingress = [{
      from: [...peers.values()].map(p => p.rule),
      ports: [{protocol: 'TCP', port: 'http'}],
    }];
    if (peers.has('ingress')) {
      np.notes.push(`Assumes the ingress controller runs in the "${K8S_INGRESS_CONTROLLER_NS}" namespace; change it if yours differs.`);
    }
  });

  // ------------------------------------------------------------ output
  const nsTpl = templates.namespace;
  const docs = [];
  if (nsTpl) {
    docs.push({kind: 'namespace', notes: [nsTpl.note], obj: k8sDeepReplace(
      JSON.parse(JSON.stringify(nsTpl.object)), {__NAME__: namespace, __NAMESPACE__: namespace})});
  }
  const rank = k => { const i = K8S_ORDER.indexOf(k); return i === -1 ? 999 : i; };
  items.slice().sort((a, b) => rank(a.kind) - rank(b.kind)).forEach(i => docs.push(i));

  const out = [];
  out.push('# Generated by ArchLens from a diagram on ' + new Date().toISOString().slice(0, 10) + '.');
  out.push('#');
  out.push('# Sample Kubernetes manifests, not a finished deployment:');
  out.push('#   - Secure defaults: non-root, read-only filesystem, no Linux capabilities,');
  out.push('#     seccomp, resource requests and limits, probes, TLS, one ServiceAccount');
  out.push('#     per workload and a default-deny NetworkPolicy.');
  out.push('#   - Images, ports, hosts and sizes are examples. Replace them.');
  out.push('#   - Diagram arrows become Service selectors, Ingress backends, mounts,');
  out.push('#     autoscaler targets and NetworkPolicy allow rules.');
  out.push('#   - Anything not generated is listed as a TODO at the end.');
  out.push(`#\n# Apply with:  kubectl apply -f archlens-diagram.yaml`);

  docs.forEach(d => {
    out.push('---');
    (d.notes || []).filter(Boolean).forEach(note => out.push('# ' + note));
    out.push(k8sToYaml(d.obj));
  });

  if (todoKinds.length || external.length) out.push('---');
  if (todoKinds.length) {
    out.push('# ---- Kubernetes objects with no ArchLens template yet ----');
    todoKinds.forEach(n => out.push(`#   - "${n.name}" (${n.service})`));
  }
  if (external.length) {
    out.push('# ---- Outside the cluster ----');
    out.push('# Managed services and tools on the diagram are not Kubernetes objects.');
    out.push('# Create them with Terraform (Export Terraform) and pass their endpoints');
    out.push('# to the workloads through a ConfigMap or Secret:');
    external.forEach(n => out.push(`#   - "${n.name}" (${n.provider} ${n.service})`));
  }
  out.push('');
  return {yaml: out.join('\n'), generated: docs.length};
}

function exportDiagramAsKubernetes() {
  if (!kubernetesExportableNodes(nodes).length) return;
  const {yaml} = buildKubernetesExport(nodes, edges);
  const blob = new Blob([yaml], {type: 'text/yaml'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'archlens-diagram.yaml';
  a.click();
  URL.revokeObjectURL(url);
}

if (typeof module !== 'undefined') {
  module.exports = {buildKubernetesExport, kubernetesExportableNodes, k8sToYaml};
}
