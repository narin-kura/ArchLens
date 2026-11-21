# Kubernetes templates for the diagram's "Export Kubernetes" button

One file per Kubernetes kind. The diagram export copies the template for each
Kubernetes node on the canvas, fills in the placeholders and connects objects
using the diagram's arrows (Service selectors, Ingress and route backends,
NetworkPolicy rules, mounts, autoscaler and budget targets, role bindings).

Placeholders:

- `__NAME__`: the node's name on the diagram, made DNS-safe
- `__NAMESPACE__`: the Namespace node's name, or `app` if none is drawn

The leading `# ` comment line becomes the note printed above the object in the
exported file. Keep every template passing ArchLens's own checks:
`tests/test_k8s_export.py` exports a diagram that uses every template and
fails if the analysis finds anything.

After editing, regenerate the browser copy:

    python scripts/gen_k8s_templates.py
