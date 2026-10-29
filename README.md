---
title: ArchLens
emoji: 🔍
colorFrom: blue
colorTo: indigo
sdk: docker
pinned: false
---

# ArchLens 🔍

[![Website](https://img.shields.io/badge/Coming%20Soon-archlens.vigyatri.com-blue?style=flat-square&logo=google-chrome)](https://archlens.vigyatri.com)
[![Hugging Face](https://img.shields.io/badge/Mirror-Hugging%20Face-gray?style=flat-square&logo=huggingface)](https://knnarin-archlens.hf.space)
[![Google Cloud Run](https://img.shields.io/badge/Powered%20by-GCP%20Cloud%20Run-gray?style=flat-square&logo=google-cloud)](https://archlens-h5axc6napq-uc.a.run.app/)

Architecture security & cost analyzer. Upload a Terraform file or describe your architecture in plain English — get back security risks and cost savings recommendations instantly.

## Features

- Parses Terraform (.tf) files
- Accepts plain-text architecture descriptions (uses Claude AI)
- Detects security risks (public storage, unencrypted DBs, open ports, missing monitoring)
- Identifies cost optimizations (oversized instances, NAT Gateway vs VPC endpoints, missing auto-scaling)
- Draw your architecture on a canvas — palette on the left, nodes and connections on the right — and the
  connections are analysed too: an internet-facing entry point wired straight into a database, a CDN
  origin that can be read directly, a function reaching a data store from outside its VPC

## Run locally

```bash
pip install -r requirements.txt
uvicorn web.app:app --host 0.0.0.0 --port 8000
# Open http://localhost:8000
```

## Pages

| Route | What it is |
|---|---|
| `/` | Home — what ArchLens does and the four ways in |
| `/analyze` | Upload a config, describe it in text, or get a stack recommended |
| `/diagram` | Full-screen canvas: drag services, connect them, analyse the topology |
| `/examples` | The 64 bundled reference architectures (AWS, Azure, GCP, Oracle Cloud), analysed in one click |

Front-end assets live in `web/static/css/` and `web/static/js/` — one shared
`app.css`, and JS split by concern (`canvas.js`, `report.js`, `suggestions.js`,
`analyze.js`, `recommend.js`, `services.js`, `terraform-export.js`, and one
`catalog_*.js` per platform).

## Examples

- Sixteen complete reference architectures per cloud, each written to pass a
  clean analysis (three-tier web, serverless API, static site, containers /
  Kubernetes, data lake, streaming, ML/GenAI, multi-region DR, IoT, media,
  governance baseline, CI/CD, migration/hybrid, workforce apps, batch/HPC):
  [`architectures/`](examples/architectures/) (AWS),
  [`architectures-azure/`](examples/architectures-azure/),
  [`architectures-gcp/`](examples/architectures-gcp/) and
  [`architectures-oracle/`](examples/architectures-oracle/). Every attribute in
  the Oracle set is checked against the `oracle/oci` provider docs.
- [`examples/terraform/main.tf`](examples/terraform/main.tf) — the opposite: a
  small, deliberately insecure stack for demoing what the report looks like.

## Service catalog

The diagram builder's palette lists every product of each platform, grouped
by that platform's own categories (retired ones are kept and flagged
`legacy`). Where a Terraform resource exists, an entry's `service` is the real
resource type, so a drawn node and a parsed `.tf` file go through the same
checks — and the diagram's **Export Terraform** can emit a real resource block.

| Platform | File | Notes |
|---|---|---|
| AWS | `catalog_aws.js` | `aws_*` types |
| Azure | `catalog_azure.js` | `azurerm_*` / `azuread_*` types |
| GCP | `catalog_gcp.js` | `google_*` types |
| Oracle Cloud | `catalog_oracle.js` | `oci_*` types, each checked against the provider's resource list |
| Kubernetes | `catalog_kubernetes.js` | every built-in kind + Gateway API + common CRDs; generated from `archlens/parsers/k8s_kinds.py` |
| Docker | `catalog_docker.js` | Compose objects, `kreuzwerker/docker` types, Docker products |
| On-premises | `catalog_onprem.js` | vSphere, OpenStack, Nutanix, Proxmox VE + physical gear; generated from `archlens/parsers/onprem_resources.py` |

## Tests

```bash
python -m pytest tests -q
```

`tests/test_reference_architectures.py` runs every reference architecture and
fixture and requires the finding counts in `tests/baseline.json`; after an
intended analyzer change, run `python tests/test_reference_architectures.py
--update` and review the diff. `tests/test_generated_catalogs.py` fails if a
generated catalog drifts from its source module.
