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
| `/examples` | The 16 bundled reference architectures, analysed in one click |

Front-end assets live in `web/static/css/` and `web/static/js/` — one shared
`app.css`, and JS split by concern (`canvas.js`, `report.js`, `suggestions.js`,
`analyze.js`, `recommend.js`, `services.js`, `catalog_aws.js`).

## Examples

- [`examples/architectures/`](examples/architectures/) — sixteen complete AWS
  reference architectures (three-tier web, serverless API, EKS platform, data
  lake, streaming, ML/GenAI, multi-region DR, IoT, media, governance baseline,
  CI/CD, migration, workforce apps, batch/HPC) written to pass a clean analysis.
  They double as the regression suite for the Terraform parser and the analyzers.
- [`examples/terraform/main.tf`](examples/terraform/main.tf) — the opposite: a
  small, deliberately insecure stack for demoing what the report looks like.

The interactive builder's AWS service list lives in
[`web/static/catalog_aws.js`](web/static/catalog_aws.js) and covers every AWS
product, grouped by AWS's own product categories.
