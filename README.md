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

## Run locally

```bash
pip install -r requirements.txt
uvicorn web.app:app --host 0.0.0.0 --port 8000
# Open http://localhost:8000
```
