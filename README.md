---
title: ArchLens
emoji: 🔍
colorFrom: blue
colorTo: indigo
sdk: docker
pinned: false
---

# ArchLens

[![Hugging Face](https://img.shields.io/badge/Live%20App-Hugging%20Face-blue?style=flat-square&logo=huggingface)](https://knnarin-archlens.hf.space)
[![Google Cloud Run](https://img.shields.io/badge/Live%20App-GCP%20Cloud%20Run-blue?style=flat-square&logo=google-cloud)](https://archlens-982110430844.us-central1.run.app/)

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
