# ArchLens Roadmap

This file tracks feature ideas and future work for ArchLens. Items are organised by priority tier. Use this as input when creating GitHub Issues or Project cards.

---

## Tier 1 — High Priority

### Multi-cloud connection mapping
**Idea:** Automatically infer connections between resources (e.g. Lambda → RDS, EC2 → S3) from IaC/config metadata rather than requiring explicit edges.  
**Value:** Richer visual and risk context; enables path-based attack surface analysis.

### Risk score summary card
**Idea:** Show a single 0–100 risk score in the results header, computed from severity weighting of all findings.  
**Value:** Gives executives / non-technical stakeholders an instant signal.

### Remediation code snippets
**Idea:** For each finding, generate a small code snippet (Terraform / CFN) showing the exact fix.  
**Value:** Saves engineers time looking up correct syntax; makes ArchLens actionable not just advisory.

### Kubernetes YAML parser
**Idea:** Parse k8s manifests (Deployment, Service, NetworkPolicy, RBAC) to detect missing resource limits, privileged containers, wildcard RBAC.  
**Value:** Highly requested cloud input; completes the container security story.

---

## Tier 2 — Medium Priority

### ARM Template parser (Azure)
**Idea:** Read Azure Resource Manager JSON templates, similar to CloudFormation parser.  
**Value:** Completes the big-three cloud coverage (AWS/GCP already covered).

### Pulumi support
**Idea:** Parse Pulumi state files (`pulumi stack export`) or Python/TypeScript program ASTs.  
**Value:** Growing Pulumi adoption; currently no IaC tool covers it well.

### Historical diff view (Pro tier)
**Idea:** Let users upload two versions of the same architecture and highlight new/removed risks.  
**Value:** Track security posture improvement over time. Requires storage — paid tier feature.

### Shareable report link (Pro tier)
**Idea:** After analysis, generate a short-lived URL that renders the report for others without re-uploading.  
**Value:** Enables team collaboration. Requires storage + auth — paid tier feature.

### GitHub Action integration
**Idea:** Publish an official `archlens-action` that runs analysis on IaC changes in PRs and posts findings as PR comments.  
**Value:** Shift-left security; engineers get feedback at PR time before merge.

---

## Tier 3 — Future / Exploratory

### VS Code extension
**Idea:** Run ArchLens inline as a VS Code extension; highlight risky resources in the editor.  
**Value:** True shift-left; developers get live feedback while writing IaC.

### Compliance mapping
**Idea:** Map findings to compliance frameworks (CIS Benchmarks, SOC 2, PCI-DSS, HIPAA) so each finding shows which controls it violates.  
**Value:** High value for regulated industries; differentiates from generic scanners.

### Cost savings estimator (cloud pricing API)
**Idea:** Pull live pricing from AWS/GCP APIs instead of static tables to give accurate estimated savings figures.  
**Value:** More credible cost findings; currently uses hardcoded pricing tables.

### Team workspace (Paid tier)
**Idea:** Shared login, shared analysis history, team-level risk dashboard.  
**Value:** Enterprise monetization path. Requires OAuth (GitHub/Google) + PostgreSQL.

### Architecture chat (LLM Q&A)
**Idea:** After analysis, allow follow-up questions: "Why is this a risk?" / "What's the cheapest way to fix this?" answered by the LLM in context of the uploaded architecture.  
**Value:** Turns ArchLens from a scanner into an interactive architecture advisor.

---

## Completed

- [x] Terraform parser
- [x] Plain text / AI description parser (Gemini primary, Anthropic fallback)
- [x] draw.io XML parser
- [x] CloudFormation YAML/JSON parser
- [x] AWS Config JSON export parser
- [x] GCP Asset Inventory JSON parser
- [x] Security analyzer (public storage, unencrypted DB, wildcard IAM, open SG, no monitoring)
- [x] Cost analyzer (oversized RDS, NAT Gateway, auto-scaling, reserved instances hint)
- [x] JSON + Markdown report download (client-side, no server storage)
- [x] Stateless architecture (temp files, no user data stored)
- [x] Hugging Face Spaces deployment (Docker, port 7860)
- [x] GitHub Actions CI/CD with HF auto-deploy + retry logic
