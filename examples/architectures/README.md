# AWS reference architectures

Sixteen complete, valid Terraform architectures covering the whole AWS service
catalogue, built to be analysed by ArchLens. Between them they use **238
distinct AWS resource types** across ~8,600 lines of HCL.

They are the counterpart to [`examples/terraform/main.tf`](../terraform/main.tf),
which is deliberately insecure. These are deliberately *correct*: every store is
encrypted with a customer-managed key, nothing stateful is reachable from the
internet, every queue has a dead-letter path, and every bucket has versioning,
Block Public Access and a lifecycle policy. Upload one and the report should come
back clean — that is the point. If a change to an analyzer starts producing
findings here, the analyzer is probably wrong.

## Running them

```bash
# One architecture
python -m archlens.cli examples/architectures/01-three-tier-web-app

# All of them
for d in examples/architectures/*/; do python -m archlens.cli "$d"; done
```

In the web app, upload the `main.tf` file directly. Each directory holds exactly
one file so the Terraform parser sees one architecture at a time.

## The architectures

| # | Architecture | What it demonstrates | Headline services |
|---|---|---|---|
| 01 | [three-tier-web-app](01-three-tier-web-app/) | The classic public web stack, each tier isolated | CloudFront, WAF, ALB, EC2 Auto Scaling, RDS Multi-AZ, ElastiCache, S3, KMS, CloudTrail, GuardDuty |
| 02 | [serverless-api](02-serverless-api/) | Pay-per-request API with async work off the request path | API Gateway (HTTP), Lambda, DynamoDB, SQS, SNS, EventBridge, Step Functions, Cognito, X-Ray |
| 03 | [static-site-cdn](03-static-site-cdn/) | Cheapest possible front end, private origin | S3, CloudFront + OAC, CloudFront Functions, ACM, Route 53, WAF, Budgets |
| 04 | [ecs-microservices](04-ecs-microservices/) | Services that talk through events, not direct calls | ECS Fargate, ECR, Cloud Map, internal ALB, EventBridge, SQS, DynamoDB, ElastiCache Serverless |
| 05 | [eks-platform](05-eks-platform/) | A Kubernetes platform other teams build on | EKS, managed node groups, Fargate profiles, IRSA, EFS, Network Firewall, Managed Prometheus/Grafana |
| 06 | [data-lake-analytics](06-data-lake-analytics/) | Medallion data lake with governed access | S3 tiering, Glue, Lake Formation, Athena, EMR Serverless, Redshift Serverless, QuickSight, MWAA, DataZone |
| 07 | [streaming-realtime](07-streaming-realtime/) | One ingest path, several serving shapes | Kinesis, Data Firehose, Managed Flink, MSK Serverless, Timestream, OpenSearch, DynamoDB |
| 08 | [ml-genai-platform](08-ml-genai-platform/) | Custom-model training beside a guard-railed RAG stack | SageMaker (domain, endpoint, Feature Store), Bedrock (knowledge base, agent, guardrail), OpenSearch Serverless |
| 09 | [multi-region-dr](09-multi-region-dr/) | Failover as a DNS change, not a restore project | Aurora Global Database, DynamoDB Global Tables, S3 CRR, Route 53 failover, Backup cross-region copy |
| 10 | [iot-edge-telemetry](10-iot-edge-telemetry/) | Per-device identity and logic that survives a WAN outage | IoT Core, Greengrass, Device Defender, SiteWise, TwinMaker, FleetWise, Timestream |
| 11 | [media-streaming](11-media-streaming/) | Live and VOD delivery sharing one CDN | MediaLive, MediaPackage, MediaConvert, MediaTailor, MediaConnect, IVS, Deadline Cloud, signed URLs |
| 12 | [security-governance-baseline](12-security-governance-baseline/) | The controls that belong in an account before any workload | Organizations, Control Tower, org CloudTrail, Config, Security Hub, GuardDuty, Macie, Inspector, Security Lake |
| 13 | [cicd-pipeline](13-cicd-pipeline/) | Build once, promote the same artefact | CodePipeline, CodeBuild in-VPC, CodeDeploy canary, CodeArtifact, Signer, Fault Injection Service |
| 14 | [migration-hybrid](14-migration-hybrid/) | Landing zone for a data-centre migration | DMS CDC, MGN, DRS, DataSync, Transfer Family, Storage Gateway, Direct Connect, Transit Gateway, Cloud WAN |
| 15 | [workforce-apps](15-workforce-apps/) | Internal desktops and the customer contact centre | Directory Service, WorkSpaces, AppStream, FSx for Windows, Connect, Lex, SES, Pinpoint, Chime SDK |
| 16 | [batch-hpc-gaming](16-batch-hpc-gaming/) | Three workloads that all care about cost per core | AWS Batch on Spot, FSx for Lustre, EFS, GameLift, Braket, Cognito, API Gateway |

## Expected findings

Fourteen of the sixteen report nothing. Two report findings on purpose, because
the alternative would be to write something less realistic:

- **01** — the public ALB security group allows `0.0.0.0/0` on 443. That is what
  a public web tier is. The log-archive bucket also has no access logging of its
  own, because pointing a log bucket at itself creates a feedback loop.
- **05** — EKS worker nodes have unrestricted egress. Nodes must reach container
  registries; the architecture puts AWS Network Firewall in that path rather
  than pretending the requirement does not exist.

Both are worth a reviewer's attention, which is why they are left in rather than
suppressed.

## Catalogue coverage

The builder's service list (`web/static/catalog_aws.js`) holds every AWS product,
grouped by AWS's own categories. Each group maps to at least one architecture:

| Catalogue group | Architectures |
|---|---|
| Compute, Containers | 01, 04, 05, 13, 16 |
| Storage | 01, 05, 06, 11, 14, 16 |
| Database | 01, 02, 06, 07, 09 |
| Networking & Content Delivery | 01, 03, 05, 14 |
| Analytics | 06, 07 |
| Application Integration | 02, 04 |
| Machine Learning & AI | 08, 15 |
| Security, Identity & Compliance | 12, 01, 02 |
| Management & Governance | 12, 05 |
| Developer Tools | 13 |
| Migration & Modernization | 14 |
| Media Services | 11 |
| Internet of Things | 10 |
| End User Computing, Business Applications | 15 |
| Games, Quantum | 16 |
| Cloud Financial Management | 03, 06, 08, 15 (Budgets) |
| Customer Enablement | — console and support services; no infrastructure to declare |

Some catalogued products have no Terraform resource at all — AWS Support,
Trusted Advisor, re:Post, Training, Marketplace, Cost Explorer, Artifact and the
retired services marked `LEGACY` in the builder. They are listed so the catalogue
is complete, and they are absent here for the same reason: there is nothing to
declare.

## Adding one

Keep to the conventions above and the examples stay useful as a regression
suite:

1. One directory, one `main.tf`, with a header comment stating the pattern, the
   services it covers, and the findings you expect.
2. Real Terraform only. If ArchLens misses a control, fix the parser or the
   analyzer — never invent an attribute that the AWS provider does not have.
3. Run it before committing. A new finding here means either the example or the
   analyzer needs work.
