"""Text parser — uses Gemini (primary) or Claude (fallback) to extract architecture."""

from __future__ import annotations
import json
import logging
import os
from pathlib import Path

from .base import BaseParser
from ..models.architecture import ArchitectureModel, Component, ComponentType, Connection

logger = logging.getLogger(__name__)

_PROMPT = """Extract the architecture components from this description and return JSON only.

Description:
{text}

Return this exact JSON structure with no extra text:
{{
  "name": "architecture name or 'unnamed'",
  "components": [
    {{
      "id": "unique_id",
      "name": "component name",
      "type": "compute|database|storage|network|iam|queue|cache|cdn|gateway|container|serverless|monitoring|other",
      "provider": "aws|gcp|azure|generic",
      "service": "specific service name e.g. ec2, s3, rds",
      "properties": {{}}
    }}
  ],
  "connections": [
    {{"source_id": "id1", "target_id": "id2", "label": "description"}}
  ]
}}"""


_ARCH_KEYWORDS = {
    # cloud providers
    "aws", "gcp", "azure", "amazon", "google cloud", "microsoft",
    # compute
    "ec2", "lambda", "function", "server", "instance", "vm", "virtual machine",
    "container", "docker", "kubernetes", "k8s", "pod", "cluster", "fargate", "ecs", "eks",
    "compute engine", "cloud run", "app engine",
    # database
    "database", " db ", "rds", "mysql", "postgres", "postgresql", "mongodb", "dynamodb",
    "redis", "elasticsearch", "cassandra", "aurora", "spanner", "firestore", "bigtable",
    "cloud sql", "sqlite",
    # storage
    "s3", " storage", "bucket", "blob", "gcs", "ebs", "efs",
    # network / gateway
    "vpc", "subnet", "load balancer", "alb", "elb", "nginx", "api gateway", "cdn",
    "cloudfront", "firewall", "nat gateway", "route53", "dns",
    # messaging / queue
    "queue", "kafka", "rabbitmq", "sqs", "sns", "pubsub", "message broker", "event",
    # tools / ci-cd
    "terraform", "ansible", "jenkins", "ci/cd", "pipeline", "deploy", "github actions",
    "gitlab", "helm", "ansible",
    # monitoring
    "cloudwatch", "datadog", "grafana", "prometheus", "monitoring", "logging",
    # general architecture terms
    "microservice", "api", "backend", "frontend", "architecture", "infrastructure",
    "service", "endpoint", "application", "web app", "mobile app", "iam", "role",
    "security group", "cache", "auto scaling", "serverless",
    # AI / ML
    "llm", "openai", "anthropic", "gemini", "gpt", "claude", "bedrock", "vertex ai",
    "sagemaker", "machine learning", "ml model", "neural network", "embedding",
    "vector database", "vector db", "pinecone", "weaviate", "chroma", "qdrant",
    "langchain", "llamaindex", "rag", "fine-tuning", "inference", "training",
    "hugging face", "ollama", "mlflow", "weights & biases", "wandb", "triton",
    "ai model", "language model", "generative ai", "chatbot", "ai pipeline",
}

_MIN_WORDS = 5

def _is_architecture_text(text: str) -> bool:
    lower = text.lower()
    words = lower.split()
    if len(words) < _MIN_WORDS:
        return False
    return any(kw in lower for kw in _ARCH_KEYWORDS)


def _strip_fences(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("```"):
        raw = "\n".join(raw.split("\n")[1:])
        raw = raw.rsplit("```", 1)[0]
    return raw.strip()


def _safe_component_type(raw: str) -> ComponentType:
    try:
        return ComponentType(raw.lower().strip())
    except ValueError:
        return ComponentType.OTHER


class TextParser(BaseParser):
    def can_parse(self, source: str | Path) -> bool:
        p = Path(source)
        if p.exists():
            return p.suffix in {".txt", ".md"}
        return isinstance(source, str) and not Path(source).exists()

    def parse(self, source: str | Path) -> ArchitectureModel:
        p = Path(source)
        text = p.read_text(encoding="utf-8") if p.exists() else str(source)
        if not text.strip():
            raise ValueError("Input text is empty. Please describe your architecture.")
        if not _is_architecture_text(text):
            raise ValueError(
                "This doesn't look like an architecture description. "
                "Please describe the services and infrastructure you use — for example: "
                "'We run a Python API on AWS EC2, a PostgreSQL RDS database, "
                "an S3 bucket for file storage, and CloudWatch for monitoring.'"
            )
        return self._parse_with_llm(text)

    def _parse_with_llm(self, text: str) -> ArchitectureModel:
        gemini_key = os.getenv("GEMINI_API_KEY")
        anthropic_key = os.getenv("ANTHROPIC_API_KEY")

        if not gemini_key and not anthropic_key:
            raise ValueError(
                "Text analysis requires an API key. "
                "Set GEMINI_API_KEY (free tier available at aistudio.google.com) "
                "or ANTHROPIC_API_KEY in your environment."
            )

        if gemini_key:
            try:
                return self._parse_gemini(text, gemini_key)
            except Exception:
                if anthropic_key:
                    return self._parse_anthropic(text, anthropic_key)
                raise
        return self._parse_anthropic(text, anthropic_key)

    def _parse_gemini(self, text: str, api_key: str) -> ArchitectureModel:
        try:
            import google.generativeai as genai
        except ImportError:
            raise ImportError("Install google-generativeai: pip install google-generativeai")

        # REST transport: default gRPC channels hang silently on Cloud Run's gVisor sandbox
        genai.configure(api_key=api_key, transport="rest")
        model = genai.GenerativeModel("gemini-2.5-flash")
        try:
            response = model.generate_content(
                _PROMPT.format(text=text),
                request_options={"timeout": 30},
            )
            raw = _strip_fences(response.text)
        except Exception as exc:
            logger.exception("Gemini text parse failed")
            raise ValueError(f"Gemini API error: {exc}") from exc

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            raise ValueError(
                "Could not parse the AI response. Try rephrasing your description "
                "with clear component names (e.g. 'EC2 instance', 'RDS database')."
            )
        return self._dict_to_model(data)

    def _parse_anthropic(self, text: str, api_key: str) -> ArchitectureModel:
        try:
            import anthropic
        except ImportError:
            raise ImportError("Install anthropic: pip install anthropic")

        client = anthropic.Anthropic(api_key=api_key, timeout=30.0, max_retries=1)
        try:
            message = client.messages.create(
                model="claude-opus-4-8",
                max_tokens=2048,
                messages=[{"role": "user", "content": _PROMPT.format(text=text)}],
            )
            raw = _strip_fences(message.content[0].text)
        except Exception as exc:
            logger.exception("Anthropic text parse failed")
            raise ValueError(f"Anthropic API error: {exc}") from exc

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            raise ValueError(
                "Could not parse the AI response. Try rephrasing your description "
                "with clear component names (e.g. 'EC2 instance', 'RDS database')."
            )
        return self._dict_to_model(data)

    def _dict_to_model(self, data: dict) -> ArchitectureModel:
        model = ArchitectureModel(name=data.get("name", "unnamed"), source="text")
        for c in data.get("components", []):
            try:
                model.components.append(Component(
                    id=c.get("id", c.get("name", "unknown")),
                    name=c.get("name", "unknown"),
                    type=_safe_component_type(c.get("type", "other")),
                    provider=c.get("provider", "generic"),
                    service=c.get("service", ""),
                    properties=c.get("properties", {}),
                ))
            except Exception:
                continue  # skip malformed component entries
        for conn in data.get("connections", []):
            try:
                model.connections.append(Connection(
                    source_id=conn["source_id"],
                    target_id=conn["target_id"],
                    label=conn.get("label", ""),
                ))
            except Exception:
                continue
        return model
