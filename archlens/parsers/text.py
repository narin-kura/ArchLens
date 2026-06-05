"""Text parser — uses Claude API to extract architecture from plain-English descriptions."""

from __future__ import annotations
import json
from pathlib import Path

from .base import BaseParser
from ..models.architecture import ArchitectureModel, Component, ComponentType


class TextParser(BaseParser):
    def can_parse(self, source: str | Path) -> bool:
        p = Path(source)
        if p.exists():
            return p.suffix in {".txt", ".md"}
        # Treat raw strings as text input
        return isinstance(source, str) and not Path(source).exists()

    def parse(self, source: str | Path) -> ArchitectureModel:
        p = Path(source)
        text = p.read_text(encoding="utf-8") if p.exists() else str(source)
        return self._parse_with_llm(text)

    def _parse_with_llm(self, text: str) -> ArchitectureModel:
        try:
            import anthropic
        except ImportError:
            raise ImportError("Install anthropic: pip install anthropic")

        client = anthropic.Anthropic()
        prompt = f"""Extract the architecture components from this description and return JSON only.

Description:
{text}

Return this exact JSON structure:
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

        message = client.messages.create(
            model="claude-opus-4-8",
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = message.content[0].text.strip()
        # Strip markdown code fences if present
        if raw.startswith("```"):
            raw = "\n".join(raw.split("\n")[1:])
            raw = raw.rsplit("```", 1)[0]

        data = json.loads(raw)
        return self._dict_to_model(data)

    def _dict_to_model(self, data: dict) -> ArchitectureModel:
        from ..models.architecture import Connection
        model = ArchitectureModel(name=data.get("name", "unnamed"), source="text")
        for c in data.get("components", []):
            model.components.append(Component(
                id=c["id"],
                name=c["name"],
                type=ComponentType(c.get("type", "other")),
                provider=c.get("provider", "generic"),
                service=c.get("service", ""),
                properties=c.get("properties", {}),
            ))
        for conn in data.get("connections", []):
            model.connections.append(Connection(
                source_id=conn["source_id"],
                target_id=conn["target_id"],
                label=conn.get("label", ""),
            ))
        return model
