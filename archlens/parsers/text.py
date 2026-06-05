"""Text parser — uses Gemini (primary) or Claude (fallback) to extract architecture."""

from __future__ import annotations
import json
import os
from pathlib import Path

from .base import BaseParser
from ..models.architecture import ArchitectureModel, Component, ComponentType, Connection

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


def _strip_fences(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("```"):
        raw = "\n".join(raw.split("\n")[1:])
        raw = raw.rsplit("```", 1)[0]
    return raw.strip()


class TextParser(BaseParser):
    def can_parse(self, source: str | Path) -> bool:
        p = Path(source)
        if p.exists():
            return p.suffix in {".txt", ".md"}
        return isinstance(source, str) and not Path(source).exists()

    def parse(self, source: str | Path) -> ArchitectureModel:
        p = Path(source)
        text = p.read_text(encoding="utf-8") if p.exists() else str(source)
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
            return self._parse_gemini(text, gemini_key)
        return self._parse_anthropic(text, anthropic_key)

    # --- Gemini ---
    def _parse_gemini(self, text: str, api_key: str) -> ArchitectureModel:
        try:
            import google.generativeai as genai
        except ImportError:
            raise ImportError("Install google-generativeai: pip install google-generativeai")

        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(_PROMPT.format(text=text))
        data = json.loads(_strip_fences(response.text))
        return self._dict_to_model(data)

    # --- Anthropic ---
    def _parse_anthropic(self, text: str, api_key: str) -> ArchitectureModel:
        try:
            import anthropic
        except ImportError:
            raise ImportError("Install anthropic: pip install anthropic")

        client = anthropic.Anthropic(api_key=api_key)
        message = client.messages.create(
            model="claude-opus-4-8",
            max_tokens=2048,
            messages=[{"role": "user", "content": _PROMPT.format(text=text)}],
        )
        data = json.loads(_strip_fences(message.content[0].text))
        return self._dict_to_model(data)

    # --- Shared ---
    def _dict_to_model(self, data: dict) -> ArchitectureModel:
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
