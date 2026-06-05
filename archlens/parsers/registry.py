"""Auto-detect the right parser from source type."""

from __future__ import annotations
from pathlib import Path

from .base import BaseParser
from .terraform import TerraformParser
from .text import TextParser


_PARSERS: list[BaseParser] = [
    TerraformParser(),
    TextParser(),
    # DrawioParser(),       — add when implemented
    # CloudExportParser(),  — add when implemented
]


def detect_parser(source: str, format_hint: str | None = None) -> BaseParser:
    if format_hint:
        mapping = {
            "terraform": TerraformParser(),
            "text": TextParser(),
        }
        if format_hint in mapping:
            return mapping[format_hint]

    for parser in _PARSERS:
        if parser.can_parse(source):
            return parser

    raise ValueError(f"Could not detect input format for: {source}")
