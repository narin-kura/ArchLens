"""Auto-detect the right parser from source type."""

from __future__ import annotations
from pathlib import Path

from .base import BaseParser
from .terraform import TerraformParser
from .text import TextParser
from .drawio import DrawioParser
from .cloudformation import CloudFormationParser
from .aws_config import AWSConfigParser
from .gcp_asset import GCPAssetParser


# Order matters: more specific parsers first, text (LLM) last as fallback
_PARSERS: list[BaseParser] = [
    TerraformParser(),
    DrawioParser(),
    CloudFormationParser(),
    AWSConfigParser(),
    GCPAssetParser(),
    TextParser(),
]


def detect_parser(source: str, format_hint: str | None = None) -> BaseParser:
    if format_hint:
        mapping = {
            "terraform": TerraformParser(),
            "drawio": DrawioParser(),
            "cloudformation": CloudFormationParser(),
            "aws_config": AWSConfigParser(),
            "gcp_asset": GCPAssetParser(),
            "text": TextParser(),
        }
        if format_hint in mapping:
            return mapping[format_hint]

    for parser in _PARSERS:
        if parser.can_parse(source):
            return parser

    raise ValueError(f"Could not detect input format for: {source}")
