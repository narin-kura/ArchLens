"""Base parser interface — all parsers implement this."""

from __future__ import annotations
from abc import ABC, abstractmethod
from pathlib import Path

from ..models.architecture import ArchitectureModel


class BaseParser(ABC):
    @abstractmethod
    def can_parse(self, source: str | Path) -> bool:
        """Return True if this parser can handle the given source."""

    @abstractmethod
    def parse(self, source: str | Path) -> ArchitectureModel:
        """Parse source into a normalized ArchitectureModel."""
