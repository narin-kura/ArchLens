"""Base analyzer interface — all analyzers implement this."""

from __future__ import annotations
from abc import ABC, abstractmethod

from ..models.architecture import ArchitectureModel
from ..models.findings import Finding


class BaseAnalyzer(ABC):
    @abstractmethod
    def analyze(self, model: ArchitectureModel) -> list[Finding]:
        """Analyze the model and return a list of findings."""
