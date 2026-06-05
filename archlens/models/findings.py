"""Finding model — output of security and cost analyzers."""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(str, Enum):
    SECURITY = "security"
    COST = "cost"


@dataclass
class Finding:
    type: FindingType
    severity: Severity
    title: str
    description: str
    component_id: str = ""
    component_name: str = ""
    recommendation: str = ""
    estimated_savings: float = 0.0   # monthly USD, cost findings only
    references: list[str] = field(default_factory=list)


@dataclass
class AnalysisReport:
    architecture_name: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def security_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.type == FindingType.SECURITY]

    @property
    def cost_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.type == FindingType.COST]

    @property
    def total_estimated_savings(self) -> float:
        return sum(f.estimated_savings for f in self.cost_findings)

    def by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]
