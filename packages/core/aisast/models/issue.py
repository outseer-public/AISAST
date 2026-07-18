"""Security issue data model"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    """Issue severity levels"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def _missing_(cls, value):
        if isinstance(value, str):
            value = value.lower()
            if value == "informational":
                return cls.INFO
            for member in cls:
                if member.value == value:
                    return member
        return None


SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {name: idx for idx, name in enumerate(SEVERITY_ORDER)}


@dataclass
class SecurityIssue:
    """Represents a security vulnerability found in code"""

    id: str
    severity: Severity
    title: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    recommendation: Optional[str] = None
    cwe_id: Optional[str] = None

    # PR review fields
    finding_type: Optional[str] = None
    attack_scenario: Optional[str] = None
    evidence: Optional[str] = None

    def to_dict(self) -> dict:
        base = {
            "id": self.id,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "recommendation": self.recommendation,
            "cwe_id": self.cwe_id,
        }
        if self.finding_type:
            base["finding_type"] = self.finding_type
        if self.attack_scenario:
            base["attack_scenario"] = self.attack_scenario
        if self.evidence:
            base["evidence"] = self.evidence
        return base
