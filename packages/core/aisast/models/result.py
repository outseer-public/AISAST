"""Scan result data model"""

import json
from dataclasses import dataclass, field
from typing import List
from aisast.models.issue import SecurityIssue


@dataclass
class ScanResult:
    """Results from a security scan"""

    repository_path: str
    issues: List[SecurityIssue] = field(default_factory=list)
    files_scanned: int = 0
    scan_time_seconds: float = 0.0
    total_cost_usd: float = 0.0
    warnings: List[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for i in self.issues if i.severity.value == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for i in self.issues if i.severity.value == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for i in self.issues if i.severity.value == "medium")

    @property
    def low_count(self) -> int:
        return sum(1 for i in self.issues if i.severity.value == "low")

    def to_dict(self) -> dict:
        result = {
            "repository_path": self.repository_path,
            "issues": [issue.to_dict() for issue in self.issues],
            "files_scanned": self.files_scanned,
            "scan_time_seconds": self.scan_time_seconds,
            "total_cost_usd": self.total_cost_usd,
            "summary": {
                "total": len(self.issues),
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            },
        }
        if self.warnings:
            result["warnings"] = self.warnings
        return result

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def to_markdown(self) -> str:
        from aisast.reporters.markdown_reporter import MarkdownReporter

        return MarkdownReporter.generate(self)
