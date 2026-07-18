"""
AISAST - AI-Native Static Application Security Testing Scanner
"""

from aisast.scanner.scanner import Scanner
from aisast.models.issue import SecurityIssue, Severity
from aisast.models.result import ScanResult
from aisast.models.fix import LWRAResult, RiskAdjustedIssue, SoftFix, CodePatch
from aisast.reporters.markdown_reporter import MarkdownReporter
from aisast.reporters.json_reporter import JSONReporter

try:
    from importlib.metadata import version

    __version__ = version("aisast")
except Exception:
    __version__ = "1.0.0-dev"

__all__ = [
    "Scanner",
    "SecurityIssue",
    "Severity",
    "ScanResult",
    "LWRAResult",
    "RiskAdjustedIssue",
    "SoftFix",
    "CodePatch",
    "MarkdownReporter",
    "JSONReporter",
]
