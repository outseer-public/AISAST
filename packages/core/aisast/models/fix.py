"""Data models for LWRA fixes — soft mitigations and code patches."""

import json
from dataclasses import dataclass, field, asdict
from typing import Optional, List


@dataclass
class SoftFix:
    """A configuration-level mitigation that can be applied without code changes."""

    fix_id: str
    type: str          # waf_rule | nginx_config | apache_config | firewall_rule |
                       # http_header | rate_limit | cloudflare_rule | vpn_restriction |
                       # immediate_rotation | aws_security_group | gcp_firewall
    title: str
    description: str
    config_snippet: str
    applies_to: str    # nginx, apache, iptables, cloudflare, aws_waf …
    time_bound: bool = True
    expiry_days: int = 14
    effort: str = "low"  # low | medium | high

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CodePatch:
    """A minimal, safe code change that fixes a confirmed vulnerability."""

    patch_id: str
    file_path: str
    line_number: int
    original_code: str
    patched_code: str
    explanation: str
    confidence: str = "high"      # high | medium | low
    breaking_change: bool = False
    test_hint: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RiskAdjustedIssue:
    """A security issue after LWRA severity re-evaluation and fix generation."""

    id: str
    title: str
    original_severity: str
    adjusted_severity: str
    adjustment_reason: str
    risk_score: float                        # 1.0 – 10.0
    immediate_action_required: bool = False
    soft_fixes: List[SoftFix] = field(default_factory=list)
    code_patch: Optional[CodePatch] = None

    def to_dict(self) -> dict:
        d = {
            "id": self.id,
            "title": self.title,
            "original_severity": self.original_severity,
            "adjusted_severity": self.adjusted_severity,
            "adjustment_reason": self.adjustment_reason,
            "risk_score": self.risk_score,
            "immediate_action_required": self.immediate_action_required,
            "soft_fixes": [f.to_dict() for f in self.soft_fixes],
            "code_patch": self.code_patch.to_dict() if self.code_patch else None,
        }
        return d


@dataclass
class LWRAResult:
    """Full output of the LWRA phase."""

    deployment_context: dict
    adjusted_issues: List[RiskAdjustedIssue] = field(default_factory=list)

    @property
    def severity_reduced(self) -> int:
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        return sum(
            1 for i in self.adjusted_issues
            if sev_rank.get(i.adjusted_severity, 0) < sev_rank.get(i.original_severity, 0)
        )

    @property
    def severity_unchanged(self) -> int:
        return sum(
            1 for i in self.adjusted_issues
            if i.adjusted_severity == i.original_severity
        )

    @property
    def soft_fixes_total(self) -> int:
        return sum(len(i.soft_fixes) for i in self.adjusted_issues)

    @property
    def code_patches_total(self) -> int:
        return sum(1 for i in self.adjusted_issues if i.code_patch is not None)

    @property
    def immediate_action_count(self) -> int:
        return sum(1 for i in self.adjusted_issues if i.immediate_action_required)

    def to_dict(self) -> dict:
        return {
            "deployment_context": self.deployment_context,
            "summary": {
                "issues_analyzed": len(self.adjusted_issues),
                "severity_reduced": self.severity_reduced,
                "severity_unchanged": self.severity_unchanged,
                "soft_fixes_total": self.soft_fixes_total,
                "code_patches_total": self.code_patches_total,
                "immediate_action_required": self.immediate_action_count,
            },
            "adjusted_issues": [i.to_dict() for i in self.adjusted_issues],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_file(cls, path) -> Optional["LWRAResult"]:
        from pathlib import Path as _Path
        p = _Path(path)
        if not p.exists():
            return None
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

        issues = []
        for raw in data.get("adjusted_issues", []):
            soft_fixes = [
                SoftFix(**{k: v for k, v in sf.items() if k in SoftFix.__dataclass_fields__})
                for sf in raw.get("soft_fixes", [])
            ]
            cp_raw = raw.get("code_patch")
            code_patch = (
                CodePatch(**{k: v for k, v in cp_raw.items() if k in CodePatch.__dataclass_fields__})
                if cp_raw else None
            )
            issues.append(RiskAdjustedIssue(
                id=raw.get("id", ""),
                title=raw.get("title", ""),
                original_severity=raw.get("original_severity", "medium"),
                adjusted_severity=raw.get("adjusted_severity", "medium"),
                adjustment_reason=raw.get("adjustment_reason", ""),
                risk_score=float(raw.get("risk_score", 5.0)),
                immediate_action_required=raw.get("immediate_action_required", False),
                soft_fixes=soft_fixes,
                code_patch=code_patch,
            ))

        return cls(
            deployment_context=data.get("deployment_context", {}),
            adjusted_issues=issues,
        )
