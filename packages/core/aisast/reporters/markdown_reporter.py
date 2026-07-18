"""Markdown output reporter"""

import re
from datetime import datetime
from pathlib import Path
from typing import Union, Optional
from aisast.models.result import ScanResult


class MarkdownReporter:
    """Generates Markdown security scan reports"""

    @staticmethod
    def save(result: ScanResult, output_path: Union[str, Path]) -> None:
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(MarkdownReporter.generate(result), encoding="utf-8")

    @staticmethod
    def generate(result: ScanResult) -> str:
        lines = []

        lines.append("# Security Scan Report")
        lines.append("")
        lines.append(f"**Repository:** `{result.repository_path}`  ")
        lines.append(f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
        lines.append(f"**Files Scanned:** {result.files_scanned}  ")

        scan_time = result.scan_time_seconds
        if scan_time >= 60:
            minutes = int(scan_time // 60)
            seconds = scan_time % 60
            time_str = f"{scan_time:.2f}s (~{minutes}m {seconds:.0f}s)"
        else:
            time_str = f"{scan_time:.2f}s"
        lines.append(f"**Scan Duration:** {time_str}  ")

        if result.total_cost_usd > 0:
            lines.append(f"**Total Cost:** ${result.total_cost_usd:.4f}  ")

        lines.append("")
        lines.append("---")
        lines.append("")

        total_issues = len(result.issues)

        if total_issues > 0:
            lines.append("## Executive Summary")
            lines.append("")

            if result.critical_count > 0:
                icon, urgency = "🔴", "**CRITICAL** - Requires immediate attention"
            elif result.high_count > 0:
                icon, urgency = "🟠", "**HIGH** - Should be fixed soon"
            elif result.medium_count > 0:
                icon, urgency = "🟡", "**MEDIUM** - Address when possible"
            else:
                icon, urgency = "🟢", "Minor issues found"

            noun = "vulnerability" if total_issues == 1 else "vulnerabilities"
            lines.append(f"{icon} **{total_issues} security {noun} found** - {urgency}")
            lines.append("")

            if result.critical_count > 0:
                lines.append(f"- 🔴 **{result.critical_count} Critical** - Require immediate attention")
            if result.high_count > 0:
                lines.append(f"- 🟠 **{result.high_count} High** - Should be fixed soon")
            if result.medium_count > 0:
                lines.append(f"- 🟡 **{result.medium_count} Medium** - Address when possible")
            if result.low_count > 0:
                lines.append(f"- 🟢 **{result.low_count} Low** - Minor issues")

            severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            primary = max(
                result.issues,
                key=lambda i: (
                    severity_order.get(i.severity.value, 0),
                    len(i.attack_scenario or ""),
                    len(i.evidence or ""),
                ),
            )
            primary_loc = (
                f"`{primary.file_path}:{primary.line_number}`"
                if primary.line_number
                else f"`{primary.file_path}`"
            )
            chain_text = primary.attack_scenario or primary.evidence or primary.description or primary.title
            chain_text = " ".join(chain_text.split())
            if len(chain_text) > 420:
                chain_text = f"{chain_text[:417]}..."

            lines.append("")
            lines.append("## Primary Exploit Chain")
            lines.append("")
            lines.append(f"**Finding:** {primary.title}")
            lines.append(f"**Location:** {primary_loc}")
            if primary.cwe_id:
                lines.append(f"**CWE:** {primary.cwe_id}")
            lines.append("")
            lines.append(chain_text)
        else:
            lines.append("## Executive Summary")
            lines.append("")
            lines.append("✅ **No security vulnerabilities found!**")
            lines.append("")
            lines.append("The security scan completed successfully with no issues detected.")

        lines.append("")
        lines.append("---")
        lines.append("")

        if total_issues > 0:
            lines.append("## Severity Distribution")
            lines.append("")
            lines.append("| Severity | Count | Percentage |")
            lines.append("|----------|-------|------------|")
            for severity_name, count in [
                ("🔴 Critical", result.critical_count),
                ("🟠 High", result.high_count),
                ("🟡 Medium", result.medium_count),
                ("🟢 Low", result.low_count),
            ]:
                if count > 0:
                    pct = (count / total_issues) * 100
                    lines.append(f"| {severity_name} | {count} | {pct:.0f}% |")

            lines.append("")
            lines.append("---")
            lines.append("")

            lines.append("## Vulnerability Overview")
            lines.append("")
            lines.append("| # | Severity | Title | Location |")
            lines.append("|---|----------|-------|----------|")

            severity_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}

            for idx, issue in enumerate(result.issues, 1):
                icon = severity_icons.get(issue.severity.value, "⚪")
                severity_text = f"{icon} {issue.severity.value.upper()}"
                title = issue.title[:60] + "..." if len(issue.title) > 60 else issue.title
                title = title.replace("|", "\\|")
                location = (
                    f"`{issue.file_path}:{issue.line_number}`"
                    if issue.line_number
                    else f"`{issue.file_path}`"
                )
                lines.append(f"| {idx} | {severity_text} | {title} | {location} |")

            lines.append("")
            lines.append("---")
            lines.append("")

            lines.append("## Detailed Findings")
            lines.append("")

            for idx, issue in enumerate(result.issues, 1):
                icon = severity_icons.get(issue.severity.value, "⚪")
                lines.append(f"### {idx}. {issue.title} [{icon} {issue.severity.value.upper()}]")
                lines.append("")
                lines.append(f"**File:** `{issue.file_path}:{issue.line_number}`  ")
                if issue.cwe_id:
                    lines.append(f"**CWE:** {issue.cwe_id}  ")
                lines.append(f"**Severity:** {icon} {issue.severity.value.capitalize()}")
                if issue.finding_type:
                    lines.append(f"**Finding Type:** {issue.finding_type.replace('_', ' ').title()}")
                lines.append("")

                lines.append("**Description:**")
                lines.append("")
                lines.append(issue.description)
                lines.append("")

                if issue.attack_scenario:
                    lines.append("**Attack Scenario:**")
                    lines.append("")
                    lines.append(issue.attack_scenario)
                    lines.append("")

                if issue.evidence:
                    lines.append("**Evidence:**")
                    lines.append("")
                    lines.append(issue.evidence)
                    lines.append("")

                if issue.code_snippet:
                    lines.append("**Code Snippet:**")
                    lines.append("")
                    ext = Path(issue.file_path).suffix.lstrip(".")
                    lang_map = {
                        "py": "python", "js": "javascript", "ts": "typescript",
                        "tsx": "typescript", "jsx": "javascript", "java": "java",
                        "go": "go", "rb": "ruby", "php": "php", "rs": "rust",
                        "cs": "csharp", "kt": "kotlin", "swift": "swift",
                    }
                    lang = lang_map.get(ext, "")
                    lines.append(f"```{lang}")
                    lines.append(issue.code_snippet)
                    lines.append("```")
                    lines.append("")

                if issue.recommendation:
                    lines.append("**Recommendation:**")
                    lines.append("")
                    lines.append(MarkdownReporter._format_recommendation(issue.recommendation))
                    lines.append("")

                if idx < len(result.issues):
                    lines.append("---")
                    lines.append("")

        lines.append("---")
        lines.append("")
        lines.append("*Generated by AISAST Security Scanner*  ")
        lines.append(f"*Report generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")

        return "\n".join(lines)

    @staticmethod
    def generate_lwra_section(lwra_report_path: Union[str, Path]) -> str:
        """
        Generate a markdown section for the LWRA report.
        Returns an empty string if the report does not exist or cannot be parsed.
        """
        from aisast.models.fix import LWRAResult

        result = LWRAResult.from_file(lwra_report_path)
        if result is None or not result.adjusted_issues:
            return ""

        sev_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "⚪"}
        lines = []

        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("## Phase 5 — LWRA Risk Adjustment")
        lines.append("")

        ctx = result.deployment_context
        env_flags = []
        if ctx.get("behind_vpn"):
            env_flags.append("VPN-only")
        if ctx.get("has_waf"):
            env_flags.append("WAF active")
        if ctx.get("has_firewall"):
            env_flags.append("firewall present")
        if ctx.get("has_rate_limiting"):
            env_flags.append("rate limiting")
        if ctx.get("environment") in ("staging", "dev"):
            env_flags.append(f"environment: {ctx.get('environment')}")

        env_summary = ", ".join(env_flags) if env_flags else "no mitigating controls detected"
        lines.append(f"**Deployment context:** {env_summary}  ")
        lines.append(
            f"**Summary:** {result.severity_reduced} severities reduced · "
            f"{result.soft_fixes_total} soft fixes generated · "
            f"{result.code_patches_total} code patches ready"
        )
        lines.append("")
        lines.append("| # | Original | Adjusted | Risk Score | Title |")
        lines.append("|---|----------|----------|------------|-------|")

        for idx, issue in enumerate(result.adjusted_issues, 1):
            orig_icon = sev_icons.get(issue.original_severity, "⚪")
            adj_icon  = sev_icons.get(issue.adjusted_severity, "⚪")
            changed   = " ↓" if issue.adjusted_severity != issue.original_severity else ""
            title_short = issue.title[:55] + "…" if len(issue.title) > 55 else issue.title
            lines.append(
                f"| {idx} | {orig_icon} {issue.original_severity.upper()} | "
                f"{adj_icon} {issue.adjusted_severity.upper()}{changed} | "
                f"{issue.risk_score:.1f} | {title_short} |"
            )

        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("### Soft Fixes & Code Patches")
        lines.append("")

        for issue in result.adjusted_issues:
            if not issue.soft_fixes and issue.code_patch is None:
                continue
            adj_icon = sev_icons.get(issue.adjusted_severity, "⚪")
            lines.append(f"#### {issue.title} [{adj_icon} {issue.adjusted_severity.upper()}]")
            lines.append("")
            lines.append(f"*Adjustment rationale:* {issue.adjustment_reason}")
            lines.append("")

            for sf in issue.soft_fixes:
                time_note = (
                    f"Time-bound: apply for ≤{sf.expiry_days} days then remove once code is fixed."
                    if sf.time_bound else "Permanent mitigation."
                )
                lines.append(f"**⚡ Soft Fix — {sf.title}** (`{sf.applies_to}`, effort: {sf.effort})")
                lines.append("")
                lines.append(sf.description)
                lines.append(f"*{time_note}*")
                lines.append("")
                lines.append("```")
                lines.append(sf.config_snippet)
                lines.append("```")
                lines.append("")

            if issue.code_patch:
                cp = issue.code_patch
                breaking = " ⚠️ **breaking change**" if cp.breaking_change else ""
                lines.append(
                    f"**🔧 1-Click Code Patch** — `{cp.file_path}:{cp.line_number}`"
                    f" (confidence: {cp.confidence}){breaking}"
                )
                lines.append("")
                lines.append(f"*{cp.explanation}*")
                if cp.test_hint:
                    lines.append(f"*After applying: {cp.test_hint}*")
                lines.append("")
                ext = Path(cp.file_path).suffix.lstrip(".")
                lang_map = {
                    "py": "python", "js": "javascript", "ts": "typescript",
                    "tsx": "typescript", "jsx": "javascript", "java": "java",
                    "go": "go", "rb": "ruby", "php": "php", "rs": "rust",
                    "cs": "csharp", "kt": "kotlin", "swift": "swift",
                }
                lang = lang_map.get(ext, "")
                lines.append("Before:")
                lines.append(f"```{lang}")
                lines.append(cp.original_code)
                lines.append("```")
                lines.append("After:")
                lines.append(f"```{lang}")
                lines.append(cp.patched_code)
                lines.append("```")
                lines.append(f"> Apply with: `aisast apply {cp.patch_id}`")
                lines.append("")

            lines.append("---")
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def _format_recommendation(recommendation: str) -> str:
        raw = recommendation or ""
        if not raw.strip():
            return raw

        normalized = raw.strip()
        normalized = re.sub(r"^\s*\d+\.\s+(\d+)\)\s+", r"\1. ", normalized)
        normalized = re.sub(r"(?<!\d)(\d+)\)\s+", r"\1. ", normalized)

        if re.search(r"\n\d+\.\s", normalized):
            return normalized

        items = re.split(r"(?=\d+\.\s+)", normalized)
        items = [item.strip() for item in items if item.strip()]
        has_numbered = any(re.match(r"\d+\.\s+", item) for item in items)

        if not has_numbered or len(items) == 0:
            return normalized

        formatted = []
        for item in items:
            match = re.match(r"(\d+)\.\s+(.*)", item, re.DOTALL)
            if match:
                num, text = match.groups()
                text = text.strip()
                text = re.sub(r"\b([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*\(\))", r"`\1`", text)
                text = re.sub(r"'([a-zA-Z_][a-zA-Z0-9_\.]*)'", r"`\1`", text)
                text = re.sub(r"([a-zA-Z0-9_\-\.]+/[a-zA-Z0-9_/\-\.]+\.[a-z]+)", r"`\1`", text)
                text = re.sub(r"\b([A-Z][A-Z0-9_]{3,})\b", r"`\1`", text)
                formatted.append(f"{num}. {text}")

        return "\n".join(formatted)
