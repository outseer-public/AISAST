"""Agent definitions for AISAST"""

from typing import Dict, Optional
from claude_agent_sdk import AgentDefinition
from aisast.prompts.loader import load_all_agent_prompts
from aisast.config import config, ThreatModelingConfig

AGENT_PROMPTS = load_all_agent_prompts()


def create_agent_definitions(
    cli_model: Optional[str] = None,
    threat_modeling_context: Optional[str] = None,
    delta_context: Optional[str] = None,
    methodology: str = ThreatModelingConfig.DEFAULT_METHODOLOGY,
) -> Dict[str, AgentDefinition]:
    """
    Create agent definitions with optional CLI model override.

    Priority hierarchy:
    1. Per-agent env vars (AISAST_<AGENT>_MODEL) - highest priority
    2. cli_model parameter (from CLI --model flag)
    3. Default "sonnet" - lowest priority

    Args:
        cli_model: Optional model name from CLI --model flag.
        threat_modeling_context: Optional context injected into the threat-modeling prompt.
        delta_context: Optional context injected into the code-review prompt for delta scans.
        methodology: Threat-modeling methodology for Phase 2 — "stride" (default), "linddun",
            or "attack-trees". Unknown values fall back to "stride".
    """
    prompt_key = ThreatModelingConfig.PROMPT_KEYS.get(methodology, "threat_modeling")
    threat_modeling_prompt = AGENT_PROMPTS[prompt_key]
    if threat_modeling_context:
        parts = threat_modeling_prompt.split("\n", 1)
        if len(parts) == 2:
            threat_modeling_prompt = (
                f"{parts[0]}\n\n{threat_modeling_context.strip()}\n\n{parts[1]}"
            )
        else:
            threat_modeling_prompt = (
                f"{threat_modeling_prompt}\n\n{threat_modeling_context.strip()}"
            )

    code_review_prompt = AGENT_PROMPTS["code_review"]
    if delta_context:
        code_review_prompt = (
            f"<delta_scan_context>\n{delta_context.strip()}\n</delta_scan_context>\n\n"
            + code_review_prompt
        )

    return {
        "assessment": AgentDefinition(
            description="Analyzes codebase architecture and creates comprehensive security documentation",
            prompt=AGENT_PROMPTS["assessment"],
            tools=["Read", "Grep", "Glob", "LS", "Write"],
            model=config.get_agent_model("assessment", cli_override=cli_model),
        ),
        "threat-modeling": AgentDefinition(
            description=f"Performs {methodology.upper()} threat modeling focused on realistic, high-impact threats",
            prompt=threat_modeling_prompt,
            tools=["Read", "Grep", "Glob", "Write", "Skill"],
            model=config.get_agent_model("threat_modeling", cli_override=cli_model),
        ),
        "threat-model-diagram": AgentDefinition(
            description="Creates a visual ASCII threat model diagram from SECURITY.md and THREAT_MODEL.json",
            prompt=AGENT_PROMPTS["threat_model_diagram"],
            tools=["Read", "Write"],
            model=config.get_agent_model("threat_model_diagram", cli_override=cli_model),
        ),
        "code-review": AgentDefinition(
            description="Applies security thinking methodology to find vulnerabilities with concrete evidence",
            prompt=code_review_prompt,
            tools=["Read", "Grep", "Glob", "Write"],
            model=config.get_agent_model("code_review", cli_override=cli_model),
        ),
        "pr-code-review": AgentDefinition(
            description="Analyzes PR diffs for introduced/enabled/regressed vulnerabilities",
            prompt=AGENT_PROMPTS["pr_code_review"],
            tools=["Read", "Grep", "Glob", "Write"],
            model=config.get_agent_model("pr_code_review", cli_override=cli_model),
        ),
        "report-generator": AgentDefinition(
            description="JSON file processor that reformats VULNERABILITIES.json to scan_results.json",
            prompt=AGENT_PROMPTS["report_generator"],
            tools=["Read", "Write"],
            model=config.get_agent_model("report_generator", cli_override=cli_model),
        ),
        "lwra": AgentDefinition(
            description="Adjusts vulnerability severity based on deployment context and generates soft fixes and code patches",
            prompt=AGENT_PROMPTS["lwra"],
            tools=["Read", "Grep", "Glob", "Write"],
            model=config.get_agent_model("lwra", cli_override=cli_model),
        ),
    }


# Default instance for backward compatibility
AISAST_AGENTS = create_agent_definitions()
