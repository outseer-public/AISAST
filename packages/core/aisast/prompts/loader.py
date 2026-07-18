"""Prompt loading utilities for AISAST"""

from pathlib import Path
from typing import Dict, Optional

PROMPTS_DIR = Path(__file__).parent

# Agents that get shared security rules injected
SECURITY_AGENTS = {"threat_modeling", "code_review", "pr_code_review"}


def load_shared_rules() -> Optional[str]:
    shared_file = PROMPTS_DIR / "agents" / "_shared" / "security_rules.txt"
    if shared_file.exists():
        return shared_file.read_text(encoding="utf-8")
    return None


def load_prompt(name: str, category: str = "agents", inject_shared: bool = True) -> str:
    """Load a prompt from file, optionally injecting shared security rules."""
    prompt_file = PROMPTS_DIR / category / f"{name}.txt"

    if not prompt_file.exists():
        raise FileNotFoundError(
            f"Prompt file not found: {prompt_file}\n"
            f"Expected: aisast/prompts/{category}/{name}.txt"
        )

    content = prompt_file.read_text(encoding="utf-8")

    if inject_shared and category == "agents" and name in SECURITY_AGENTS:
        shared_rules = load_shared_rules()
        if shared_rules:
            lines = content.split("\n", 1)
            if len(lines) == 2:
                role_line, rest = lines
                content = f"{role_line}\n\n{shared_rules}\n{rest}"
            else:
                content = f"{shared_rules}\n\n{content}"

    return content


def load_all_agent_prompts() -> Dict[str, str]:
    """Load all agent prompts as a dictionary."""
    try:
        return {
            "assessment": load_prompt("assessment"),
            "threat_modeling": load_prompt("threat_modeling"),
            "threat_modeling_linddun": load_prompt("threat_modeling_linddun"),
            "threat_modeling_attack_trees": load_prompt("threat_modeling_attack_trees"),
            "threat_model_diagram": load_prompt("threat_model_diagram"),
            "code_review": load_prompt("code_review"),
            "pr_code_review": load_prompt("pr_code_review"),
            "report_generator": load_prompt("report_generator"),
            "lwra": load_prompt("lwra"),
        }
    except FileNotFoundError as e:
        raise RuntimeError(
            f"Failed to load AISAST prompts: {e}\n"
            f"Ensure aisast/prompts/ directory is included in package."
        ) from e
