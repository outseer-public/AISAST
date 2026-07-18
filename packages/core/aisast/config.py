"""Configuration management for AISAST"""

import os
from pathlib import Path
from typing import Dict, Optional, Set


class LanguageConfig:
    """Configuration for supported programming languages"""

    SUPPORTED_LANGUAGES = {
        "python": [".py"],
        "javascript": [".js", ".jsx"],
        "typescript": [".ts", ".tsx"],
        "go": [".go"],
        "ruby": [".rb"],
        "java": [".java"],
        "php": [".php"],
        "csharp": [".cs"],
        "rust": [".rs"],
        "kotlin": [".kt"],
        "swift": [".swift"],
    }

    @classmethod
    def get_all_extensions(cls) -> Set[str]:
        extensions = set()
        for exts in cls.SUPPORTED_LANGUAGES.values():
            extensions.update(exts)
        return extensions

    @classmethod
    def detect_languages(cls, repo: Path, sample_size: int = 100) -> Set[str]:
        """Detect languages present in repository by sampling files."""
        languages = set()
        try:
            sample_files = list(repo.glob("**/*"))[:sample_size]
            for file in sample_files:
                if not file.is_file():
                    continue
                ext = file.suffix.lower()
                for lang, extensions in cls.SUPPORTED_LANGUAGES.items():
                    if ext in extensions:
                        languages.add(lang)
                        break
        except (OSError, PermissionError):
            pass
        return languages


class ScanConfig:
    """Configuration for scan behavior and exclusions"""

    EXCLUDED_DIRS_COMMON = {
        ".git",
        "dist",
        "build",
        ".eggs",
    }

    EXCLUDED_DIRS_PYTHON = {
        "env",
        "venv",
        ".venv",
        "__pycache__",
        ".pytest_cache",
        ".tox",
        ".mypy_cache",
    }

    EXCLUDED_DIRS_JS = {
        "node_modules",
        ".next",
        ".nuxt",
        "coverage",
        ".yarn",
        ".pnp",
    }

    EXCLUDED_DIRS_GO = {"vendor", "bin"}

    EXCLUDED_DIRS_RUBY = {"vendor/bundle", ".bundle"}

    EXCLUDED_DIRS_JAVA = {"target", ".gradle", ".mvn"}

    EXCLUDED_DIRS_CSHARP = {"bin", "obj", "packages"}

    EXCLUDED_DIRS_RUST = {"target"}

    @classmethod
    def get_excluded_dirs(cls, languages: Optional[Set[str]] = None) -> Set[str]:
        """Get exclusion directories based on detected languages."""
        dirs = cls.EXCLUDED_DIRS_COMMON.copy()

        if languages is None:
            dirs.update(cls.EXCLUDED_DIRS_PYTHON)
            dirs.update(cls.EXCLUDED_DIRS_JS)
            dirs.update(cls.EXCLUDED_DIRS_GO)
            dirs.update(cls.EXCLUDED_DIRS_RUBY)
            dirs.update(cls.EXCLUDED_DIRS_JAVA)
            dirs.update(cls.EXCLUDED_DIRS_CSHARP)
            dirs.update(cls.EXCLUDED_DIRS_RUST)
        else:
            if "python" in languages:
                dirs.update(cls.EXCLUDED_DIRS_PYTHON)
            if "javascript" in languages or "typescript" in languages:
                dirs.update(cls.EXCLUDED_DIRS_JS)
            if "go" in languages:
                dirs.update(cls.EXCLUDED_DIRS_GO)
            if "ruby" in languages:
                dirs.update(cls.EXCLUDED_DIRS_RUBY)
            if "java" in languages or "kotlin" in languages:
                dirs.update(cls.EXCLUDED_DIRS_JAVA)
            if "csharp" in languages:
                dirs.update(cls.EXCLUDED_DIRS_CSHARP)
            if "rust" in languages:
                dirs.update(cls.EXCLUDED_DIRS_RUST)

        return dirs


class ThreatModelingConfig:
    """Configuration for selectable threat-modeling methodologies (Phase 2)"""

    DEFAULT_METHODOLOGY = "stride"

    # Maps a --methodology value to the AGENT_PROMPTS key that supplies its prompt.
    # "stride" intentionally reuses the original "threat_modeling" key so the
    # default path is byte-for-byte unchanged from before methodology selection existed.
    PROMPT_KEYS = {
        "stride": "threat_modeling",
        "linddun": "threat_modeling_linddun",
        "attack-trees": "threat_modeling_attack_trees",
    }

    SUPPORTED = list(PROMPT_KEYS.keys())


class AgentConfig:
    """Configuration for agent model selection"""

    DEFAULTS = {
        "assessment": "sonnet",
        "threat_modeling": "sonnet",
        "threat_model_diagram": "sonnet",
        "code_review": "sonnet",
        "pr_code_review": "sonnet",
        "report_generator": "sonnet",
        "lwra": "sonnet",
    }

    DEFAULT_MAX_TURNS = 50
    DEFAULT_PR_REVIEW_TIMEOUT_SECONDS = 240
    DEFAULT_PR_REVIEW_ATTEMPTS = 4

    @classmethod
    def get_agent_model(cls, agent_name: str, cli_override: Optional[str] = None) -> str:
        """
        Get the model for a specific agent.

        Priority: per-agent env var > CLI override > default
        Env vars: AISAST_ASSESSMENT_MODEL, AISAST_CODE_REVIEW_MODEL, etc.
        """
        env_var = f"AISAST_{agent_name.upper()}_MODEL"
        env_value = os.getenv(env_var)
        if env_value:
            return env_value
        if cli_override:
            return cli_override
        return cls.DEFAULTS.get(agent_name, "sonnet")

    @classmethod
    def get_all_agent_models(cls) -> Dict[str, str]:
        return {agent: cls.get_agent_model(agent) for agent in cls.DEFAULTS.keys()}

    @classmethod
    def get_max_turns(cls) -> int:
        try:
            return int(os.getenv("AISAST_MAX_TURNS", cls.DEFAULT_MAX_TURNS))
        except ValueError:
            return cls.DEFAULT_MAX_TURNS

    @classmethod
    def get_pr_review_timeout_seconds(cls) -> int:
        try:
            timeout = int(
                os.getenv(
                    "AISAST_PR_REVIEW_TIMEOUT_SECONDS",
                    cls.DEFAULT_PR_REVIEW_TIMEOUT_SECONDS,
                )
            )
        except ValueError:
            return cls.DEFAULT_PR_REVIEW_TIMEOUT_SECONDS
        return timeout if timeout >= 1 else cls.DEFAULT_PR_REVIEW_TIMEOUT_SECONDS

    @classmethod
    def get_pr_review_attempts(cls) -> int:
        try:
            attempts = int(
                os.getenv("AISAST_PR_REVIEW_ATTEMPTS", cls.DEFAULT_PR_REVIEW_ATTEMPTS)
            )
        except ValueError:
            return cls.DEFAULT_PR_REVIEW_ATTEMPTS
        return attempts if attempts >= 1 else cls.DEFAULT_PR_REVIEW_ATTEMPTS


config = AgentConfig()
