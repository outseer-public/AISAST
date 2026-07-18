"""Interactive deployment context collector for the LWRA phase."""

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich import box
from rich.prompt import Confirm, Prompt


@dataclass
class DeploymentContext:
    """Captured deployment environment answers."""

    public_internet: bool = True
    has_waf: bool = False
    behind_vpn: bool = False
    has_firewall: bool = False
    has_rate_limiting: bool = False
    user_access: str = "public"        # public | authenticated | admin
    environment: str = "production"    # production | staging | dev
    cloud_provider: Optional[str] = None  # aws | gcp | azure | on-premise | None
    has_reverse_proxy: bool = False
    proxy_type: Optional[str] = None   # nginx | apache | cloudflare | aws_alb | other
    custom_notes: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict) -> "DeploymentContext":
        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in valid_keys})


def collect_deployment_context(console: Console) -> DeploymentContext:
    """
    Run an interactive questionnaire and return a populated DeploymentContext.
    Called once before the LWRA agent runs.
    """
    console.print()
    console.print(
        Panel(
            "[bold cyan]Phase 5: LWRA — Lightweight Risk Adjustment Agent[/bold cyan]\n\n"
            "[white]Answer a few questions about how this application is deployed.\n"
            "The agent will adjust vulnerability severity to reflect what is actually\n"
            "exploitable in your environment, and generate targeted mitigations.[/white]",
            box=box.ROUNDED,
            border_style="cyan",
        )
    )
    console.print()

    ctx = DeploymentContext()

    ctx.environment = Prompt.ask(
        "  [bold yellow]Environment[/bold yellow]",
        choices=["production", "staging", "dev"],
        default="production",
    )

    ctx.public_internet = Confirm.ask(
        "\n  [bold yellow]Is the app exposed to the public internet?[/bold yellow]",
        default=True,
    )

    ctx.behind_vpn = Confirm.ask(
        "\n  [bold yellow]Is the app only reachable via VPN or internal network?[/bold yellow]",
        default=False,
    )

    ctx.has_waf = Confirm.ask(
        "\n  [bold yellow]Is there a WAF in front of the app?[/bold yellow]\n"
        "  [dim](Cloudflare WAF, AWS WAF, ModSecurity, Azure Front Door, etc.)[/dim]",
        default=False,
    )

    ctx.has_reverse_proxy = Confirm.ask(
        "\n  [bold yellow]Is the app behind a reverse proxy or load balancer?[/bold yellow]\n"
        "  [dim](nginx, Apache, AWS ALB, Cloudflare, etc.)[/dim]",
        default=False,
    )

    if ctx.has_reverse_proxy:
        ctx.proxy_type = Prompt.ask(
            "  [bold yellow]Which reverse proxy / load balancer?[/bold yellow]",
            choices=["nginx", "apache", "cloudflare", "aws_alb", "gcp_lb", "azure_agw", "other"],
            default="nginx",
        )

    ctx.has_firewall = Confirm.ask(
        "\n  [bold yellow]Is there a network-level firewall restricting inbound connections?[/bold yellow]",
        default=False,
    )

    ctx.has_rate_limiting = Confirm.ask(
        "\n  [bold yellow]Does the app have rate limiting / throttling in place?[/bold yellow]",
        default=False,
    )

    ctx.user_access = Prompt.ask(
        "\n  [bold yellow]Who can use this application?[/bold yellow]",
        choices=["public", "authenticated", "admin"],
        default="public",
    )

    cloud_choice = Prompt.ask(
        "\n  [bold yellow]Cloud provider / hosting?[/bold yellow]",
        choices=["aws", "gcp", "azure", "on-premise", "none"],
        default="none",
    )
    ctx.cloud_provider = None if cloud_choice == "none" else cloud_choice

    console.print()
    return ctx


def save_context(ctx: DeploymentContext, aisast_dir: Path) -> Path:
    """Persist deployment context to .aisast/LWRA_CONTEXT.json."""
    path = aisast_dir / "LWRA_CONTEXT.json"
    path.write_text(ctx.to_json(), encoding="utf-8")
    return path


def load_context(aisast_dir: Path) -> Optional[DeploymentContext]:
    """Load existing deployment context if present."""
    path = aisast_dir / "LWRA_CONTEXT.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return DeploymentContext.from_dict(data)
    except Exception:
        return None
