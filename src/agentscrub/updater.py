"""agentscrub update — check PyPI for updates and upgrade to latest release."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

from . import __version__

PYPI_JSON_URL = "https://pypi.org/pypi/agentscrub/json"


def parse_version_tuple(v_str: str) -> tuple[int, ...]:
    """Parse version string like '1.1.34' or '1.1.10rc1' into integer tuple (1, 1, 10)."""
    base = re.split(r"(?:a|b|rc|dev)", v_str, maxsplit=1, flags=re.IGNORECASE)[0]
    parts = [int(p) for p in re.findall(r"\d+", base)]
    return tuple(parts) if parts else (0, 0, 0)


def fetch_latest_pypi_version(timeout: float = 5.0) -> str:
    """Fetch latest published version string from PyPI."""
    req = urllib.request.Request(
        PYPI_JSON_URL,
        headers={"User-Agent": f"agentscrub/{__version__}"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        return str(data["info"]["version"])


def detect_installer() -> list[str]:
    """Detect if agentscrub should be updated via pipx or sys.executable pip."""
    prefix = str(Path(sys.prefix).resolve())
    executable = str(Path(sys.executable).resolve())
    if "pipx" in prefix or "/pipx/" in executable or "pipx/venvs" in executable:
        pipx_path = shutil.which("pipx")
        if pipx_path:
            return [pipx_path, "upgrade", "agentscrub"]

    # Default to sys.executable -m pip install --upgrade agentscrub
    cmd = [sys.executable, "-m", "pip", "install", "--upgrade", "agentscrub"]
    return cmd


def run_update(*, check_only: bool = False, yes: bool = False) -> int:
    """Execute update workflow."""
    from .cli import p

    p(f"Checking PyPI for agentscrub updates (current: [bold]v{__version__}[/bold])...")
    try:
        remote_version = fetch_latest_pypi_version()
    except Exception as err:
        p(f"[red]Failed to check PyPI for updates:[/red] {err}")
        return 1

    current_tuple = parse_version_tuple(__version__)
    remote_tuple = parse_version_tuple(remote_version)

    if remote_tuple <= current_tuple:
        p(f"[bold green]agentscrub is up to date (v{__version__}).[/bold green]")
        return 0

    p(f"\n[bold green]New version available![/bold green] v{__version__} -> [bold cyan]v{remote_version}[/bold cyan]\n")

    if check_only:
        p("Run [bold]agentscrub update[/bold] to upgrade to the latest release.")
        return 0

    if not yes:
        try:
            ans = input(f"Upgrade agentscrub to v{remote_version}? [Y/n]: ").strip().lower()
            if ans and not ans.startswith("y") and ans != "":
                p("[yellow]Update cancelled.[/yellow]")
                return 0
        except (KeyboardInterrupt, EOFError):
            p("\n[yellow]Update cancelled.[/yellow]")
            return 130

    cmd = detect_installer()
    p(f"Running update command: [dim]{' '.join(cmd)}[/dim]")

    res = subprocess.run(cmd)
    if res.returncode != 0 and "-m" in cmd and "pip" in cmd:
        # Retry with --break-system-packages for PEP 668 managed environments
        fallback_cmd = [*cmd, "--break-system-packages"]
        p("[yellow]Retrying with --break-system-packages...[/yellow]")
        res = subprocess.run(fallback_cmd)

    if res.returncode == 0:
        p(f"\n[bold green]Successfully updated agentscrub to v{remote_version}![/bold green]")
        return 0
    else:
        p(f"\n[red]Update command failed with exit code {res.returncode}.[/red]")
        return res.returncode
