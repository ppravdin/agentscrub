"""agentscrub update — check PyPI for updates and upgrade to latest release."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

from packaging.version import InvalidVersion, Version

from . import __version__

PYPI_JSON_URL = "https://pypi.org/pypi/agentscrub/json"


def parse_version_tuple(v_str: str) -> Version:
    """Parse a version using complete PEP 440 ordering semantics."""
    try:
        return Version(v_str)
    except InvalidVersion:
        return Version("0")


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
    prefix_parts = tuple(part.lower() for part in Path(sys.prefix).resolve().parts)
    pipx_layout = any(
        prefix_parts[index : index + 3] == ("pipx", "venvs", "agentscrub")
        for index in range(len(prefix_parts) - 2)
    )
    if pipx_layout:
        pipx_path = shutil.which("pipx")
        if pipx_path:
            return [pipx_path, "upgrade", "agentscrub"]

    # Default to sys.executable -m pip install --upgrade agentscrub
    cmd = [sys.executable, "-m", "pip", "install", "--upgrade", "agentscrub"]
    return cmd


def _display_process_output(result: subprocess.CompletedProcess[str]) -> None:
    """Replay captured installer output so update diagnostics reach the user."""
    for stream, output in ((sys.stdout, result.stdout), (sys.stderr, result.stderr)):
        if isinstance(output, str) and output:
            stream.write(output)
            stream.flush()


def run_update(*, check_only: bool = False, yes: bool = False) -> int:
    """Execute update workflow."""
    from .cli import p

    p(f"Checking PyPI for agentscrub updates (current: [bold]v{__version__}[/bold])...")
    try:
        remote_version = fetch_latest_pypi_version()
    except Exception as err:
        p(f"[red]Failed to check PyPI for updates:[/red] {err}")
        return 1

    current_version = parse_version_tuple(__version__)
    remote_version_parsed = parse_version_tuple(remote_version)

    if remote_version_parsed <= current_version:
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

    res = subprocess.run(cmd, capture_output=True, text=True)
    _display_process_output(res)
    output = "\n".join(
        value for value in (getattr(res, "stdout", None), getattr(res, "stderr", None))
        if isinstance(value, str)
    ).lower()
    pep668_failure = (
        "externally-managed-environment" in output
        or "externally managed environment" in output
    )
    is_pip_command = len(cmd) >= 3 and cmd[1:3] == ["-m", "pip"]
    if res.returncode != 0 and is_pip_command and pep668_failure:
        # Retry only for the specific PEP 668 protection error. Network,
        # index, dependency, and permission failures must not opt out of it.
        fallback_cmd = [*cmd, "--break-system-packages"]
        p(
            "[yellow]PyPI marked this environment as externally managed; "
            "retrying with --break-system-packages...[/yellow]"
        )
        res = subprocess.run(fallback_cmd, capture_output=True, text=True)
        _display_process_output(res)

    if res.returncode == 0:
        p(f"\n[bold green]Successfully updated agentscrub to v{remote_version}![/bold green]")
        return 0
    else:
        p(f"\n[red]Update command failed with exit code {res.returncode}.[/red]")
        return res.returncode
