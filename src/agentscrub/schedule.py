"""User-cron management for agentscrub."""
from __future__ import annotations
import shutil
import subprocess

_MARKER = "# managed by agentscrub"


def _bin() -> str:
    b = shutil.which("agentscrub")
    if not b:
        raise RuntimeError("agentscrub not found in PATH — install it first with pipx")
    return b


def _current_cron() -> str:
    r = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else ""


def install() -> str:
    """Add daily 3am agentscrub run. Returns the installed cron line."""
    cron = _current_cron()
    if _MARKER in cron:
        raise ValueError("already installed — use 'agentscrub schedule status' to see it")
    # % must be escaped in crontab; this writes one log file per day and prunes old ones
    line = (
        f"0 3 * * * mkdir -p ~/.agentscrub/logs && "
        f"{_bin()} run --yes > ~/.agentscrub/logs/$(date +\\%Y\\%m\\%d).log 2>&1 {_MARKER}"
    )
    subprocess.run(
        ["crontab", "-"],
        input=cron.rstrip() + "\n" + line + "\n",
        text=True, check=True,
    )
    return line


def uninstall() -> bool:
    """Remove agentscrub from crontab. Returns True if something was removed."""
    cron = _current_cron()
    if _MARKER not in cron:
        return False
    new = "\n".join(l for l in cron.splitlines() if _MARKER not in l) + "\n"
    subprocess.run(["crontab", "-"], input=new, text=True, check=True)
    return True


def status() -> str | None:
    """Return the installed cron line, or None."""
    for line in _current_cron().splitlines():
        if _MARKER in line:
            return line
    return None
