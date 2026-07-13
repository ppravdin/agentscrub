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
    if not shutil.which("crontab"):
        raise RuntimeError("crontab not found — install cron first")
    r = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    if r.returncode == 0:
        return r.stdout
    err = (r.stderr or "").strip()
    if "no crontab for" in err.lower():
        return ""
    raise RuntimeError(err or "could not read user crontab")


def _write_cron(cron: str) -> None:
    if not shutil.which("crontab"):
        raise RuntimeError("crontab not found — install cron first")
    r = subprocess.run(["crontab", "-"], input=cron, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout or "could not write user crontab").strip())


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
    _write_cron(cron.rstrip() + "\n" + line + "\n")
    installed = status()
    if installed != line:
        raise RuntimeError("cron accepted the install but the agentscrub entry is not present in crontab")
    return line


def uninstall() -> bool:
    """Remove agentscrub from crontab. Returns True if something was removed."""
    cron = _current_cron()
    if _MARKER not in cron:
        return False
    new = "\n".join(l for l in cron.splitlines() if _MARKER not in l) + "\n"
    _write_cron(new)
    return True


def status() -> str | None:
    """Return the installed cron line, or None."""
    for line in _current_cron().splitlines():
        if _MARKER in line:
            return line
    return None
