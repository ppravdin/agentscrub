"""Backup rotation and rollback."""
from __future__ import annotations
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .discover import ScanTarget

BACKUP_ROOT = Path.home() / ".agentscrub" / "backups"
LOG_DIR     = Path.home() / ".agentscrub" / "logs"
_FMT = "%Y%m%d-%H%M%S"

_RSYNC_PROTECTED = (
    ".credentials.json",
    "mcp.json",
    "mcp_config.json",
    ".mcp.json",
    ".mcp-auth/",
)


def _protected_excludes(target: ScanTarget) -> list[str]:
    args: list[str] = []
    patterns = list(_RSYNC_PROTECTED)
    if target.tool == "codex":
        patterns.extend(("auth.json", "config.toml"))
    for pattern in patterns:
        args.extend(["--exclude", pattern])
    return args


@dataclass
class Backup:
    path: Path       # where the backup lives
    source: Path     # original directory it came from
    tool: str
    display: str
    created: datetime

    @property
    def age_str(self) -> str:
        delta = datetime.now() - self.created
        if delta.days == 0:
            return "today"
        if delta.days == 1:
            return "yesterday"
        return f"{delta.days}d ago"

    @property
    def size_str(self) -> str:
        r = subprocess.run(["du", "-sh", str(self.path)],
                           capture_output=True, text=True)
        return r.stdout.split()[0] if r.returncode == 0 else "?"


def backup(targets: list[ScanTarget], max_keep: int = 5) -> list[Backup]:
    """
    rsync each target into BACKUP_ROOT/<tool>/<timestamp>/.
    Rotates: keeps only the newest max_keep per tool.
    Returns the newly-created Backup objects.
    """
    BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime(_FMT)
    created: list[Backup] = []

    for target in targets:
        tool_dir = BACKUP_ROOT / target.tool
        tool_dir.mkdir(parents=True, exist_ok=True)
        dest = tool_dir / ts
        dest.mkdir(parents=True, exist_ok=True)

        r = subprocess.run(
            ["rsync", "-a", str(target.path) + "/", str(dest) + "/"],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            print(f"  [WARN] backup failed for {target.path}: {r.stderr[:200]}", flush=True)
            continue

        created.append(Backup(
            path=dest,
            source=target.path,
            tool=target.tool,
            display=target.display,
            created=datetime.now(),
        ))

        # Rotate: delete oldest beyond max_keep
        all_bups = sorted(tool_dir.iterdir())  # oldest first
        for old in all_bups[:-max_keep] if len(all_bups) > max_keep else []:
            shutil.rmtree(old, ignore_errors=True)

    return created


def list_backups(targets: list[ScanTarget]) -> list[Backup]:
    """All backups for the given targets, newest first."""
    if not BACKUP_ROOT.exists():
        return []
    tool_map = {t.tool: t for t in targets}
    result: list[Backup] = []

    for tool_dir in sorted(BACKUP_ROOT.iterdir()):
        tool = tool_dir.name
        target = tool_map.get(tool)
        if target is None:
            continue
        for ts_dir in sorted(tool_dir.iterdir(), reverse=True):
            try:
                created = datetime.strptime(ts_dir.name, _FMT)
            except ValueError:
                continue
            result.append(Backup(
                path=ts_dir,
                source=target.path,
                tool=tool,
                display=target.display,
                created=created,
            ))

    return result


def rotate_logs(max_keep: int = 30) -> None:
    """Keep only the newest max_keep daily log files."""
    if not LOG_DIR.exists():
        return
    logs = sorted(LOG_DIR.glob("*.log"))  # oldest first by name (YYYYMMDD)
    for old in logs[:-max_keep] if len(logs) > max_keep else []:
        old.unlink(missing_ok=True)


def rollback(b: Backup) -> bool:
    """Restore backup b → b.source. Returns True on success."""
    target = ScanTarget(path=b.source, tool=b.tool, display=b.display)
    r = subprocess.run(
        ["rsync", "-a", "--delete", *_protected_excludes(target), str(b.path) + "/", str(b.source) + "/"],
        capture_output=True, text=True,
    )
    return r.returncode == 0
