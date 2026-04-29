"""Auto-discover AI coding assistant log directories on this machine."""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class ScanTarget:
    path: Path
    tool: str           # short id  e.g. "claude"
    display: str        # human label  e.g. "Claude Code"
    exclude_dirs: frozenset[str] = field(default_factory=frozenset)
    exclude_files: frozenset[str] = field(default_factory=frozenset)

    def excluded(self, p: Path) -> bool:
        if p.name in self.exclude_files:
            return True
        return any(part in self.exclude_dirs for part in p.parts)


# Registry — add new tools here, no code changes needed elsewhere
_REGISTRY: list[dict] = [
    dict(
        tool="claude",
        display="Claude Code",
        dirs=["~/.claude"],
        exclude_files={".credentials.json"},
    ),
    dict(
        tool="codex",
        display="OpenAI Codex CLI",
        dirs=["~/.codex"],
        exclude_files={"auth.json"},
    ),
    dict(
        tool="cursor",
        display="Cursor / Antigravity",
        dirs=["~/.antigravity-server", "~/.cursor/logs"],
        exclude_dirs={"bin", "extensions", "node_modules"},
    ),
    dict(
        tool="aider",
        display="Aider",
        dirs=["~/.aider"],
    ),
    dict(
        tool="continue",
        display="Continue",
        dirs=["~/.continue"],
    ),
    dict(
        tool="windsurf",
        display="Windsurf",
        dirs=["~/.windsurf"],
        exclude_dirs={"extensions"},
    ),
    dict(
        tool="zed",
        display="Zed AI",
        dirs=["~/.config/zed/conversations"],
    ),
]


def discover(extra: list[Path] | None = None) -> list[ScanTarget]:
    """Return every known AI-tool dir that exists on this machine, plus any extras."""
    targets: list[ScanTarget] = []
    seen: set[Path] = set()

    for spec in _REGISTRY:
        for raw in spec["dirs"]:
            p = Path(raw).expanduser()
            if p.exists() and p not in seen:
                seen.add(p)
                targets.append(ScanTarget(
                    path=p,
                    tool=spec["tool"],
                    display=spec["display"],
                    exclude_dirs=frozenset(spec.get("exclude_dirs", set())),
                    exclude_files=frozenset(spec.get("exclude_files", set())),
                ))
                break  # only first existing dir per tool

    for p in (extra or []):
        p = p.expanduser().resolve()
        if p.exists() and p not in seen:
            seen.add(p)
            targets.append(ScanTarget(path=p, tool="custom", display=str(p)))

    return targets
